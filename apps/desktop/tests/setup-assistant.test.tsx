import React from 'react';
import {afterEach,beforeEach,it,expect,vi} from 'vitest';
import {render,screen,fireEvent,waitFor,cleanup,within} from '@testing-library/react';
const ipc=vi.hoisted(()=>({invoke:vi.fn(),listen:vi.fn(async()=>()=>{})}));
vi.mock('@tauri-apps/api/core',()=>({invoke:ipc.invoke}));
vi.mock('@tauri-apps/api/event',()=>({listen:ipc.listen}));
import {SetupAssistant,type SetupReport} from '../src/SetupAssistant';
const report:SetupReport={items:[{label:'Текущее соединение',ok:false,message:'Контрольный запрос не прошёл'}],action:'none',selected:'test',recommendation:null,tested:0,total:1,changed:false,check_id:'check',healthy:false};
const plan={id:'plan',changes:['Прокси Windows: выключен → включён'],steps:['Переподключить и проверить интернет'],blockers:[],reconnect:true};
let value:SetupReport;
beforeEach(()=>{value=structuredClone(report);ipc.invoke.mockReset();ipc.invoke.mockImplementation(async(command:string)=>{
 if(command==='setup_check')return structuredClone(value);
 if(command==='prepare_setup_plan')return structuredClone(plan);
 if(command==='snapshot')return {platform:'windows'};
 if(command==='ai_state')return {available:true,phase:'idle'};
 throw new Error('Unexpected command '+command);
})});
afterEach(()=>{cleanup();vi.clearAllMocks()});
function begin(){fireEvent.click(screen.getByRole('button',{name:'Проверить и настроить'}))}
it('starts with one action and opens one modal with a read-only repair preview',async()=>{
 render(<SetupAssistant onAction={vi.fn()} active/>);
 expect(screen.getAllByRole('button')).toHaveLength(1);expect(ipc.invoke).not.toHaveBeenCalled();begin();
 const dialog=await screen.findByRole('dialog',{name:'Ремонт подключения'});
 await within(dialog).findByRole('button',{name:'Исправить'});
 expect(screen.getAllByRole('dialog')).toHaveLength(1);
 expect(within(dialog).getAllByRole('button').map(x=>x.textContent)).toEqual(['Закрыть','Исправить']);
 expect(within(dialog).getByText('Прокси Windows: выключен → включён')).toBeTruthy();
 expect(screen.queryByRole('button',{name:'Подготовить план настройки'})).toBeNull();
 expect(ipc.invoke.mock.calls.map(([c])=>c)).toEqual(['setup_check','prepare_setup_plan']);
 fireEvent.click(within(dialog).getByRole('button',{name:'Закрыть'}));
 expect(screen.queryByRole('dialog')).toBeNull();expect(screen.getByRole('button',{name:'Проверить и настроить'})).toBe(document.activeElement);
 expect(ipc.invoke.mock.calls.some(([c])=>['apply_setup_plan','connect','stop'].includes(c))).toBe(false);
});
it('one explicit repair click applies the displayed backend plan and automatically checks the result',async()=>{
 const original=ipc.invoke.getMockImplementation()!;
 ipc.invoke.mockImplementation(async(command:string,...args:unknown[])=>{if(command==='apply_setup_plan'){value={...report,healthy:true};return {verified:true,connected:true,undo_id:'undo',message:'Проверено'}}return original(command,...args)});
 render(<SetupAssistant onAction={vi.fn()} active/>);begin();
 fireEvent.click(await screen.findByRole('button',{name:'Исправить'}));
 await screen.findByText('Всё в порядке');
 expect(ipc.invoke).toHaveBeenCalledWith('apply_setup_plan',{planId:'plan',approved:true});
 expect(ipc.invoke.mock.calls.filter(([c])=>c==='setup_check')).toHaveLength(2);
 expect(screen.getAllByRole('dialog')).toHaveLength(1);
 expect(screen.getByRole('button',{name:'Готово'})).toBeTruthy();
});
it('a healthy result has only Done and never prepares a repair or starts AI',async()=>{
 value={...report,healthy:true};render(<SetupAssistant onAction={vi.fn()} active/>);begin();await screen.findByText('Всё в порядке');
 const dialog=screen.getByRole('dialog');expect(within(dialog).getAllByRole('button').map(x=>x.textContent)).toEqual(['Готово']);
 expect(screen.getByText('Подключение работает. Ничего менять не нужно.')).toBeTruthy();expect(ipc.invoke.mock.calls.map(([c])=>c)).toEqual(['setup_check']);
});
it('stale checks cannot prepare or apply a repair',async()=>{
 value={...report,changed:true};render(<SetupAssistant onAction={vi.fn()}/>);begin();await screen.findByText('Проверку нужно повторить');
 expect(screen.queryByRole('button',{name:'Исправить'})).toBeNull();expect(ipc.invoke.mock.calls.map(([c])=>c)).toEqual(['setup_check']);
});
it('blocked plans show why and cannot be applied',async()=>{
 const original=ipc.invoke.getMockImplementation()!;ipc.invoke.mockImplementation(async(command:string,...args:unknown[])=>command==='prepare_setup_plan'?{...plan,blockers:['Сначала обновите компонент']}:original(command,...args));
 render(<SetupAssistant onAction={vi.fn()}/>);begin();await screen.findByRole('alert');expect(screen.getByRole('button',{name:'Исправить'}).hasAttribute('disabled')).toBe(true);
 expect(ipc.invoke.mock.calls.some(([c])=>c==='apply_setup_plan')).toBe(false);
});
it('read-only check errors leave a retry and never claim health',async()=>{
 ipc.invoke.mockRejectedValue(new Error('Проверка недоступна'));render(<SetupAssistant onAction={vi.fn()}/>);begin();await screen.findByText(/Проверка недоступна/);
 expect(screen.queryByText('Всё в порядке')).toBeNull();expect(screen.getByRole('button',{name:'Проверить снова'})).toBeTruthy();
});
it('closing an unfinished check prevents its late result from opening or applying a plan',async()=>{
 let resolve!:(v:SetupReport)=>void;ipc.invoke.mockImplementation(()=>new Promise<SetupReport>(r=>{resolve=r}));render(<SetupAssistant onAction={vi.fn()}/>);begin();
 fireEvent.click(screen.getByRole('button',{name:'Закрыть'}));resolve(report);
 await waitFor(()=>expect(screen.queryByRole('dialog')).toBeNull());expect(ipc.invoke.mock.calls).toHaveLength(1);
});
it('macOS helper installation has its consent text in the same dialog',async()=>{
 value={...report,action:'helper'};const action=vi.fn(async()=>{});render(<SetupAssistant onAction={action}/>);begin();
 const button=await screen.findByRole('button',{name:'Обновить компонент'});expect(screen.getByText(/права администратора подтвердите в системном окне/)).toBeTruthy();expect(action).not.toHaveBeenCalled();
 fireEvent.click(button);await waitFor(()=>expect(action).toHaveBeenCalledWith('helper',expect.anything()));
 expect(screen.getAllByRole('dialog')).toHaveLength(1);expect(screen.getByRole('button',{name:'Проверить снова'})).toBeTruthy();
});
it('Windows repair explicitly previews automatic proxy changes before applying',async()=>{
 value={...report,action:'windows_proxy'};render(<SetupAssistant onAction={vi.fn()} active/>);begin();await screen.findByRole('button',{name:'Исправить'});
 expect(ipc.invoke).toHaveBeenCalledWith('prepare_setup_plan',{checkId:'check',options:{patch:{windows_proxy_auto:true},select_recommended:true,connect_after:true}});
 expect(ipc.invoke.mock.calls.some(([c])=>c==='apply_setup_plan')).toBe(false);
});
it('extra tools are mounted only after opening the details',async()=>{
 render(<SetupAssistant onAction={vi.fn()} active/>);begin();await screen.findByRole('button',{name:'Исправить'});
 expect(ipc.invoke.mock.calls.some(([c])=>c==='ai_state')).toBe(false);
 fireEvent.click(screen.getByText('Подробности и другие варианты'));await screen.findByRole('button',{name:'Объяснить результаты с ИИ'});
 expect(screen.getByRole('button',{name:'Подготовить план настройки'})).toBeTruthy();expect(ipc.invoke.mock.calls.some(([c])=>c==='apply_setup_plan')).toBe(false);
});
it('repair failures are shown after the automatic recheck and do not claim success',async()=>{
 const original=ipc.invoke.getMockImplementation()!;ipc.invoke.mockImplementation(async(command:string,...args:unknown[])=>{if(command==='apply_setup_plan')throw new Error('Прежние настройки возвращены');return original(command,...args)});
 render(<SetupAssistant onAction={vi.fn()} active/>);begin();fireEvent.click(await screen.findByRole('button',{name:'Исправить'}));
 await screen.findByText(/Прежние настройки возвращены/);await screen.findByRole('button',{name:'Исправить'});expect(screen.queryByText('Всё в порядке')).toBeNull();
 expect(ipc.invoke.mock.calls.filter(([c])=>c==='apply_setup_plan')).toHaveLength(1);
});
it('a healthy local proxy never claims that the entire Mac is protected',async()=>{
 value={...report,healthy:true,scope:'local_proxy'};render(<SetupAssistant onAction={vi.fn()} active/>);begin();
 await screen.findByText('Локальный прокси работает');
 expect(screen.queryByText('Всё в порядке')).toBeNull();
 expect(screen.getByText(/Для трафика всего Mac включите системный VPN/)).toBeTruthy();
 expect(ipc.invoke.mock.calls.map(([c])=>c)).toEqual(['setup_check']);
});
it('partial site failure does not offer a disruptive automatic repair',async()=>{
 value={...report,healthy:false,partial:true,scope:'mac_system'};render(<SetupAssistant onAction={vi.fn()} active/>);begin();
 await screen.findByText('Часть проверок связи не прошла');
 expect(screen.queryByText('Всё в порядке')).toBeNull();expect(screen.queryByRole('button',{name:'Исправить'})).toBeNull();
 expect(screen.getByRole('button',{name:'Проверить снова'})).toBeTruthy();
 expect(ipc.invoke.mock.calls.map(([c])=>c)).toEqual(['setup_check']);
});
