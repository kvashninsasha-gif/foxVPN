import React from 'react';
import {afterEach,beforeEach,it,expect,vi} from 'vitest';
import {render,screen,fireEvent,waitFor,cleanup} from '@testing-library/react';
const ipc=vi.hoisted(()=>({invoke:vi.fn(),listen:vi.fn(async()=>()=>{})}));
vi.mock('@tauri-apps/api/core',()=>({invoke:ipc.invoke}));
vi.mock('@tauri-apps/api/event',()=>({listen:ipc.listen}));
import {SetupAssistant,type SetupReport} from '../src/SetupAssistant';
const report:SetupReport={items:[{label:'Текущее соединение',ok:true,message:'HTTPS проверен'}],action:'windows_proxy',selected:'test',recommendation:null,tested:0,total:1,changed:false};
beforeEach(()=>{ipc.invoke.mockResolvedValue(structuredClone(report))});
afterEach(()=>{cleanup();vi.clearAllMocks()});
it('Windows repair requires explicit confirmation and cancel makes no changes',async()=>{
 const action=vi.fn(async()=>{});render(<SetupAssistant onAction={action} active/>);
 fireEvent.click(screen.getByRole('button',{name:'Проверить и настроить'}));
 fireEvent.click(await screen.findByRole('button',{name:'Настроить Windows автоматически'}));
 expect(action).not.toHaveBeenCalled();expect(screen.getByRole('dialog')).toBeTruthy();
 fireEvent.click(screen.getByRole('button',{name:'Отмена'}));expect(action).not.toHaveBeenCalled();
 fireEvent.click(screen.getByRole('button',{name:'Настроить Windows автоматически'}));
 fireEvent.click(screen.getByRole('button',{name:'Подтвердить настройку'}));
 await waitFor(()=>expect(action).toHaveBeenCalledWith('windows_proxy',expect.objectContaining({selected:'test'})));
 expect(ipc.invoke.mock.calls[0][0]).toBe('setup_check');expect(ipc.invoke.mock.calls.some(([command])=>command==='ai_state')).toBe(false);
});
it('macOS installer is offered as a consented action, never started by the check',async()=>{
 ipc.invoke.mockResolvedValue({...report,action:'helper'});const action=vi.fn(async()=>{});render(<SetupAssistant onAction={action}/>);
 fireEvent.click(screen.getByRole('button',{name:'Проверить и настроить'}));
 fireEvent.click(await screen.findByRole('button',{name:'Установить или обновить компонент macOS'}));
 expect(action).not.toHaveBeenCalled();expect(screen.getByText(/Установка может перезапустить VPN/)).toBeTruthy();
 fireEvent.click(screen.getByRole('button',{name:'Подтвердить настройку'}));await waitFor(()=>expect(action).toHaveBeenCalledWith('helper',expect.anything()));
});
it('active sessions cannot select another server and changed reports cannot recommend it',async()=>{
 ipc.invoke.mockResolvedValue({...report,action:'none',recommendation:{id:'other',name:'Проверенный',latency_ms:40}});
 render(<SetupAssistant onAction={vi.fn()} active/>);fireEvent.click(screen.getByRole('button',{name:'Проверить и настроить'}));
 expect((await screen.findByRole('button',{name:'Выбрать рекомендуемый сервер'})).hasAttribute('disabled')).toBe(true);
 cleanup();ipc.invoke.mockResolvedValue({...report,action:'none',changed:true,recommendation:{id:'other',name:'Устаревший',latency_ms:40}});
 render(<SetupAssistant onAction={vi.fn()}/>);fireEvent.click(screen.getByRole('button',{name:'Проверить и настроить'}));await screen.findByText(/HTTPS проверен/);
 expect(screen.queryByRole('button',{name:'Выбрать рекомендуемый сервер'})).toBeNull();
});
it('backend failure does not claim successful diagnostics or perform repairs',async()=>{
 ipc.invoke.mockRejectedValue(new Error('Проверка недоступна'));const action=vi.fn();render(<SetupAssistant onAction={action}/>);
 fireEvent.click(screen.getByRole('button',{name:'Проверить и настроить'}));await screen.findByText(/Проверка недоступна/);
 expect(action).not.toHaveBeenCalled();expect(screen.queryByText('HTTPS проверен')).toBeNull();
});
it('starts with one check action, then keeps a healthy result short and technical details collapsed',async()=>{
 ipc.invoke.mockImplementation(async(command:string)=>{
  if(command==='setup_check')return {...report,action:'none',healthy:true,check_id:'healthy-check'};
  if(command==='ai_state')return {available:false,phase:'idle'};
  if(command==='snapshot')return {platform:'windows'};
 });
 render(<SetupAssistant onAction={vi.fn()} active/>);
 expect(screen.queryByRole('button',{name:'Объяснить результаты с ИИ'})).toBeNull();
 expect(screen.queryByText('План исправления')).toBeNull();expect(ipc.invoke).not.toHaveBeenCalled();
 fireEvent.click(screen.getByRole('button',{name:'Проверить и настроить'}));
 await screen.findByText('Всё в порядке');expect(screen.getByText('Подключение работает. Ничего менять не нужно.')).toBeTruthy();
 const technical=screen.getByText(/HTTPS проверен/);expect(technical.closest('details')?.open).toBe(false);
 expect(screen.getByText('Изменить настройки').closest('details')?.open).toBe(false);
 expect(screen.queryByText('Подключению нужна настройка')).toBeNull();
 expect(ipc.invoke.mock.calls.some(([command])=>['ai_explain','ai_download','prepare_setup_plan','apply_setup_plan','connect','stop'].includes(command))).toBe(false);
});
it('never infers a healthy VPN just from successful technical checks or action none',async()=>{
 ipc.invoke.mockResolvedValue({...report,action:'none',healthy:false,check_id:'not-verified'});
 render(<SetupAssistant onAction={vi.fn()}/>);fireEvent.click(screen.getByRole('button',{name:'Проверить и настроить'}));
 await screen.findByText('Подключению нужна настройка');expect(screen.queryByText('Всё в порядке')).toBeNull();
 expect(screen.getByText(/Подготовьте план переподключения/)).toBeTruthy();
});
it('a failed check shows next steps and previews exact changes before any repair',async()=>{
 ipc.invoke.mockImplementation(async(command:string)=>{
  if(command==='setup_check')return {...report,healthy:false,check_id:'repair-check',items:[{label:'Прокси Windows',ok:false,message:'Техническая причина'}]};
  if(command==='snapshot')return {platform:'windows'};
  if(command==='ai_state')return {available:true,phase:'idle'};
  if(command==='prepare_setup_plan')return {id:'repair-plan',changes:['Прокси Windows: выключен → включён'],steps:['Переподключить сервер','Проверить подключение'],blockers:[],reconnect:true};
 });
 const action=vi.fn();render(<SetupAssistant onAction={action} active/>);fireEvent.click(screen.getByRole('button',{name:'Проверить и настроить'}));
 await screen.findByText('Подключению нужна настройка');expect(screen.getByText(/Подготовьте план: foxVPN покажет/)).toBeTruthy();
 expect(screen.getByText(/Техническая причина/).closest('details')?.open).toBe(false);
 expect(screen.queryByRole('button',{name:'Настроить Windows автоматически'})).toBeNull();
 fireEvent.click(screen.getByRole('button',{name:'Подготовить план настройки'}));
 await screen.findByText('Прокси Windows: выключен → включён');expect(screen.getByText('Переподключить сервер')).toBeTruthy();
 expect(action).not.toHaveBeenCalled();expect(ipc.invoke.mock.calls.some(([command])=>command==='apply_setup_plan')).toBe(false);
 fireEvent.click(screen.getByRole('button',{name:'Применить план'}));
 expect(screen.getByRole('dialog').textContent).toContain('Прокси Windows: выключен → включён');
 expect(ipc.invoke.mock.calls.some(([command])=>command==='apply_setup_plan')).toBe(false);
 fireEvent.click(screen.getByRole('button',{name:'Отмена'}));expect(action).not.toHaveBeenCalled();
});
it('changed diagnostics expose no AI action or applicable plan',async()=>{
 ipc.invoke.mockResolvedValue({...report,check_id:'changed-check',changed:true,healthy:false});
 render(<SetupAssistant onAction={vi.fn()}/>);fireEvent.click(screen.getByRole('button',{name:'Проверить и настроить'}));
 await screen.findByText('Проверку нужно повторить');expect(screen.queryByRole('button',{name:'Объяснить результаты с ИИ'})).toBeNull();
 expect(screen.queryByRole('button',{name:'Подготовить план настройки'})).toBeNull();
 expect(ipc.invoke.mock.calls.some(([command])=>command==='ai_state')).toBe(false);
});
