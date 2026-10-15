import React from 'react';
import {afterEach,beforeEach,it,expect,vi} from 'vitest';
import {render,screen,fireEvent,waitFor,cleanup,act} from '@testing-library/react';
const ipc=vi.hoisted(()=>({invoke:vi.fn(),listen:vi.fn(async()=>()=>{})}));
vi.mock('@tauri-apps/api/core',()=>({invoke:ipc.invoke}));
vi.mock('@tauri-apps/api/event',()=>({listen:ipc.listen}));
import {LocalAssistant} from '../src/LocalAssistant';
import type {SetupReport} from '../src/SetupAssistant';
const info={model:'Qwen3-0.6B',available:false,phase:'idle',downloaded:0,total:639446688};
const report:SetupReport={items:[],action:'connect',selected:'PRIVATE_SERVER_ID',recommendation:null,tested:1,total:2,changed:false,check_id:'opaque-backend-check'};
beforeEach(()=>{ipc.invoke.mockImplementation(async(command:string)=>command==='ai_state'?info:undefined)});
afterEach(()=>{cleanup();vi.clearAllMocks();vi.useRealTimers()});
it('never downloads or starts inference automatically, and download cancellation makes no request',async()=>{
 render(<LocalAssistant report={report}/>);fireEvent.click(await screen.findByRole('button',{name:'Скачать ИИ-помощника'}));
 expect(screen.getByRole('dialog')).toBeTruthy();expect(ipc.invoke.mock.calls.map(c=>c[0])).toEqual(['ai_state']);
 fireEvent.click(screen.getByRole('button',{name:'Не сейчас'}));expect(ipc.invoke.mock.calls.map(c=>c[0])).toEqual(['ai_state']);
});
it('downloads only after explicit consent',async()=>{
 render(<LocalAssistant report={report}/>);fireEvent.click(await screen.findByRole('button',{name:'Скачать ИИ-помощника'}));
 fireEvent.click(screen.getByRole('button',{name:'Скачать модель'}));
 await waitFor(()=>expect(ipc.invoke).toHaveBeenCalledWith('ai_download',{consent:true}));
 expect(ipc.invoke.mock.calls.some(c=>c[0]==='ai_explain')).toBe(false);
});
it('sends only backend check ID and displays model output as text without performing repairs',async()=>{
 ipc.invoke.mockImplementation(async(command:string)=>command==='ai_state'?{...info,available:true}:{text:'<script>run_shell()</script>',advice:'Проверьте подключение',elapsed_ms:123});
 render(<LocalAssistant report={report}/>);fireEvent.click(await screen.findByRole('button',{name:'Объяснить результаты с ИИ'}));
 await screen.findByText('<script>run_shell()</script>');
 expect(ipc.invoke).toHaveBeenCalledWith('ai_explain',{checkId:'opaque-backend-check'});
 expect(JSON.stringify(ipc.invoke.mock.calls)).not.toContain('PRIVATE_SERVER_ID');
 expect(document.querySelector('.ai-answer script')).toBeNull();
 expect(ipc.invoke.mock.calls.every(c=>['ai_state','ai_explain'].includes(c[0]))).toBe(true);
});
it('disables explanation for changed or missing diagnostics and respects application lock',async()=>{
 ipc.invoke.mockResolvedValue({...info,available:true});
 const view=render(<LocalAssistant report={{...report,changed:true}}/>);
 expect(screen.queryByRole('button',{name:'Объяснить результаты с ИИ'})).toBeNull();
 view.rerender(<LocalAssistant report={null}/>);expect(screen.queryByRole('button',{name:'Объяснить результаты с ИИ'})).toBeNull();
 expect(ipc.invoke).not.toHaveBeenCalled();
 view.rerender(<LocalAssistant report={report} locked/>);expect((await screen.findByRole('button',{name:'Объяснить результаты с ИИ'})).hasAttribute('disabled')).toBe(true);
});
it('allows cancellation while model download is in progress',async()=>{
 ipc.invoke.mockImplementation(async(command:string)=>command==='ai_state'?{...info,phase:'download'}:undefined);
 render(<LocalAssistant report={report}/>);fireEvent.click(await screen.findByRole('button',{name:'Отменить действие ИИ'}));
 await waitFor(()=>expect(ipc.invoke).toHaveBeenCalledWith('ai_cancel'));
 expect(screen.getByRole('button',{name:'Скачать ИИ-помощника'}).hasAttribute('disabled')).toBe(true);
});
it('failed inference preserves ordinary diagnostic actions and claims no successful repair',async()=>{
 ipc.invoke.mockImplementation(async(command:string)=>{if(command==='ai_state')return {...info,available:true};throw new Error('Результаты устарели')});
 render(<LocalAssistant report={report}/>);fireEvent.click(await screen.findByRole('button',{name:'Объяснить результаты с ИИ'}));
 await screen.findByText(/Результаты устарели/);expect(screen.queryByText('Объяснение ИИ')).toBeNull();
});

it('does not expose or initialize AI before a completed diagnostic check',()=>{
 render(<LocalAssistant report={null}/>);
 expect(screen.queryByRole('button')).toBeNull();expect(ipc.invoke).not.toHaveBeenCalled();
});
it('healthy results can be explained without downloading a model or changing settings',async()=>{
 ipc.invoke.mockImplementation(async(command:string)=>command==='ai_state'?info:{text:'Всё в порядке. Подключение работает.',advice:'Ничего менять не нужно.',elapsed_ms:0});
 render(<LocalAssistant report={{...report,healthy:true}}/>);
 fireEvent.click(await screen.findByRole('button',{name:'Объяснить результаты с ИИ'}));
 await screen.findByText('Всё в порядке. Подключение работает.');
 expect(screen.queryByRole('button',{name:'Скачать ИИ-помощника'})).toBeNull();
 expect(ipc.invoke.mock.calls.every(([command])=>['ai_state','ai_explain'].includes(command))).toBe(true);
});
it('discards an old AI reply after a new diagnostic result arrives',async()=>{
 let resolve!:(value:unknown)=>void;
 ipc.invoke.mockImplementation(async(command:string)=>command==='ai_state'?{...info,available:true}:new Promise(value=>{resolve=value}));
 const view=render(<LocalAssistant report={report}/>);fireEvent.click(await screen.findByRole('button',{name:'Объяснить результаты с ИИ'}));
 view.rerender(<LocalAssistant report={{...report,check_id:'new-check'}}/>);
 await act(async()=>{resolve({text:'Устаревший совет',advice:'Старый шаг',elapsed_ms:100});await Promise.resolve()});
 expect(screen.queryByText('Устаревший совет')).toBeNull();expect(screen.queryByText('Старый шаг')).toBeNull();
});
it('expires the visible AI action and requires another explicit diagnostic check',async()=>{
 vi.useFakeTimers();ipc.invoke.mockImplementation(async(command:string)=>command==='ai_state'?{...info,available:true}:undefined);
 render(<LocalAssistant report={report}/>);await act(async()=>{await Promise.resolve()});
 await act(async()=>{vi.advanceTimersByTime(120000);await Promise.resolve()});
 expect(screen.getByText(/Результаты проверки устарели/)).toBeTruthy();
 const explain=screen.getByRole('button',{name:'Объяснить результаты с ИИ'});expect(explain.hasAttribute('disabled')).toBe(true);fireEvent.click(explain);
 expect(ipc.invoke.mock.calls.some(([command])=>command==='ai_explain')).toBe(false);vi.useRealTimers();
});
