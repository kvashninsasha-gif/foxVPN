import React from 'react';
import {afterEach,beforeEach,it,expect,vi} from 'vitest';
import {render,screen,fireEvent,waitFor,cleanup} from '@testing-library/react';
const ipc=vi.hoisted(()=>({invoke:vi.fn(),listen:vi.fn(async()=>()=>{})}));
vi.mock('@tauri-apps/api/core',()=>({invoke:ipc.invoke}));vi.mock('@tauri-apps/api/event',()=>({listen:ipc.listen}));
import {MacGuiRecovery} from '../src/MacGuiRecovery';
const restored={pending:false,restored:true,failed:false,prior_version:'0.1.28',recovery_id:'receipt-id'};
beforeEach(()=>{ipc.invoke.mockResolvedValue(restored)});afterEach(()=>{cleanup();vi.clearAllMocks()});
it('reports recovery without acknowledging, connecting or starting another update',async()=>{
 render(<MacGuiRecovery native locked={false} onDone={vi.fn(async()=>{})}/>);await screen.findByText('Возвращено прежнее приложение');
 expect(ipc.invoke.mock.calls.map(([c])=>c)).toEqual(['gui_update_recovery']);expect(screen.getByText(/Профиль сохранён/)).toBeTruthy();
});
it('only explicit acknowledgement clears the exact receipt and refreshes',async()=>{
 const done=vi.fn(async()=>{});ipc.invoke.mockImplementation(async(c:string)=>c==='gui_update_recovery'?restored:undefined);
 render(<MacGuiRecovery native locked={false} onDone={done}/>);await screen.findByText('Возвращено прежнее приложение');fireEvent.click(screen.getByRole('button',{name:'Результат проверен, закрыть сообщение'}));
 await waitFor(()=>expect(done).toHaveBeenCalledTimes(1));expect(ipc.invoke).toHaveBeenCalledWith('acknowledge_gui_recovery',{recoveryId:'receipt-id',approved:true});
 expect(ipc.invoke.mock.calls.some(([c])=>c==='connect'||c==='install_app_update')).toBe(false);
});
it('pending readiness cannot be acknowledged and failure remains visible',async()=>{
 ipc.invoke.mockResolvedValue({...restored,pending:true,restored:false});const view=render(<MacGuiRecovery native locked={false} onDone={vi.fn(async()=>{})}/>);
 await screen.findByText('Проверка нового приложения');expect(screen.queryByRole('button')).toBeNull();view.unmount();
 ipc.invoke.mockResolvedValue({...restored,restored:false,failed:true});render(<MacGuiRecovery native locked={false} onDone={vi.fn(async()=>{})}/>);await screen.findByText('Обновление приложения требует проверки');
});
it('an acknowledgement error preserves the result and never claims readiness',async()=>{
 ipc.invoke.mockImplementation(async(c:string)=>{if(c==='gui_update_recovery')return restored;throw new Error('Журнал изменился')});render(<MacGuiRecovery native locked={false} onDone={vi.fn(async()=>{})}/>);
 await screen.findByText('Возвращено прежнее приложение');fireEvent.click(screen.getByRole('button',{name:'Результат проверен, закрыть сообщение'}));await screen.findByText(/Журнал изменился/);expect(screen.getByText('Возвращено прежнее приложение')).toBeTruthy();
});
