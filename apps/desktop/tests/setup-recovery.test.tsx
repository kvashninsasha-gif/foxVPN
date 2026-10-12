import React from 'react';
import {afterEach,beforeEach,it,expect,vi} from 'vitest';
import {render,screen,fireEvent,waitFor,cleanup} from '@testing-library/react';
const ipc=vi.hoisted(()=>({invoke:vi.fn(),listen:vi.fn(async()=>()=>{})}));
vi.mock('@tauri-apps/api/core',()=>({invoke:ipc.invoke}));vi.mock('@tauri-apps/api/event',()=>({listen:ipc.listen}));
import {SetupRecovery} from '../src/SetupRecovery';
const pending={pending:true,recovery_id:'opaque-recovery',can_restore:true,phase:'saving',originally_active:true,error:null};
beforeEach(()=>{ipc.invoke.mockResolvedValue(pending)});afterEach(()=>{cleanup();vi.clearAllMocks()});
it('startup only checks recovery and does not restore or connect without consent',async()=>{
 render(<SetupRecovery native locked={false} onDone={vi.fn(async()=>{})}/>);await screen.findByText('Настройка была прервана');
 expect(ipc.invoke.mock.calls.map(([c])=>c)).toEqual(['setup_recovery_state']);fireEvent.click(screen.getByRole('button',{name:'Вернуть параметры до сбоя'}));
 expect(screen.getByRole('dialog').textContent).toContain('Подключение после возврата запускается отдельно');fireEvent.click(screen.getByRole('button',{name:'Отмена'}));
 expect(ipc.invoke.mock.calls.some(([c])=>c==='restore_setup_recovery')).toBe(false);
});
it('restoration uses the exact receipt and explicit consent, then refreshes',async()=>{
 const done=vi.fn(async()=>{});ipc.invoke.mockImplementation(async(c:string)=>{if(c==='restore_setup_recovery')return;if(c==='setup_recovery_state')return done.mock.calls.length?{...pending,pending:false}:pending;throw new Error(c)});
 render(<SetupRecovery native locked={false} onDone={done}/>);await screen.findByText('Настройка была прервана');fireEvent.click(screen.getByRole('button',{name:'Вернуть параметры до сбоя'}));fireEvent.click(screen.getByRole('button',{name:'Подтвердить восстановление'}));
 await waitFor(()=>expect(done).toHaveBeenCalledTimes(1));expect(ipc.invoke).toHaveBeenCalledWith('restore_setup_recovery',{recoveryId:'opaque-recovery',approved:true});
 expect(ipc.invoke.mock.calls.some(([c])=>c==='connect')).toBe(false);
});
it('corrupt or subsequently changed journals cannot restore and keeping current data is separately confirmed',async()=>{
 ipc.invoke.mockResolvedValue({...pending,recovery_id:null,can_restore:false,error:'Журнал не прошёл проверку'});render(<SetupRecovery native locked={false} onDone={vi.fn(async()=>{})}/>);
 await screen.findByText('Журнал не прошёл проверку');expect(screen.getByRole('button',{name:'Вернуть параметры до сбоя'}).hasAttribute('disabled')).toBe(true);
 fireEvent.click(screen.getByRole('button',{name:'Оставить текущие параметры'}));expect(ipc.invoke.mock.calls.some(([c])=>c==='discard_setup_recovery')).toBe(false);
 fireEvent.click(screen.getByRole('button',{name:'Подтвердить восстановление'}));await waitFor(()=>expect(ipc.invoke).toHaveBeenCalledWith('discard_setup_recovery',{recoveryId:null,approved:true}));
});
it('failed restoration keeps the journal visible and never claims success',async()=>{
 ipc.invoke.mockImplementation(async(c:string)=>{if(c==='setup_recovery_state')return pending;throw new Error('Остановка не подтверждена')});render(<SetupRecovery native locked={false} onDone={vi.fn(async()=>{})}/>);
 await screen.findByText('Настройка была прервана');fireEvent.click(screen.getByRole('button',{name:'Вернуть параметры до сбоя'}));fireEvent.click(screen.getByRole('button',{name:'Подтвердить восстановление'}));await screen.findByText(/Остановка не подтверждена/);expect(screen.queryByText(/Прежние параметры возвращены/)).toBeNull();
});
