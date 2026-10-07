import React from 'react';
import {afterEach,it,expect,vi} from 'vitest';
import {render,screen,fireEvent,waitFor,cleanup} from '@testing-library/react';
const ipc=vi.hoisted(()=>({invoke:vi.fn(),copy:vi.fn()}));
vi.mock('@tauri-apps/api/core',()=>({invoke:ipc.invoke}));
vi.mock('@tauri-apps/plugin-clipboard-manager',()=>({writeText:ipc.copy}));
import {Diagnostics} from '../src/Diagnostics';
afterEach(()=>{cleanup();vi.clearAllMocks();});
it('copies a useful Windows report with only the declared non-sensitive fields',async()=>{
 ipc.invoke.mockResolvedValue({version:'0.1.15',platform:'windows',architecture:'x86_64',core_present:true,core_verified:true,status:'connected',proxy_port:2090,system_vpn_supported:false,profile:'private fixture must never be copied',secret:'private fixture key'});
 render(<Diagnostics/>);fireEvent.click(screen.getByRole('button',{name:'Проверить сборку'}));
 fireEvent.click(await screen.findByRole('button',{name:'Скопировать диагностику'}));
 await waitFor(()=>expect(ipc.copy).toHaveBeenCalledOnce());
 const report=ipc.copy.mock.calls[0][0];
 expect(report).toContain('127.0.0.1:2090');expect(report).toContain('недоступен в этой сборке');expect(report).not.toContain('private fixture');
});
it('reports a missing component without claiming verified integrity',async()=>{
 ipc.invoke.mockResolvedValue({version:'0.1.15',platform:'windows',architecture:'x86_64',core_present:false,core_verified:false,status:'disconnected',proxy_port:null,system_vpn_supported:false});
 render(<Diagnostics/>);fireEvent.click(screen.getByRole('button',{name:'Проверить сборку'}));
 await screen.findByText(/Компонент VPN: отсутствует/);
 expect(screen.getByText(/Контрольная сумма: не проверена или не совпадает/)).toBeTruthy();
});
