import React from 'react';
import {afterEach,it,expect,vi} from 'vitest';
import {render,screen,fireEvent,cleanup,waitFor} from '@testing-library/react';
const ipc=vi.hoisted(()=>({invoke:vi.fn()}));
vi.mock('@tauri-apps/api/core',()=>({invoke:ipc.invoke}));
import {WindowsProxySetup} from '../src/WindowsProxySetup';
afterEach(()=>{cleanup();vi.clearAllMocks();});
it('warns that a ready local core does not configure Windows browsers',async()=>{
 ipc.invoke.mockResolvedValue({supported:true,enabled:false,matches:false,script_configured:false});
 render(<WindowsProxySetup connected port={2080}/>);
 await screen.findByText('Прокси Windows не указывает на foxVPN');
 expect(screen.getByText(/Адрес: 127.0.0.1 · порт: 2080/)).toBeTruthy();
 fireEvent.click(screen.getByRole('button',{name:'Открыть прокси Windows'}));
 await waitFor(()=>expect(ipc.invoke.mock.calls.some(([name])=>name==='open_windows_proxy_settings')).toBe(true));
 expect(ipc.invoke.mock.calls.every(([name])=>['windows_proxy_status','open_windows_proxy_settings'].includes(name))).toBe(true);
});
it('warns about a configured proxy whose local core is stopped',async()=>{
 ipc.invoke.mockResolvedValue({supported:true,enabled:true,matches:true,script_configured:false});
 render(<WindowsProxySetup connected={false} port={2090}/>);
 await screen.findByText('Прокси Windows включён, foxVPN отключён');
 expect(screen.getByText(/выключите ручной прокси Windows/)).toBeTruthy();
});
it('does not claim a verified browser route when a script is saved',async()=>{
 ipc.invoke.mockResolvedValue({supported:true,enabled:true,matches:true,script_configured:true});
 render(<WindowsProxySetup connected port={2080}/>);
 await screen.findByText(/Сохранён адрес сценария/);
 expect(screen.getByText(/Расширения браузера/)).toBeTruthy();
});
