import React from 'react';
import {afterEach,beforeEach,it,expect,vi} from 'vitest';
import {render,screen,act,waitFor,cleanup} from '@testing-library/react';
const ipc=vi.hoisted(()=>({invoke:vi.fn(),listen:vi.fn(async()=>()=>{}),enabled:vi.fn(async()=>false)}));
vi.mock('@tauri-apps/api/core',()=>({invoke:ipc.invoke}));
vi.mock('@tauri-apps/api/event',()=>({listen:ipc.listen}));
vi.mock('@tauri-apps/plugin-autostart',()=>({isEnabled:ipc.enabled,enable:vi.fn(),disable:vi.fn()}));
vi.mock('@tauri-apps/plugin-clipboard-manager',()=>({readText:vi.fn(),writeText:vi.fn()}));
vi.mock('@tauri-apps/plugin-dialog',()=>({open:vi.fn(),save:vi.fn()}));
// Optional assistants and independent background polling are outside the root readiness path.
vi.mock('../src/SetupAssistant',()=>({SetupAssistant:()=>null}));
vi.mock('../src/Updates',()=>({Updates:()=>null}));
vi.mock('../src/polling',()=>({startVisiblePolling:()=>()=>{}}));
import {App} from '../src/App';
import ru from '../../../locales/ru.json';
import type {Snapshot} from '../src/types';
const fixture:Snapshot={platform:'macos',status:'disconnected',proxy_port:null,core_version:'1.14.3',connection_plan:'ready',logs:[],profile:{version:1,selected:'test',subscriptions:[],rules:[],servers:[{id:'test',name:'Проверенный профиль',address:'example.com',port:443,uuid:'public-test-fixture',transport:'tcp',security:'tls',params:{},favorite:false,group:'Основные',subscription:null,latency_ms:88,download_mbps:16.4,status:'available',successes:1,failures:0,last_error:null}],settings:{mode:'smart',tun:true,kill_switch:true,proxy_acknowledged:false,proxy_port:2080,dns_protection:true,dns_provider:'cloudflare',dns_transport:'https',auto_connect:false,start_minimized:false,restore:true,health_interval:30,failover:true,favorites_only:false,strategy:'balanced',subscription_interval:21600}}};
let resolveSnapshot:(value:Snapshot)=>void,rejectSnapshot:(error:unknown)=>void;
let frames:Map<number,FrameRequestCallback>,nextFrame:number;
const confirmations=()=>ipc.invoke.mock.calls.filter(([command])=>command==='confirm_app_readiness');
async function paint(){const batch=[...frames.entries()];frames.clear();await act(async()=>{for(const[,callback]of batch)callback(16);await Promise.resolve()})}
async function loaded(){await act(async()=>{resolveSnapshot(structuredClone(fixture));await Promise.resolve()});await screen.findByText('Проверенный профиль');await waitFor(()=>expect(screen.queryByText(ru.loading)).toBeNull())}
beforeEach(()=>{
 frames=new Map();nextFrame=0;vi.stubGlobal('requestAnimationFrame',(callback:FrameRequestCallback)=>{const id=++nextFrame;frames.set(id,callback);return id});vi.stubGlobal('cancelAnimationFrame',(id:number)=>frames.delete(id));
 const pending=new Promise<Snapshot>((resolve,reject)=>{resolveSnapshot=resolve;rejectSnapshot=reject});
 ipc.invoke.mockReset();ipc.listen.mockImplementation(async()=>()=>{});ipc.enabled.mockResolvedValue(false);
 ipc.invoke.mockImplementation(async(command:string)=>{
  if(command==='snapshot')return pending;
  if(command==='setup_recovery_state')return {pending:false};
  if(command==='gui_update_recovery')return {pending:false,restored:false,failed:false,recovery_id:null,prior_version:null};
  if(command==='confirm_app_readiness')return;
  throw new Error('Unexpected command '+command);
 });
});
afterEach(()=>{cleanup();vi.unstubAllGlobals();vi.clearAllMocks()});
it('withholds readiness during profile loading and confirms once only after loaded root content has painted',async()=>{
 render(<App/>);expect(screen.getByText(ru.loading)).toBeTruthy();expect(confirmations()).toHaveLength(0);expect(frames.size).toBe(0);
 await paint();expect(confirmations()).toHaveLength(0);
 await loaded();expect(confirmations()).toHaveLength(0);expect(frames.size).toBe(1);
 await paint();expect(screen.getByText('Проверенный профиль')).toBeTruthy();expect(confirmations()).toHaveLength(0);expect(frames.size).toBe(1);
 await paint();expect(confirmations()).toHaveLength(1);await paint();expect(confirmations()).toHaveLength(1);
 expect(ipc.invoke.mock.calls.some(([command])=>command==='connect'||command==='install_app_update')).toBe(false);
});
it('a failed initial snapshot can finish the loading indicator but never confirms readiness',async()=>{
 render(<App/>);await act(async()=>{rejectSnapshot(new Error('Профиль не загружен'));await Promise.resolve()});await screen.findByText(/Профиль не загружен/);
 expect(screen.queryByText(ru.loading)).toBeNull();await paint();await paint();expect(confirmations()).toHaveLength(0);expect(frames.size).toBe(0);
});
it('unmount during profile loading cannot confirm readiness when that snapshot later resolves',async()=>{
 const app=render(<App/>);app.unmount();await act(async()=>{resolveSnapshot(structuredClone(fixture));await Promise.resolve()});await paint();await paint();
 expect(confirmations()).toHaveLength(0);expect(frames.size).toBe(0);
});
it.each([false,true])('unmount cancels pending readiness paint callbacks (first frame already run: %s)',async(firstPaint)=>{
 const app=render(<App/>);await loaded();if(firstPaint)await paint();expect(confirmations()).toHaveLength(0);expect(frames.size).toBe(1);
 app.unmount();await paint();await paint();expect(frames.size).toBe(0);expect(confirmations()).toHaveLength(0);
});
