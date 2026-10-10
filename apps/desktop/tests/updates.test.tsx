import React from 'react';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {cleanup,fireEvent,act,render,screen,within,waitFor} from '@testing-library/react';
const ipc=vi.hoisted(()=>({invoke:vi.fn(),listen:vi.fn(async()=>()=>{})}));
vi.mock('@tauri-apps/api/core',()=>({invoke:ipc.invoke}));
vi.mock('@tauri-apps/api/event',()=>({listen:ipc.listen}));
import {Updates,type UpdateInfo,type UpdateOffer} from '../src/Updates';
let info:UpdateInfo,offer:UpdateOffer|null;
const refresh=vi.fn(async()=>{});
beforeEach(()=>{info={supported:true,current:'0.1.6',auto_check:true,skipped_version:null,helper_required:false,helper_starting:false,error:null};offer={current:'0.1.6',version:'0.1.7',notes:'Новые возможности'};ipc.invoke.mockReset();ipc.listen.mockClear();refresh.mockClear();ipc.invoke.mockImplementation(async(command:string)=>{if(command==='update_state')return {...info};if(command==='check_app_update')return offer;if(command==='skip_app_update'||command==='update_preferences'||command==='cancel_app_update'||command==='install_network_helper')return;throw new Error('unexpected '+command)});});
afterEach(cleanup);
function mount(blocked=false){return render(<Updates ready showSettings blocked={blocked} onRefresh={refresh}/>)}
const installs=()=>ipc.invoke.mock.calls.filter(([c])=>c==='install_app_update');
describe('update consent and startup',()=>{
 it('component replacement keeps the dialog locked and never opens a second installer',async()=>{
  ipc.invoke.mockImplementation(async(c:string)=>{if(c==='update_state')return info;if(c==='check_app_update')return offer;if(c==='install_app_update')return new Promise(()=>{});throw Error(c)});
  mount();await screen.findByRole('dialog');fireEvent.click(screen.getByRole('button',{name:'Обновить',exact:true}));
  const progress=ipc.listen.mock.calls.find(([name])=>name==='app-update-progress')?.[1] as unknown as ((event:unknown)=>void);
  expect(progress).toBeTruthy();act(()=>progress({payload:{stage:'component',downloaded:0,total:null}}));
  expect(screen.getByRole('heading',{name:'Обновляем сетевой компонент'})).toBeTruthy();
  expect(screen.getByRole('button',{name:'Закрыть обновление'}).hasAttribute('disabled')).toBe(true);
  expect(screen.getByRole('button',{name:'Отменить скачивание'}).hasAttribute('disabled')).toBe(true);
  expect(ipc.invoke.mock.calls.some(([c])=>c==='install_network_helper')).toBe(false);
 });
 it('Windows overview exposes manual update checking with platform-specific text',async()=>{
  info.platform='windows';info.auto_check=false;offer=null;
  render(<Updates ready showSettings={false} showOverview blocked={false} onRefresh={refresh}/>);
  const button=await screen.findByRole('button',{name:'Проверить обновления'});
  expect(screen.getByText(/Windows-релизы/)).toBeTruthy();expect(screen.queryByText(/Mac-релизы/)).toBeNull();
  fireEvent.click(button);await screen.findByText('У вас актуальная версия foxVPN.');expect(installs()).toHaveLength(0);
 });
 it('Windows update consent explains proxy restoration and never invokes a macOS installer',async()=>{
  info.platform='windows';mount();await screen.findByRole('dialog');
  expect(screen.getByText(/прежний прокси восстановится/)).toBeTruthy();expect(screen.queryByText(/macOS может отдельно/)).toBeNull();
  expect(installs()).toHaveLength(0);expect(ipc.invoke.mock.calls.some(([c])=>c==='install_network_helper')).toBe(false);
 });

 it('shows both versions but never downloads without approval',async()=>{mount();await screen.findByRole('dialog');expect(within(screen.getByRole('dialog')).getByText('0.1.6')).toBeTruthy();expect(within(screen.getByRole('dialog')).getByText('0.1.7')).toBeTruthy();expect(installs()).toHaveLength(0);fireEvent.click(screen.getByRole('button',{name:'Позже',exact:true}));expect(screen.queryByRole('dialog')).toBeNull();expect(installs()).toHaveLength(0)});
 it('explicit update sends exact offered version and approval once',async()=>{ipc.invoke.mockImplementation(async(c:string)=>{if(c==='update_state')return info;if(c==='check_app_update')return offer;if(c==='install_app_update')return new Promise(()=>{});throw Error(c)});mount();await screen.findByRole('dialog');const button=screen.getByRole('button',{name:'Обновить',exact:true});fireEvent.click(button);fireEvent.click(button);expect(installs()).toHaveLength(1);expect(installs()[0][1]).toEqual({version:'0.1.7',approved:true});expect(screen.getByRole('button',{name:'Закрыть обновление'}).hasAttribute('disabled')).toBe(true);expect(document.activeElement).toBe(screen.getByRole('button',{name:'Отменить скачивание'}))});
 it('skip persists only that version and manual check can offer it again',async()=>{mount();await screen.findByRole('dialog');fireEvent.click(screen.getByRole('button',{name:'Пропустить эту версию'}));await waitFor(()=>expect(screen.queryByRole('dialog')).toBeNull());expect(ipc.invoke).toHaveBeenCalledWith('skip_app_update',{version:'0.1.7'});fireEvent.click(screen.getByRole('button',{name:'Проверить обновления'}));await screen.findByRole('dialog');expect(installs()).toHaveLength(0)});
 it('skipped version does not prompt on startup',async()=>{info.skipped_version='0.1.7';mount();await screen.findByText('Версия 0.1.6');await waitFor(()=>expect(ipc.invoke).toHaveBeenCalledWith('check_app_update',{manual:false}));expect(screen.queryByRole('dialog')).toBeNull()});
 it('disabled automatic check makes no network check until manual request',async()=>{info.auto_check=false;mount();await screen.findByText('Версия 0.1.6');expect(ipc.invoke.mock.calls.some(([c])=>c==='check_app_update')).toBe(false);fireEvent.click(screen.getByRole('button',{name:'Проверить обновления'}));await screen.findByRole('dialog')});
 it('does not show a second modal over server import',async()=>{const view=mount(true);await screen.findByText('Версия 0.1.6');await waitFor(()=>expect(ipc.invoke).toHaveBeenCalledWith('check_app_update',{manual:false}));expect(screen.queryByRole('dialog')).toBeNull();view.rerender(<Updates ready showSettings blocked={false} onRefresh={refresh}/>);await screen.findByRole('dialog')});
 it('current version stays quiet and manual check reports it',async()=>{offer=null;mount();await screen.findByText('Версия 0.1.6');await waitFor(()=>expect(ipc.invoke).toHaveBeenCalledWith('check_app_update',{manual:false}));expect(screen.queryByRole('dialog')).toBeNull();fireEvent.click(screen.getByRole('button',{name:'Проверить обновления'}));await screen.findByText('У вас актуальная версия foxVPN.')});
 it('failed signature/download remains visible and never reports success',async()=>{ipc.invoke.mockImplementation(async(c:string)=>{if(c==='update_state')return info;if(c==='check_app_update')return offer;if(c==='install_app_update')throw 'Подпись недействительна';throw Error(c)});mount();await screen.findByRole('dialog');fireEvent.click(screen.getByRole('button',{name:'Обновить',exact:true}));await screen.findByRole('alert');expect(screen.getByText('Подпись недействительна')).toBeTruthy();expect(screen.queryByText('Перезапускаем foxVPN')).toBeNull();await waitFor(()=>expect(refresh).toHaveBeenCalled())});
 it('cancel only calls cancellation while download is active',async()=>{ipc.invoke.mockImplementation(async(c:string)=>{if(c==='update_state')return info;if(c==='check_app_update')return offer;if(c==='install_app_update')return new Promise(()=>{});if(c==='cancel_app_update')return;throw Error(c)});mount();await screen.findByRole('dialog');fireEvent.click(screen.getByRole('button',{name:'Обновить',exact:true}));fireEvent.click(screen.getByRole('button',{name:'Отменить скачивание'}));expect(ipc.invoke).toHaveBeenCalledWith('cancel_app_update')});
 it('network helper asks separately without starting system installer automatically',async()=>{info.auto_check=false;info.helper_required=true;mount();await screen.findByRole('dialog',{name:'Обновите сетевой компонент'});expect(ipc.invoke.mock.calls.some(([c])=>c==='install_network_helper')).toBe(false);fireEvent.click(screen.getByRole('button',{name:'Открыть установщик'}));await waitFor(()=>expect(ipc.invoke).toHaveBeenCalledWith('install_network_helper'))});
 it('component notice closes itself once the installer finished',async()=>{
  info.auto_check=false;info.helper_required=true;
  let calls=0;
  ipc.invoke.mockImplementation(async(c:string)=>{
   if(c==='update_state'){calls+=1;return calls>1?{...info,helper_required:false}:{...info}}
   if(c==='install_network_helper')return;
   throw Error(c)});
  mount();await screen.findByRole('dialog',{name:'Обновите сетевой компонент'});
  fireEvent.click(screen.getByRole('button',{name:'Открыть установщик'}));
  await waitFor(()=>expect(screen.getAllByText(/проверит компонент автоматически/).length).toBeGreaterThan(0));
  await waitFor(()=>expect(screen.queryByRole('dialog')).toBeNull(),{timeout:6000});
  expect(screen.getAllByText('Сетевой компонент установлен. Можно подключать VPN.').length).toBeGreaterThan(0);
  await waitFor(()=>expect(refresh).toHaveBeenCalled());
 });
 it('restarting component waits instead of demanding a reinstall',async()=>{
  vi.useFakeTimers();
  try{
   info.auto_check=false;info.helper_starting=true;let calls=0;
   ipc.invoke.mockImplementation(async(c:string)=>{if(c==='update_state'){calls+=1;return calls>1?{...info,helper_starting:false}:{...info}}throw Error(c)});
   mount();await act(async()=>{});
   expect(screen.queryByRole('dialog')).toBeNull();expect(screen.getByText(/Сетевой компонент запускается/)).toBeTruthy();
   expect(ipc.invoke.mock.calls.some(([c])=>c==='install_network_helper')).toBe(false);
   await act(async()=>{await vi.advanceTimersByTimeAsync(3500)});
   expect(calls).toBeGreaterThan(1);expect(refresh).toHaveBeenCalled();
  }finally{cleanup();vi.useRealTimers()}
 });
 it('startup check error does not produce a modal and retry stays available',async()=>{ipc.invoke.mockImplementation(async(c:string)=>{if(c==='update_state')return info;if(c==='check_app_update')throw 'Нет сети';throw Error(c)});mount();await screen.findByRole('alert');expect(screen.queryByRole('dialog')).toBeNull();expect(screen.getByRole('button',{name:'Проверить обновления'}).hasAttribute('disabled')).toBe(false)});
 it('cancel is disabled while cancellation is pending and the dialog survives other busy state',async()=>{
  ipc.invoke.mockImplementation(async(c:string)=>{if(c==='update_state')return info;if(c==='check_app_update')return offer;if(c==='install_app_update'||c==='cancel_app_update')return new Promise(()=>{});throw Error(c)});
  const view=mount();await screen.findByRole('dialog');fireEvent.click(screen.getByRole('button',{name:'Обновить',exact:true}));
  view.rerender(<Updates ready showSettings blocked onRefresh={refresh}/>);expect(screen.getByRole('dialog')).toBeTruthy();
  fireEvent.click(screen.getByRole('button',{name:'Отменить скачивание'}));const button=screen.getByRole('button',{name:'Отменяем…'});expect(button.hasAttribute('disabled')).toBe(true);fireEvent.click(button);
  expect(ipc.invoke.mock.calls.filter(([c])=>c==='cancel_app_update')).toHaveLength(1);
 });
 it('keyboard focus stays within the consent dialog and returns after Later',async()=>{
  render(<div className="shell"><button>Предыдущая кнопка</button></div>);const previous=screen.getByRole('button',{name:'Предыдущая кнопка'});previous.focus();
  mount();const dialog=await screen.findByRole('dialog');await waitFor(()=>expect(document.activeElement).toBe(screen.getByRole('button',{name:'Позже',exact:true})));
  const last=screen.getByRole('button',{name:'Обновить',exact:true}),first=screen.getByRole('button',{name:'Закрыть обновление'});last.focus();fireEvent.keyDown(document,{key:'Tab'});expect(document.activeElement).toBe(first);
  fireEvent.keyDown(document,{key:'Tab',shiftKey:true});expect(document.activeElement).toBe(last);expect(dialog.contains(document.activeElement)).toBe(true);
  expect((document.querySelector('.shell') as HTMLElement).inert).toBe(true);fireEvent.click(screen.getByRole('button',{name:'Позже',exact:true}));
  expect(document.activeElement).toBe(previous);expect((document.querySelector('.shell') as HTMLElement).inert).toBe(false);expect(installs()).toHaveLength(0);
 });
 it('failed cancellation allows retry without closing the installation window',async()=>{
  ipc.invoke.mockImplementation(async(c:string)=>{if(c==='update_state')return info;if(c==='check_app_update')return offer;if(c==='install_app_update')return new Promise(()=>{});if(c==='cancel_app_update')throw 'Не удалось отменить';throw Error(c)});
  mount();await screen.findByRole('dialog');fireEvent.click(screen.getByRole('button',{name:'Обновить',exact:true}));fireEvent.click(screen.getByRole('button',{name:'Отменить скачивание'}));await screen.findByText('Не удалось отменить');expect(screen.getByRole('button',{name:'Отменить скачивание'}).hasAttribute('disabled')).toBe(false);expect(screen.getByRole('dialog')).toBeTruthy();
 });

});

it('initial updater failure leaves a retry that restores manual checking',async()=>{
 let first=true;ipc.invoke.mockImplementation(async(c:string)=>{if(c==='update_state'){if(first){first=false;throw 'Компонент занят'}return {...info,auto_check:false}}if(c==='check_app_update')return null;throw Error(c)});
 mount();await screen.findByRole('alert');fireEvent.click(screen.getByRole('button',{name:'Повторить проверку обновлений'}));
 await screen.findByText('У вас актуальная версия foxVPN.');expect(installs()).toHaveLength(0);
});
it('a failed progress listener never hides update controls',async()=>{
 ipc.listen.mockRejectedValueOnce('Нет подписки на события');info.auto_check=false;mount();await screen.findByRole('button',{name:'Проверить обновления'});expect(installs()).toHaveLength(0);
});
it('header action reopens a deferred update without another request or installation',async()=>{
 render(<div id="app-update-actions"/>);mount();await screen.findByRole('dialog');fireEvent.click(screen.getByRole('button',{name:'Позже',exact:true}));
 const checks=ipc.invoke.mock.calls.filter(([c])=>c==='check_app_update').length;
 fireEvent.click(screen.getByRole('button',{name:'Обновить приложение до 0.1.7'}));await screen.findByRole('dialog');
 expect(ipc.invoke.mock.calls.filter(([c])=>c==='check_app_update')).toHaveLength(checks);expect(installs()).toHaveLength(0);
});
it('StrictMode initialization shares the backend request and keeps the active result',async()=>{
 info.auto_check=false;render(<React.StrictMode><Updates ready showSettings blocked={false} onRefresh={refresh}/></React.StrictMode>);
 await screen.findByText('Версия 0.1.6');expect(ipc.invoke.mock.calls.filter(([c])=>c==='update_state')).toHaveLength(1);
});

it('toolbar failure remains visible on pages without an update settings panel',async()=>{
 info.auto_check=false;ipc.invoke.mockImplementation(async(c:string)=>{if(c==='update_state')return info;if(c==='check_app_update')throw 'Нет связи с GitHub';throw Error(c)});
 render(<><div id="app-update-actions"/><div id="app-update-feedback"/><Updates ready showSettings={false} blocked={false} onRefresh={refresh}/></>);
 fireEvent.click(await screen.findByRole('button',{name:'Обновления приложения'}));await screen.findByRole('alert');expect(screen.getByText('Нет связи с GitHub')).toBeTruthy();
});
