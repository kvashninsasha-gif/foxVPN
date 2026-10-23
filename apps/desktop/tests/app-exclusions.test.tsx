import React from 'react';
import {beforeEach,afterEach,it,expect,vi} from 'vitest';
import {render,screen,fireEvent,waitFor,cleanup} from '@testing-library/react';
const ipc=vi.hoisted(()=>({invoke:vi.fn()}));
vi.mock('@tauri-apps/api/core',()=>({invoke:ipc.invoke}));
import {ApplicationExclusions} from '../src/ApplicationExclusions';
const app={name:'Windows App',path:'/Applications/Windows App.app'};
beforeEach(()=>{ipc.invoke.mockReset();ipc.invoke.mockResolvedValue([app]);});afterEach(cleanup);
it('adds an installed app only to a draft and saves with original list after explicit consent',async()=>{
 const save=vi.fn(async()=>{});render(<ApplicationExclusions apps={[]} visible locked={false} tun onSave={save}/>);
 expect(ipc.invoke).not.toHaveBeenCalled();
 fireEvent.click(screen.getByRole('button',{name:'Добавить приложение'}));
 fireEvent.change(screen.getByRole('textbox',{name:'Поиск приложения'}),{target:{value:'windows'}});
 fireEvent.click(await screen.findByRole('button',{name:'Добавить Windows App в исключения'}));
 expect(save).not.toHaveBeenCalled();expect(screen.getByText(app.path)).toBeTruthy();
 fireEvent.click(screen.getByRole('button',{name:'Сохранить исключения'}));
 await waitFor(()=>expect(save).toHaveBeenCalledWith([app],[]));
 expect(ipc.invoke.mock.calls.every(([c])=>c==='list_macos_apps')).toBe(true);
});
it('keeps pending selection across tabs and rejects discarding the expected baseline on fresh snapshots',async()=>{
 const save=vi.fn(async()=>{throw new Error('Исключения изменились в другом окне')});
 const {rerender}=render(<ApplicationExclusions apps={[]} visible locked={false} tun onSave={save}/>);
 fireEvent.click(screen.getByRole('button',{name:'Добавить приложение'}));fireEvent.click(await screen.findByRole('button',{name:'Добавить Windows App в исключения'}));
 const other={name:'Other',path:'/Applications/Other.app'};
 rerender(<ApplicationExclusions apps={[other]} visible={false} locked={false} tun onSave={save}/>);
 expect(screen.queryByRole('button',{name:'Сохранить исключения'})).toBeNull();
 rerender(<ApplicationExclusions apps={[other]} visible locked={false} tun onSave={save}/>);
 fireEvent.click(screen.getByRole('button',{name:'Сохранить исключения'}));
 await screen.findByRole('alert');expect(save).toHaveBeenCalledWith([app],[]);
 fireEvent.click(screen.getByRole('button',{name:'Отменить изменения исключений'}));
 expect(screen.getByText(other.path)).toBeTruthy();expect(screen.queryByText(app.path)).toBeNull();
});
it('locks modifications during VPN and explains inactive proxy mode',()=>{
 render(<ApplicationExclusions apps={[app]} visible locked tun={false} onSave={vi.fn()}/>);
 expect(screen.getByRole('button',{name:'Добавить приложение'}).hasAttribute('disabled')).toBe(true);
 expect(screen.getByRole('button',{name:'Убрать Windows App из исключений'}).hasAttribute('disabled')).toBe(true);
 expect(screen.getByText(/после включения/)).toBeTruthy();expect(ipc.invoke).not.toHaveBeenCalled();
});
it('native picker cancellation keeps selections and duplicate choice never adds a second entry',async()=>{
 const save=vi.fn(async()=>{});ipc.invoke.mockImplementation(async(c:string)=>c==='pick_macos_app'?null:[app]);
 render(<ApplicationExclusions apps={[app]} visible locked={false} tun onSave={save}/>);
 fireEvent.click(screen.getByRole('button',{name:'Добавить приложение'}));
 await screen.findByRole('button',{name:'Добавить Windows App в исключения'});
 expect(screen.getByRole('button',{name:'Добавить Windows App в исключения'}).hasAttribute('disabled')).toBe(true);
 fireEvent.click(screen.getByRole('button',{name:'Выбрать .app в Finder'}));
 await waitFor(()=>expect(ipc.invoke).toHaveBeenCalledWith('pick_macos_app'));
 expect(screen.queryByRole('button',{name:'Сохранить исключения'})).toBeNull();expect(save).not.toHaveBeenCalled();
});

it('Windows chooses exe natively without scanning Mac apps and explains proxy scope',async()=>{
 const exe={name:'Browser',path:'C:\\Apps\\browser.exe'};const save=vi.fn(async()=>{});
 ipc.invoke.mockResolvedValue(exe);
 render(<ApplicationExclusions platform="windows" apps={[]} visible locked={false} tun={false} onSave={save}/>);
 expect(screen.getByText(/к локальному прокси foxVPN/)).toBeTruthy();
 fireEvent.click(screen.getByRole('button',{name:'Добавить приложение'}));
 await waitFor(()=>expect(ipc.invoke).toHaveBeenCalledWith('pick_windows_app'));
 expect(screen.queryByRole('dialog')).toBeNull();
 fireEvent.click(await screen.findByRole('button',{name:'Сохранить исключения'}));
 await waitFor(()=>expect(save).toHaveBeenCalledWith([exe],[]));
 expect(ipc.invoke).not.toHaveBeenCalledWith('list_macos_apps');
});
