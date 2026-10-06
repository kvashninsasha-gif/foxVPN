import {afterEach,expect,it,vi} from 'vitest';
import {applyTheme,readTheme,saveTheme,watchTheme} from '../src/theme';
afterEach(()=>{localStorage.clear();vi.unstubAllGlobals();});
it('persists explicit dark choice and restores it despite light system',()=>{
 vi.stubGlobal('matchMedia',()=>({matches:false}));saveTheme('dark');expect(readTheme()).toBe('dark');applyTheme(readTheme());expect(document.documentElement.dataset.theme).toBe('dark');saveTheme('light');expect(document.documentElement.dataset.theme).toBe('light');
});
it('follows system changes only when system is selected and releases listener',()=>{
 let callback=()=>{};const media={matches:false,addEventListener:vi.fn((_e,cb)=>{callback=cb}),removeEventListener:vi.fn()};vi.stubGlobal('matchMedia',()=>media);
 const stop=watchTheme('system');media.matches=true;callback();expect(document.documentElement.dataset.theme).toBe('dark');stop();expect(media.removeEventListener).toHaveBeenCalled();applyTheme('light');expect(document.documentElement.dataset.theme).toBe('light');
});
it('invalid stored choice falls back to system',()=>{localStorage.setItem('foxvpn-theme','invalid');expect(readTheme()).toBe('system');});
