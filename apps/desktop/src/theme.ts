export type Theme='system'|'light'|'dark';
const key='foxvpn-theme';
export function readTheme():Theme {
  try { const value=localStorage.getItem(key);if(value==='light'||value==='dark')return value; }catch{}
  return 'system';
}
export function applyTheme(theme:Theme) {
  const dark=theme==='dark'||(theme==='system'&&window.matchMedia?.('(prefers-color-scheme: dark)').matches);
  document.documentElement.dataset.theme=dark?'dark':'light';
  document.documentElement.style.colorScheme=dark?'dark':'light';
}
export function saveTheme(theme:Theme) { try{localStorage.setItem(key,theme);}catch{} applyTheme(theme); }
export function watchTheme(theme:Theme) {
  applyTheme(theme);
  const media=window.matchMedia?.('(prefers-color-scheme: dark)');
  const update=()=>applyTheme(theme);
  media?.addEventListener('change',update);
  return ()=>media?.removeEventListener('change',update);
}
