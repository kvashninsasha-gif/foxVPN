import React,{useEffect,useState} from 'react';
import {invoke} from '@tauri-apps/api/core';
import {Plus,Trash2,X,Search} from 'lucide-react';
import type {Application} from './types';

export function ApplicationExclusions({apps,visible,locked,tun,onSave,platform='macos'}:{platform?:'macos'|'windows';apps:Application[];visible:boolean;locked:boolean;tun:boolean;onSave:(apps:Application[],expected:Application[])=>Promise<void>}){
 const windows=platform==='windows';
 const [draft,setDraft]=useState<Application[]|null>(null),[base,setBase]=useState<Application[]>(apps);
 const [catalog,setCatalog]=useState<Application[]>([]),[open,setOpen]=useState(false),[query,setQuery]=useState(''),[busy,setBusy]=useState(false),[error,setError]=useState('');
 const chosen=draft??apps,dirty=draft!==null&&JSON.stringify(draft)!==JSON.stringify(apps);
 useEffect(()=>{if(draft!==null&&JSON.stringify(draft)===JSON.stringify(apps))setDraft(null)},[apps,draft]);
 function change(next:Application[]){if(draft===null)setBase(apps);setDraft(next);setError('')}
 async function list(){if(locked||busy)return;if(windows){await pick();return;}setOpen(true);setBusy(true);setError('');try{setCatalog(await invoke<Application[]>('list_macos_apps'))}catch(e){setError(String(e))}finally{setBusy(false)}}
 async function pick(){setBusy(true);setError('');try{const app=await invoke<Application|null>(windows?'pick_windows_app':'pick_macos_app');if(app){if(!chosen.some(a=>a.path===app.path))change([...chosen,app]);setOpen(false)}}catch(e){setError(String(e))}finally{setBusy(false)}}
 async function save(){setBusy(true);setError('');try{await onSave(chosen,base);setDraft(null)}catch(e){setError(String(e))}finally{setBusy(false)}}
 return <section className="panel app-exclusions" hidden={!visible} aria-label="Приложения без VPN">
  <div className="panel-heading"><h3>Приложения без VPN</h3><button className="secondary" disabled={locked||busy||chosen.length>=100} onClick={()=>void list()}><Plus size={16}/>Добавить приложение</button></div>
  <p>{windows?'Выбранные .exe работают напрямую, когда обращаются к локальному прокси foxVPN. Остальные программы этим прокси не перехватываются.':'Выбранные приложения и их встроенные вспомогательные процессы работают напрямую.'} Явные правила сайтов имеют приоритет над обычными исключениями. Отдельный выбор маршрута торрентов имеет высший приоритет.</p>
  {!windows&&!tun&&<p className="banner">Исключения начнут работать после включения «VPN всего Mac» в настройках.</p>}
  <p className="footnote">Список можно менять при работающем VPN. При сохранении приложение кратко переподключится; сетевые соединения выбранных программ потребуется открыть заново. {windows?'Вспомогательные .exe добавляются отдельно. Системный VPN Windows здесь не включается.':'Системный DNS остаётся под защитой foxVPN.'}</p>
  {chosen.length===0?<p className="empty small">{windows?'Исключений пока нет. Выберите исполняемый файл программы .exe.':'Исключений пока нет. Например, можно добавить Windows App.'}</p>:<ul className="app-exclusions-list">{chosen.map(app=><li key={app.path}><div><b>{app.name}</b><span>{app.path}</span></div><button className="icon-button" aria-label={`Убрать ${app.name} из исключений`} disabled={locked||busy} onClick={()=>change(chosen.filter(a=>a.path!==app.path))}><Trash2 size={17}/></button></li>)}</ul>}
  {error&&<p role="alert" className="notice bad">{error}</p>}
  {dirty&&<div className="bottom-toolbar"><button className="primary" disabled={locked||busy} onClick={()=>void save()}>Сохранить исключения</button><button className="secondary" disabled={busy} onClick={()=>{setDraft(null);setError('')}}>Отменить изменения исключений</button><span role="status">Есть несохранённые исключения</span></div>}
  {open&&visible&&<div className="modal-backdrop"><section className="modal app-picker" role="dialog" aria-modal="true" aria-label="Выбор приложения без VPN"><div className="modal-heading"><h2>Выберите приложение</h2><button aria-label="Закрыть выбор приложения" className="icon-button" disabled={busy} onClick={()=>setOpen(false)}><X size={20}/></button></div><label className="search"><Search size={17}/><input aria-label="Поиск приложения" placeholder="Название приложения, например Windows App" value={query} onChange={e=>setQuery(e.target.value)}/></label>{busy?<p role="status">Загружаем приложения…</p>:<ul className="app-exclusions-list app-catalog">{catalog.filter(a=>a.name.toLocaleLowerCase().includes(query.toLocaleLowerCase())).map(app=>{const selected=chosen.some(a=>a.path===app.path);return <li key={app.path}><div><b>{app.name}</b><span>{app.path}</span></div><button className="secondary" disabled={locked||selected||chosen.length>=100} aria-label={`Добавить ${app.name} в исключения`} onClick={()=>{change([...chosen,app]);setOpen(false)}}>{selected?'Добавлено':'Добавить'}</button></li>})}</ul>}{error&&<p role="alert" className="notice bad">{error}</p>}<div className="modal-actions"><button className="secondary" disabled={locked||busy} onClick={()=>void pick()}>Выбрать .app в Finder</button><button className="secondary" disabled={busy} onClick={()=>setOpen(false)}>Готово</button></div></section></div>}
 </section>
}
