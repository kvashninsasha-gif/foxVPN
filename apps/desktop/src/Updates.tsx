import React,{useEffect,useRef,useState} from 'react';
import {createPortal} from 'react-dom';
import {invoke} from '@tauri-apps/api/core';
import {listen} from '@tauri-apps/api/event';
import {Download,RefreshCw,X} from 'lucide-react';
export type UpdateInfo={supported:boolean;current:string;auto_check:boolean;skipped_version:string|null;helper_required:boolean;error:string|null};
export type UpdateOffer={current:string;version:string;notes:string};
type Progress={stage:'downloading'|'verifying'|'installing';downloaded:number;total:number|null};
type Props={ready:boolean;showSettings:boolean;blocked:boolean;onRefresh:()=>Promise<unknown>};
export function Updates({ready,showSettings,blocked,onRefresh}:Props){
 const [info,setInfo]=useState<UpdateInfo|null>(null),[offer,setOffer]=useState<UpdateOffer|null>(null),[visible,setVisible]=useState(false),[phase,setPhase]=useState('idle'),[progress,setProgress]=useState<Progress|null>(null),[message,setMessage]=useState(''),[error,setError]=useState(''),[helperLater,setHelperLater]=useState(false),[helperBusy,setHelperBusy]=useState(false);
 const inFlight=useRef(false),mounted=useRef(true);
 const installing=['downloading','verifying','installing','restarting'].includes(phase);
 async function check(manual:boolean,settings?:UpdateInfo){
  if(inFlight.current)return;inFlight.current=true;setPhase('checking');if(manual){setError('');setMessage('Проверяем GitHub…')}
  try{const value=await invoke<UpdateOffer|null>('check_app_update',{manual});if(!mounted.current)return;setOffer(value);if(value&&(manual||value.version!==(settings??info)?.skipped_version)){setError('');setVisible(true);setMessage('')}else if(manual)setMessage('У вас актуальная версия foxVPN.')}
  catch(e){if(mounted.current){setError(String(e));if(manual)setMessage('')}}finally{inFlight.current=false;if(mounted.current)setPhase('idle')}
 }
 useEffect(()=>{if(!ready)return;let alive=true;mounted.current=true;let dispose:(()=>void)|undefined;
  (async()=>{try{dispose=await listen<Progress>('app-update-progress',event=>{if(alive){setProgress(event.payload);setPhase(event.payload.stage)}});if(!alive){dispose();return}
    const value=await invoke<UpdateInfo>('update_state');if(!alive)return;setInfo(value);if(value.error)setError(value.error);if(value.supported&&value.auto_check&&!value.error)await check(false,value);
   }catch{/* Older builds and web previews do not expose updater commands. */}})();
  return()=>{alive=false;mounted.current=false;dispose?.()};
 },[ready]);
 useEffect(()=>{if(!visible||installing)return;const escape=(event:KeyboardEvent)=>{if(event.key==='Escape')setVisible(false)};document.addEventListener('keydown',escape);return()=>document.removeEventListener('keydown',escape)},[visible,installing]);
 async function install(){
  if(!offer||inFlight.current)return;inFlight.current=true;setError('');setPhase('downloading');setProgress(null);
  try{await invoke('install_app_update',{version:offer.version,approved:true});if(mounted.current)setPhase('restarting')}
  catch(e){if(mounted.current){setError(String(e));setPhase('idle');await onRefresh().catch(()=>{})}}finally{inFlight.current=false}
 }
 async function skip(){if(!offer||inFlight.current)return;inFlight.current=true;try{await invoke('skip_app_update',{version:offer.version});setInfo(v=>v?{...v,skipped_version:offer.version}:v);setVisible(false)}catch(e){setError(String(e))}finally{inFlight.current=false}}
 async function toggle(value:boolean){if(inFlight.current)return;inFlight.current=true;try{await invoke('update_preferences',{enabled:value});setInfo(v=>v?{...v,auto_check:value}:v);setError('')}catch(e){setError(String(e))}finally{inFlight.current=false}}
 async function helperCheck(){setHelperBusy(true);try{const value=await invoke<UpdateInfo>('update_state');setInfo(value);await onRefresh();setMessage(value.helper_required?'Сетевой компонент ещё не обновлён. Завершите установку в системном окне macOS.':'Сетевой компонент готов. Можно подключать VPN.')}catch(e){setError(String(e))}finally{setHelperBusy(false)}}
 useEffect(()=>{const open=!blocked&&((visible&&!!offer)||(!!info?.helper_required&&!helperLater&&!visible));const shell=document.querySelector<HTMLElement>('.shell');if(open&&shell)shell.inert=true;return()=>{if(shell)shell.inert=false}},[visible,offer,blocked,info?.helper_required,helperLater]);
 if(!info?.supported)return null;
 const title=phase==='downloading'?'Скачиваем обновление':phase==='verifying'?'Проверяем подписи':phase==='installing'?'Устанавливаем обновление':phase==='restarting'?'Перезапускаем foxVPN':'Доступно обновление foxVPN';
 const dialog=visible&&offer&&!blocked?<div className="modal-backdrop update-backdrop" onClick={e=>{if(e.target===e.currentTarget&&!installing)setVisible(false)}}><section className="modal update-dialog" role="dialog" aria-modal="true" aria-labelledby="update-title"><div className="modal-heading"><h2 id="update-title">{title}</h2><button className="icon-button" aria-label="Закрыть обновление" disabled={installing} onClick={()=>setVisible(false)}><X size={21}/></button></div>
   <p className="update-version">У вас версия <b>{offer.current}</b>. Доступна версия <b>{offer.version}</b>.</p>
   <p>Обновить приложение?</p>{offer.notes&&<div className="update-notes">{offer.notes}</div>}
   <p className="footnote">Скачивание начнётся после вашего согласия. Профили и настройки сохранятся. Перед установкой VPN будет отключён, затем foxVPN перезапустится. macOS может отдельно запросить доступ к Keychain и подтверждение обновления сетевого компонента.</p>
   {error&&<div className="notice bad" role="alert">{error}</div>}
   {installing&&<div className="update-progress" role="status"><progress max={progress?.total??1} value={progress?.total?Math.min(progress.downloaded,progress.total):undefined}/><span>{title}{phase==='downloading'&&progress&&' · '+(progress.downloaded/1048576).toFixed(1)+' МБ'}{phase==='downloading'&&progress?.total&&' из '+(progress.total/1048576).toFixed(1)+' МБ'}</span></div>}
   <div className="modal-actions">{installing?<button className="secondary" disabled={!['downloading','verifying'].includes(phase)} onClick={()=>{void invoke('cancel_app_update').catch(e=>setError(String(e)))}}>Отменить скачивание</button>:<><button className="secondary" onClick={()=>void skip()}>Пропустить эту версию</button><button className="secondary" autoFocus onClick={()=>setVisible(false)}>Позже</button><button className="primary" onClick={()=>void install()}><Download size={17}/>Обновить</button></>}</div>
  </section></div>:null;
 const helperDialog=info.helper_required&&!helperLater&&!visible&&!blocked?<div className="modal-backdrop update-backdrop"><section className="modal" role="dialog" aria-modal="true" aria-labelledby="helper-update-title"><h2 id="helper-update-title">Обновите сетевой компонент</h2><p className="update-version">foxVPN {info.current} установлен. Для VPN на всём Mac подтвердите обновление сетевого компонента в установщике macOS.</p><p className="footnote">Компонент проверяет подпись приложения. После замены сборки нужно ваше подтверждение. Пароль вводите только в системном окне.</p>{error&&<div className="notice bad" role="alert">{error}</div>}{message&&<p role="status">{message}</p>}<div className="modal-actions"><button className="secondary" disabled={helperBusy} onClick={()=>setHelperLater(true)}>Позже</button><button className="secondary" disabled={helperBusy} onClick={()=>void helperCheck()}>Проверить компонент</button><button className="primary" disabled={helperBusy} onClick={async()=>{setHelperBusy(true);try{await invoke('install_network_helper');setMessage('Установщик открыт. Завершите установку в macOS, затем нажмите «Проверить компонент».')}catch(e){setError(String(e))}finally{setHelperBusy(false)}}}>Открыть установщик</button></div></section></div>:null;
 return <>{showSettings&&<section className="panel setting-panel"><div className="panel-heading"><h3>Обновления foxVPN</h3><span className="badge">Версия {info.current}</span></div><label className="switch-row"><div><b>Проверять обновления при запуске</b><span>Проверяем GitHub. Скачиваем и устанавливаем только после вашего согласия.</span></div><input type="checkbox" checked={info.auto_check} disabled={installing||phase==='checking'} onChange={e=>void toggle(e.target.checked)}/></label><p className="footnote">Предварительные Mac-релизы foxVPN · Apple Silicon. Версии для iPhone проверяются отдельно.</p><button className="secondary" disabled={installing||phase==='checking'||blocked} onClick={()=>void check(true)}><RefreshCw size={17}/>{phase==='checking'?'Проверяем…':'Проверить обновления'}</button>{info.helper_required&&<button className="secondary" onClick={()=>setHelperLater(false)}>Обновить сетевой компонент</button>}{message&&<p role="status">{message}</p>}{error&&!visible&&<div className="notice bad" role="alert">{error}</div>}</section>}{dialog&&createPortal(dialog,document.body)}{helperDialog&&createPortal(helperDialog,document.body)}</>;
}
