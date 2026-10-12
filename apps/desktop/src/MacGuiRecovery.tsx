import React,{useEffect,useState} from 'react';
import {invoke} from '@tauri-apps/api/core';
import {listen} from '@tauri-apps/api/event';
type Info={pending:boolean;restored:boolean;failed:boolean;prior_version:string|null;recovery_id:string|null;guidance?:string|null};
export function MacGuiRecovery({native,locked,onDone}:{native:boolean;locked:boolean;onDone:()=>Promise<unknown>}){
 const [info,setInfo]=useState<Info|null>(null),[message,setMessage]=useState(''),[busy,setBusy]=useState(false);
 async function refresh(){if(!native)return;try{setInfo(await invoke<Info>('gui_update_recovery')??null)}catch(e){setMessage(String(e))}}
 useEffect(()=>{if(!native)return;let alive=true,dispose:(()=>void)|undefined;void invoke<Info>('gui_update_recovery').then(v=>{if(alive)setInfo(v??null)}).catch(e=>{if(alive)setMessage(String(e))});void listen('gui-update-recovery-changed',()=>{if(alive)void refresh()}).then(stop=>{if(alive)dispose=stop;else stop()}).catch(()=>{});return()=>{alive=false;dispose?.()}},[native]);
 useEffect(()=>{if(!native||!info?.pending)return;const timer=setInterval(()=>void refresh(),1500);return()=>clearInterval(timer)},[native,info?.pending]);
 async function acknowledge(){if(!info?.recovery_id)return;setBusy(true);setMessage('');try{await invoke('acknowledge_gui_recovery',{recoveryId:info.recovery_id,approved:true});await refresh();await onDone()}catch(e){setMessage(String(e))}finally{setBusy(false)}}
 if(!info?.pending&&!info?.restored&&!info?.failed)return message?<p role="alert">{message}</p>:null;
 return <section className="panel" aria-label="Восстановление приложения"><h3>{info.pending?'Проверка нового приложения':info.restored?'Возвращено прежнее приложение':'Обновление приложения требует проверки'}</h3>
 <p>{info.guidance??(info.pending?'foxVPN ожидает загрузки профиля и интерфейса. Автоматическое подключение отложено до завершения проверки.':info.restored?`Новое приложение не подтвердило готовность. Возвращена проверенная версия ${info.prior_version??''}. Профиль сохранён; подключение запускается отдельно.`:'Автоматическое восстановление не завершено. Проверьте установленную версию и при необходимости используйте проверенный архив приложения. Профиль не заменялся резервной копией.')}</p>
 {message&&<p role="alert">{message}</p>}{!info.pending&&<><p>{info.restored?'Проблемная версия пропускается при автоматической проверке обновлений. ':''}Подтверждение закроет сообщение о восстановлении.</p><button disabled={locked||busy||!info.recovery_id} className="secondary" onClick={()=>void acknowledge()}>Результат проверен, закрыть сообщение</button></>}
 </section>;
}
