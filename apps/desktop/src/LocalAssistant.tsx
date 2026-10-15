import React,{useEffect,useRef,useState} from 'react';
import {invoke} from '@tauri-apps/api/core';
import {listen} from '@tauri-apps/api/event';
import type {SetupReport} from './SetupAssistant';

type Info={model:string;available:boolean;phase:'idle'|'download'|'thinking';downloaded:number;total:number};
type Answer={text:string;advice:string;elapsed_ms:number};
type Progress={stage:string;downloaded:number;total:number};
export function LocalAssistant({report,locked=false}:{report:SetupReport|null;locked?:boolean}){
 const [info,setInfo]=useState<Info|null>(null),[answer,setAnswer]=useState<Answer|null>(null);
 const [busy,setBusy]=useState(false),[confirm,setConfirm]=useState(false),[message,setMessage]=useState('');
 const [progress,setProgress]=useState<Progress|null>(null);
 const generation=useRef(0),[expired,setExpired]=useState(false);
 const valid=!!report?.check_id&&!report.changed;
 useEffect(()=>{const token=++generation.current;setAnswer(null);setMessage('');setExpired(false);if(!valid)return;let alive=true;let dispose:(()=>void)|undefined;
  const expiry=setTimeout(()=>{if(alive){generation.current++;setExpired(true);setAnswer(null)}},120000);
  void invoke<Info>('ai_state').then(v=>{if(alive&&token===generation.current&&typeof v.available==='boolean')setInfo(v)}).catch(()=>{});
  void listen<Progress>('ai-progress',e=>{if(alive)setProgress(e.payload)}).then(stop=>{if(alive)dispose=stop;else stop()}).catch(()=>{});
  return()=>{alive=false;generation.current++;clearTimeout(expiry);dispose?.()};
 },[report?.check_id,report?.changed]);
 useEffect(()=>{if(!busy&&info?.phase!=='download'&&info?.phase!=='thinking')return;
  let alive=true;const timer=setInterval(()=>{void invoke<Info>('ai_state').then(v=>{if(alive)setInfo(v)}).catch(()=>{})},1000);
  return()=>{alive=false;clearInterval(timer)};
 },[busy,info?.phase]);
 async function refresh(){setInfo(await invoke<Info>('ai_state'))}
 async function download(){if(!valid||expired)return;setConfirm(false);setBusy(true);setMessage('');setProgress({stage:'download',downloaded:0,total:639446688});
  try{await invoke('ai_download',{consent:true});setMessage('Модель скачана и проверена. Теперь запустите проверку подключения и попросите объяснение.')}
  catch(e){setMessage(String(e))}finally{setBusy(false);setProgress(null);await refresh().catch(()=>{})}
 }
 async function explain(){if(!valid||!report?.check_id||expired)return;const token=generation.current;setBusy(true);setMessage('');setAnswer(null);setProgress({stage:'thinking',downloaded:0,total:639446688});
  try{const value=await invoke<Answer>('ai_explain',{checkId:report.check_id});if(token===generation.current)setAnswer(value)}catch(e){if(token===generation.current)setMessage(String(e))}
  finally{setBusy(false);setProgress(null);await refresh().catch(()=>{})}
 }
 const running=busy||(info!==null&&info.phase!=='idle');
 const stage=progress?.stage??info?.phase;
 const count=progress?.downloaded??info?.downloaded??0;
 const total=progress?.total??info?.total??639446688;
 const downloading=running&&(stage==='download'||stage==='verify');
 if(!valid)return <p className="footnote">Сначала нажмите «Проверить и настроить».</p>;
 return <div className="local-assistant">
  <h4>Помощь ИИ</h4>
  <p className="footnote">Объяснит результат этой проверки и предложит следующий шаг. Запускается только по вашей кнопке.</p>
  <details><summary>О локальном помощнике</summary><p className="footnote">Работает на вашем устройстве без отправки диагностики в интернет. Qwen3‑0.6B · отдельная загрузка около 640 МБ. Освобождает память после ответа. Настройки изменяются только по подтверждённому плану foxVPN.</p></details>
  {!info&&!report.healthy&&<p className="footnote">Помощник доступен в установленном приложении foxVPN.</p>}
  <div className="bottom-toolbar">
   {info&&!info.available&&!report.healthy&&<button className="secondary" disabled={locked||running||expired} onClick={()=>setConfirm(true)}>Скачать ИИ-помощника</button>}
   {(info?.available||report.healthy)&&<>
    <button className="secondary" disabled={locked||running||expired} onClick={()=>void explain()}>Объяснить результаты с ИИ</button>
    {!report.healthy&&<button className="secondary" disabled={locked||running||expired} onClick={()=>setConfirm(true)}>Проверить или скачать модель повторно</button>}
   </>}
   {running&&<button className="secondary" onClick={()=>{void invoke('ai_cancel').then(()=>setMessage('Останавливаем помощника…')).catch(e=>setMessage(String(e)))}}>Отменить действие ИИ</button>}
  </div>
  {expired&&<p role="status">Результаты проверки устарели. Нажмите «Проверить и настроить» ещё раз.</p>}
  {downloading&&<div role="status"><progress aria-label="Загрузка модели" value={Math.min(count,total)} max={total}/><p>{stage==='verify'?'Проверяем модель…':`Скачано ${Math.round(count/1000000)} из ${Math.round(total/1000000)} МБ`}</p></div>}
  {running&&!downloading&&<p role="status">Помощник готовит объяснение…</p>}
  {message&&<p role="status">{message}</p>}
  {answer&&<div className="ai-answer" aria-live="polite"><b>Объяснение ИИ</b><p className="ai-text">{answer.text}</p>
   <p className="footnote">{report.healthy?'Настройки не изменялись.':'Ответ ИИ может быть неточным. Настройки не изменялись.'}</p><b>Проверенный следующий шаг</b><p>{answer.advice}</p></div>}
  {confirm&&<div className="modal-backdrop"><section className="modal" role="dialog" aria-modal="true" aria-label="Загрузка ИИ-помощника">
   <h2>Скачать локальную модель?</h2><p>foxVPN скачает около 640 МБ с Hugging Face, из официального репозитория Qwen, и проверит файл перед запуском. Для сохранения потребуется свободное место на устройстве. Диагностика, серверы и ключи доступа при загрузке не передаются.</p>
   <p>Модель необязательна: обычная проверка и настройка работают без неё. На время ответа возможна дополнительная нагрузка на процессор и память.</p>
   <div className="modal-actions"><button className="secondary" onClick={()=>setConfirm(false)}>Не сейчас</button><button className="primary" disabled={locked||running||expired} onClick={()=>void download()}>Скачать модель</button></div>
  </section></div>}
 </div>;
}
