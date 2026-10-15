import React,{useEffect,useState} from 'react';
import {invoke} from '@tauri-apps/api/core';
import {listen} from '@tauri-apps/api/event';
import {LocalAssistant} from './LocalAssistant';
import {ConfigurationAssistant} from './ConfigurationAssistant';
import {useConfigurationSession,type ConfigurationSession} from './configurationSession';
export type SetupReport={items:{label:string;ok:boolean;message:string}[];action:string;selected:string|null;recommendation:{id:string;name:string;latency_ms:number}|null;tested:number;total:number;changed:boolean;check_id?:string;healthy?:boolean};
type Action='connect'|'helper'|'windows_proxy'|'add_server'|'select';
function nextSteps(report:SetupReport){
 if(report.changed)return ['Подключение изменилось во время проверки. Нажмите «Проверить и настроить» ещё раз.'];
 switch(report.action){
  case 'reinstall':return ['Скачайте свежую сборку foxVPN из нашего GitHub и переустановите приложение.','После установки повторите проверку.'];
  case 'add_server':return ['Добавьте ссылку на VPN-сервер от вашего провайдера.','Выберите добавленный сервер и повторите проверку.'];
  case 'helper':return ['Нажмите «Установить или обновить компонент macOS».','Подтвердите установку в системном окне macOS, затем повторите проверку.'];
  case 'wait_helper':return ['Подождите несколько секунд, пока сетевой компонент запустится.','Нажмите «Проверить и настроить» ещё раз.'];
  case 'windows_proxy':return ['Подготовьте план: foxVPN покажет, как изменит подключение браузеров Windows.','Проверьте предложенные изменения и подтвердите их. Приложение применит план и проверит результат.'];
  case 'connect':return ['Нажмите «Перейти к подключению».','Дождитесь подключения и повторите проверку.'];
  default:return [report.recommendation?'Подготовьте план: foxVPN предложит проверенный сервер и покажет изменения.':'Подготовьте план переподключения. foxVPN покажет изменения до их применения.','Подтвердите подходящий план. Если проверка результата не пройдёт, приложение попробует вернуть прежние настройки.'];
 }
}
export function SetupAssistant({locked=false,active=false,onAction,session}:{locked?:boolean;active?:boolean;onAction:(action:Action,report:SetupReport)=>Promise<void>;session?:ConfigurationSession}){
 const [report,setReport]=useState<SetupReport|null>(null),[busy,setBusy]=useState(false),[message,setMessage]=useState(''),[confirm,setConfirm]=useState<Action|null>(null);
 const localSession=useConfigurationSession(),configuration=session??localSession;
 const [checked,setChecked]=useState(false);
 useEffect(()=>{let alive=true,dispose:(()=>void)|undefined;void listen<string>('setup-check-progress',e=>{if(alive)setMessage(e.payload)}).then(stop=>{if(alive)dispose=stop;else stop()}).catch(()=>{});return()=>{alive=false;dispose?.()}},[]);
 async function check(){setBusy(true);setReport(null);setConfirm(null);setMessage('Проверяем подключение…');try{setReport(await invoke<SetupReport>('setup_check'));setChecked(true);setMessage('')}catch(e){setMessage(String(e))}finally{setBusy(false)}}
 async function apply(action:Action){if(!report)return;setBusy(true);setConfirm(null);try{await onAction(action,report);setReport(null);setMessage('Повторите проверку, чтобы проверить результат')}catch(e){setMessage(String(e))}finally{setBusy(false)}}
 const disabled=busy||locked||configuration.phase!==null;
 const healthy=report?.healthy===true&&!report.changed;
 const configurable=report&&!report.changed&&!['reinstall','add_server','helper','wait_helper'].includes(report.action);
 const summary=healthy?'Всё в порядке':report?.changed?'Проверку нужно повторить':report?.action==='connect'?'Сервер доступен. VPN пока отключён':'Подключению нужна настройка';
 return <section className="panel setting-panel" aria-label="Проверка и настройка"><h3>Проверка и настройка</h3><p className="footnote">Проверим подключение и подскажем, что делать. Изменения применяются только после вашего подтверждения.</p><button className="primary" disabled={disabled} onClick={()=>void check()}>{busy?'Проверяем…':'Проверить и настроить'}</button>{message&&<p role="status">{message}</p>}
  {report&&<>
   <div className={`setup-result ${healthy?'healthy':''}`} aria-live="polite"><h4>{summary}</h4>{healthy?<p>Подключение работает. Ничего менять не нужно.</p>:<ol>{nextSteps(report).map((step,i)=><li key={i}>{step}</li>)}</ol>}</div>
   {!healthy&&<div className="bottom-toolbar">{report.action==='add_server'&&<button className="secondary" disabled={disabled||report.changed} onClick={()=>void apply('add_server')}>Добавить сервер</button>}{report.action==='connect'&&<button className="primary" disabled={disabled||active||report.changed} onClick={()=>void apply('connect')}>Перейти к подключению</button>}{report.action==='helper'&&<button className="secondary" disabled={disabled||report.changed} onClick={()=>setConfirm('helper')}>Установить или обновить компонент macOS</button>}{report.action==='windows_proxy'&&!report.check_id&&<button className="primary" disabled={disabled||report.changed} onClick={()=>setConfirm('windows_proxy')}>Настроить Windows автоматически</button>}</div>}
   <details className="diagnostic-details"><summary>Подробности проверки</summary>{report.items.map((item,i)=><p key={i}><b>{item.ok?'✓':'!'} {item.label}</b> — {item.message}</p>)}{report.tested>0&&report.tested<report.total&&!active&&<p className="footnote">Проверена часть серверов: {report.tested} из {report.total}. Скорость большим файлом не измерялась.</p>}{report.recommendation&&report.recommendation.id!==report.selected&&!report.changed&&<p>Рекомендуемый сервер: <b>{report.recommendation.name}</b> · {report.recommendation.latency_ms} мс <button className="secondary" disabled={disabled||active} onClick={()=>void apply('select')}>Выбрать рекомендуемый сервер</button></p>}<p className="footnote">Проверка соединения не подтверждает отсутствие всех сетевых утечек. Windows подключает совместимые приложения через локальный прокси; VPN всего Mac требует сетевого компонента.</p></details>
   {report.check_id&&!report.changed&&<LocalAssistant report={report} locked={disabled}/>}
  </>}
  {checked&&<div hidden={!configurable&&!configuration.result&&configuration.phase===null}>{healthy?<details><summary>Изменить настройки</summary><ConfigurationAssistant report={report} locked={busy||locked} onDone={check} session={configuration}/></details>:<ConfigurationAssistant report={report} locked={busy||locked} onDone={check} session={configuration}/>}</div>}
  {confirm&&<div className="modal-backdrop"><section className="modal" role="dialog" aria-modal="true" aria-label="Подтверждение настройки"><h2>Подтвердите изменение</h2><p>{confirm==='helper'?'Откроется штатный установщик сетевого компонента macOS. Установка может перезапустить VPN. Права администратора подтверждайте только в системном окне. После завершения повторите проверку.':'foxVPN переподключит выбранный сервер и включит автоматическую настройку прокси Windows. Прежние параметры будут сохранены; сценарий настройки и автоматическое определение временно выключатся. При отключении параметры восстановятся. Если прежний ручной прокси уже указывает на foxVPN, он будет выключен. Это изменит маршрут совместимых браузеров.'}</p><div className="modal-actions"><button className="secondary" disabled={disabled} onClick={()=>setConfirm(null)}>Отмена</button><button className="primary" disabled={disabled} onClick={()=>void apply(confirm)}>Подтвердить настройку</button></div></section></div>}
 </section>;
}
