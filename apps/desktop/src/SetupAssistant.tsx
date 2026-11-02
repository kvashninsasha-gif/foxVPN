import React,{useEffect,useRef,useState} from 'react';
import {invoke} from '@tauri-apps/api/core';
import {listen} from '@tauri-apps/api/event';
import {LocalAssistant} from './LocalAssistant';
import {ConfigurationAssistant} from './ConfigurationAssistant';
import {useConfigurationSession,type ConfigurationSession} from './configurationSession';
export type SetupReport={items:{label:string;ok:boolean;message:string}[];action:string;selected:string|null;recommendation:{id:string;name:string;latency_ms:number}|null;tested:number;total:number;changed:boolean;check_id?:string;healthy?:boolean;scope?:string;partial?:boolean};
type Action='connect'|'helper'|'windows_proxy'|'add_server'|'select';
type RepairPlan={id:string;changes:string[];steps:string[];blockers:string[];reconnect:boolean;scope?:string};
function summary(report:SetupReport){
 if(report.partial&&!report.changed)return 'Часть проверок связи не прошла';
 if(report.healthy&&!report.changed&&report.scope==='local_proxy')return 'Локальный прокси работает';
 if(report.healthy&&!report.changed)return 'Всё в порядке';
 if(report.changed)return 'Проверку нужно повторить';
 if(report.action==='connect')return 'VPN пока отключён';
 if(report.action==='helper')return 'Нужно обновить сетевой компонент';
 if(report.action==='add_server')return 'Добавьте VPN-сервер';
 if(report.action==='wait_helper')return 'Сетевой компонент запускается';
 return 'Подключению нужна настройка';
}
function explanation(report:SetupReport){
 if(report.partial&&!report.changed)return 'Основное соединение работает. Повторите проверку позднее; настройки автоматически не менялись.';
 if(report.healthy&&!report.changed&&report.scope==='local_proxy')return 'Проверен только локальный прокси. Для трафика всего Mac включите системный VPN в настройках.';
 if(report.healthy&&!report.changed)return 'Подключение работает. Ничего менять не нужно.';
 if(report.changed)return 'Подключение или настройки изменились во время проверки.';
 if(report.action==='helper')return 'Откроем установщик macOS. Установка может прервать VPN; права администратора подтвердите в системном окне.';
 if(report.action==='add_server')return 'Нужна ссылка на сервер от вашего VPN-провайдера.';
 if(report.action==='wait_helper')return 'Подождите несколько секунд и повторите проверку.';
 if(report.action==='reinstall')return 'Ядро VPN не прошло проверку. Откройте «Обновления» и установите проверенную сборку foxVPN.';
 if(report.action==='connect')return 'Сервер доступен. Можно подключиться и проверить интернет.';
 return 'Проверка нашла проблему. Ниже показано, что foxVPN предлагает сделать.';
}
export function SetupAssistant({locked=false,active=false,onAction,session}:{locked?:boolean;active?:boolean;onAction:(action:Action,report:SetupReport)=>Promise<void>;session?:ConfigurationSession}){
 const [open,setOpen]=useState(false),[report,setReport]=useState<SetupReport|null>(null),[plan,setPlan]=useState<RepairPlan|null>(null);
 const [busy,setBusy]=useState(false),[message,setMessage]=useState(''),[advanced,setAdvanced]=useState(false),[installerOpened,setInstallerOpened]=useState(false);
 const localSession=useConfigurationSession(),configuration=session??localSession;
 const dialog=useRef<HTMLDialogElement>(null),entry=useRef<HTMLButtonElement>(null),generation=useRef(0),mounted=useRef(true),checking=useRef(false);
 const changing=configuration.phase==='apply'||configuration.phase==='undo'||configuration.phase==='checking';
 useEffect(()=>{mounted.current=true;return()=>{mounted.current=false;generation.current++}},[]);
 useEffect(()=>{if(!open)return;const el=dialog.current;if(el&&!el.open){if(typeof el.showModal==='function')el.showModal();else el.setAttribute('open','')}return()=>{if(el?.open&&typeof el.close==='function')el.close()}},[open]);
 useEffect(()=>{if(!plan)return;const timer=setTimeout(()=>{setPlan(null);setMessage('Проверка устарела. Нажмите «Проверить снова».')},115000);return()=>clearTimeout(timer)},[plan]);
 useEffect(()=>{let alive=true,dispose:(()=>void)|undefined;void listen<string>('setup-check-progress',e=>{if(alive&&checking.current)setMessage(e.payload)}).then(stop=>{if(alive)dispose=stop;else stop()}).catch(()=>{});return()=>{alive=false;dispose?.()}},[]);
 async function check(){
  const token=++generation.current;checking.current=true;setBusy(true);setReport(null);setPlan(null);setInstallerOpened(false);setAdvanced(false);setMessage('Проверяем подключение…');
  try{
   const value=await invoke<SetupReport>('setup_check');
   if(!mounted.current||token!==generation.current)return;
   setReport(value);setMessage('');
   if(value.check_id&&!value.changed&&!value.healthy&&!value.partial&&!['reinstall','add_server','helper','wait_helper'].includes(value.action)){
    setMessage('Подбираем исправление…');
    const prepared=await invoke<RepairPlan>('prepare_setup_plan',{checkId:value.check_id,options:{patch:value.action==='windows_proxy'?{windows_proxy_auto:true}:{},select_recommended:true,connect_after:true}});
    if(mounted.current&&token===generation.current){setPlan(prepared);setMessage('')}
   }
  }catch(e){if(mounted.current&&token===generation.current)setMessage(String(e))}
  finally{if(mounted.current&&token===generation.current){checking.current=false;setBusy(false)}}
 }
 function close(){if(changing)return;generation.current++;checking.current=false;setBusy(false);setOpen(false);setPlan(null);setReport(null);setAdvanced(false);entry.current?.focus()}
 async function repair(){
  if(!plan||busy||locked||changing||plan.blockers.length)return;
  const id=plan.id;setPlan(null);configuration.setOperationId(id);configuration.setPhase('apply');configuration.setMessage('');
  try{
   const result=await invoke<import('./configurationSession').ConfigurationOutcome>('apply_setup_plan',{planId:id,approved:true});
   configuration.setResult(result);configuration.setMessage(result.message);configuration.setPhase('checking');await check();
  }catch(e){configuration.setMessage(String(e));configuration.setPhase('checking');await check()}
  finally{configuration.setOperationId(null);configuration.setPhase(null)}
 }
 async function special(action:Action){
  if(!report||busy||locked||changing)return;
  if(action==='add_server'){const value=report;close();await onAction(action,value);return}
  setBusy(true);setMessage('');try{await onAction(action,report);if(action==='helper'){setInstallerOpened(true);setMessage('Завершите установку в macOS, затем повторите проверку.')}else{await check()}}catch(e){setMessage(String(e))}finally{setBusy(false)}
 }
 async function cancel(){if(!configuration.operationId)return;try{await invoke('cancel_setup_plan',{operationId:configuration.operationId});configuration.setMessage('Останавливаем исправление и возвращаем настройки…')}catch(e){configuration.setMessage(String(e))}}
 const disabled=busy||locked||configuration.phase!==null;
 const healthy=report?.healthy===true&&!report.changed&&!report.partial;
 const configurable=report&&!report.changed&&!report.partial&&!['reinstall','add_server','helper','wait_helper'].includes(report.action);
 const primary=plan?'Исправить':report?.action==='add_server'?'Добавить сервер':report?.action==='helper'&&!installerOpened?'Обновить компонент':report?.action==='windows_proxy'&&!report.check_id?'Настроить Windows':report?.action==='connect'&&!report.check_id?'Подключиться':'Проверить снова';
 async function primaryAction(){
  if(plan){await repair();return}
  if(report?.action==='add_server'){await special('add_server');return}
  if(report?.action==='helper'&&!installerOpened){await special('helper');return}
  if(report?.action==='windows_proxy'&&!report.check_id){await special('windows_proxy');return}
  if(report?.action==='connect'&&!report.check_id){await special('connect');return}
  await check();
 }
 return <section className="panel setting-panel repair-entry" aria-label="Проверка и настройка">
  <div><h3>Проверка и настройка</h3><p className="footnote">Если интернет не работает, foxVPN проверит подключение и предложит исправление.</p></div>
  <button ref={entry} className="secondary" disabled={locked||configuration.phase!==null} onClick={()=>{configuration.setMessage('');setOpen(true);void check()}}>Проверить и настроить</button>
  {open&&<dialog ref={dialog} className="modal repair-dialog" aria-label="Ремонт подключения" aria-describedby="repair-description" onCancel={e=>{e.preventDefault();close()}}>
   <h2>Ремонт подключения</h2>
   <div className={`setup-result ${healthy?'healthy':''}`} aria-live="polite"><h3>{changing?'Исправляем подключение…':busy?'Проверяем подключение…':report?summary(report):'Проверка не завершена'}</h3><p id="repair-description">{changing?'Дождитесь проверки результата.':report?explanation(report):'Проверка не меняет настройки подключения.'}</p></div>
   {message&&<p role="status">{message}</p>}{configuration.message&&<p role="status">{configuration.message}</p>}
   {plan&&<div className="repair-preview"><h4>Что сделаем</h4>{plan.changes.length>0&&<ul>{plan.changes.map((v,i)=><li key={i}>{v}</li>)}</ul>}<ol>{plan.steps.map((v,i)=><li key={i}>{v}</li>)}</ol>{plan.blockers.map((v,i)=><p role="alert" key={i}>{v}</p>)}<p className="footnote">Изменения начнутся после «Исправить». При ошибке foxVPN попробует вернуть прежние настройки.</p></div>}
   {report&&!busy&&<details className="diagnostic-details" onToggle={e=>setAdvanced(e.currentTarget.open)}><summary>Подробности и другие варианты</summary>
    {report.items.map((item,i)=><p key={i}><b>{item.ok?'✓':'!'} {item.label}</b> — {item.message}</p>)}
    {report.tested>0&&report.tested<report.total&&!active&&<p className="footnote">Проверено серверов: {report.tested} из {report.total}. Большой тест скорости не выполнялся.</p>}
    {advanced&&report.check_id&&!report.changed&&<LocalAssistant report={report} locked={disabled} inlineConfirmation/>}
    {advanced&&configurable&&<ConfigurationAssistant report={report} locked={busy||locked} onDone={check} session={configuration} inlineConfirmation onPlanChanged={()=>setPlan(null)}/>}
   </details>}
   {report?.action==='windows_proxy'&&!report.check_id&&<p className="footnote">foxVPN переподключится, включит ручной прокси Windows и временно выключит автоматический сценарий. Прежние параметры вернутся при отключении.</p>}
   <div className="modal-actions repair-actions">
    {(configuration.phase==='apply'||configuration.phase==='undo')&&configuration.operationId?<button className="secondary" onClick={()=>void cancel()}>Остановить исправление</button>:<button className={healthy?'primary':'secondary'} disabled={changing} onClick={close}>{healthy?'Готово':'Закрыть'}</button>}
    {!healthy&&<button className="primary" disabled={disabled||!!plan?.blockers.length||(report?.action==='connect'&&!report.check_id&&active)} onClick={()=>void primaryAction()}>{changing?'Исправляем…':busy?'Проверяем…':primary}</button>}
   </div>
  </dialog>}
 </section>;
}
