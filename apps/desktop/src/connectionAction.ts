import {useEffect,useRef,useState} from 'react';

type Phase='connecting'|'disconnecting'|'cancelling'|null;
type Attempt={cancelled:boolean;connectDone:boolean;stopDone:boolean};

// Cancellation is a second IPC request: it must remain available while connect
// is unresolved. Keep the action locked until both commands acknowledge it.
export function useConnectionAction({stop,refresh,onError}:{stop:()=>Promise<unknown>;refresh:(current?:()=>boolean)=>Promise<unknown>;onError:(error:unknown,action:'connect'|'stop')=>void}){
 const [phase,setPhase]=useState<Phase>(null),[elapsed,setElapsed]=useState(0);
 const current=useRef<Attempt|null>(null),mounted=useRef(true),started=useRef(0);
 const callbacks=useRef({stop,refresh,onError});callbacks.current={stop,refresh,onError};
 useEffect(()=>{mounted.current=true;return()=>{mounted.current=false}},[]);
 useEffect(()=>{if(!phase)return;const update=()=>setElapsed(Math.floor((Date.now()-started.current)/1000));update();const timer=setInterval(update,1000);return()=>clearInterval(timer)},[phase]);
 function finish(attempt:Attempt){if(current.current!==attempt||!attempt.connectDone||!attempt.stopDone)return;current.current=null;if(mounted.current)setPhase(null)}
 function report(error:unknown,action:'connect'|'stop'){if(mounted.current)callbacks.current.onError(error,action)}
 async function start(connect:(cancelled:()=>boolean)=>Promise<unknown>){
  if(current.current)return;
  const attempt:Attempt={cancelled:false,connectDone:false,stopDone:true};current.current=attempt;started.current=Date.now();setElapsed(0);setPhase('connecting');
  try{await connect(()=>attempt.cancelled);if(!attempt.cancelled&&mounted.current)await callbacks.current.refresh(()=>current.current===attempt&&!attempt.cancelled)}
  catch(error){if(!attempt.cancelled)report(error,'connect')}
  finally{attempt.connectDone=true;finish(attempt)}
 }
 async function disconnect(){
  const existing=current.current;
  if(existing?.cancelled)return;
  const attempt=existing??{cancelled:false,connectDone:true,stopDone:true};
  attempt.cancelled=true;attempt.stopDone=false;current.current=attempt;
  if(!existing){started.current=Date.now();setElapsed(0)}
  setPhase(existing?'cancelling':'disconnecting');
  try{await callbacks.current.stop();if(mounted.current)await callbacks.current.refresh(()=>current.current===attempt)}
  catch(error){report(error,'stop')}
  finally{attempt.stopDone=true;finish(attempt)}
 }
 return {phase,elapsed,start,disconnect,pending:()=>current.current!==null};
}
