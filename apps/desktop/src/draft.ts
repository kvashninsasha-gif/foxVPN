import {useCallback,useRef,useState} from 'react';

/** Keep local edits over fresh snapshots; untouched fields always follow storage. */
export function useDraft<T extends object>(initial:T){
 const base=useRef(initial),pending=useRef<Partial<T>>({});
 const [value,setValue]=useState(initial),[dirty,setDirty]=useState(false);
 const latest=useCallback(()=>({...base.current,...pending.current}),[]);
 const publish=useCallback(()=>{setValue(latest());setDirty(Object.keys(pending.current).length>0)},[latest]);
 const accept=useCallback((next:T)=>{
  base.current=next;
  for(const key of Object.keys(pending.current) as (keyof T)[]){
   if(JSON.stringify(pending.current[key])===JSON.stringify(next[key]))delete pending.current[key];
  }
  publish();
 },[publish]);
 const change=useCallback(<K extends keyof T>(key:K,next:T[K])=>{
  if(JSON.stringify(base.current[key])===JSON.stringify(next))delete pending.current[key];
  else pending.current[key]=next;
  publish();
 },[publish]);
 const reset=useCallback(()=>{pending.current={};publish()},[publish]);
 return {value,dirty,change,accept,reset,latest};
}
