/** Pause all polling while the WebView is hidden; never overlap IPC requests. */
export function startVisiblePolling(poll:(resumed:boolean)=>Promise<void>, interval:number) {
  let timer:ReturnType<typeof setTimeout>|undefined;
  let disposed=false, running=false, resumePending=false;
  function clear(){if(timer!==undefined)clearTimeout(timer);timer=undefined;}
  function schedule(){if(!disposed&&!document.hidden)timer=setTimeout(()=>void tick(false),interval);}
  async function tick(resumed:boolean){
    clear();
    if(disposed||document.hidden)return;
    resumePending ||= resumed;
    if(running)return;
    running=true;
    const resume=resumePending;resumePending=false;
    try{await poll(resume);}catch{/* A subsequent tick can recover from IPC/network errors. */}
    finally{
      running=false;
      if(resumePending&&!disposed&&!document.hidden)void tick(true);
      else schedule();
    }
  }
  function visibility(){clear();if(!document.hidden)void tick(true);}
  document.addEventListener('visibilitychange',visibility);schedule();
  return()=>{disposed=true;clear();document.removeEventListener('visibilitychange',visibility);};
}
