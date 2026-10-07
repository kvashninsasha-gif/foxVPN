import React,{useState} from 'react';
import {invoke} from '@tauri-apps/api/core';
import {writeText} from '@tauri-apps/plugin-clipboard-manager';
type Report={version:string;platform:string;architecture:string;core_present:boolean;core_verified:boolean;status:string;proxy_port:number|null;system_vpn_supported:boolean};
export function Diagnostics(){
 const [report,setReport]=useState<Report|null>(null),[busy,setBusy]=useState(false),[message,setMessage]=useState('');
 const text=report?`foxVPN ${report.version}\nПлатформа: ${report.platform} / ${report.architecture}\nКомпонент VPN: ${report.core_present?'найден':'отсутствует'}\nКонтрольная сумма: ${report.core_verified?'совпадает':'не проверена или не совпадает'}\nСостояние: ${report.status}\nЛокальный прокси: ${report.proxy_port?`127.0.0.1:${report.proxy_port}`:'не запущен'}\nСистемный VPN: ${report.system_vpn_supported?'поддерживается компонентом macOS':'недоступен в этой сборке'}`:'';
 async function check(){setBusy(true);setMessage('');try{setReport(await invoke<Report>('connection_diagnostics'))}catch(e){setMessage(String(e))}finally{setBusy(false)}}
 return <><p className="footnote">Проверка версии, компонента и режима подключения. Отчёт не содержит адресов серверов, ключей и профилей.</p><div className="bottom-toolbar"><button className="secondary" disabled={busy} onClick={()=>void check()}>{busy?'Проверяем…':'Проверить сборку'}</button>{report&&<button className="secondary" onClick={async()=>{try{await writeText(text);setMessage('Отчёт скопирован')}catch(e){setMessage(String(e))}}}>Скопировать диагностику</button>}</div>{report&&<pre>{text}</pre>}{message&&<p role="status">{message}</p>}</>;
}
