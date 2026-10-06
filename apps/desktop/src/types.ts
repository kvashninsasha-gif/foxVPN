export type Mode='smart'|'vpn'|'direct'|'custom';
export type Server={id:string;name:string;address:string;port:number;uuid:string;transport:string;security:string;params:Record<string,string>;favorite:boolean;group:string;subscription:string|null;latency_ms:number|null;download_mbps:number|null;status:string;successes:number;failures:number;last_error:string|null};
export type Rule={domain:string;route:string};
export type Settings={mode:Mode;tun:boolean;kill_switch:boolean;proxy_acknowledged:boolean;proxy_port:number;dns_protection:boolean;dns_provider:string;dns_transport:string;auto_connect:boolean;start_minimized:boolean;restore:boolean;health_interval:number;auto_metrics?:boolean;metric_interval?:number;failover:boolean;favorites_only:boolean;strategy:string;subscription_interval:number};
export type Subscription={id:string;name:string;url:string;updated_at:number|null;server_count:number};
export type Profile={version:number;servers:Server[];selected:string|null;rules:Rule[];settings:Settings;subscriptions:Subscription[]};
export type Snapshot={profile:Profile;status:string;proxy_port:number|null;core_version:string;connection_plan:'needs_server'|'needs_proxy_consent'|'ready';logs:string[];helper_available?:boolean;connection_error?:string|null};
export type Traffic={upload:number;download:number;vpn_upload:number;vpn_download:number;direct_upload:number;direct_download:number;connections:{domain:string;route:string;upload:number;download:number}[]};
