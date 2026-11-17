#!/usr/bin/env python3
"""Offline real XHTTP/REALITY fixture; no user profile or remote VPS."""
import argparse,sys,base64,http.server,json,os,queue,re,secrets,socket,ssl,subprocess,tempfile,threading,time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--xray',type=Path,required=True);p.add_argument('--generator',type=Path,required=True);p.add_argument('--core',type=Path);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
UUID='11111111-1111-4111-8111-111111111111'
def port():
 with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
def wait_port(n,child):
 deadline=time.monotonic()+6
 while time.monotonic()<deadline:
  assert child.poll() is None,'fixture process exited'
  try:
   with socket.create_connection(('127.0.0.1',n),timeout=.1):return
  except OSError:time.sleep(.025)
 raise AssertionError('fixture listener not ready')
def launch(binary,path):return subprocess.Popen([str(binary),'run','-config',str(path)],stdin=subprocess.DEVNULL,stdout=open(path.with_suffix('.log'),'w'),stderr=subprocess.STDOUT)
def reap(child):
 if child and child.poll() is None:child.kill()
 if child:child.wait(timeout=8)
results=[]
with tempfile.TemporaryDirectory(prefix='foxvpn-xhttp-') as temp:
 root=Path(temp);marker=secrets.token_hex(12)
 class HTTP(http.server.BaseHTTPRequestHandler):
  def do_GET(self):
   body=marker.encode();self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
  def log_message(self,*_):pass
 origin=http.server.ThreadingHTTPServer(('127.0.0.1',0),HTTP);origin_port=origin.server_port
 threading.Thread(target=origin.serve_forever,daemon=True).start()
 cert=root/'cert.pem';key=root/'key.pem'
 subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-subj','/CN=fixture.invalid','-days','1'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
 context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_3;context.set_alpn_protocols(['h2']);context.load_cert_chain(cert,key)
 class TLSHTTP(HTTP):
  def setup(self):
   self.request.settimeout(3)
   self.request=context.wrap_socket(self.request,server_side=True)
   super().setup()
 class TLSFixtureServer(http.server.ThreadingHTTPServer):
  def handle_error(self,request,address):
   if isinstance(sys.exc_info()[1],(ssl.SSLEOFError,TimeoutError)):return
   super().handle_error(request,address)
 tls=TLSFixtureServer(('127.0.0.1',0),TLSHTTP);tls_port=tls.server_port
 threading.Thread(target=tls.serve_forever,daemon=True).start()
 private=base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip('=')
 output=subprocess.check_output([str(a.xray),'x25519','-i',private],text=True,timeout=5)
 public=re.search(r'(?:Password(?: \(PublicKey\))?|PublicKey):\s*(\S+)',output).group(1)
 try:
  for security,mode in [('none','packet-up'),('reality','auto'),('reality','packet-up'),('reality','stream-up'),('reality','stream-one')]:
   server=None;client=None
   case=root/(security+'-'+mode);case.mkdir();access=case/'access.log';server_port=port()
   stream={'network':'xhttp','security':security,'xhttpSettings':{'path':'/fox-test'}}
   if security=='reality':stream['realitySettings']={'show':True,'target':f'127.0.0.1:{tls_port}','serverNames':['fixture.invalid'],'privateKey':private,'shortIds':['abcd']}
   server_cfg={'log':{'loglevel':'debug','access':str(access)},'inbounds':[{'listen':'127.0.0.1','port':server_port,'protocol':'vless','settings':{'clients':[{'id':UUID}],'decryption':'none'},'streamSettings':stream}],'outbounds':[{'protocol':'freedom','settings':{'finalRules':[{'action':'allow','ip':['127.0.0.1']}]}}]}
   server_path=case/'server.json';server_path.write_text(json.dumps(server_cfg));server=launch(a.xray,server_path)
   try:
    wait_port(server_port,server)
    uri=f'vless://{UUID}@127.0.0.1:{server_port}?type=xhttp&security={security}&mode={mode}&path=%2Ffox-test'
    if security=='reality':uri+=f'&sni=fixture.invalid&pbk={public}&sid=abcd&fp=chrome'
    if a.core:
     client=subprocess.Popen([str(a.generator),'engine',uri,str(a.core)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
     ready=queue.Queue();threading.Thread(target=lambda:ready.put(client.stdout.readline()),daemon=True).start();data=json.loads(ready.get(timeout=20));proxy_port=data['proxy_port'];auth=[]
    else:
     proxy_port=port();cfg=json.loads(subprocess.check_output([str(a.generator),'config',uri,str(proxy_port)],timeout=8));cfg['log']['loglevel']='debug';
     if security=='reality':cfg['outbounds'][0]['streamSettings']['realitySettings']['show']=True
     client_path=case/'client.json';client_path.write_text(json.dumps(cfg));client=launch(a.xray,client_path);wait_port(proxy_port,client);auth=['--proxy-user','foxvpn:public-fixture-password']
    response=subprocess.run(['curl','--noproxy','','--proxy',f'socks5h://127.0.0.1:{proxy_port}',*auth,'--connect-timeout','4','--max-time','12','-sS',f'http://127.0.0.1:{origin_port}/token'],capture_output=True,text=True,timeout=15)
    assert response.returncode==0 and response.stdout==marker,(security,mode,'transport did not return the origin marker',response.stderr[:500],[(f.name,f.read_text()[-1800:]) for f in case.glob('*.log')])
    deadline=time.monotonic()+3
    while time.monotonic()<deadline and (not access.exists() or f'127.0.0.1:{origin_port}' not in access.read_text()):time.sleep(.05)
    assert access.exists() and f'127.0.0.1:{origin_port}' in access.read_text(),'direct fallback cannot count as transport success'
    if a.core:
     if sys.platform=='win32' and security=='none':client.kill();client.wait(timeout=10)
     else:client.stdin.close();assert client.wait(timeout=10)==0
     for listener in [proxy_port,data['transport_port']]:
      deadline=time.monotonic()+3
      while True:
       try:
        with socket.create_connection(('127.0.0.1',listener),timeout=.1):pass
       except OSError:break
       assert time.monotonic()<deadline,'transport process/listener leaked after parent stop'
       time.sleep(.05)
    results.append({'security':security,'mode':mode,'passed':True});print(security,mode,'passed',flush=True)
   finally:reap(client);reap(server)
 finally:origin.shutdown();origin.server_close();tls.shutdown();tls.server_close()
a.report.parent.mkdir(parents=True,exist_ok=True);a.report.write_text(json.dumps({'passed':True,'through_engine':bool(a.core),'cases':results},indent=2)+'\n')
