#!/usr/bin/env python3
"""Exercise iOS-generated URLTest with local VLESS fixtures; never create a TUN.
Usage on macOS: python3 test-failover.py --core /path/to/sing-box-1.14.2
The CLI must come from the pinned upstream revision. This is not iPhone acceptance.
"""
import argparse, http.client, http.server, json, socket, subprocess, tempfile, threading, time
from pathlib import Path


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class Echo(http.server.BaseHTTPRequestHandler):
    def reply(self):
        time.sleep(.02)  # Avoid a zero-millisecond history on loopback.
        self.send_response(204)
        self.send_header('Content-Length', '0')
        self.end_headers()
    do_GET = do_HEAD = reply
    def log_message(self, *_): pass


def main():
    args = argparse.ArgumentParser()
    args.add_argument('--core', required=True, type=Path)
    core = args.parse_args().core.resolve()
    version = subprocess.check_output([str(core), 'version'], text=True)
    assert '1.14.2' in version and 'af6e64c3b69e6132ebaee0e1a3d24e93903f6709' in version, 'Use pinned upstream core'
    shared = Path(__file__).resolve().parents[1] / 'Shared'
    ports = [free_port() for _ in range(4)]
    assert len(set(ports)) == 4
    primary, reserve, mixed, api = ports
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Echo)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    processes = []
    try:
        with tempfile.TemporaryDirectory(prefix='foxvpn-failover-') as folder:
            root = Path(folder)
            swift = root / 'main.swift'
            swift.write_text('''import Foundation
var profile = VPNProfile()
_ = try profile.importLinks("vless://00000000-0000-4000-8000-000000000001@127.0.0.1:" + CommandLine.arguments[1] + "?type=tcp&security=none#First\\nvless://00000000-0000-4000-8000-000000000002@127.0.0.1:" + CommandLine.arguments[2] + "?type=tcp&security=none#Reserve")
profile.settings.ios.automatic_server = true
print(try TunnelConfiguration.make(profile: profile, apiPort: Int(CommandLine.arguments[3])!, secret: "local-fixture"))
''')
            binary = root / 'generate'
            subprocess.run(['swiftc', *map(str, sorted(shared.glob('*.swift'))), str(swift), '-o', str(binary)], check=True)
            config = json.loads(subprocess.check_output([str(binary), str(primary), str(reserve), str(api)]))
            tags = [x['tag'] for x in config['outbounds'] if x['type'] == 'vless']
            config['inbounds'] = [{'type':'mixed','tag':'fixture-in','listen':'127.0.0.1','listen_port':mixed}]
            config['route']['auto_detect_interface'] = False
            auto = next(x for x in config['outbounds'] if x['tag'] == 'vpn')
            auto.update(url=f'http://127.0.0.1:{server.server_port}/', interval='1s')
            def start(name, value):
                path = root / (name + '.json'); path.write_text(json.dumps(value))
                proc = subprocess.Popen([str(core), 'run', '-c', str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                processes.append(proc); return proc
            for index, port in enumerate([primary, reserve], 1):
                start(f'server-{index}', {'log':{'disabled':True}, 'inbounds':[{'type':'vless','listen':'127.0.0.1','listen_port':port,'users':[{'uuid':f'00000000-0000-4000-8000-00000000000{index}'}]}], 'outbounds':[{'type':'direct','tag':'direct'}], 'route':{'final':'direct','default_domain_resolver':'bootstrap'},'dns':{'servers':[{'type':'local','tag':'bootstrap'}]}})
            engine = start('client', config)
            def current():
                connection = http.client.HTTPConnection('127.0.0.1', api, timeout=2)
                try:
                    connection.request('GET', '/proxies', headers={'Authorization':'Bearer local-fixture'})
                    response = connection.getresponse(); assert response.status == 200
                    return json.loads(response.read())['proxies']
                finally: connection.close()
            def wait_for(tag, require_all=False):
                end = time.monotonic() + 15
                while time.monotonic() < end:
                    assert engine.poll() is None, 'Client core exited: ' + engine.stderr.read().decode()
                    try:
                        proxies = current()
                        if proxies['vpn']['now'] == tag and (not require_all or all(proxies[t]['history'] for t in tags)): return
                    except (OSError, AssertionError, KeyError): pass
                    time.sleep(.2)
                raise AssertionError('URLTest did not choose expected local server')
            def through_proxy():
                connection = http.client.HTTPConnection('127.0.0.1', mixed, timeout=3)
                try:
                    connection.request('GET', f'http://127.0.0.1:{server.server_port}/')
                    response = connection.getresponse(); assert response.status == 204; response.read()
                finally: connection.close()
            wait_for(tags[0], require_all=True); through_proxy()
            processes[0].terminate(); processes[0].wait(timeout=5)
            wait_for(tags[1]); through_proxy()
            assert engine.poll() is None
            print('PASS: generated iOS pool switched from failed local VLESS server to reserve; client process and mixed listener stayed active, HTTP 204 passed before/after. No TUN or external network used.')
    finally:
        server.shutdown(); server.server_close()
        for proc in processes:
            if proc.poll() is None:
                proc.terminate()
                try: proc.wait(timeout=5)
                except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=5)


if __name__ == '__main__': main()
