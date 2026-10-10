#!/usr/bin/env python3
"""Mandatory rootless startup gate for the binaries inside the final artifact.

Fixtures come from foxVPN's Rust production config generator. Only loopback
listeners are opened: no TUN, route/DNS/PF/proxy changes or external requests.
Missing cores/generator, timeouts, early exits and the old regression fail the
gate. No skip flag. Reports bind results to the SHA256 of the tested binaries.
"""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time


def ports():
    with socket.socket() as proxy, socket.socket() as api:
        proxy.bind(('127.0.0.1', 0))
        api.bind(('127.0.0.1', 0))
        return proxy.getsockname()[1], api.getsockname()[1]


def check_and_start(core, source, directory, legacy=False):
    cfg = json.loads(json.dumps(source))
    if len(cfg['inbounds']) != 1 or cfg['inbounds'][0]['type'] != 'mixed' or cfg['inbounds'][0]['listen'] != '127.0.0.1':
        raise RuntimeError('Startup fixtures must contain only one loopback mixed inbound')
    if cfg['outbounds'][0]['server'] != '127.0.0.1':
        raise RuntimeError('Public fixture must not use a remote VPN server')
    port, api = ports()
    cfg['inbounds'][0]['listen_port'] = port
    cfg['experimental']['clash_api']['external_controller'] = f'127.0.0.1:{api}'
    if legacy:
        cfg['dns']['servers'][0]['detour'] = 'direct'
    path = directory / 'public.json'
    path.write_text(json.dumps(cfg), encoding='utf-8')
    env = os.environ.copy()
    env.pop('FOXVPN_CORE_UID', None)
    # This proves that check alone does not exercise the original failure.
    result = subprocess.run([str(core), 'check', '-c', str(path)], env=env,
                            stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
    if result.returncode:
        raise RuntimeError('Core check rejected public fixture: ' + result.stderr.decode('utf-8', 'replace')[:2000])
    with (directory / 'core.log').open('w+b') as log:
        child = subprocess.Popen([str(core), 'run', '-c', str(path)], env=env,
                                 stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 15
            ready_at = None
            while time.monotonic() < deadline:
                status = child.poll()
                if status is not None:
                    log.seek(0)
                    detail = log.read().decode('utf-8', 'replace')
                    if legacy and status != 0 and 'empty direct outbound' in detail:
                        return
                    raise RuntimeError(f'Core exited ({status}): {detail[:2000]}')
                if not legacy:
                    ready = False
                    connection = http.client.HTTPConnection('127.0.0.1', api, timeout=0.15)
                    try:
                        connection.request('GET', '/version', headers={'Authorization': 'Bearer public-startup-token'})
                        response = connection.getresponse()
                        payload = json.loads(response.read())
                        if response.status == 200 and isinstance(payload.get('version'), str):
                            with socket.create_connection(('127.0.0.1', port), timeout=0.15):
                                ready = True
                                ready_at = ready_at or time.monotonic()
                    except (OSError, http.client.HTTPException, ValueError):
                        pass
                    finally:
                        connection.close()
                    if not ready:
                        ready_at = None
                    if ready_at and time.monotonic() - ready_at >= 0.2:
                        return
                time.sleep(0.05)
            raise RuntimeError('Legacy config did not fail' if legacy else 'Core did not become ready')
        finally:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=3)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--generator', required=True, type=Path)
    parser.add_argument('--core', action='append', required=True, type=Path)
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    args.report.unlink(missing_ok=True)  # even missing inputs invalidate stale success
    generator = args.generator.resolve(strict=True)
    cores = [p.resolve(strict=True) for p in args.core]
    fixtures = json.loads(subprocess.check_output([str(generator)], timeout=15))
    root = Path(__file__).resolve().parent.parent
    version = json.loads((root / 'apps/desktop/src-tauri/tauri.conf.json').read_text(encoding='utf-8'))['version']
    if fixtures.get('engine_version') != version:
        raise RuntimeError('Fixture generator version differs from the release; rebuild it')
    cases = fixtures['cases']
    if len(cases) != 72 or len({c['name'] for c in cases}) != 72:
        raise RuntimeError('Expected all 72 distinct production startup cases')
    legacy = next(c['config'] for c in cases if c['name'] == 'tun-dns-Smart-cloudflare-https')
    results = []
    for core in cores:
        digest = hashlib.sha256(core.read_bytes()).hexdigest()
        version = subprocess.check_output([str(core), 'version'], timeout=15).decode('utf-8', 'replace').splitlines()[0]
        with tempfile.TemporaryDirectory(prefix='foxvpn-startup-') as directory:
            work = Path(directory)
            check_and_start(core, legacy, work, legacy=True)
            for case in cases:
                try:
                    check_and_start(core, case['config'], work)
                except Exception as error:
                    raise RuntimeError(f'{core.name}: {case["name"]}: {error}') from error
        if hashlib.sha256(core.read_bytes()).hexdigest() != digest:
            raise RuntimeError('Core changed during verification')
        results.append({'sha256': digest, 'version': version, 'name': core.name,
                        'cases': [case['name'] for case in cases], 'legacy_rejected': True})
        print(f'{core.name}: 72 startup cases passed; legacy runtime failure reproduced', flush=True)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps({'engine_version': version, 'cores': results}, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
