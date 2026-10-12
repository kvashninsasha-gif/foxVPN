#!/usr/bin/env python3
"""Reproducible core from pinned GPL source, reviewed dependency overlay and Go toolchain."""
import argparse, hashlib, json, os, pathlib, platform, shutil, subprocess, tarfile
ROOT = pathlib.Path(__file__).resolve().parents[1]
VERSION = '1.14.3-foxVPN.2'
TOOLCHAIN = 'go1.26.9'
TAGS = 'with_utls,with_gvisor,with_clash_api'

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def build(target, work, network=False, scan=False):
    manifest = json.loads((ROOT/'vendor/sing-box-source.json').read_text())
    archive = ROOT/f"vendor/sing-box-{manifest['version']}-source.tar.gz"
    if manifest['version'] != '1.14.3' or digest(archive) != manifest['sha256']:
        raise SystemExit('Pinned upstream source digest differs')
    if network and not target.startswith('darwin-'):
        raise SystemExit('Privilege-drop network core is macOS only')
    work.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive) as src:
        prefix = src.getnames()[0].split('/')[0]
        source = work/prefix
        if source.exists(): shutil.rmtree(source)
        src.extractall(work, filter='data')
    for name in ['go.mod', 'go.sum']:
        shutil.copyfile(ROOT/'vendor/core-patches'/name, source/name)
    if network:
        run = source/'cmd/sing-box/cmd_run.go'
        text = run.read_text(); needle = '\t\truntimeDebug.FreeOSMemory()'
        if text.count(needle) != 1: raise SystemExit('Privilege-drop patch context differs')
        run.write_text(text.replace(needle, '\t\tif err := foxDropPrivileges(); err != nil { cancel(); instance.Close(); return err }\n'+needle))
        shutil.copyfile(ROOT/'scripts/macos/privilege_drop.go', source/'cmd/sing-box/foxvpn_privilege_drop.go')
    goos, arch = target.split('-')
    env = os.environ.copy()
    env.update(GOTOOLCHAIN=TOOLCHAIN, GOOS=goos, GOARCH=arch, CGO_ENABLED='0' if goos=='windows' else '1', MACOSX_DEPLOYMENT_TARGET='13.0')
    binary = ROOT/'core'/('foxvpn-network-core' if network else ('sing-box.exe' if goos=='windows' else 'sing-box'))
    binary.parent.mkdir(exist_ok=True)
    stage = work/('network-core' if network else 'proxy-core')
    subprocess.run(['go','build','-mod=readonly','-trimpath','-tags',TAGS,'-ldflags',f'-s -w -X github.com/sagernet/sing-box/constant.Version={VERSION}','-o',str(stage),'./cmd/sing-box'],cwd=source,env=env,check=True)
    report = work/'govulncheck.json'
    if scan:
        with report.open('w') as out:
            subprocess.run([os.environ.get('GOVULNCHECK','govulncheck'),'-mode=binary','-format=json',str(stage)],stdout=out,env=env,check=True)
        packages=work/'compiled-packages.json'
        with packages.open('w') as out:
            subprocess.run(['go','list','-mod=readonly','-tags',TAGS,'-deps','-json','./cmd/sing-box'],cwd=source,env=env,stdout=out,check=True)
        with (work/'advisory-assessment.json').open('w') as out:
            subprocess.run(['python3' if goos!='windows' else 'python', str(ROOT/'scripts/check-go-advisories.py'),str(report),'--compiled-packages',str(packages)],stdout=out,check=True)
    if goos=='darwin':
        subprocess.run(['/usr/bin/codesign','--force','--sign','-','--options','runtime','--identifier','ru.smartvpn.network-core' if network else 'ru.smartvpn.proxy-core',str(stage)],check=True)
    shutil.copyfile(stage,binary); binary.chmod(0o755)
    info = dict(version='v'+VERSION, upstream_version=manifest['version'], platform=target, binary_sha256=digest(binary), source_archive_sha256=manifest['sha256'], source=manifest['source'], toolchain=TOOLCHAIN, tags=TAGS, dependency_overlay_sha256={n:digest(ROOT/'vendor/core-patches'/n) for n in ['go.mod','go.sum']}, official_binary=False, vulnerability_scan='assessed-binary-symbols-pass' if scan else 'not-run')
    if network: info['patch']='scripts/macos/privilege_drop.go'
    (ROOT/'core'/('network-version.json' if network else 'version.json')).write_text(json.dumps(info,indent=2)+'\n')
    print('Built pinned core', VERSION, target, info['binary_sha256'])

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--platform',choices=['darwin-arm64','darwin-amd64','windows-amd64']);p.add_argument('--work-dir',required=True);p.add_argument('--network',action='store_true');p.add_argument('--scan',action='store_true');a=p.parse_args()
    target=a.platform or (('windows' if platform.system()=='Windows' else 'darwin')+'-'+('arm64' if platform.machine().lower() in ('arm64','aarch64') else 'amd64'))
    build(target,pathlib.Path(a.work_dir).resolve(),a.network,a.scan)
