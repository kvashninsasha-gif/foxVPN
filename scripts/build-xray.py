#!/usr/bin/env python3
"""Build the pinned XHTTP sidecar, audit it, then stage verified resources."""
import argparse,hashlib,importlib.util,json,os,platform,shutil,subprocess,tarfile
from pathlib import Path
root=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('--platform',choices=['windows-amd64','darwin-arm64'],default='darwin-arm64');p.add_argument('--work-dir',type=Path,required=True);a=p.parse_args()
m=json.loads((root/'vendor/xray-source.json').read_text());archive=root/f'vendor/xray-{m["version"]}-source.tar.gz'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(archive)==m['sha256'];a.work_dir.mkdir(parents=True,exist_ok=True)
with tarfile.open(archive) as t:
 source=a.work_dir/t.getnames()[0].split('/')[0]
 if source.exists():shutil.rmtree(source)
 t.extractall(a.work_dir,filter='data')
for name in ['go.mod','go.sum']:shutil.copy2(root/'vendor/xray-patches'/name,source/name)
goos,arch=a.platform.split('-');env=dict(os.environ,GOTOOLCHAIN=m['toolchain'],GOOS=goos,GOARCH=arch,CGO_ENABLED='0')
stage=a.work_dir/('xray.exe' if goos=='windows' else 'xray')
subprocess.run(['go','build','-mod=readonly','-trimpath','-ldflags','-s -w','-o',str(stage),'./main'],cwd=source,env=env,check=True)
with (a.work_dir/'govulncheck.json').open('w') as f:subprocess.run([os.environ.get('GOVULNCHECK','govulncheck'),'-mode=binary','-format=json',str(stage)],env=env,stdout=f,check=True)
with (a.work_dir/'compiled-packages.json').open('w') as f:subprocess.run(['go','list','-mod=readonly','-deps','-json','./main'],env=env,cwd=source,stdout=f,check=True)
spec=importlib.util.spec_from_file_location('gate',root/'scripts/check-go-advisories.py');gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
gate.ROOT_MODULE='github.com/xtls/xray-core';gate.ROOT_PACKAGE=gate.ROOT_MODULE+'/main';gate.EXPECTED_GO=m['toolchain']
report=gate.assess((a.work_dir/'govulncheck.json').read_text(),(a.work_dir/'compiled-packages.json').read_text())
(a.work_dir/'advisory-assessment.json').write_text(json.dumps(report,indent=2))
if not report['passed'] or report['finding_count']:raise SystemExit('Xray advisory gate failed; no resource staged')
if goos=='darwin':subprocess.run(['codesign','--force','--sign','-','--options','runtime',str(stage)],check=True)
(root/'core').mkdir(exist_ok=True);shutil.copy2(stage,root/'core/xray');(root/'core/xray').chmod(0o755)
if goos=='windows':shutil.copy2(stage,root/'core/xray.exe')
(root/'core/xray-version.json').write_text(json.dumps(dict(m,platform=a.platform,binary_sha256=sha(stage),vulnerability_scan='zero-findings'),indent=2)+'\n')
print('Pinned Xray built and audited:',m['version'],a.platform)
