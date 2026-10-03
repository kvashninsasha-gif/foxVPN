#!/usr/bin/env python3
"""Build the macOS TUN core from the included GPL upstream source + small patch."""
import argparse,hashlib,json,os,pathlib,subprocess,tarfile,shutil,platform
root=pathlib.Path(__file__).resolve().parent.parent
p=argparse.ArgumentParser();p.add_argument('--work-dir',required=True);a=p.parse_args()
work=pathlib.Path(a.work_dir).resolve();work.mkdir(parents=True,exist_ok=True)
with tarfile.open(root/'vendor/sing-box-1.14.2-source.tar.gz') as archive:
 prefix=archive.getnames()[0].split('/')[0]
 archive.extractall(work,filter='data')
source=work/prefix
run=source/'cmd/sing-box/cmd_run.go'
s=run.read_text();needle='\t\truntimeDebug.FreeOSMemory()'
assert s.count(needle)==1
s=s.replace(needle,'\t\tif err := foxDropPrivileges(); err != nil { cancel(); instance.Close(); return err }\n'+needle)
run.write_text(s);shutil.copy2(root/'scripts/macos/privilege_drop.go',source/'cmd/sing-box/foxvpn_privilege_drop.go')
env=os.environ.copy();env.update(GOTOOLCHAIN='go1.25.5',CGO_ENABLED='1',MACOSX_DEPLOYMENT_TARGET='13.0')
binary=root/'core/foxvpn-network-core'
subprocess.run(['go','build','-trimpath','-tags','with_utls,with_gvisor,with_clash_api','-ldflags','-s -w -X github.com/sagernet/sing-box/constant.Version=1.14.2-foxVPN.1','-o',str(binary),'./cmd/sing-box'],cwd=source,env=env,check=True)
subprocess.run(['/usr/bin/codesign','--force','--sign','-','--options','runtime','--identifier','ru.smartvpn.network-core',str(binary)],check=True)
info={'version':'1.14.2-foxVPN.1','upstream_version':'1.14.2','binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'source_archive_sha256':hashlib.sha256((root/'vendor/sing-box-1.14.2-source.tar.gz').read_bytes()).hexdigest(),'patch':'scripts/macos/privilege_drop.go + build-network-core.py','platform':'darwin-'+('arm64' if platform.machine()=='arm64' else 'amd64'),'official_binary':False}
(root/'core/network-version.json').write_text(json.dumps(info,indent=2)+'\n')
print('Built network core; pinned SHA256:',info['binary_sha256'])
