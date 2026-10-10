#!/usr/bin/env python3
"""Package a sealed macOS Apple Silicon app and sign its version-bound update.
Publish the immutable GitHub release assets first, then copy macos.json to
updates/macos.json and commit the feed. Never rotate an existing signing key.
"""
import argparse, hashlib, json, os, plistlib, subprocess, tarfile, sys
from pathlib import Path
from datetime import datetime, timezone
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('bundle', type=Path)
parser.add_argument('--out-dir', type=Path, required=True)
parser.add_argument('--key', type=Path, default=Path.home()/'.config/foxvpn-release/updater.key')
parser.add_argument('--notes-file', type=Path)
parser.add_argument('--startup-generator', type=Path, required=True)
args=parser.parse_args()
root=Path(__file__).resolve().parent.parent
config=json.loads((root/'apps/desktop/src-tauri/tauri.macos.conf.json').read_text())
version=json.loads((root/'apps/desktop/src-tauri/tauri.conf.json').read_text())['version']
app=args.bundle.resolve();out=args.out_dir.resolve();key=args.key.resolve()
if not key.is_file() or not Path(str(key)+'.pub').is_file():raise SystemExit('Signing key missing. Restore the original private key; do not generate a replacement.')
if Path(str(key)+'.pub').read_text().strip()!=config['plugins']['updater']['pubkey']:raise SystemExit('Private key public pair differs from the key embedded in foxVPN')
if not config['plugins']['updater'].get('requireSignedVersion'):raise SystemExit('requireSignedVersion must be enabled')
info=plistlib.loads((app/'Contents/Info.plist').read_bytes())
if info['CFBundleIdentifier']!='ru.smartvpn.router' or info['CFBundleShortVersionString']!=version:raise SystemExit('Bundle identifier/version differ from project')
subprocess.run(['/usr/bin/codesign','--verify','--deep','--strict',str(app)],check=True)
if subprocess.check_output(['lipo','-archs',str(app/'Contents/MacOS'/info['CFBundleExecutable'])],text=True).strip()!='arm64':raise SystemExit('Only the verified Apple Silicon target is published by this script')
for file in app.rglob('*'):
 if file.is_symlink():raise SystemExit('Symlinks are not supported in update bundles')
 if file.suffix.lower() in {'.p12','.pfx','.mobileprovision','.enc'}:raise SystemExit('Private material must not enter release')
out.mkdir(parents=True,exist_ok=True)
subprocess.run([sys.executable,str(root/'scripts/test-core-startup.py'),
 '--generator',str(args.startup_generator.resolve()),
 '--core',str(app/'Contents/Resources/core/sing-box'),
 '--core',str(app/'Contents/Resources/network/foxvpn-network-core'),
 '--report',str(out/'macos-core-startup.json')],check=True)
name=f'foxVPN-{version}-macOS-arm64.app.tar.gz';archive=out/name
if archive.exists():raise SystemExit('An updater archive already exists; never overwrite published release assets')
with tarfile.open(archive,'w:gz') as tar:tar.add(app,arcname='foxVPN.app')
cli=root/'apps/desktop/node_modules/.bin/tauri'
result=subprocess.run([str(cli),'signer','sign','--private-key-path',str(key),'--app-version',version,str(archive)],capture_output=True,text=True)
if result.returncode:raise SystemExit('Tauri update signing failed; check the signing key/password environment locally')
signature=Path(str(archive)+'.sig').read_text().strip()
notes=args.notes_file.read_text().strip() if args.notes_file else 'Обновление foxVPN. Профили и настройки сохраняются.'
feed={'version':version,'notes':notes,'pub_date':datetime.now(timezone.utc).isoformat().replace('+00:00','Z'),'platforms':{'darwin-aarch64':{'url':f'https://github.com/kvashninsasha-gif/smart-vpn-router/releases/download/v{version}/{name}','signature':signature}}}
(out/'macos.json').write_text(json.dumps(feed,ensure_ascii=False,indent=2)+'\n')
(out/(name+'.sha256')).write_text(hashlib.sha256(archive.read_bytes()).hexdigest()+'  '+name+'\n')
print(f'Created version-bound update {version}; signing key stayed outside release')
print('Publish assets, verify GitHub digests, then commit updates/macos.json')
