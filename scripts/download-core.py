#!/usr/bin/env python3
"""Download pinned official sing-box, validate GitHub release SHA256, extract executable."""
import argparse,hashlib,json,platform,pathlib,tarfile,zipfile,io,urllib.request,sys
# Redirected Windows stdout may default to cp1252 and reject Russian messages.
for stream in (sys.stdout,sys.stderr):
 if hasattr(stream,"reconfigure"):stream.reconfigure(encoding="utf-8",errors="replace")
VERSION="1.14.2"
a=argparse.ArgumentParser();a.add_argument('--platform',choices=['darwin-arm64','darwin-amd64','windows-amd64']);args=a.parse_args()
name=args.platform or (('windows' if platform.system()=='Windows' else 'darwin')+'-'+('arm64' if platform.machine().lower() in ('arm64','aarch64') else 'amd64'))
root=pathlib.Path(__file__).resolve().parents[1];suffix='.zip' if name.startswith('windows') else '.tar.gz';filename=f'sing-box-{VERSION}-{name}{suffix}'
request=urllib.request.Request(f'https://api.github.com/repos/SagerNet/sing-box/releases/tags/v{VERSION}',headers={'User-Agent':'SmartVPN-build'})
release=json.load(urllib.request.urlopen(request,timeout=30));asset=next((x for x in release['assets'] if x['name']==filename),None)
if not asset:raise SystemExit('В официальном релизе нет нужного архива')
expected=asset.get('digest','')
if not expected or not expected.startswith('sha256:'):raise SystemExit('Релиз не содержит SHA256. Требуется отдельная проверка поставщика; загрузка остановлена.')
data=urllib.request.urlopen(asset['browser_download_url'],timeout=60).read();digest=hashlib.sha256(data).hexdigest()
if expected!='sha256:'+digest:raise SystemExit('SHA256 не совпадает; ядро не установлено')
if suffix=='.zip':
 with zipfile.ZipFile(io.BytesIO(data)) as archive:
  key=next(n for n in archive.namelist() if n.endswith('/sing-box.exe'));binary=archive.read(key)
else:
 with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as archive:
  key=next(m for m in archive.getmembers() if m.name.endswith('/sing-box'));binary=archive.extractfile(key).read()
path=root/'core'/'sing-box';path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(binary);path.chmod(0o755)
if name.startswith('windows'):(root/'core'/'sing-box.exe').write_bytes(binary)
(root/'core'/'version.json').write_text(json.dumps({'version':'v'+VERSION,'platform':name,'archive_sha256':digest,'binary_sha256':hashlib.sha256(binary).hexdigest(),'source':asset['browser_download_url']},indent=2))
print('Компонент VPN загружен и проверен:',VERSION,name)
