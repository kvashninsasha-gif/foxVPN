#!/usr/bin/env python3
"""Fetch public immutable previous installers; test code verifies original signed version."""
import hashlib,json,os,pathlib,urllib.request
out=pathlib.Path('target/signed-windows-fixtures');out.mkdir(parents=True,exist_ok=True)
for version in ['0.1.26','0.1.27']:
 headers={'User-Agent':'foxVPN-public-fixture'}
 if os.environ.get('GITHUB_TOKEN'):headers['Authorization']='Bearer '+os.environ['GITHUB_TOKEN']
 req=urllib.request.Request(f'https://api.github.com/repos/kvashninsasha-gif/foxVPN/releases/tags/v{version}',headers=headers)
 release=json.load(urllib.request.urlopen(req,timeout=30))
 for name in [f'foxVPN_{version}_x64-setup.exe',f'foxVPN_{version}_x64-setup.exe.sig']:
  asset=next(a for a in release['assets'] if a['name']==name)
  if not asset.get('digest','').startswith('sha256:'):raise SystemExit('Missing public fixture digest')
  data=urllib.request.urlopen(asset['browser_download_url'],timeout=90).read()
  if len(data)!=asset['size'] or 'sha256:'+hashlib.sha256(data).hexdigest()!=asset['digest']:raise SystemExit('Fixture size/digest mismatch')
  (out/name).write_bytes(data)
print('Downloaded two public immutable original-key signed Windows fixtures')
