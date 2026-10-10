#!/usr/bin/env python3
"""Seal the app while retaining pinned, separately signed network resources."""
import argparse
import hashlib
import json
import re
from pathlib import Path
import shutil
import subprocess
import sys

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('bundle', type=Path)
parser.add_argument('--identity', default='-')
args = parser.parse_args()
if sys.platform != 'darwin':
    parser.error('macOS is required')
root = Path(__file__).resolve().parent.parent
bundle = args.bundle.resolve()
if bundle.suffix != '.app' or not (bundle / 'Contents/Info.plist').is_file():
    parser.error('a built .app is required')
metadata = json.loads((root / 'core/network-version.json').read_text())
core = root / 'core/foxvpn-network-core'
if hashlib.sha256(core.read_bytes()).hexdigest() != metadata['binary_sha256']:
    raise SystemExit('network core SHA256 differs from pinned metadata')
for binary in [core, root / 'core/foxvpn-helper']:
    subprocess.run(['codesign', '--verify', '--strict', str(binary)], check=True)
    signature = subprocess.run(['codesign', '-d', '--verbose=4', str(binary)], capture_output=True, text=True, check=True)
    if 'runtime' not in next(line for line in signature.stderr.splitlines() if line.startswith('CodeDirectory')):
        raise SystemExit('network binaries must have Hardened Runtime')
resources = bundle / 'Contents/Resources/network'
resources.mkdir(parents=True, exist_ok=True)
for name in ['foxvpn-helper', 'foxvpn-network-core', 'network-version.json']:
    shutil.copy2(root / 'core' / name, resources / name)
version = json.loads((root / 'apps/desktop/src-tauri/tauri.conf.json').read_text())['version']
protocol = int(re.search(r'pub const PROTOCOL: u32 = (\d+);', (root / 'src/network_helper.rs').read_text()).group(1))
actual = json.loads(subprocess.check_output([str(resources / 'foxvpn-helper'), '--component-version'], timeout=15))
if actual != {'version': version, 'protocol': protocol}:
    raise SystemExit('Packaged helper version/protocol differs from the app; rebuild it')
(resources / 'component-version.json').write_text(json.dumps({'version': version, 'protocol': protocol}, indent=2)+'\n')
subprocess.run(['codesign', '--force', '--sign', args.identity, '--options', 'runtime', str(bundle)], check=True)
subprocess.run(['codesign', '--verify', '--deep', '--strict', str(bundle)], check=True)
print('App sealed; pinned network resources and Hardened Runtime verified')
