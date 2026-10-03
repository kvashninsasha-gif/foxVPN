#!/usr/bin/env python3
"""Seal the app while retaining pinned, separately signed network resources."""
import argparse
import hashlib
import json
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
subprocess.run(['codesign', '--force', '--sign', args.identity, '--options', 'runtime', str(bundle)], check=True)
subprocess.run(['codesign', '--verify', '--deep', '--strict', str(bundle)], check=True)
print('App sealed; pinned network resources and Hardened Runtime verified')
