#!/usr/bin/env python3
"""Build the pinned GPL sing-box source for iPhone and Apple Silicon simulator."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--work-dir', type=Path, required=True)
parser.add_argument('--go', default='go')
args = parser.parse_args()
ios = Path(__file__).resolve().parent.parent
repo = ios.parent.parent
archive = repo / 'vendor/sing-box-1.14.2-source.tar.gz'
expected = json.loads((repo / 'core/network-version.json').read_text())['source_archive_sha256']
if hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
    raise SystemExit('Upstream source SHA256 mismatch')
work = args.work_dir.resolve()
work.mkdir(parents=True, exist_ok=True)
with tarfile.open(archive) as source:
    source.extractall(work, filter='data')
module = next(p.parent for p in work.glob('*/go.mod'))
tools = work / 'tools'
tools.mkdir(exist_ok=True)
go_binary = Path(args.go).resolve() if Path(args.go).is_file() else None
env = dict(os.environ, GOBIN=str(tools), PATH=str(tools) + os.pathsep + (str(go_binary.parent) + os.pathsep if go_binary else "") + os.environ['PATH'])
subprocess.run([args.go, 'install', 'github.com/sagernet/gomobile/cmd/gomobile@v0.1.12', 'github.com/sagernet/gomobile/cmd/gobind@v0.1.12'], env=env, check=True)
framework = ios / 'Frameworks/Libbox.xcframework'
framework.parent.mkdir(exist_ok=True)
subprocess.run([str(tools / 'gomobile'), 'bind', '-target', 'ios/arm64,iossimulator/arm64', '-iosversion', '16.0', '-libname', 'box', '-trimpath', '-buildvcs=false', '-tags', 'with_utls,with_gvisor,with_quic,with_clash_api,with_low_memory', '-ldflags', '-s -w -X github.com/sagernet/sing-box/constant.Version=1.14.2', '-o', str(framework), './experimental/libbox'], cwd=module, env=env, check=True)
print('Built', framework)
