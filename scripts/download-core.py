#!/usr/bin/env python3
"""Legacy entry now delegates to audited pinned source; never replaces with stock binary."""
import argparse,pathlib,subprocess,sys,tempfile
p=argparse.ArgumentParser();p.add_argument('--platform',choices=['darwin-arm64','darwin-amd64','windows-amd64']);p.add_argument('--work-dir');a=p.parse_args()
root=pathlib.Path(__file__).resolve().parents[1]
command=[sys.executable,str(root/'scripts/build-core.py'),'--scan']
if a.platform:command+=['--platform',a.platform]
if a.work_dir:subprocess.run(command+['--work-dir',a.work_dir],check=True)
else:
 with tempfile.TemporaryDirectory(prefix='foxvpn-core-') as work:subprocess.run(command+['--work-dir',work],check=True)
