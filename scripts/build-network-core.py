#!/usr/bin/env python3
"""Compatibility entry for the shared pinned macOS network-core build."""
import pathlib,runpy,sys
sys.argv.append('--network')
runpy.run_path(str(pathlib.Path(__file__).with_name('build-core.py')),run_name='__main__')
