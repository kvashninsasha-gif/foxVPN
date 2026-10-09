#!/usr/bin/env python3
"""Test the actual release EXE's headless recovery entry on a disposable runner."""
import ctypes as c
from ctypes import wintypes as w
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import tempfile
import threading

if sys.platform != "win32" or os.environ.get("FOXVPN_TEST_ALLOW_SYSTEM_PROXY") != "1":
    raise SystemExit("Requires disposable Windows runner and explicit test opt-in")

class Value(c.Union):
    _fields_ = [("number", w.DWORD), ("text", c.c_void_p), ("time", w.FILETIME)]
class Option(c.Structure):
    _fields_ = [("kind", w.DWORD), ("value", Value)]
class Options(c.Structure):
    _fields_ = [("size", w.DWORD), ("connection", c.c_void_p),
                ("count", w.DWORD), ("error", w.DWORD), ("options", c.POINTER(Option))]

wininet = c.WinDLL("wininet", use_last_error=True)
wininet.InternetQueryOptionW.argtypes = [c.c_void_p, w.DWORD, c.c_void_p, c.POINTER(w.DWORD)]
wininet.InternetSetOptionW.argtypes = [c.c_void_p, w.DWORD, c.c_void_p, w.DWORD]
kernel = c.WinDLL("kernel32", use_last_error=True)
kernel.GlobalFree.argtypes = [c.c_void_p]
kernel.GlobalFree.restype = c.c_void_p

def read():
    items = (Option * 4)(*[Option(kind=k) for k in (10, 2, 3, 4)])
    options = Options(c.sizeof(Options), None, 4, 0, items)
    size = w.DWORD(c.sizeof(options))
    assert wininet.InternetQueryOptionW(None, 75, c.byref(options), c.byref(size))
    result = [items[0].value.number]
    for item in items[1:]:
        pointer = item.value.text
        try:
            result.append(c.wstring_at(pointer) if pointer else "")
        finally:
            if pointer: kernel.GlobalFree(pointer)
    return tuple(result)

def write(config):
    buffers = [c.create_unicode_buffer(s) for s in config[1:]]
    items = (Option * 4)(Option(kind=1, value=Value(number=config[0])),
        *[Option(kind=k, value=Value(text=c.cast(b, c.c_void_p).value))
          for k, b in zip((2, 3, 4), buffers)])
    options = Options(c.sizeof(Options), None, 4, 0, items)
    assert wininet.InternetSetOptionW(None, 75, c.byref(options), c.sizeof(options))
    wininet.InternetSetOptionW(None, 39, None, 0)
    wininet.InternetSetOptionW(None, 37, None, 0)

exe = Path(sys.argv[1]).resolve()
assert exe.is_file()
before = read()
with tempfile.TemporaryDirectory(prefix="foxvpn-release-guardian-") as temp:
    env = dict(os.environ, APPDATA=temp)
    process = subprocess.Popen([str(exe), "--foxvpn-proxy-guardian"], env=env,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        process.stdin.write((json.dumps(2080) + "\n").encode()); process.stdin.flush()
        reply = queue.Queue()
        threading.Thread(target=lambda: reply.put(process.stdout.readline()), daemon=True).start()
        assert reply.get(timeout=15).strip() == b"FOXVPN_PROXY_READY"
        assert read() == (3, "127.0.0.1:2080", before[2], before[3])
        process.stdin.close()
        assert process.wait(timeout=15) == 0
        expected = before
        if before[0] & 2 and before[1].strip() == "127.0.0.1:2080":
            expected = ((before[0] & ~2) | 1, *before[1:])
        assert read() == expected
        assert not (Path(temp) / "ru.smartvpn.router/windows-proxy-session.json").exists()
    finally:
        if process.poll() is None:
            process.kill(); process.wait(timeout=10)
        write(before)
print("Release EXE proxy configuration and restoration verified")
