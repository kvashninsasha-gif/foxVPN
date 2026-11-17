#!/usr/bin/env python3
"""Test the actual release EXE's headless recovery entry on a disposable runner."""
import ctypes as c
from ctypes import wintypes as w
import json
import http.server
import uuid
import os
from pathlib import Path
import queue
import subprocess
import sys
import tempfile
import threading
import time

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
original = read()
before = (1, original[1], "*;*.com", original[3])
# Seed a wildcard only inside the restoration guard below.
def managed_bypass():
    return "localhost;127.*;[::1]"

def chrome_uses_system_proxy(temp):
    chrome = next((Path(base)/"Google/Chrome/Application/chrome.exe"
        for base in (os.environ.get("PROGRAMFILES", ""), os.environ.get("PROGRAMFILES(X86)", ""))
        if (Path(base)/"Google/Chrome/Application/chrome.exe").is_file()), None)
    assert chrome, "Chrome is required for the Windows browser regression"
    token = "foxvpn-browser-" + uuid.uuid4().hex
    hits = []
    class Proxy(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            ok = self.path.startswith("http://foxvpn-proxy-test.invalid/")
            if ok: hits.append(self.path)
            body = ("<html><body>"+token+"</body></html>").encode() if ok else b"unrelated"
            self.send_response(200 if ok else 502)
            self.send_header("Content-Length", str(len(body))); self.end_headers()
            self.wfile.write(body)
        def log_message(self, *_): pass
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 2080), Proxy)
    thread = threading.Thread(target=server.serve_forever, daemon=True);thread.start()
    try:
        result = subprocess.run([str(chrome), "--headless=new", "--disable-gpu", "--no-first-run",
            "--no-default-browser-check", "--disable-background-networking",
            "--disable-features=HttpsUpgrades", "--user-data-dir="+str(Path(temp)/"chrome"),
            "--dump-dom", "http://foxvpn-proxy-test.invalid/probe"],
            capture_output=True, text=True, timeout=35)
        assert token in result.stdout and hits, "Chrome did not use the managed Windows proxy"
        print("Chrome used Windows proxy despite inherited wildcard bypass", flush=True)
    finally:
        server.shutdown();server.server_close();thread.join(timeout=3)

with tempfile.TemporaryDirectory(prefix="foxvpn-release-guardian-") as temp:
    env = dict(os.environ, APPDATA=temp)
    process = subprocess.Popen([str(exe), "--foxvpn-proxy-guardian"], env=env,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        write(before)
        process.stdin.write((json.dumps(2080) + "\n").encode()); process.stdin.flush()
        reply = queue.Queue()
        threading.Thread(target=lambda: reply.put(process.stdout.readline()), daemon=True).start()
        assert reply.get(timeout=15).strip() == b"FOXVPN_PROXY_READY"
        assert read() == (3, "127.0.0.1:2080", managed_bypass(), before[3])
        chrome_uses_system_proxy(temp)
        process.stdin.close()
        assert process.wait(timeout=15) == 0
        expected = before
        if before[0] & 2 and before[1].strip() == "127.0.0.1:2080":
            expected = ((before[0] & ~2) | 1, *before[1:])
        assert read() == expected
        assert not (Path(temp) / "ru.smartvpn.router/windows-proxy-session.json").exists()
        # Kill the guardian too: next ordinary launch must recover before reading
        # even a broken encrypted profile, without relying on GUI initialization.
        write(before)
        process = subprocess.Popen([str(exe), "--foxvpn-proxy-guardian"], env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW)
        process.stdin.write(b"2080\n"); process.stdin.flush()
        reply = queue.Queue()
        threading.Thread(target=lambda: reply.put(process.stdout.readline()), daemon=True).start()
        assert reply.get(timeout=15).strip() == b"FOXVPN_PROXY_READY"
        process.kill(); process.wait(timeout=10)
        data = Path(temp) / "ru.smartvpn.router"
        (data / "profile.enc").write_bytes(b"corrupt-test-profile")
        main = subprocess.Popen([str(exe)], env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            deadline = time.monotonic() + 15
            while (read() != expected or (data / "windows-proxy-session.json").exists()) and time.monotonic() < deadline:
                time.sleep(0.05)
            assert read() == expected
            assert not (data / "windows-proxy-session.json").exists()
        finally:
            if main.poll() is None: main.kill()
            main.wait(timeout=10)
    finally:
        if process.poll() is None:
            process.kill(); process.wait(timeout=10)
        write(original)
print("Release EXE proxy restore and recovery before corrupt profile verified")
