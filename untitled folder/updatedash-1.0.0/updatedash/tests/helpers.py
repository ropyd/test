"""Shared test helpers: a throwaway App on a random port and a tiny cookie-aware HTTP client."""
import http.cookiejar
import json
import shutil
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from udash.config import load_config  # noqa: E402
from udash.server import App, make_handler  # noqa: E402

PASSWORD = "correct horse battery"


def write_config(tmp, extra=""):
    p = Path(tmp) / "config.yaml"
    p.write_text(f'''listen: "127.0.0.1:0"
username: admin
password: "{PASSWORD}"
transport: local
discover: false
secret_key_file: "{tmp}/secret.key"
{extra}
''')
    return p


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class Client:
    def __init__(self, base):
        self.base = base
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar), NoRedirect)

    def call(self, method, path, body=None, headers=None, csrf=True):
        h = dict(headers or {})
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
        if method == "POST" and csrf:
            h.setdefault("X-Requested-With", "updatedash")
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=h)
        try:
            r = self.opener.open(req, timeout=15)
        except urllib.error.HTTPError as e:
            r = e
        raw = r.read()
        try:
            parsed = json.loads(raw) if raw else None
        except ValueError:
            parsed = raw
        return r.status, parsed, r.headers

    def get(self, path, **kw):
        return self.call("GET", path, **kw)

    def post(self, path, body=None, **kw):
        return self.call("POST", path, body or {}, **kw)

    def login(self, password=PASSWORD):
        return self.post("/api/login", {"username": "admin", "password": password})


class AppCase(unittest.TestCase):
    extra_config = ""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="udtest-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        cfg = load_config(write_config(self.tmp, self.extra_config))
        self.app = App(cfg, state_dir=Path(self.tmp) / "state", base_dir=ROOT)
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.app))
        self.srv.daemon_threads = True
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"
        self.c = Client(self.base)

    def signed_in(self):
        st, _, _ = self.c.login()
        self.assertEqual(st, 200)
        return self.c
