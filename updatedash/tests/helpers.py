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
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from udash.config import load_config  # noqa: E402
from udash.server import App, LimitedServer, make_handler, wrap_tls  # noqa: E402

PASSWORD = "correct horse battery"


class FakeVault:
    key = b"k" * 32

    def derive(self, label):
        import hashlib
        import hmac
        return hmac.new(self.key, label, hashlib.sha256).digest()

    def encrypt(self, s):
        return "enc:" + s[::-1]

    def decrypt(self, t):
        return t[4:][::-1]


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
    def __init__(self, base, cafile=None):
        self.base = base
        self.jar = http.cookiejar.CookieJar()
        handlers = [urllib.request.HTTPCookieProcessor(self.jar), NoRedirect]
        if cafile:
            import ssl
            handlers.append(urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=cafile)))
        self.opener = urllib.request.build_opener(*handlers)

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

    def prepare(self):
        """Hook for subclasses: runs after the temp dir exists and before the app starts."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="udtest-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.prepare()
        cfg = load_config(write_config(self.tmp, self.extra_config.replace("__TMP__", self.tmp)))
        self.app = App(cfg, state_dir=Path(self.tmp) / "state", base_dir=ROOT)
        self.srv = LimitedServer(("127.0.0.1", 0), make_handler(self.app), max_connections=self.app.cfg["max_connections"])
        wrap_tls(self.srv, self.app)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)
        self.port = self.srv.server_address[1]
        scheme = "https" if self.app.tls else "http"
        host = "localhost" if self.app.tls else "127.0.0.1"
        self.base = f"{scheme}://{host}:{self.port}"
        self.c = Client(self.base, cafile=self.app.tls_cert)

    def signed_in(self):
        st, _, _ = self.c.login()
        self.assertEqual(st, 200)
        return self.c
