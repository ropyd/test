"""HTTP server: login/sessions, CSRF protection, JSON API and static files."""
import http.cookies
import json
import logging
import mimetypes
import re
import signal
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import __version__
from .auth import Auth, AuthError, Locked
from .config import STATE_DIR, is_trusted_proxy, load_config
from .core import Dash
from .store import AccessStore, Audit, LogStore, Settings, ValidationError, Vault

log = logging.getLogger("updatedash")
COOKIE = "ud_session"
PUBLIC_STATIC = {"login.html", "login.js", "style.css"}
PRIVATE_STATIC = {"index.html", "app.js"}
MAX_BODY = 65536
STARTED = time.time()


class App:
    """Everything the request handlers need."""

    def __init__(self, cfg=None, state_dir=None, base_dir=None):
        self.cfg = cfg or load_config()
        self.state_dir = Path(state_dir or STATE_DIR)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.base_dir = Path(base_dir or Path(__file__).resolve().parent.parent)
        self.static = self.base_dir / "static"
        vault = Vault(self.cfg["secret_key_file"], self.state_dir)
        self.auth = Auth(self.cfg, self.state_dir, vault)
        self.settings = Settings(self.state_dir / "settings.json", {"log_retention": self.cfg["log_retention"]})
        self.access = AccessStore(self.state_dir / "access.json", vault)
        self.logs = LogStore(self.state_dir / "logs")
        self.audit = Audit(self.state_dir / "audit.log")
        self.dash = Dash(self.cfg, self.state_dir, vault, self.access, self.logs, self.settings, self.audit,
                         self.base_dir)
        self.tls = bool(self.cfg["tls_cert"] and self.cfg["tls_key"])
        if self.auth.plaintext_in_config:
            log.warning("the config has a plaintext `password`; change it in Settings or store `password_hash`")


def make_handler(app):
    cfg, auth, dash = app.cfg, app.auth, app.dash

    class H(BaseHTTPRequestHandler):
        server_version = "updatedash"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            if self.path.startswith(("/healthz", "/static/", "/api/services", "/api/jobs")):
                return
            log.info("%s - %s", self.address_string(), fmt % args)

        # -- request helpers
        def client_ip(self):
            peer = self.client_address[0]
            if is_trusted_proxy(cfg, peer):
                fwd = [x.strip() for x in self.headers.get("X-Forwarded-For", "").split(",") if x.strip()]
                for ip in reversed(fwd):
                    if not is_trusted_proxy(cfg, ip):
                        return ip
            return peer

        def is_https(self):
            return app.tls or (is_trusted_proxy(cfg, self.client_address[0])
                               and self.headers.get("X-Forwarded-Proto", "").lower() == "https")

        def session_user(self):
            raw = self.headers.get("Cookie", "")
            try:
                jar = http.cookies.SimpleCookie(raw)
            except http.cookies.CookieError:
                return None
            return auth.check_session(jar[COOKIE].value) if COOKIE in jar else None

        def cookie(self, value, max_age):
            parts = [f"{COOKIE}={value}", "Path=/", "HttpOnly", "SameSite=Strict", f"Max-Age={max_age}"]
            if self.is_https():
                parts.append("Secure")
            return "; ".join(parts)

        def origin_ok(self):
            origin = self.headers.get("Origin")
            if not origin:
                return True
            host = self.headers.get("Host", "")
            if is_trusted_proxy(cfg, self.client_address[0]) and self.headers.get("X-Forwarded-Host"):
                host = self.headers["X-Forwarded-Host"].split(",")[0].strip()
            return urlparse(origin).netloc.lower() == host.lower()

        def send_body(self, code, body, ctype, extra=None, cache="no-store"):
            data = body if isinstance(body, bytes) else body.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", cache)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
                             "form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
            if self.is_https():
                self.send_header("Strict-Transport-Security", "max-age=31536000")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)

        def send_json(self, code, obj, extra=None):
            self.send_body(code, json.dumps(obj), "application/json", extra)

        def redirect(self, to):
            self.send_body(302, b"", "text/plain", {"Location": to})

        def read_body(self):
            try:
                n = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                raise ValidationError("bad Content-Length")
            if n > MAX_BODY:
                raise ValidationError("request too large")
            try:
                body = json.loads(self.rfile.read(n) or b"{}")
            except ValueError:
                raise ValidationError("invalid JSON")
            if not isinstance(body, dict):
                raise ValidationError("expected a JSON object")
            return body

        def static_file(self, name):
            f = app.static / name
            if not f.is_file():
                return self.send_json(404, {"error": "not found"})
            ctype = (mimetypes.guess_type(name)[0] or "application/octet-stream") + "; charset=utf-8"
            self.send_body(200, f.read_bytes(), ctype, cache="no-cache")

        # -- routing
        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            try:
                self._get()
            except Exception:  # noqa: BLE001
                log.exception("unhandled error in GET %s", self.path)
                self.send_json(500, {"error": "internal error"})

        def do_POST(self):
            try:
                self._post()
            except ValidationError as e:
                self.send_json(400, {"error": str(e)})
            except AuthError as e:
                self.send_json(400, {"error": str(e)})
            except ValueError as e:
                self.send_json(409, {"error": str(e)})
            except Exception:  # noqa: BLE001
                log.exception("unhandled error in POST %s", self.path)
                self.send_json(500, {"error": "internal error"})

        def _get(self):
            url = urlparse(self.path)
            path = url.path
            if path == "/healthz":
                return self.send_body(200, b"ok", "text/plain")
            if path == "/login":
                return self.static_file("login.html")
            if path.startswith("/static/") and path[8:] in PUBLIC_STATIC:
                return self.static_file(path[8:])
            user = self.session_user()
            if not user:
                if path.startswith("/api/"):
                    return self.send_json(401, {"error": "not signed in"})
                return self.redirect("/login")
            q = parse_qs(url.query)
            if path == "/":
                return self.static_file("index.html")
            if path.startswith("/static/") and path[8:] in PRIVATE_STATIC:
                return self.static_file(path[8:])
            if path == "/api/me":
                return self.send_json(200, {"user": user, "version": __version__,
                                            "plaintext_password": auth.plaintext_in_config})
            if path == "/api/services":
                return self.send_json(200, dash.view())
            if path == "/api/inventory":
                return self.send_json(200, dash.inventory())
            if path == "/api/settings":
                return self.send_json(200, app.settings.public())
            if path == "/api/audit":
                n = min(int((q.get("limit") or ["50"])[0] or 50), 200)
                return self.send_json(200, {"events": app.audit.tail(n)})
            if path == "/api/about":
                return self.send_json(200, {"version": __version__, "uptime": int(time.time() - STARTED),
                                            "transport": cfg["transport"], "tls": app.tls})
            if path == "/api/logs":
                try:
                    ctid = int((q.get("ctid") or [""])[0])
                except ValueError:
                    return self.send_json(400, {"error": "ctid required"})
                return self.send_json(200, {"logs": app.logs.list(ctid), "retention": app.settings.get("log_retention")})
            if path == "/api/access":
                try:
                    ctid = int((q.get("ctid") or [""])[0])
                except ValueError:
                    return self.send_json(400, {"error": "ctid required"})
                return self.send_json(200, {"access": app.access.public(ctid)})
            m = re.fullmatch(r"/api/jobs/([0-9a-f]{12})", path)
            if m:
                try:
                    since = max(0, int((q.get("since") or ["0"])[0] or 0))
                except ValueError:
                    since = 0
                v = dash.job_view(m.group(1), since)
                return self.send_json(200, v) if v else self.send_json(404, {"error": "unknown job"})
            self.send_json(404, {"error": "not found"})

        def _post(self):
            path = urlparse(self.path).path
            if self.headers.get("X-Requested-With") != "updatedash" or not self.origin_ok():
                return self.send_json(403, {"error": "request rejected (missing header or cross-origin)"})
            ip = self.client_ip()
            body = self.read_body()
            if path == "/api/login":
                try:
                    tok = auth.login(ip, str(body.get("username", "")), str(body.get("password", "")))
                except Locked as e:
                    app.audit.append("-", ip, "login.locked", f"retry in {e.retry_after}s")
                    return self.send_json(429, {"error": f"Too many failed attempts. Try again in {e.retry_after} seconds."},
                                          {"Retry-After": str(e.retry_after)})
                if not tok:
                    app.audit.append(str(body.get("username", ""))[:40], ip, "login.fail")
                    return self.send_json(401, {"error": "Invalid username or password."})
                app.audit.append(auth.username, ip, "login.ok")
                return self.send_json(200, {"ok": True}, {"Set-Cookie": self.cookie(tok, auth.session_seconds)})
            user = self.session_user()
            if not user:
                return self.send_json(401, {"error": "not signed in"})
            if path == "/api/logout":
                app.audit.append(user, ip, "logout")
                return self.send_json(200, {"ok": True}, {"Set-Cookie": self.cookie("", 0)})
            if path == "/api/password":
                tok = auth.change_password(str(body.get("current", "")), str(body.get("new", "")))
                app.audit.append(user, ip, "password.change")
                return self.send_json(200, {"ok": True}, {"Set-Cookie": self.cookie(tok, auth.session_seconds)})
            if path == "/api/settings":
                changed = app.settings.update(body)
                if "log_retention" in changed:
                    removed = app.logs.prune_all(changed["log_retention"])
                    app.audit.append(user, ip, "settings.log_retention", f"{changed['log_retention']} (removed {removed} logs)")
                return self.send_json(200, app.settings.public())
            ctid = body.get("ctid")
            if ctid is not None and (isinstance(ctid, bool) or not isinstance(ctid, int)):
                raise ValidationError("ctid must be a number")
            if path == "/api/allow":
                action = body.get("action")
                if ctid is None or not 0 < ctid < 10 ** 9 or action not in ("add", "remove"):
                    raise ValidationError("bad container or action")
                ok, msg = dash.set_allowed(ctid, action == "add")
                app.audit.append(user, ip, f"allow.{action}", f"CT {ctid} -> {'ok' if ok else msg}")
                return self.send_json(200 if ok else 409, {"ok": ok, "message": msg})
            if path == "/api/access/test":
                res = dash.access_test(body)
                app.audit.append(user, ip, "access.test", f"{body.get('user')}@{body.get('host')} -> {'ok' if res['ok'] else 'fail'}")
                return self.send_json(200, res)
            if path == "/api/access/save":
                return self.send_json(200, dash.access_save(body, actor=user))
            if path == "/api/access/remove":
                if ctid is None:
                    raise ValidationError("ctid required")
                dash.access_remove(ctid, actor=user)
                return self.send_json(200, {"ok": True})
            if ctid is not None and ctid not in dash.services:
                return self.send_json(404, {"error": "unknown container"})
            if path == "/api/check":
                dash.check_async(ctid)
                return self.send_json(202, {"ok": True})
            if path == "/api/cancel":
                if ctid is None:
                    raise ValidationError("ctid required")
                dash.cancel(ctid, actor=user)
                return self.send_json(202, {"ok": True})
            if path == "/api/update":
                kind = body.get("kind", "app")
                if ctid is None or kind not in ("app", "os"):
                    raise ValidationError("bad container or kind")
                return self.send_json(202, {"job": dash.start_update(ctid, kind, actor=user)})
            self.send_json(404, {"error": "not found"})

    return H


def serve(app):
    host, _, port = app.cfg["listen"].rpartition(":")
    srv = ThreadingHTTPServer((host or "127.0.0.1", int(port)), make_handler(app))
    srv.daemon_threads = True
    if app.tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(app.cfg["tls_cert"], app.cfg["tls_key"])
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    stop = threading.Event()

    def scheduler():
        app.dash.check_all()
        while not stop.is_set():
            if stop.wait(60):
                break
            if time.time() - app.dash.last_sweep >= app.cfg["check_interval_minutes"] * 60:
                app.dash.check_all()

    threading.Thread(target=scheduler, daemon=True).start()

    def on_signal(signum, _frame):
        log.info("signal %s: shutting down", signum)
        stop.set()
        threading.Thread(target=srv.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    log.info("updatedash %s listening on %s%s (transport=%s, discover=%s)", __version__,
             "https://" if app.tls else "http://", app.cfg["listen"], app.cfg["transport"], app.cfg["discover"])
    srv.serve_forever()
    srv.server_close()
    if app.dash.running_jobs():
        log.info("waiting for running updates to finish (up to 60s)")
    app.dash.shutdown(wait=60)
    return 0
