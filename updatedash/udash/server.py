"""HTTP server: login, revocable sessions, two-factor, CSRF protection, JSON API and static files."""
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
from .config import STATE_DIR, is_allowed_client, is_trusted_proxy, load_config
from .core import Dash
from .scripts_catalog import ScriptCatalog, build_plan
from .automation import Automation
from .theme import PRESETS, ThemeStore, theme_css
from .tokens import TokenStore
from .store import AccessStore, Audit, HostRegistry, LogStore, Settings, ValidationError, Vault

log = logging.getLogger("updatedash")
COOKIE_PLAIN, COOKIE_HOST = "ud_session", "__Host-ud_session"
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
        try:
            self.state_dir.chmod(0o700)
        except OSError:
            pass
        self.base_dir = Path(base_dir or Path(__file__).resolve().parent.parent)
        self.static = self.base_dir / "static"
        vault = Vault(self.cfg["secret_key_file"], self.state_dir)
        self.auth = Auth(self.cfg, self.state_dir, vault)
        self.settings = Settings(self.state_dir / "settings.json", {"log_retention": self.cfg["log_retention"]})
        self.access = AccessStore(self.state_dir / "access.json", vault)
        self.logs = LogStore(self.state_dir / "logs")
        self.audit = Audit(self.state_dir / "audit.log")
        self.hosts = HostRegistry(self.state_dir / "hosts.json", self.cfg.get("pve"))
        self.tokens = TokenStore(self.state_dir / "tokens.json")
        self.theme = ThemeStore(self.state_dir / "theme.json")
        self.catalog = ScriptCatalog(self.state_dir / "catalog.json", token=self.cfg.get("github_token", ""))
        self.dash = Dash(self.cfg, self.state_dir, vault, self.access, self.logs, self.settings, self.audit,
                         self.base_dir, self.hosts)
        self.automation = Automation(self.state_dir / "automation.json", self.dash, self.audit)
        self.tls_cert = self.tls_key = self.tls_fingerprint = None
        if self.cfg["tls_cert"] and self.cfg["tls_key"]:
            self.tls_cert, self.tls_key = self.cfg["tls_cert"], self.cfg["tls_key"]
        elif self.cfg["tls"] == "auto":
            from . import tls
            self.tls_cert, self.tls_key, self.tls_fingerprint = tls.ensure_self_signed(
                self.state_dir / "tls", self.cfg["tls_names"])
        self.tls = bool(self.tls_cert)
        self.proxy_headers_seen = False        # forwarded headers arrived from a peer we don't trust
        if self.auth.plaintext_in_config:
            log.warning("the config has a plaintext `password`; change it in Settings or store `password_hash`")


class LimitedServer(ThreadingHTTPServer):
    """Threaded server with a cap on simultaneous connections (a flood can't spawn unlimited threads)."""
    daemon_threads = True

    def __init__(self, *a, max_connections=64, **k):
        super().__init__(*a, **k)
        self._slots = threading.BoundedSemaphore(max_connections)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


def make_handler(app):
    cfg, auth, dash = app.cfg, app.auth, app.dash

    class H(BaseHTTPRequestHandler):
        server_version = "updatedash"
        sys_version = ""
        protocol_version = "HTTP/1.1"
        timeout = cfg["socket_timeout"]           # idle/slow clients are dropped (slowloris)

        def log_message(self, fmt, *args):
            if self.path.startswith(("/healthz", "/static/", "/api/services", "/api/jobs")):
                return
            log.info("%s - %s", self.address_string(), fmt % args)

        def handle(self):
            if isinstance(self.connection, ssl.SSLSocket):     # handshake here, in this thread, with the timeout
                try:
                    self.connection.do_handshake()
                except (ssl.SSLError, OSError):
                    return
            super().handle()

        # -- request helpers
        def trusted_peer(self):
            return is_trusted_proxy(cfg, self.client_address[0])

        def client_ip(self):
            peer = self.client_address[0]
            if self.trusted_peer():
                fwd = [x.strip() for x in self.headers.get("X-Forwarded-For", "").split(",") if x.strip()]
                for ip in reversed(fwd):
                    if not is_trusted_proxy(cfg, ip):
                        return ip
            elif self.headers.get("X-Forwarded-For") or self.headers.get("X-Forwarded-Proto"):
                app.proxy_headers_seen = True
            return peer

        def is_https(self):
            return app.tls or (self.trusted_peer() and self.headers.get("X-Forwarded-Proto", "").lower() == "https")

        def session(self):
            """The current session dict, or None. Looked up on every call: one handler object serves many requests
            on a keep-alive connection, so nothing about a request may be remembered between calls."""
            try:
                jar = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
            except http.cookies.CookieError:
                return None
            for name in (COOKIE_HOST, COOKIE_PLAIN):
                if name in jar:
                    return auth.sessions.validate(jar[name].value)
            return None

        def cookie(self, value, max_age):
            # __Host- cookies must be Secure, Path=/ and carry no Domain: other sites/subdomains can't overwrite them.
            name = COOKIE_HOST if self.is_https() else COOKIE_PLAIN
            parts = [f"{name}={value}", "Path=/", "HttpOnly", "SameSite=Strict", f"Max-Age={max_age}"]
            if self.is_https():
                parts.append("Secure")
            return "; ".join(parts)

        def origin_ok(self):
            sfs = self.headers.get("Sec-Fetch-Site")
            if sfs and sfs not in ("same-origin", "none"):
                return False
            origin = self.headers.get("Origin")
            if not origin:
                return True
            host = self.headers.get("Host", "")
            if self.trusted_peer() and self.headers.get("X-Forwarded-Host"):
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
            self.send_header("Cross-Origin-Opener-Policy", "same-origin")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
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
            data = f.read_bytes()
            mode = app.theme.theme["mode"]
            if name.endswith(".html") and mode != "auto":          # a fixed light/dark choice is applied before the page paints
                data = data.replace(b'<html lang="en">', f'<html lang="en" data-mode="{mode}">'.encode(), 1)
            self.send_body(200, data, ctype, cache="no-cache")

        def warnings(self):
            w = []
            if auth.plaintext_in_config:
                w.append("The config file still holds a plaintext password. Set a new one under Settings → Password.")
            if not self.is_https():
                w.append("This connection is not encrypted: passwords and the session cookie cross the network in clear text. "
                         "Turn on `tls: auto` or put the dashboard behind an HTTPS reverse proxy.")
            if app.proxy_headers_seen and not cfg["_trusted_nets"]:
                w.append("Requests arrive through a reverse proxy but `trust_proxy` is not set, so every visitor looks like "
                         "the proxy: the login lockout and audit log cannot tell clients apart. Set `trust_proxy` in the config.")
            if not auth.totp_enabled:
                w.append("Two-factor sign-in is off. This tool can run commands as root in your containers: turn it on under Settings.")
            return w

        # -- routing
        def do_HEAD(self):
            self.do_GET()

        def blocked(self):
            """Network allowlist (allow_from). Checked first, for every request, using the real client address."""
            if is_allowed_client(cfg, self.client_ip()):
                return False
            self.send_json(403, {"error": "forbidden"})
            return True

        def do_GET(self):
            try:
                if self.path != "/healthz" and self.blocked():
                    return
                self._get()
            except (ValidationError, AuthError) as e:
                self.send_json(400, {"error": str(e)})
            except Exception:  # noqa: BLE001
                log.exception("unhandled error in GET %s", self.path)
                self.send_json(500, {"error": "internal error"})

        def do_POST(self):
            try:
                if self.blocked():
                    return
                self._post()
            except (ValidationError, AuthError) as e:
                self.send_json(400, {"error": str(e)})
            except ValueError as e:
                self.send_json(409, {"error": str(e)})
            except Exception:  # noqa: BLE001
                log.exception("unhandled error in POST %s", self.path)
                self.send_json(500, {"error": "internal error"})

        def token_summary(self, q):
            """Read-only counts for other dashboards, authenticated with a bearer token (never a session cookie)."""
            ip = self.client_ip()
            try:
                auth.throttle_check(ip)
            except Locked as e:
                return self.send_json(429, {"error": "too many failed attempts"}, {"Retry-After": str(e.retry_after)})
            header = self.headers.get("Authorization", "")
            rec = app.tokens.verify(header[7:].strip()) if header.lower().startswith("bearer ") else None
            if not rec:
                auth.throttle_fail(ip)
                return self.send_json(401, {"error": "a valid bearer token is required"},
                                      {"WWW-Authenticate": 'Bearer realm="updatedash"'})
            wait = app.tokens.allow(rec["id"])
            if wait:
                return self.send_json(429, {"error": "rate limit exceeded"}, {"Retry-After": str(wait)})
            want_detail = (q.get("detail") or ["0"])[0] == "1"
            return self.send_json(200, dash.summary(detail=want_detail and rec["detail"]))

        def _get(self):
            url = urlparse(self.path)
            path = url.path
            self.client_ip()                          # also notes forwarded headers from untrusted peers
            if path == "/healthz":
                return self.send_body(200, b"ok", "text/plain")
            if path == "/login":
                return self.static_file("login.html")
            if path == "/theme.css":
                return self.send_body(200, theme_css(app.theme.theme), "text/css; charset=utf-8", cache="no-cache")
            if path == "/api/login-info":
                return self.send_json(200, {"totp": auth.totp_enabled})
            if path.startswith("/static/") and path[8:] in PUBLIC_STATIC:
                return self.static_file(path[8:])
            if path == "/api/v1/summary":
                return self.token_summary(parse_qs(url.query))
            sess = self.session()
            if not sess:
                if path.startswith("/api/"):
                    return self.send_json(401, {"error": "not signed in"})
                return self.redirect("/login")
            user = sess["user"]
            q = parse_qs(url.query)
            if path == "/":
                return self.static_file("index.html")
            if path.startswith("/static/") and path[8:] in PRIVATE_STATIC:
                return self.static_file(path[8:])
            if path == "/api/me":
                return self.send_json(200, {"user": user, "version": __version__, "warnings": self.warnings(),
                                            "totp": auth.totp_enabled})
            if path == "/api/services":
                return self.send_json(200, dash.view())
            if path == "/api/inventory":
                try:
                    host = int((q.get("host") or ["0"])[0] or 0)
                except ValueError:
                    return self.send_json(400, {"error": "bad host"})
                return self.send_json(200, dash.inventory(host))
            if path == "/api/node-info":
                try:
                    host = int((q.get("host") or ["0"])[0] or 0)
                except ValueError:
                    return self.send_json(400, {"error": "bad host"})
                return self.send_json(200, dash.node_info(host))
            if path == "/api/hosts/my-ip":
                target = (q.get("host") or [""])[0].strip()
                if not re.fullmatch(r"[A-Za-z0-9._:-]{1,253}", target):
                    return self.send_json(400, {"error": "bad address"})
                return self.send_json(200, {"ip": dash.local_ip_for(target)})
            if path == "/api/hosts":
                return self.send_json(200, {"hosts": dash.hosts_view()})
            if path == "/api/hosts/setup-script":
                ips = [x for x in (q.get("ips") or [""])[0].split(",") if x.strip()]
                script = dash.host_setup_script(ips, (q.get("allow") or [""])[0], (q.get("protected") or [""])[0],
                                                (q.get("manage") or ["1"])[0] != "0")
                return self.send_json(200, {"script": script, "dashboard_ips": ips})
            if path == "/api/settings":
                return self.send_json(200, app.settings.public())
            if path == "/api/audit":
                n = min(int((q.get("limit") or ["50"])[0] or 50), 200)
                ok, bad = app.audit.verify()
                return self.send_json(200, {"events": app.audit.tail(n), "chain_ok": ok, "chain_broken_at": bad})
            if path == "/api/about":
                return self.send_json(200, {"version": __version__, "uptime": int(time.time() - STARTED),
                                            "transport": cfg["transport"], "tls": app.tls,
                                            "tls_fingerprint": app.tls_fingerprint})
            if path == "/api/system":
                try:
                    sid = int((q.get("ctid") or [""])[0])
                except ValueError:
                    return self.send_json(400, {"error": "ctid required"})
                v = dash.system_view(sid)
                return self.send_json(200, v) if v else self.send_json(404, {"error": "unknown container"})
            if path == "/api/sessions":
                return self.send_json(200, {"sessions": auth.sessions.list(sess["id"])})
            if path == "/api/theme":
                return self.send_json(200, {"theme": app.theme.theme, "presets": PRESETS})
            if path == "/api/catalog":
                app.catalog.refresh_async()                                 # no-op while the cache is fresh
                try:
                    limit = int((q.get("limit") or ["30"])[0] or 30)
                    offset = max(0, int((q.get("offset") or ["0"])[0] or 0))
                except ValueError:
                    return self.send_json(400, {"error": "bad paging"})
                found = app.catalog.search((q.get("q") or [""])[0][:80], (q.get("tag") or [""])[0][:30], limit, offset)
                return self.send_json(200, dict(found, status=app.catalog.status(), tags=app.catalog.tags()))
            if path == "/api/automation":
                return self.send_json(200, app.automation.public())
            if path == "/api/tokens":
                return self.send_json(200, {"tokens": app.tokens.list()})
            if path == "/api/summary-preview":
                return self.send_json(200, dash.summary(detail=True))
            if path == "/api/2fa":
                return self.send_json(200, auth.two_factor_status())
            if path == "/api/custom-commands":
                return self.send_json(200, {"commands": dash.commands_needing_approval()})
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
            ua = self.headers.get("User-Agent", "")
            body = self.read_body()
            if path == "/api/login":
                try:
                    tok = auth.login(ip, str(body.get("username", "")), str(body.get("password", "")),
                                     str(body.get("code", "")), ua)
                except Locked as e:
                    app.audit.append("-", ip, "login.locked", f"retry in {e.retry_after}s")
                    return self.send_json(429, {"error": f"Too many failed attempts. Try again in {e.retry_after} seconds."},
                                          {"Retry-After": str(e.retry_after)})
                if not tok:
                    app.audit.append(str(body.get("username", ""))[:40], ip, "login.fail")
                    return self.send_json(401, {"error": "Invalid username, password or code."})
                app.audit.append(auth.username, ip, "login.ok")
                return self.send_json(200, {"ok": True}, {"Set-Cookie": self.cookie(tok, auth.sessions.absolute)})
            sess = self.session()
            if not sess:
                return self.send_json(401, {"error": "not signed in"})
            user = sess["user"]
            if path == "/api/logout":
                auth.sessions.revoke(sess["id"])
                app.audit.append(user, ip, "logout")
                return self.send_json(200, {"ok": True}, {"Set-Cookie": self.cookie("", 0)})
            if path == "/api/password":
                tok = auth.change_password(str(body.get("current", "")), str(body.get("new", "")), ip, ua)
                app.audit.append(user, ip, "password.change", "all other sessions ended")
                return self.send_json(200, {"ok": True}, {"Set-Cookie": self.cookie(tok, auth.sessions.absolute)})
            if path == "/api/sessions/revoke":
                sid = str(body.get("id", ""))
                if sid == sess["id"]:
                    raise ValidationError("use Sign out to end your own session")
                ok = auth.sessions.revoke(sid)
                app.audit.append(user, ip, "session.revoke", sid[:12])
                return self.send_json(200, {"ok": ok})
            if path == "/api/sessions/revoke-all":
                auth.sessions.revoke_all(keep=sess["id"])
                app.audit.append(user, ip, "session.revoke_all")
                return self.send_json(200, {"ok": True})
            if path == "/api/theme":
                t = app.theme.set(body.get("preset") or body.get("theme"))
                app.audit.append(user, ip, "theme.change", f"{t['mode']} {t['background']['type']}")
                return self.send_json(200, {"theme": t})
            if path == "/api/theme/reset":
                app.audit.append(user, ip, "theme.reset")
                return self.send_json(200, {"theme": app.theme.reset()})
            if path == "/api/catalog/refresh":
                started = app.catalog.refresh_async(force=True)
                app.audit.append(user, ip, "catalog.refresh", "started" if started else "already running")
                return self.send_json(202, {"started": started})
            if path == "/api/install/plan":
                apps = body.get("apps")
                host = body.get("host", 0)
                if isinstance(host, bool) or not isinstance(host, int):
                    raise ValidationError("bad host")
                hcfg = app.hosts.get(host)
                plan = build_plan(app.catalog, apps, node_name=hcfg["name"] if hcfg else "",
                                  opt_out_diagnostics=body.get("opt_out_diagnostics", True) is not False)
                app.audit.append(user, ip, "install.plan", ",".join(a["slug"] for a in plan["apps"])[:200] + f" on host {host}")
                return self.send_json(200, plan)
            if path == "/api/automation/notify":
                n = app.automation.set_notify(body)
                app.audit.append(user, ip, "automation.notify", f"{n['kind']} enabled={n['enabled']}")
                return self.send_json(200, {"notify": n})
            if path == "/api/automation/notify/test":
                app.audit.append(user, ip, "automation.notify_test")
                return self.send_json(200, app.automation.test())
            if path == "/api/automation/auto":
                a = app.automation.set_auto(body)
                app.audit.append(user, ip, "automation.auto", f"{len(a['uids'])} container(s) at {a['hour']}:00")
                return self.send_json(200, {"auto": a})
            if path == "/api/tokens/create":
                token, rec = app.tokens.create(body.get("name"), bool(body.get("detail")))
                app.audit.append(user, ip, "token.create", f"{rec['name']} (detail={rec['detail']})")
                return self.send_json(200, {"token": token, "info": rec})
            if path == "/api/tokens/revoke":
                ok = app.tokens.revoke(str(body.get("id", "")))
                app.audit.append(user, ip, "token.revoke", str(body.get("id", ""))[:12])
                return self.send_json(200, {"ok": ok})
            if path == "/api/2fa/begin":
                res = auth.totp_begin(str(body.get("password", "")))
                app.audit.append(user, ip, "2fa.begin")
                return self.send_json(200, res)
            if path == "/api/2fa/enable":
                codes = auth.totp_enable(str(body.get("code", "")))
                app.audit.append(user, ip, "2fa.enable")
                return self.send_json(200, {"ok": True, "recovery_codes": codes})
            if path == "/api/2fa/disable":
                auth.totp_disable(str(body.get("password", "")), str(body.get("code", "")))
                app.audit.append(user, ip, "2fa.disable")
                return self.send_json(200, {"ok": True})
            if path == "/api/settings":
                changed = app.settings.update(body)
                if "log_retention" in changed:
                    removed = app.logs.prune_all(changed["log_retention"])
                    app.audit.append(user, ip, "settings.log_retention", f"{changed['log_retention']} (removed {removed} logs)")
                return self.send_json(200, app.settings.public())
            ctid = body.get("ctid")
            if ctid is not None and (isinstance(ctid, bool) or not isinstance(ctid, int)):
                raise ValidationError("ctid must be a number")
            if path == "/api/hosts/hostkey":
                return self.send_json(200, dash.host_hostkeys(body))
            if path == "/api/hosts/add":
                res = dash.add_host(body, actor=user)
                return self.send_json(200, res)
            if path == "/api/hosts/remove":
                hidx = body.get("idx")
                if isinstance(hidx, bool) or not isinstance(hidx, int):
                    raise ValidationError("idx must be a number")
                dash.remove_host(hidx, actor=user)
                return self.send_json(200, {"ok": True})
            if path == "/api/allow":
                action = body.get("action")
                host = body.get("host", 0)
                if isinstance(host, bool) or not isinstance(host, int) or not 0 <= host < 8:
                    raise ValidationError("bad host")
                if ctid is None or not 0 < ctid < 10 ** 9 or action not in ("add", "remove"):
                    raise ValidationError("bad container or action")
                ok, msg = dash.set_allowed(ctid, action == "add", host)
                app.audit.append(user, ip, f"allow.{action}", f"host {host} CT {ctid} -> {'ok' if ok else msg}")
                return self.send_json(200 if ok else 409, {"ok": ok, "message": msg})
            if path == "/api/access/hostkey":
                return self.send_json(200, dash.access_hostkeys(body))
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


def wrap_tls(srv, app):
    """Serve HTTPS when a certificate is configured. The handshake happens in the handler thread (see H.handle)."""
    if app.tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(app.tls_cert, app.tls_key)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)


def serve(app):
    host, _, port = app.cfg["listen"].rpartition(":")
    srv = LimitedServer((host or "127.0.0.1", int(port)), make_handler(app), max_connections=app.cfg["max_connections"])
    wrap_tls(srv, app)
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
    if app.tls_fingerprint:
        log.info("self-signed certificate fingerprint %s", app.tls_fingerprint)
    srv.serve_forever()
    srv.server_close()
    if app.dash.running_jobs():
        log.info("waiting for running updates to finish (up to 60s)")
    app.dash.shutdown(wait=60)
    return 0
