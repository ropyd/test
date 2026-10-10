import json
import time
import unittest
from pathlib import Path

from tests.helpers import PASSWORD, AppCase, Client

SERVICES = '''services:
  - name: demo-update
    ctid: 201
    current: "echo 1.0.0"
    latest: {type: command, cmd: "echo 1.2.0"}
    update: "echo running update; sleep 0.2; echo done"
  - name: demo-current
    ctid: 202
    current: "echo v2.0.0"
    latest: {type: command, cmd: "echo 2.0.0"}
  - name: demo-slow
    ctid: 203
    update: "echo starting; sleep 30; echo never"
  - name: demo-fail
    ctid: 204
    update: "echo oops; exit 3"
  - name: no-app
    ctid: 205
    os_updates: false
'''


class TestAuthFlow(AppCase):
    def test_unauthenticated_access(self):
        st, _, h = self.c.get("/")
        self.assertEqual((st, h["Location"]), (302, "/login"))
        self.assertEqual(self.c.get("/api/services")[0], 401)
        self.assertEqual(self.c.get("/static/app.js")[0], 302)
        self.assertEqual(self.c.get("/healthz")[0], 200)
        self.assertEqual(self.c.get("/login")[0], 200)
        self.assertEqual(self.c.get("/static/login.js")[0], 200)
        self.assertEqual(self.c.post("/api/update", {"ctid": 1, "kind": "app"})[0], 401)

    def test_login_logout(self):
        self.assertEqual(self.c.login("nope")[0], 401)
        st, _, h = self.c.login()
        self.assertEqual(st, 200)
        cookie = h["Set-Cookie"]
        for flag in ("HttpOnly", "SameSite=Strict", "Path=/"):
            self.assertIn(flag, cookie)
        self.assertNotIn("Secure", cookie)                          # plain http here
        self.assertEqual(self.c.get("/api/me")[1]["user"], "admin")
        self.assertEqual(self.c.get("/")[0], 200)
        self.assertEqual(self.c.post("/api/logout")[0], 200)
        self.assertEqual(self.c.get("/api/me")[0], 401)

    def test_csrf_and_origin(self):
        self.assertEqual(self.c.post("/api/login", {"username": "admin", "password": PASSWORD}, csrf=False)[0], 403)
        st, _, _ = self.c.post("/api/login", {"username": "admin", "password": PASSWORD},
                               headers={"Origin": "http://evil.example"})
        self.assertEqual(st, 403)
        st, _, _ = self.c.post("/api/login", {"username": "admin", "password": PASSWORD},
                               headers={"Origin": self.base})
        self.assertEqual(st, 200)

    def test_lockout_over_http(self):
        for _ in range(5):
            self.assertEqual(self.c.login("bad")[0], 401)
        st, body, h = self.c.login(PASSWORD)
        self.assertEqual(st, 429)
        self.assertIn("Retry-After", h)

    def test_security_headers(self):
        _, _, h = self.c.get("/login")
        self.assertIn("default-src 'self'", h["Content-Security-Policy"])
        self.assertNotIn("unsafe-inline", h["Content-Security-Policy"])
        self.assertEqual(h["X-Frame-Options"], "DENY")
        self.assertEqual(h["X-Content-Type-Options"], "nosniff")

    def test_password_change(self):
        c = self.signed_in()
        st, body, _ = c.post("/api/password", {"current": "wrong", "new": "a-brand-new-password"})
        self.assertEqual(st, 400)
        self.assertEqual(c.post("/api/password", {"current": PASSWORD, "new": "short"})[0], 400)
        st, _, h = c.post("/api/password", {"current": PASSWORD, "new": "a-brand-new-password"})
        self.assertEqual(st, 200)
        self.assertEqual(c.get("/api/me")[0], 200)                  # got a fresh cookie
        other = Client(self.base)
        self.assertEqual(other.login(PASSWORD)[0], 401)
        self.assertEqual(other.login("a-brand-new-password")[0], 200)

    def test_malformed_requests(self):
        c = self.signed_in()
        self.assertEqual(c.post("/api/update", {"ctid": "x", "kind": "app"})[0], 400)
        self.assertEqual(c.post("/api/update", {"ctid": True, "kind": "app"})[0], 400)
        self.assertEqual(c.post("/api/nope")[0], 404)
        self.assertEqual(c.get("/api/jobs/zzzzzzzzzzzz")[0], 404)
        self.assertEqual(c.get("/static/../app.py")[0], 404)
        self.assertEqual(c.get("/static/%2e%2e/app.py")[0], 404)


class TestUpdatesAndLogs(AppCase):
    extra_config = SERVICES

    def wait(self, c, jid, secs=20):
        end = time.time() + secs
        while time.time() < end:
            j = c.get(f"/api/jobs/{jid}")[1]
            if j["status"] not in ("running", "queued"):
                return j
            time.sleep(0.1)
        self.fail("job did not finish")

    def services(self, c):
        return {s["ctid"]: s for s in c.get("/api/services")[1]["services"]}

    def test_statuses_and_actions(self):
        c = self.signed_in()
        self.app.dash.check_all()
        s = self.services(c)
        self.assertEqual(s[201]["status"], "update")
        self.assertEqual((s[201]["installed"], s[201]["latest"]), ("1.0.0", "1.2.0"))
        self.assertEqual(s[202]["status"], "current")
        self.assertEqual(s[205]["status"], "nocheck")
        self.assertTrue(s[201]["can_app_update"])
        self.assertFalse(s[205]["can_app_update"])

    def test_update_no_app_defined_is_refused(self):
        c = self.signed_in()
        st, body, _ = c.post("/api/update", {"ctid": 205, "kind": "app"})
        self.assertEqual(st, 409)
        self.assertIn("OS upgrade only", body["error"])

    def test_update_runs_and_is_logged(self):
        c = self.signed_in()
        st, body, _ = c.post("/api/update", {"ctid": 201, "kind": "app"})
        self.assertEqual(st, 202)
        # a second request while it runs is refused
        st2, _, _ = c.post("/api/update", {"ctid": 201, "kind": "app"})
        self.assertIn(st2, (202, 409))
        j = self.wait(c, body["job"])
        self.assertEqual(j["status"], "ok")
        self.assertIn("running update", "\n".join(j["lines"]))
        logs = c.get("/api/logs?ctid=201")[1]
        self.assertGreaterEqual(len(logs["logs"]), 1)
        self.assertEqual(logs["logs"][0]["status"], "ok")
        # the log survives in the store (not only in memory)
        self.app.dash.jobs.clear()
        again = c.get(f"/api/jobs/{body['job']}")[1]
        self.assertEqual(again["status"], "ok")

    def test_failed_update_is_reported(self):
        c = self.signed_in()
        jid = c.post("/api/update", {"ctid": 204, "kind": "app"})[1]["job"]
        j = self.wait(c, jid)
        self.assertEqual(j["status"], "failed")
        self.assertIn("exit code 3", "\n".join(j["lines"]))

    def test_retention_setting_limits_stored_logs(self):
        c = self.signed_in()
        self.assertEqual(c.post("/api/settings", {"log_retention": 0})[0], 400)
        self.assertEqual(c.post("/api/settings", {"log_retention": "2"})[0], 400)
        self.assertEqual(c.post("/api/settings", {"log_retention": 3})[1]["log_retention"], 3)
        for _ in range(5):
            self.wait(c, c.post("/api/update", {"ctid": 204, "kind": "app"})[1]["job"])
            time.sleep(0.01)
        self.assertEqual(len(c.get("/api/logs?ctid=204")[1]["logs"]), 3)
        # lowering it prunes existing logs immediately
        c.post("/api/settings", {"log_retention": 1})
        logs = c.get("/api/logs?ctid=204")[1]
        self.assertEqual(len(logs["logs"]), 1)
        self.assertEqual(logs["retention"], 1)
        # a new run keeps just the newest
        newest = self.wait(c, c.post("/api/update", {"ctid": 204, "kind": "app"})[1]["job"])
        logs = c.get("/api/logs?ctid=204")[1]["logs"]
        self.assertEqual([l["id"] for l in logs], [newest["id"]])
        # other containers are unaffected by retention on this one
        self.wait(c, c.post("/api/update", {"ctid": 201, "kind": "app"})[1]["job"])
        self.assertEqual(len(c.get("/api/logs?ctid=201")[1]["logs"]), 1)

    def test_cancel(self):
        c = self.signed_in()
        jid = c.post("/api/update", {"ctid": 203, "kind": "app"})[1]["job"]
        time.sleep(0.6)
        self.assertEqual(c.post("/api/cancel", {"ctid": 203})[0], 202)
        j = self.wait(c, jid, 10)
        self.assertEqual(j["status"], "failed")
        self.assertIn("Cancelled", "\n".join(j["lines"]))
        self.assertEqual(c.post("/api/cancel", {"ctid": 203})[0], 409)   # nothing running now

    def test_audit_trail(self):
        c = self.signed_in()
        self.wait(c, c.post("/api/update", {"ctid": 204, "kind": "app"})[1]["job"])
        c.post("/api/settings", {"log_retention": 4})
        actions = [e["action"] for e in c.get("/api/audit")[1]["events"]]
        for a in ("login.ok", "update.app", "update.app.failed", "settings.log_retention"):
            self.assertIn(a, actions)


class TestAccessApi(AppCase):
    extra_config = SERVICES

    def test_validation_errors(self):
        c = self.signed_in()
        for body in ({"host": "-oProxyCommand=x", "user": "root", "auth": "password", "secret": "x"},
                     {"host": "h", "user": "Bad User", "auth": "password", "secret": "x"},
                     {"host": "h", "user": "root", "auth": "token", "secret": "x"},
                     {"host": "h", "user": "root", "auth": "password", "port": 99999, "secret": "x"},
                     {"host": "h", "user": "root", "auth": "password"}):
            self.assertEqual(c.post("/api/access/test", body)[0], 400, body)
        st, body, _ = c.post("/api/access/test", {"host": "h", "user": "root", "auth": "key", "secret": "not a key"})
        self.assertEqual(st, 400)
        self.assertIn("private key", body["error"])

    def test_unverified_host_key_is_refused(self):
        c = self.signed_in()
        body = {"custom": True, "name": "vm", "host": "127.0.0.1", "port": 1, "user": "root", "auth": "password", "secret": "pw"}
        st, out, _ = c.post("/api/access/save", body)
        self.assertEqual(st, 400)
        self.assertIn("not trusted yet", out["error"])
        self.assertEqual(c.post("/api/access/test", body)[0], 400)
        self.assertEqual(c.get("/api/services")[1]["total"], 5)                   # nothing was added
        st, out, _ = c.post("/api/access/save", dict(body, trust_fingerprint="SHA256:made-up"))
        self.assertEqual(st, 400)                                                  # nothing listens there to confirm it

    def test_secrets_never_leave_the_server(self):
        self.app.dash.runner.hostkey_known = lambda host, port: True              # no sshd here; host-key step has its own test
        c = self.signed_in()
        secret = "S3cret-Pass-word-XYZ"
        st, body, _ = c.post("/api/access/save", {"custom": True, "name": "docker vm", "host": "127.0.0.1", "port": 1,
                                                  "user": "root", "auth": "password", "secret": secret})
        self.assertEqual(st, 200)
        ctid = body["ctid"]
        self.assertGreaterEqual(ctid, 10_000_000)
        self.assertFalse(body["test"]["ok"])                         # nothing listens on port 1
        blob = json.dumps(body)
        self.assertNotIn(secret, blob)
        everything = json.dumps([c.get("/api/services")[1], c.get(f"/api/access?ctid={ctid}")[1],
                                 c.get("/api/audit")[1]])
        self.assertNotIn(secret, everything)
        self.assertNotIn(secret, (Path(self.app.state_dir) / "access.json").read_text())
        for p in Path(self.app.state_dir).rglob("*"):
            if p.is_file() and p.name != "secret.key":
                self.assertNotIn(secret, p.read_text(errors="ignore"), p)
        svc = {s["ctid"]: s for s in c.get("/api/services")[1]["services"]}[ctid]
        self.assertEqual(svc["access"]["mode"], "ssh")
        self.assertTrue(svc["access"]["has_secret"])
        self.assertEqual(svc["name"], "docker vm")
        self.assertFalse(svc["snapshot"])
        # removing a custom host removes it from the dashboard
        self.assertEqual(c.post("/api/access/remove", {"ctid": ctid})[0], 200)
        self.assertNotIn(ctid, {s["ctid"] for s in c.get("/api/services")[1]["services"]})
        self.assertEqual(c.post("/api/access/remove", {"ctid": ctid})[0], 400)

    def test_override_on_existing_container_and_back(self):
        self.app.dash.runner.hostkey_known = lambda host, port: True
        c = self.signed_in()
        st, body, _ = c.post("/api/access/save", {"ctid": 202, "host": "127.0.0.1", "port": 1, "user": "root",
                                                  "auth": "password", "secret": "pw-for-202"})
        self.assertEqual(st, 200)
        s = {x["ctid"]: x for x in c.get("/api/services")[1]["services"]}[202]
        self.assertEqual(s["access"]["mode"], "ssh")
        c.post("/api/access/remove", {"ctid": 202})
        s = {x["ctid"]: x for x in c.get("/api/services")[1]["services"]}[202]
        self.assertEqual(s["access"]["mode"], "gate")
        self.assertEqual(c.post("/api/access/save", {"ctid": 99999, "host": "h", "user": "root",
                                                     "auth": "password", "secret": "x"})[0], 400)


if __name__ == "__main__":
    unittest.main()


# ======================================================================== HTTP-level security
import socket  # noqa: E402
import urllib.error  # noqa: E402
import urllib.request  # noqa: E402

import tests.helpers as H  # noqa: E402
from udash import auth as A  # noqa: E402


def raw_cookie_get(base, path, cookie_header):
    req = urllib.request.Request(base + path, headers={"Cookie": cookie_header})
    try:
        r = urllib.request.build_opener(H.NoRedirect).open(req, timeout=10)
    except urllib.error.HTTPError as e:
        r = e
    return r.status


def cookie_value(client):
    return next(c.value for c in client.jar if c.name.endswith("ud_session"))


class TestSessionsOverHttp(AppCase):
    def test_a_stolen_cookie_stops_working_when_the_session_ends(self):
        c = self.signed_in()
        stolen = f"ud_session={cookie_value(c)}"
        self.assertEqual(raw_cookie_get(self.base, "/api/me", stolen), 200)
        self.assertEqual(c.post("/api/logout")[0], 200)
        self.assertEqual(raw_cookie_get(self.base, "/api/me", stolen), 401)       # server-side revocation, not just a cleared cookie

    def test_list_and_revoke_other_sessions(self):
        a, b = self.signed_in(), H.Client(self.base)
        b.login()
        rows = a.get("/api/sessions")[1]["sessions"]
        self.assertEqual(len(rows), 2)
        self.assertEqual(sum(r["current"] for r in rows), 1)
        other = next(r for r in rows if not r["current"])
        self.assertEqual(a.post("/api/sessions/revoke", {"id": next(r["id"] for r in rows if r["current"])})[0], 400)
        self.assertEqual(a.post("/api/sessions/revoke", {"id": other["id"]})[0], 200)
        self.assertEqual(b.get("/api/me")[0], 401)
        self.assertEqual(a.get("/api/me")[0], 200)
        b.login()
        self.assertEqual(a.post("/api/sessions/revoke-all")[0], 200)
        self.assertEqual(b.get("/api/me")[0], 401)
        self.assertEqual(a.get("/api/me")[0], 200)

    def test_password_change_ends_other_sessions(self):
        a, b = self.signed_in(), H.Client(self.base)
        b.login()
        self.assertEqual(a.post("/api/password", {"current": H.PASSWORD, "new": "a-brand-new-password"})[0], 200)
        self.assertEqual(b.get("/api/me")[0], 401)
        self.assertEqual(a.get("/api/me")[0], 200)


class TestTwoFactorOverHttp(AppCase):
    def test_full_setup_login_and_disable(self):
        import base64
        import time
        c = self.signed_in()
        self.assertTrue(any("Two-factor" in w for w in c.get("/api/me")[1]["warnings"]))
        self.assertEqual(c.post("/api/2fa/begin", {"password": "wrong"})[0], 400)
        secret = c.post("/api/2fa/begin", {"password": H.PASSWORD})[1]["secret"]
        self.assertEqual(c.post("/api/2fa/enable", {"code": "000000"})[0], 400)
        code = A.hotp(base64.b32decode(secret), int(time.time() // 30))
        st, out, _ = c.post("/api/2fa/enable", {"code": code})
        self.assertEqual(st, 200)
        codes = out["recovery_codes"]
        self.assertEqual(len(codes), 10)
        self.assertEqual(c.get("/api/2fa")[1], {"enabled": True, "recovery_left": 10})
        anon = H.Client(self.base)
        self.assertTrue(anon.get("/api/login-info")[1]["totp"])
        self.assertEqual(anon.login()[0], 401)                                     # password alone: refused, same message as any failure
        st, out, _ = anon.post("/api/login", {"username": "admin", "password": H.PASSWORD, "code": codes[0]})
        self.assertEqual(st, 200)
        self.assertFalse(any("Two-factor" in w for w in anon.get("/api/me")[1]["warnings"]))
        self.assertEqual(H.Client(self.base).post("/api/login", {"username": "admin", "password": H.PASSWORD, "code": codes[0]})[0], 401)
        st, _, _ = anon.post("/api/2fa/disable", {"password": H.PASSWORD, "code": codes[1]})
        self.assertEqual(st, 200)
        self.assertFalse(H.Client(self.base).get("/api/login-info")[1]["totp"])


class TestRequestHardening(AppCase):
    extra_config = "socket_timeout: 1\nmax_connections: 8\n"

    def test_cross_site_fetch_metadata_is_rejected(self):
        for site, want in (("cross-site", 403), ("same-site", 403), ("same-origin", 200), ("none", 200)):
            st, _, _ = self.c.post("/api/login", {"username": "admin", "password": H.PASSWORD},
                                   headers={"Sec-Fetch-Site": site})
            self.assertEqual(st, want, site)

    def test_headers(self):
        _, _, h = self.c.get("/login")
        self.assertEqual(h["Cross-Origin-Opener-Policy"], "same-origin")
        self.assertEqual(h["Cross-Origin-Resource-Policy"], "same-origin")
        self.assertIn("camera=()", h["Permissions-Policy"])
        self.assertNotIn("Python", h["Server"])                                      # no interpreter version disclosure

    def test_slow_clients_are_dropped(self):
        s = socket.create_connection(("127.0.0.1", self.port))
        s.sendall(b"GET /healthz HTTP/1.1\r\nHost: x\r\n")                           # never finishes the request
        s.settimeout(5)
        t0 = time.time()
        self.assertEqual(s.recv(100), b"")                                           # server closed it
        self.assertLess(time.time() - t0, 4)
        s.close()

    def test_connection_cap(self):
        held = [socket.create_connection(("127.0.0.1", self.port)) for _ in range(8)]
        time.sleep(0.3)
        extra = socket.create_connection(("127.0.0.1", self.port))
        extra.settimeout(3)
        try:
            self.assertEqual(extra.recv(10), b"")                                    # over the cap: closed immediately
        finally:
            extra.close()
            for h in held:
                h.close()
        time.sleep(0.5)
        self.assertEqual(self.c.get("/healthz")[0], 200)                             # recovers


class TestUnencryptedWarnings(AppCase):
    def test_warns_when_not_encrypted_and_when_a_proxy_is_not_declared(self):
        c = self.signed_in()
        w = c.get("/api/me")[1]["warnings"]
        self.assertTrue(any("not encrypted" in x for x in w))
        self.assertFalse(any("trust_proxy" in x for x in w))
        c.get("/api/me", headers={"X-Forwarded-For": "203.0.113.9", "X-Forwarded-Proto": "https"})
        w = c.get("/api/me")[1]["warnings"]
        self.assertTrue(any("trust_proxy" in x for x in w))

    def test_forged_forwarded_headers_are_ignored_without_trust_proxy(self):
        for _ in range(5):
            self.c.post("/api/login", {"username": "admin", "password": "bad"}, headers={"X-Forwarded-For": "198.51.100.1"})
        # a different claimed address does not get a fresh allowance: the real peer is what counts
        st, _, _ = self.c.post("/api/login", {"username": "admin", "password": H.PASSWORD}, headers={"X-Forwarded-For": "198.51.100.2"})
        self.assertEqual(st, 429)


class TestBehindTrustedProxy(AppCase):
    extra_config = 'trust_proxy: ["127.0.0.1"]\n'

    def test_client_ip_and_secure_cookie_come_from_the_proxy_headers(self):
        h = {"X-Forwarded-For": "203.0.113.7", "X-Forwarded-Proto": "https"}
        st, _, headers = self.c.post("/api/login", {"username": "admin", "password": H.PASSWORD}, headers=h)
        self.assertEqual(st, 200)
        cookie = headers["Set-Cookie"]
        self.assertTrue(cookie.startswith("__Host-ud_session="), cookie)
        for flag in ("Secure", "HttpOnly", "SameSite=Strict", "Path=/"):
            self.assertIn(flag, cookie)
        self.assertNotIn("Domain", cookie)
        self.assertIn("Strict-Transport-Security", headers)
        token = cookie.split("=", 1)[1].split(";")[0]
        self.assertEqual(raw_cookie_get(self.base, "/api/me", f"__Host-ud_session={token}"), 200)
        events = self.signed_in().get("/api/audit")[1]["events"]
        self.assertTrue(any(e["ip"] == "203.0.113.7" for e in events))

    def test_lockout_is_per_forwarded_client_not_per_proxy(self):
        for _ in range(5):
            self.c.post("/api/login", {"username": "admin", "password": "bad"}, headers={"X-Forwarded-For": "198.51.100.1"})
        blocked = self.c.post("/api/login", {"username": "admin", "password": H.PASSWORD}, headers={"X-Forwarded-For": "198.51.100.1"})[0]
        other = self.c.post("/api/login", {"username": "admin", "password": H.PASSWORD}, headers={"X-Forwarded-For": "198.51.100.2"})[0]
        self.assertEqual((blocked, other), (429, 200))

    def test_a_spoofed_leftmost_forwarded_address_does_not_help_an_attacker(self):
        # clients can prepend entries; only the entry added by the trusted proxy (rightmost) counts
        for i in range(5):
            self.c.post("/api/login", {"username": "admin", "password": "bad"},
                        headers={"X-Forwarded-For": f"10.9.9.{i}, 198.51.100.50"})
        st, _, _ = self.c.post("/api/login", {"username": "admin", "password": H.PASSWORD},
                               headers={"X-Forwarded-For": "10.9.9.99, 198.51.100.50"})
        self.assertEqual(st, 429)


class TestHttps(AppCase):
    extra_config = "tls: auto\n"

    def test_serves_tls_with_secure_host_cookie_and_hsts(self):
        st, _, h = self.c.login()
        self.assertEqual(st, 200)
        cookie = h["Set-Cookie"]
        self.assertTrue(cookie.startswith("__Host-ud_session="))
        self.assertIn("Secure", cookie)
        self.assertIn("Strict-Transport-Security", self.c.get("/login")[2])
        w = self.c.get("/api/me")[1]["warnings"]
        self.assertFalse(any("not encrypted" in x for x in w))
        about = self.c.get("/api/about")[1]
        self.assertTrue(about["tls"])
        self.assertTrue(about["tls_fingerprint"].startswith("SHA256:"))

    def test_plain_http_to_a_tls_port_does_not_hang_the_server(self):
        s = socket.create_connection(("127.0.0.1", self.port))
        s.sendall(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
        s.settimeout(5)
        try:
            s.recv(100)
        except (socket.timeout, OSError):
            pass
        s.close()
        self.assertEqual(self.c.get("/healthz")[0], 200)


class TestCustomCommandApproval(AppCase):
    extra_config = '''services:
  - name: custom
    ctid: 301
    current: "echo 1"
    update: "/usr/local/bin/my-update.sh"
  - name: builtin
    ctid: 302
    current: "cat /root/.sonarr 2>/dev/null || cat /opt/*_version.txt 2>/dev/null"
'''

    def test_lists_only_commands_the_gate_would_refuse(self):
        c = self.signed_in()
        cmds = c.get("/api/custom-commands")[1]["commands"]
        self.assertEqual(sorted(cmds), ["/usr/local/bin/my-update.sh", "echo 1"])

    def test_audit_chain_is_reported(self):
        c = self.signed_in()
        out = c.get("/api/audit")[1]
        self.assertTrue(out["chain_ok"])
        self.assertIsNone(out["chain_broken_at"])


class TestKeepAliveIsolation(AppCase):
    """One connection serves many requests (browsers, and reverse proxies that reuse upstream connections).
    Authentication state must never carry over from one request to the next."""

    def conn(self):
        import http.client
        return http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)

    def get(self, c, path, cookie=None):
        c.request("GET", path, headers={"Cookie": cookie} if cookie else {})
        r = c.getresponse()
        r.read()
        return r.status

    def test_a_cookieless_request_does_not_inherit_the_previous_requests_login(self):
        cookie = f"ud_session={cookie_value(self.signed_in())}"
        c = self.conn()
        self.assertEqual(self.get(c, "/api/me", cookie), 200)
        self.assertEqual(self.get(c, "/api/me"), 401)                    # same connection, no cookie: must not be signed in
        self.assertEqual(self.get(c, "/api/services"), 401)
        self.assertEqual(self.get(c, "/api/me", cookie), 200)

    def test_a_valid_request_is_not_poisoned_by_an_earlier_anonymous_one(self):
        cookie = f"ud_session={cookie_value(self.signed_in())}"
        c = self.conn()
        self.assertEqual(self.get(c, "/api/me"), 401)
        self.assertEqual(self.get(c, "/api/me", cookie), 200)            # this was the browser sign-in failure

    def test_two_users_interleaved_on_one_connection(self):
        a = self.signed_in()
        b = H.Client(self.base)
        b.login()
        ca, cb = f"ud_session={cookie_value(a)}", f"ud_session={cookie_value(b)}"
        a.post("/api/sessions/revoke", {"id": next(r["id"] for r in a.get("/api/sessions")[1]["sessions"] if not r["current"])})
        c = self.conn()
        self.assertEqual(self.get(c, "/api/me", ca), 200)
        self.assertEqual(self.get(c, "/api/me", cb), 401)                # b was revoked; must not borrow a's state
        self.assertEqual(self.get(c, "/api/me", ca), 200)


class TestNetworkAllowlist(AppCase):
    extra_config = 'allow_from: ["10.99.0.0/16", "192.0.2.5"]\n'

    def test_clients_outside_the_allowlist_get_nothing(self):
        for path in ("/login", "/", "/api/me", "/static/login.js", "/api/login-info"):
            self.assertEqual(self.c.get(path)[0], 403, path)
        self.assertEqual(self.c.login()[0], 403)                                       # not even a login attempt
        self.assertEqual(self.c.get("/healthz")[0], 200)                               # liveness stays reachable for monitors

    def test_a_forged_forwarded_address_cannot_get_in(self):
        self.assertEqual(self.c.get("/login", headers={"X-Forwarded-For": "10.99.1.1"})[0], 403)   # no trust_proxy: ignored


class TestAllowlistBehindProxy(AppCase):
    extra_config = 'allow_from: ["203.0.113.0/24"]\ntrust_proxy: ["127.0.0.1"]\n'

    def test_the_forwarded_client_address_is_what_counts(self):
        self.assertEqual(self.c.get("/login", headers={"X-Forwarded-For": "203.0.113.50"})[0], 200)
        self.assertEqual(self.c.get("/login", headers={"X-Forwarded-For": "198.51.100.9"})[0], 403)
        self.assertEqual(self.c.get("/login", headers={"X-Forwarded-For": "198.51.100.9, 203.0.113.50"})[0], 200)   # proxy appended the real one
        self.assertEqual(self.c.get("/login", headers={"X-Forwarded-For": "203.0.113.50, 198.51.100.9"})[0], 403)   # spoofed leftmost
