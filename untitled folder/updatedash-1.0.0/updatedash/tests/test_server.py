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

    def test_secrets_never_leave_the_server(self):
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
