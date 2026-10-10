"""Notifications and opt-in automatic system updates."""
import json
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from tests.helpers import AppCase, Client
from udash.automation import Automation, clean_notify
from udash.store import ValidationError


class Sink:
    """A tiny local HTTP server that records what it is sent."""

    def __init__(self, status=200):
        self.got, outer = [], self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                outer.got.append((dict(self.headers), self.rfile.read(n).decode()))
                self.send_response(status)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass

        self.srv = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}/topic"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


class TestValidation(unittest.TestCase):
    def test_urls(self):
        self.assertEqual(clean_notify({"kind": "ntfy", "url": "http://127.0.0.1:8080/t", "enabled": True})["enabled"], True)
        self.assertFalse(clean_notify({"url": "", "enabled": False})["enabled"])
        with self.assertRaises(ValidationError):                       # can't switch on with nowhere to send
            clean_notify({"url": "", "enabled": True})
        for bad in ("ftp://x/y", "file:///etc/passwd", "javascript:alert(1)", "http://user:pw@127.0.0.1/", "http://169.254.169.254/latest/",
                    "http://0.0.0.0/", "not a url", "http://" + "a" * 400):
            with self.assertRaises(ValidationError, msg=bad):
                clean_notify({"url": bad, "enabled": True})
        with self.assertRaises(ValidationError):
            clean_notify({"kind": "sms", "url": "http://127.0.0.1/"})


class TestAutomation(AppCase):
    extra_config = 'services:\n  - name: web\n    ctid: 601\n  - name: db\n    ctid: 602\n'

    def setUp(self):
        super().setUp()
        self.sink = Sink()
        self.addCleanup(self.sink.close)
        self.a = self.app.automation
        self.dash = self.app.dash
        for uid in (601, 602):
            self.dash.state[uid].update(status="current", ct_status="running", os_updates=0, os_security=0)

    def test_notifies_once_per_problem_and_again_after_it_clears(self):
        self.a.set_notify({"kind": "ntfy", "url": self.sink.url, "enabled": True})
        self.dash.state[601].update(os_updates=3, os_security=2)
        self.a._notify_new()
        self.assertEqual(len(self.sink.got), 1)
        headers, body = self.sink.got[0]
        self.assertIn("web: 2 security update(s)", body)
        self.assertNotIn("db", body)
        self.assertIn("1 update", headers["Title"])
        self.a._notify_new()                                   # unchanged: no repeat
        self.assertEqual(len(self.sink.got), 1)
        self.dash.state[602].update(status="update", installed="1.0", latest="1.1")
        self.a._notify_new()                                   # something new: only the new item is announced
        self.assertEqual(len(self.sink.got), 2)
        self.assertIn("db: 1.0 → 1.1", self.sink.got[1][1])
        self.assertNotIn("web", self.sink.got[1][1])
        self.dash.state[601].update(os_updates=0, os_security=0)
        self.a._notify_new()
        self.dash.state[601].update(os_updates=1, os_security=1)
        self.a._notify_new()                                   # cleared, then back: announced again
        self.assertEqual(len(self.sink.got), 3)

    def test_disabled_sends_nothing_and_webhook_is_json(self):
        self.dash.state[601].update(os_security=1, os_updates=1)
        self.a._notify_new()
        self.assertEqual(self.sink.got, [])
        self.a.set_notify({"kind": "webhook", "url": self.sink.url, "enabled": True})
        self.assertTrue(self.a.test()["ok"])
        payload = json.loads(self.sink.got[0][1])
        self.assertIn("text", payload)
        self.assertIn("content", payload)

    def test_failing_endpoint_is_reported_not_raised(self):
        bad = Sink(status=500)
        self.addCleanup(bad.close)
        self.a.set_notify({"kind": "ntfy", "url": bad.url, "enabled": True})
        self.assertEqual(self.a.test(), {"ok": False, "message": "HTTP 500"})
        self.dash.state[601].update(os_security=1, os_updates=1)
        self.a.after_sweep()                                   # must not raise

    def test_redirects_are_not_followed(self):
        class R(BaseHTTPRequestHandler):
            def do_POST(self):
                self.send_response(302)
                self.send_header("Location", "http://169.254.169.254/")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass
        srv = HTTPServer(("127.0.0.1", 0), R)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        self.a.set_notify({"kind": "ntfy", "url": f"http://127.0.0.1:{srv.server_address[1]}/", "enabled": True})
        self.assertFalse(self.a.test()["ok"])

    def test_auto_update_runs_once_per_day_after_the_hour_only_when_security_is_pending(self):
        started = []
        self.dash.start_update = lambda uid, kind, actor="?": started.append((uid, kind, actor)) or "job"
        self.a.set_auto({"uids": [601, 602], "hour": 3})
        self.dash.state[601].update(os_security=2, os_updates=4)
        day = time.mktime((2026, 10, 12, 2, 0, 0, 0, 0, -1))
        self.assertEqual(self.a.run_auto(day), [])                              # before 03:00
        self.assertEqual(self.a.run_auto(day + 3600 * 1.5), [601])              # 03:30; 602 has nothing pending
        self.assertEqual(started, [(601, "os", "schedule")])
        self.assertEqual(self.a.run_auto(day + 3600 * 5), [])                   # not twice the same day
        self.assertEqual(self.a.run_auto(day + 86400 + 3600 * 4), [601])        # next day, still pending
        self.dash.state[601].update(ct_status="stopped")
        self.assertEqual(self.a.run_auto(day + 2 * 86400 + 3600 * 4), [])       # stopped containers are left alone

    def test_nothing_is_automatic_by_default(self):
        started = []
        self.dash.start_update = lambda *a, **k: started.append(a)
        self.dash.state[601].update(os_security=5, os_updates=5)
        self.assertEqual(self.a.run_auto(time.time() + 86400), [])
        self.assertEqual(started, [])

    def test_persistence_and_api(self):
        self.signed_in()
        c = self.c
        self.assertEqual(c.post("/api/automation/auto", {"uids": [601], "hour": 4})[0], 200)
        self.assertEqual(c.post("/api/automation/auto", {"uids": [999], "hour": 4})[0], 400)    # unknown container
        self.assertEqual(c.post("/api/automation/auto", {"uids": [601], "hour": 25})[0], 400)
        self.assertEqual(c.post("/api/automation/notify", {"kind": "ntfy", "url": "http://169.254.169.254/", "enabled": True})[0], 400)
        self.assertEqual(c.post("/api/automation/notify", {"kind": "ntfy", "url": self.sink.url, "enabled": True})[0], 200)
        st, out, _ = c.get("/api/automation")
        self.assertEqual((out["auto"]["uids"], out["auto"]["hour"], out["notify"]["enabled"]), ([601], 4, True))
        svc = {s["ctid"]: s for s in c.get("/api/services")[1]["services"]}
        self.assertTrue(svc[601]["auto_system"])
        self.assertFalse(svc[602]["auto_system"])
        again = Automation(self.a.path, self.dash, self.app.audit)
        self.assertEqual(again.public()["auto"]["uids"], [601])
        self.assertEqual(Client(self.base).post("/api/automation/auto", {"uids": []})[0], 401)   # login required
        events = [e["action"] for e in c.get("/api/audit")[1]["events"]]
        self.assertIn("automation.auto", events)


if __name__ == "__main__":
    unittest.main()
