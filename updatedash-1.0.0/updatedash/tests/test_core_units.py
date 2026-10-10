import json
import os
import unittest
from pathlib import Path

from tests.helpers import ROOT  # importing helpers also puts the project on sys.path
from udash import auth as A
from udash import store as S
from udash.util import safe_link, same


assert ROOT.is_dir()


class TestUtil(unittest.TestCase):
    def test_same(self):
        self.assertTrue(same("v4.0.20.3014", "4.0.20.3014"))
        self.assertTrue(same("1.2", "1.2.0"))
        self.assertTrue(same("1.2.3-ubuntu1", "1.2.3"))
        self.assertFalse(same("1.2", "1.20"))
        self.assertFalse(same("", "1.0"))
        self.assertFalse(same("2.2.0", "v2.4.0"))

    def test_safe_link(self):
        self.assertEqual(safe_link("https://x.dev/y"), "https://x.dev/y")
        self.assertIsNone(safe_link("javascript:alert(1)"))
        self.assertIsNone(safe_link("http://insecure"))
        self.assertIsNone(safe_link(None))


class FakeVault:
    key = b"k" * 32

    def derive(self, label):
        import hashlib, hmac
        return hmac.new(self.key, label, hashlib.sha256).digest()

    def encrypt(self, s):
        return "enc:" + s[::-1]

    def decrypt(self, t):
        return t[4:][::-1]


class TestAuth(unittest.TestCase):
    def make(self, tmp, **cfg):
        c = {"username": "admin", "session_hours": 1, "password": "a-long-password"}
        c.update(cfg)
        return A.Auth(c, Path(tmp), FakeVault())

    def test_hash_roundtrip(self):
        h = A.hash_password("secret-pass-123")
        self.assertTrue(A.verify_password("secret-pass-123", h))
        self.assertFalse(A.verify_password("secret-pass-124", h))
        self.assertFalse(A.verify_password("x", "garbage"))
        self.assertNotEqual(h, A.hash_password("secret-pass-123"))  # salted

    def test_login_and_session(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            a = self.make(d)
            self.assertIsNone(a.login("1.1.1.1", "admin", "wrong"))
            self.assertIsNone(a.login("1.1.1.1", "root", "a-long-password"))
            tok = a.login("1.1.1.1", "admin", "a-long-password")
            self.assertEqual(a.check_session(tok), "admin")
            self.assertIsNone(a.check_session(tok[:-2] + "xx"))
            self.assertIsNone(a.check_session("nonsense"))
            self.assertIsNone(a.check_session(""))

    def test_session_expiry(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            a = self.make(d)
            tok = a.make_session()
            a.session_seconds = -10
            self.assertIsNone(a.check_session(a.make_session()))
            self.assertEqual(a.check_session(tok), "admin")

    def test_lockout(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            a = self.make(d)
            for _ in range(A.Auth.MAX_PER_IP):
                self.assertIsNone(a.login("9.9.9.9", "admin", "bad"))
            with self.assertRaises(A.Locked) as cm:
                a.login("9.9.9.9", "admin", "a-long-password")      # even the right password is refused
            self.assertGreater(cm.exception.retry_after, 0)
            self.assertIsNotNone(a.login("8.8.8.8", "admin", "a-long-password"))  # other IPs unaffected

    def test_change_password_invalidates_sessions(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            a = self.make(d)
            old = a.make_session()
            with self.assertRaises(A.AuthError):
                a.change_password("wrong", "another-long-pass")
            with self.assertRaises(A.AuthError):
                a.change_password("a-long-password", "short")
            new = a.change_password("a-long-password", "another-long-pass")
            self.assertIsNone(a.check_session(old))
            self.assertEqual(a.check_session(new), "admin")
            # persisted for the next start, and wins over the config
            b = self.make(d)
            self.assertIsNotNone(b.login("1.1.1.1", "admin", "another-long-pass"))
            self.assertEqual(oct(os.stat(Path(d) / "auth.json").st_mode & 0o777), "0o600")

    def test_sessions_survive_a_restart(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            tok = self.make(d).make_session()                       # plaintext password in config (re-salted each start)
            self.assertEqual(self.make(d).check_session(tok), "admin")
            h = A.hash_password("a-long-password")                   # stored hash in config
            tok = self.make(d, password=None, password_hash=h).make_session()
            self.assertEqual(self.make(d, password=None, password_hash=h).check_session(tok), "admin")
            self.assertIsNone(self.make(d, password="a-different-pass").check_session(tok))  # changed password => signed out

    def test_requires_a_password(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(A.AuthError):
                A.Auth({"username": "admin", "session_hours": 1}, Path(d), FakeVault())
            with self.assertRaises(A.AuthError):
                A.Auth({"username": "admin", "session_hours": 1, "password": "CHANGE-ME"}, Path(d), FakeVault())


class TestSettingsAndLogs(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.d = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, self.d, True)

    def job(self, ctid, n, status="ok"):
        return {"id": f"{ctid:04x}{n:08x}", "ctid": ctid, "service": "s", "kind": "app", "status": status,
                "lines": [f"line {n}"], "started": 1_700_000_000 + n, "ended": 1_700_000_001 + n, "by": "admin"}

    def test_settings_validation_and_persistence(self):
        s = S.Settings(Path(self.d) / "s.json", {"log_retention": 5})
        self.assertEqual(s.get("log_retention"), 5)
        s.update({"log_retention": 1})
        self.assertEqual(S.Settings(Path(self.d) / "s.json", {"log_retention": 5}).get("log_retention"), 1)
        for bad in (0, 201, "3", 2.5, True, None):
            with self.assertRaises(S.ValidationError):
                s.update({"log_retention": bad})
        with self.assertRaises(S.ValidationError):
            s.update({"bogus": 1})

    def test_retention_is_per_container(self):
        ls = S.LogStore(Path(self.d) / "logs")
        for n in range(1, 6):
            ls.save(self.job(101, n))
        for n in range(1, 3):
            ls.save(self.job(102, n))
        self.assertEqual(len(ls.list(101)), 5)
        ls.prune(101, 2)
        got = ls.list(101)
        self.assertEqual([m["started"] for m in got], [1_700_000_005, 1_700_000_004])   # newest two
        self.assertEqual(len(ls.list(102)), 2)                                            # untouched
        ls.prune_all(1)
        self.assertEqual(len(ls.list(101)), 1)
        self.assertEqual(len(ls.list(102)), 1)
        self.assertEqual(ls.list(101)[0]["started"], 1_700_000_005)

    def test_retention_one_keeps_exactly_one(self):
        ls = S.LogStore(Path(self.d) / "logs")
        for n in range(1, 4):
            ls.save(self.job(7, n))
            ls.prune(7, 1)
        self.assertEqual(len(ls.list(7)), 1)

    def test_running_log_is_never_pruned(self):
        ls = S.LogStore(Path(self.d) / "logs")
        ls.save(self.job(7, 1, "running"))
        for n in range(2, 5):
            ls.save(self.job(7, n))
        ls.prune(7, 1)
        statuses = sorted(m["status"] for m in ls.list(7))
        self.assertEqual(statuses, ["ok", "running"])

    def test_load_and_interrupted(self):
        ls = S.LogStore(Path(self.d) / "logs")
        j = self.job(9, 1, "running")
        ls.save(j)
        self.assertEqual(ls.load(j["id"])["status"], "running")
        self.assertIsNone(ls.load("../../etc/passwd"))
        self.assertIsNone(ls.load("zzzzzzzzzzzz"))
        self.assertEqual(ls.mark_interrupted(), 1)
        d = ls.load(j["id"])
        self.assertEqual(d["status"], "interrupted")
        self.assertIn("restarted", d["lines"][-1])

    def test_log_truncation(self):
        ls = S.LogStore(Path(self.d) / "logs")
        j = self.job(5, 1)
        j["lines"] = [f"l{i}" for i in range(S.MAX_LOG_LINES + 500)]
        ls.save(j)
        lines = ls.load(j["id"])["lines"]
        self.assertLessEqual(len(lines), S.MAX_LOG_LINES + 1)
        self.assertTrue(any("omitted" in x for x in lines))
        self.assertEqual(lines[-1], f"l{S.MAX_LOG_LINES + 499}")


class TestAccessStore(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.d = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, self.d, True)
        self.vault = FakeVault()
        self.store = S.AccessStore(Path(self.d) / "access.json", self.vault)

    def test_validation(self):
        ok = {"host": "10.0.0.5", "port": 22, "user": "root", "auth": "password"}
        self.assertEqual(S.clean_access(ok)["host"], "10.0.0.5")
        for field, bad in (("host", "-oProxyCommand=x"), ("host", "a b"), ("host", ""), ("host", "x;y"),
                           ("user", "Root"), ("user", "-x"), ("user", "a b"), ("port", 0), ("port", 70000),
                           ("port", "abc"), ("auth", "token")):
            with self.assertRaises(S.ValidationError, msg=f"{field}={bad!r}"):
                S.clean_access(dict(ok, **{field: bad}))
        with self.assertRaises(S.ValidationError):
            S.clean_access(ok, custom=True)                                  # name required
        self.assertTrue(S.clean_access(dict(ok, name="docker vm"), custom=True)["custom"])

    def test_secrets_are_encrypted_and_never_public(self):
        f = S.clean_access({"host": "h.lan", "user": "root", "auth": "password"})
        self.store.set(110, f, secret="hunter2-password")
        raw = (Path(self.d) / "access.json").read_text()
        self.assertNotIn("hunter2-password", raw)
        self.assertEqual(self.store.secrets(110)[0], "hunter2-password")
        pub = self.store.public(110)
        self.assertTrue(pub["has_secret"])
        self.assertNotIn("secret", json.dumps({k: v for k, v in pub.items() if k != "has_secret"}))
        self.assertEqual(oct(os.stat(Path(self.d) / "access.json").st_mode & 0o777), "0o600")

    def test_keep_or_replace_secret(self):
        f = S.clean_access({"host": "h.lan", "user": "root", "auth": "password"})
        self.store.set(110, f, secret="one-pass-word")
        self.store.set(110, dict(f, port=2222), secret=None)           # None = keep
        self.assertEqual(self.store.secrets(110)[0], "one-pass-word")
        self.store.set(110, f, secret="two-pass-word")                  # replace
        self.assertEqual(self.store.secrets(110)[0], "two-pass-word")
        with self.assertRaises(S.ValidationError):
            self.store.set(111, f, secret=None)                         # nothing stored, nothing supplied

    def test_custom_hosts_and_persistence(self):
        f = S.clean_access({"host": "h.lan", "user": "root", "auth": "key", "name": "docker-vm"}, custom=True)
        cid = self.store.add_custom(f, "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----", "pp")
        self.assertGreaterEqual(cid, S.CUSTOM_BASE)
        again = S.AccessStore(Path(self.d) / "access.json", self.vault)
        self.assertEqual([c for c, _ in again.customs()], [cid])
        self.assertEqual(again.secrets(cid)[1], "pp")
        cid2 = again.add_custom(f, "-----BEGIN KEY-----", None)
        self.assertEqual(cid2, cid + 1)
        self.assertTrue(again.remove(cid))
        self.assertFalse(again.remove(cid))

    def test_failed_add_does_not_burn_an_id(self):
        f = S.clean_access({"host": "h.lan", "user": "root", "auth": "password", "name": "x"}, custom=True)
        with self.assertRaises(S.ValidationError):
            self.store.add_custom(f, "", None)
        self.assertEqual(self.store.next_custom, S.CUSTOM_BASE)


class TestAudit(unittest.TestCase):
    def test_append_tail_rotate(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            a = S.Audit(Path(d) / "audit.log", max_bytes=300, keep=2)
            for i in range(20):
                a.append("admin", "1.2.3.4", "x", f"event {i}")
            rows = a.tail(5)
            self.assertEqual(len(rows), 5)
            self.assertEqual(rows[0]["detail"], "event 19")
            self.assertTrue((Path(d) / "audit.log.1").exists())
            self.assertEqual(oct(os.stat(Path(d) / "audit.log").st_mode & 0o777), "0o600")


if __name__ == "__main__":
    unittest.main()
