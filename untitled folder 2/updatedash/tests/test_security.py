"""Security-focused tests: passwords, TOTP, sessions, login throttling, audit chain, TLS."""
import hashlib
import json
import os
import socket
import ssl
import tempfile
import threading
import time
import unittest
from pathlib import Path

from tests.helpers import FakeVault
from udash import auth as A
from udash import tls
from udash.store import Audit

PW = "a-long-password"


def make_auth(tmp, **cfg):
    c = {"username": "admin", "session_hours": 1, "session_idle_minutes": 30, "password": PW}
    c.update(cfg)
    return A.Auth(c, Path(tmp), FakeVault())


class TmpCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="udsec-")
        self.addCleanup(__import__("shutil").rmtree, self.tmp, True)


class TestPasswords(TmpCase):
    def test_roundtrip_and_salting(self):
        h = A.hash_password("secret-pass-123")
        self.assertTrue(A.verify_password("secret-pass-123", h))
        self.assertFalse(A.verify_password("secret-pass-124", h))
        self.assertFalse(A.verify_password("x", "garbage"))
        self.assertNotEqual(h, A.hash_password("secret-pass-123"))

    @unittest.skipUnless(hasattr(hashlib, "scrypt"), "no scrypt in this Python")
    def test_scrypt_uses_owasp_minimum_and_old_hashes_still_verify(self):
        self.assertTrue(A.hash_password("pw-123456789").startswith("scrypt$16384$8$5$"))
        salt = b"s" * 16
        old = "scrypt$16384$8$1$" + A._b64(salt) + "$" + A._b64(hashlib.scrypt(b"old-password-1", salt=salt, n=16384, r=8, p=1, dklen=32))
        self.assertTrue(A.verify_password("old-password-1", old))

    def test_pbkdf2_fallback_hash_verifies(self):
        salt = b"s" * 16
        h = "pbkdf2$1000$" + A._b64(salt) + "$" + A._b64(hashlib.pbkdf2_hmac("sha256", b"pw-123456789", salt, 1000, 32))
        self.assertTrue(A.verify_password("pw-123456789", h))
        self.assertFalse(A.verify_password("other", h))

    def test_absurd_lengths_are_refused_before_hashing(self):
        a = make_auth(self.tmp)
        self.assertIsNone(a.login("1.1.1.1", "admin", "x" * (A.MAX_PASSWORD + 1)))
        self.assertIsNone(a.login("1.1.1.1", "u" * 65, PW))
        with self.assertRaises(A.AuthError):
            a.change_password(PW, "y" * (A.MAX_PASSWORD + 1))

    def test_requires_a_password(self):
        for cfg in ({"username": "admin", "session_hours": 1}, {"username": "admin", "session_hours": 1, "password": "CHANGE-ME"},
                    {"username": "admin", "session_hours": 1, "password_hash": "CHANGE-ME"}):
            with self.assertRaises(A.AuthError):
                A.Auth(cfg, Path(self.tmp), FakeVault())


class TestTotp(unittest.TestCase):
    SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"      # ASCII "12345678901234567890", the RFC 6238 test key

    def test_rfc6238_vectors(self):
        key = b"12345678901234567890"
        for t, eight in ((59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
                         (1234567890, "89005924"), (2000000000, "69279037")):
            self.assertEqual(A.hotp(key, t // 30, 8), eight, t)
            self.assertEqual(A.hotp(key, t // 30, 6), eight[-6:], t)

    def test_window_and_replay(self):
        self.assertEqual(A.totp_match(self.SECRET, "287082", now=59), 1)
        self.assertEqual(A.totp_match(self.SECRET, "287082", now=59 + 30), 1)          # one step late is accepted
        self.assertIsNone(A.totp_match(self.SECRET, "287082", now=59 + 120))           # too old
        self.assertIsNone(A.totp_match(self.SECRET, "287082", now=59, last=1))         # already used: replay refused
        self.assertIsNone(A.totp_match(self.SECRET, "000000", now=59))
        for bad in ("", "12345", "1234567", "abcdef", "287 082"):
            self.assertIsNone(A.totp_match(self.SECRET, bad, now=59))

    def test_uri_and_secret_shape(self):
        s = A.new_totp_secret()
        self.assertEqual(len(s), 32)
        self.assertNotEqual(s, A.new_totp_secret())
        uri = A.otpauth_uri(s, "admin")
        self.assertTrue(uri.startswith("otpauth://totp/Update%20Dashboard:admin?secret="))


class TestSessions(TmpCase):
    def store(self, **kw):
        return A.SessionStore(Path(self.tmp) / "sessions.json", kw.get("absolute", 3600), kw.get("idle", 600), kw.get("max", 20))

    def test_create_validate_revoke(self):
        s = self.store()
        tok = s.create("admin", "1.2.3.4", "UA")
        self.assertEqual(s.validate(tok)["user"], "admin")
        self.assertIsNone(s.validate("not-a-token"))
        self.assertIsNone(s.validate(""))
        self.assertTrue(s.revoke(s._id(tok)))
        self.assertIsNone(s.validate(tok))                                  # a stolen cookie dies with the session

    def test_idle_and_absolute_expiry(self):
        s = self.store(absolute=3600, idle=600)
        tok = s.create("admin", "x", "")
        s.data[s._id(tok)]["last"] -= 700
        self.assertIsNone(s.validate(tok))
        tok = s.create("admin", "x", "")
        s.data[s._id(tok)]["created"] -= 4000
        self.assertIsNone(s.validate(tok))

    def test_activity_extends_the_idle_window_but_not_the_absolute_one(self):
        s = self.store(absolute=3600, idle=600)
        tok = s.create("admin", "x", "")
        s.data[s._id(tok)]["last"] -= 500
        self.assertIsNotNone(s.validate(tok))                               # touched
        s.data[s._id(tok)]["created"] -= 3700
        self.assertIsNone(s.validate(tok))

    def test_tokens_are_not_stored_and_file_is_private(self):
        s = self.store()
        tok = s.create("admin", "x", "")
        raw = (Path(self.tmp) / "sessions.json").read_text()
        self.assertNotIn(tok, raw)
        self.assertEqual(oct(os.stat(Path(self.tmp) / "sessions.json").st_mode & 0o777), "0o600")
        self.assertEqual(self.store().validate(tok)["user"], "admin")       # survives a restart

    def test_revoke_all_keeps_one_and_cap_evicts_oldest(self):
        s = self.store(max=3)
        toks = [s.create("admin", "x", "") for _ in range(3)]
        s.data[s._id(toks[0])]["last"] -= 100
        new = s.create("admin", "x", "")                                    # over the cap: least recently used goes
        self.assertIsNone(s.validate(toks[0]))
        self.assertIsNotNone(s.validate(new))
        s.revoke_all(keep=s._id(new))
        self.assertEqual([r["id"] for r in s.list(s._id(new))], [s._id(new)])
        self.assertTrue(s.list(s._id(new))[0]["current"])


class TestLoginFlow(TmpCase):
    def test_lockout_and_other_ips_unaffected(self):
        a = make_auth(self.tmp)
        for _ in range(A.Auth.MAX_PER_IP):
            self.assertIsNone(a.login("9.9.9.9", "admin", "bad"))
        with self.assertRaises(A.Locked) as cm:
            a.login("9.9.9.9", "admin", PW)                                 # even the right password is refused
        self.assertGreater(cm.exception.retry_after, 0)
        self.assertIsNotNone(a.login("8.8.8.8", "admin", PW))

    def test_global_cap_stops_distributed_guessing(self):
        a = make_auth(self.tmp)
        for i in range(A.Auth.MAX_GLOBAL):
            a.login(f"10.0.{i // 250}.{i % 250}", "admin", "bad")
        with self.assertRaises(A.Locked):
            a.login("7.7.7.7", "admin", PW)

    def test_change_password_ends_other_sessions(self):
        a = make_auth(self.tmp)
        old = a.login("1.1.1.1", "admin", PW)
        other = a.login("2.2.2.2", "admin", PW)
        with self.assertRaises(A.AuthError):
            a.change_password("wrong", "another-long-pass")
        with self.assertRaises(A.AuthError):
            a.change_password(PW, "short")
        new = a.change_password(PW, "another-long-pass")
        self.assertIsNone(a.check_session(old))
        self.assertIsNone(a.check_session(other))
        self.assertEqual(a.check_session(new), "admin")
        b = make_auth(self.tmp)                                              # persisted, wins over the config
        self.assertIsNotNone(b.login("1.1.1.1", "admin", "another-long-pass"))
        self.assertEqual(oct(os.stat(Path(self.tmp) / "auth.json").st_mode & 0o777), "0o600")

    def test_sessions_survive_a_restart(self):
        tok = make_auth(self.tmp).login("1.1.1.1", "admin", PW)
        self.assertEqual(make_auth(self.tmp).check_session(tok), "admin")


class TestTwoFactor(TmpCase):
    def enable(self, a):
        res = a.totp_begin(PW)
        code = A.hotp(__import__("base64").b32decode(res["secret"]), int(time.time() // 30))
        return res["secret"], a.totp_enable(code)

    def test_setup_requires_a_valid_code_and_the_password(self):
        a = make_auth(self.tmp)
        with self.assertRaises(A.AuthError):
            a.totp_begin("wrong")
        a.totp_begin(PW)
        with self.assertRaises(A.AuthError):
            a.totp_enable("000000")
        self.assertFalse(a.totp_enabled)
        with self.assertRaises(A.AuthError):
            a.totp_enable("abcdef")

    def test_login_needs_the_code_and_a_code_cannot_be_reused(self):
        a = make_auth(self.tmp)
        secret, codes = self.enable(a)
        self.assertTrue(a.totp_enabled)
        self.assertEqual(len(codes), A.RECOVERY_CODES)
        self.assertIsNone(a.login("1.1.1.1", "admin", PW))                  # password alone is no longer enough
        self.assertIsNone(a.login("1.1.1.1", "admin", PW, "000000"))
        step = int(time.time() // 30)
        code = A.hotp(__import__("base64").b32decode(secret), step + 1)     # a fresh step (the setup code used this one)
        self.assertIsNotNone(a.login("1.1.1.1", "admin", PW, code))
        self.assertIsNone(a.login("1.1.1.1", "admin", PW, code))            # replay refused

    def test_recovery_codes_work_once(self):
        a = make_auth(self.tmp)
        _, codes = self.enable(a)
        self.assertIsNotNone(a.login("1.1.1.1", "admin", PW, codes[0]))
        self.assertIsNone(a.login("1.1.1.1", "admin", PW, codes[0]))
        self.assertEqual(a.two_factor_status()["recovery_left"], A.RECOVERY_CODES - 1)
        self.assertIsNotNone(a.login("1.1.1.1", "admin", PW, codes[1].upper().replace("-", " ")))   # formatting is forgiven
        self.assertIsNone(a.login("1.1.1.1", "admin", PW, "aaaaaa-bbbbbb"))

    def test_secret_and_codes_are_not_stored_in_clear(self):
        a = make_auth(self.tmp)
        secret, codes = self.enable(a)
        raw = (Path(self.tmp) / "auth.json").read_text()
        self.assertNotIn(secret, raw)
        for c in codes:
            self.assertNotIn(c, raw)
            self.assertNotIn(c.replace("-", ""), raw)
        self.assertEqual(json.loads(raw)["totp"]["enabled"], True)

    def test_wrong_codes_count_towards_the_lockout(self):
        a = make_auth(self.tmp)
        self.enable(a)
        for _ in range(A.Auth.MAX_PER_IP):
            self.assertIsNone(a.login("5.5.5.5", "admin", PW, "000000"))
        with self.assertRaises(A.Locked):
            a.login("5.5.5.5", "admin", PW, "000000")

    def test_disable_needs_password_and_code_and_survives_restart(self):
        a = make_auth(self.tmp)
        secret, codes = self.enable(a)
        self.assertTrue(make_auth(self.tmp).totp_enabled)                   # persisted
        with self.assertRaises(A.AuthError):
            a.totp_disable("wrong", codes[0])
        with self.assertRaises(A.AuthError):
            a.totp_disable(PW, "000000")
        a.totp_disable(PW, codes[2])
        self.assertFalse(a.totp_enabled)
        self.assertIsNotNone(a.login("1.1.1.1", "admin", PW))
        self.assertFalse(make_auth(self.tmp).totp_enabled)


class TestAuditChain(TmpCase):
    def log(self, **kw):
        return Audit(Path(self.tmp) / "audit.log", **kw)

    def lines(self):
        return (Path(self.tmp) / "audit.log").read_text().splitlines()

    def test_chain_verifies_and_continues_after_restart(self):
        a = self.log()
        for i in range(5):
            a.append("admin", "1.1.1.1", "x", f"e{i}")
        self.assertEqual(a.verify(), (True, None))
        b = self.log()                                                        # restart continues the same chain
        b.append("admin", "1.1.1.1", "x", "after restart")
        self.assertEqual(b.verify(), (True, None))
        self.assertEqual(b.tail(1)[0]["detail"], "after restart")

    def test_editing_or_deleting_a_record_is_detected(self):
        a = self.log()
        for i in range(6):
            a.append("admin", "1.1.1.1", "login.ok", f"e{i}")
        ls = self.lines()
        edited = ls[:]
        rec = json.loads(edited[2])
        rec["user"] = "someone-else"
        edited[2] = json.dumps(rec)
        (Path(self.tmp) / "audit.log").write_text("\n".join(edited) + "\n")
        ok, at = self.log().verify()
        self.assertFalse(ok)
        self.assertEqual(at, 2)
        (Path(self.tmp) / "audit.log").write_text("\n".join(ls[:2] + ls[3:]) + "\n")          # a record removed
        self.assertFalse(self.log().verify()[0])

    def test_chain_survives_rotation(self):
        a = self.log(max_bytes=400, keep=3)
        for i in range(30):
            a.append("admin", "1.1.1.1", "x", f"event {i}")
        self.assertTrue((Path(self.tmp) / "audit.log.1").exists())
        self.assertEqual(a.verify(), (True, None))
        self.assertEqual(a.tail(1)[0]["detail"], "event 29")


class TestTls(TmpCase):
    def test_generate_reuse_renew_and_serve(self):
        c, k, fp = tls.ensure_self_signed(self.tmp, ["updatedash.example.ca", "10.10.56.16"])
        self.assertEqual(oct(os.stat(k).st_mode & 0o777), "0o600")
        self.assertEqual(tls.ensure_self_signed(self.tmp, ["updatedash.example.ca", "10.10.56.16"])[2], fp)   # reused
        c2, k2, fp2 = tls.ensure_self_signed(self.tmp, ["another-name.example.ca"])
        self.assertNotEqual(fp2, fp)                                                                            # new name => new cert
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(c2, k2)
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]

        def run():
            conn, _ = srv.accept()
            s = ctx.wrap_socket(conn, server_side=True)
            s.sendall(b"hello")
            s.close()

        threading.Thread(target=run, daemon=True).start()
        cctx = ssl.create_default_context()
        cctx.load_verify_locations(c2)
        with cctx.wrap_socket(socket.create_connection(("127.0.0.1", port)), server_hostname="localhost") as s:
            self.assertEqual(s.recv(5), b"hello")
            self.assertGreaterEqual(s.version(), "TLSv1.2")


if __name__ == "__main__":
    unittest.main()
