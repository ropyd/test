"""Direct-SSH tests against a throwaway sshd on localhost (skipped if sshd isn't available)."""
import os
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from tests.helpers import ROOT
from udash.runner import Runner
from udash.store import AccessStore, clean_access

SSHD = shutil.which("sshd") or ("/usr/sbin/sshd" if os.path.exists("/usr/sbin/sshd") else None)
KEYGEN = shutil.which("ssh-keygen")


class FakeVault:
    def encrypt(self, s):
        return "enc:" + s[::-1]

    def decrypt(self, t):
        return t[4:][::-1]


def keygen(path, passphrase=""):
    subprocess.run([KEYGEN, "-q", "-t", "ed25519", "-N", passphrase, "-f", str(path)], check=True)
    return Path(path).read_text(), Path(str(path) + ".pub").read_text()


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def spawn_sshd(workdir, hostkey, port, authorized):
    """Start a throwaway sshd; returns the Popen once it accepts connections."""
    workdir = Path(workdir)
    cfg = workdir / f"sshd_config_{port}"
    base = f"""Port {port}
ListenAddress 127.0.0.1
HostKey {hostkey}
PidFile {workdir}/sshd_{port}.pid
AuthorizedKeysFile {authorized}
PasswordAuthentication yes
KbdInteractiveAuthentication no
PubkeyAuthentication yes
UsePAM no
StrictModes no
LogLevel ERROR
MaxStartups 100:30:200
"""
    # OpenSSH 9.8+ penalises sources that connect and drop before authenticating (which key scans and readiness probes
    # do); older versions don't know the option, so fall back to the plain config.
    for extra in ("PerSourcePenalties no\n", ""):
        cfg.write_text(base + extra)
        proc = subprocess.Popen([SSHD, "-D", "-e", "-f", str(cfg)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        time.sleep(0.3)
        if proc.poll() is None:
            break
        out = proc.stdout.read().decode()
        proc.stdout.close()
        if "PerSourcePenalties" not in out:
            raise unittest.SkipTest("sshd could not start here: " + out[:200])
    for _ in range(50):
        if proc.poll() is not None:
            raise unittest.SkipTest("sshd stopped unexpectedly: " + proc.stdout.read().decode()[:200])
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close()
            return proc
        except OSError:
            time.sleep(0.1)
    proc.kill()
    raise unittest.SkipTest("sshd did not start in time")


def stop_sshd(proc):
    proc.terminate()
    try:
        proc.wait(5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(5)
    proc.stdout.close()


@unittest.skipUnless(SSHD and KEYGEN, "sshd not available")
class TestRealSsh(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = Path(tempfile.mkdtemp(prefix="udssh-"))
        cls.port = free_port()
        cls.hostkey = cls.d / "hostkey"
        keygen(cls.hostkey)
        cls.key, pub1 = keygen(cls.d / "client")
        cls.pkey, pub2 = keygen(cls.d / "client_pp", "pass phrase 1")
        (cls.d / "authorized_keys").write_text(pub1 + pub2)
        os.chmod(cls.d / "authorized_keys", 0o600)
        cls.proc = spawn_sshd(cls.d, cls.hostkey, cls.port, cls.d / "authorized_keys")

    @classmethod
    def tearDownClass(cls):
        stop_sshd(cls.proc)
        shutil.rmtree(cls.d, True)

    def setUp(self):
        self.state = Path(tempfile.mkdtemp(prefix="udstate-"))
        self.addCleanup(shutil.rmtree, self.state, True)
        self.access = AccessStore(self.state / "access.json", FakeVault())
        self.runner = Runner({"transport": "pve", "pve": {"host": "unused"}}, self.state, self.access, ROOT)
        self.user = os.environ.get("USER") or subprocess.run(["id", "-un"], capture_output=True, text=True).stdout.strip()

    def trust(self, port=None):
        """What the user does in the UI: fetch the key, compare the fingerprint, confirm."""
        keys = self.runner.scan_hostkeys("127.0.0.1", port or self.port)
        self.assertTrue(keys, "sshd returned no host key")
        self.assertTrue(self.runner.trust_hostkey("127.0.0.1", port or self.port, keys[0]["fingerprint"]))
        return keys[0]["fingerprint"]

    def entry(self, auth="key", **kw):
        return clean_access(dict({"host": "127.0.0.1", "port": self.port, "user": self.user, "auth": auth}, **kw))

    def test_key_login_and_exec(self):
        e = self.entry()
        self.trust()
        res = self.runner.test_ssh(e, self.key, "")
        self.assertEqual(res["user"], self.user)
        self.assertTrue(res["fingerprint"].startswith("SHA256:"))
        if os.geteuid() != 0:                       # a normal user is "connected but not root"
            self.assertFalse(res["ok"])
            self.assertIn("not root", res["message"])
        # run a command through the same path updates use, streaming lines
        self.access.set(300, e, secret=self.key)
        seen = []
        rc, out = self.runner.exec(300, "echo hello; echo world >&2; id -un", 20, seen.append)
        self.assertEqual(rc, 0)
        self.assertEqual(out[:2], ["hello", "world"])
        self.assertEqual(seen, out)
        self.assertEqual(out[2], self.user)
        # the exit status is passed through
        self.assertEqual(self.runner.exec(300, "exit 7", 20)[0], 7)
        # nothing is left behind on disk
        self.assertEqual(list(self.runner.keydir.glob("k-*")), [])

    def test_key_with_passphrase_via_askpass(self):
        e = self.entry()
        self.trust()
        self.assertEqual(self.runner.test_ssh(e, self.pkey, "pass phrase 1")["user"], self.user)
        bad = self.runner.test_ssh(e, self.pkey, "wrong passphrase")
        self.assertFalse(bad["ok"])
        self.assertNotIn("user", bad)
        self.assertNotIn("wrong passphrase", bad["message"])

    def test_wrong_key_is_rejected_with_a_hint(self):
        other, _ = keygen(self.state / "other")
        self.trust()
        res = self.runner.test_ssh(self.entry(), other, "")
        self.assertFalse(res["ok"])
        self.assertIn("Permission denied", res["message"])
        self.assertIn("PermitRootLogin", res["message"])

    def test_connection_refused_hint(self):
        res = self.runner.test_ssh(self.entry(port=1), self.key, "")
        self.assertFalse(res["ok"])
        self.assertIn("sshd installed", res["message"])

    def test_password_is_delivered_through_askpass_and_masked(self):
        # The test sshd cannot verify passwords (not root), so it rejects them; what matters is that the
        # configured password reaches ssh's askpass hook, never a terminal prompt, and is masked in output.
        spy = self.state / "askpass-spy.sh"
        seen = self.state / "seen-password"
        spy.write_text(f'#!/bin/sh\nprintf "%s" "$UPDATEDASH_ASKPASS_VALUE" > {seen}\nprintf "%s\\n" "$UPDATEDASH_ASKPASS_VALUE"\n')
        os.chmod(spy, 0o755)
        self.runner.askpass = str(spy)
        self.trust()
        res = self.runner.test_ssh(self.entry("password"), "Sup3r-Secret-pw", "")
        self.assertFalse(res["ok"])
        self.assertEqual(seen.read_text(), "Sup3r-Secret-pw")
        self.assertNotIn("Sup3r-Secret-pw", res["message"])

    def test_unknown_host_is_refused_until_the_fingerprint_is_confirmed(self):
        e = self.entry()
        res = self.runner.test_ssh(e, self.key, "")
        self.assertFalse(res["ok"])
        self.assertNotIn("user", res)                                          # no login happened
        self.assertIn("not trusted yet", res["message"])
        self.assertFalse(self.runner.hostkey_known("127.0.0.1", self.port))
        self.assertFalse((self.state / "known_hosts").exists())                # nothing was saved by trying

    def test_scanned_fingerprint_matches_the_servers_real_key(self):
        real = subprocess.run([KEYGEN, "-lf", str(self.hostkey) + ".pub"], capture_output=True, text=True).stdout
        fps = {k["fingerprint"] for k in self.runner.scan_hostkeys("127.0.0.1", self.port)}
        self.assertIn(real.split()[1], fps)

    def test_key_line_parsing_is_strict(self):
        from udash.runner import key_fingerprint
        blob = "AAAAC3NzaC1lZDI1NTE5AAAAIPLdK7BLlUcB11piKVQaDMvrqbwTJ1EKaYiG3COPM56z"
        good = f"[h]:22 ssh-ed25519 {blob}"
        self.assertEqual(key_fingerprint(good, "[h]:22")["type"], "ED25519")
        self.assertTrue(key_fingerprint(good, "[h]:22")["fingerprint"].startswith("SHA256:"))
        for bad in (good, f"[h]:22 ssh-dss {blob}", "[h]:22 ssh-ed25519 !!!notbase64", f"[h]:22 ssh-ed25519 {blob} extra",
                    "# comment", "", f"other ssh-ed25519 {blob}"):
            self.assertIsNone(key_fingerprint(bad, "[x]:22" if bad == good else "[h]:22"), bad)

    def test_a_wrong_fingerprint_trusts_nothing(self):
        self.assertFalse(self.runner.trust_hostkey("127.0.0.1", self.port, "SHA256:" + "A" * 43))
        self.assertFalse(self.runner.hostkey_known("127.0.0.1", self.port))
        self.assertFalse((self.state / "known_hosts").exists())

    def test_host_key_is_pinned_until_forgotten(self):
        port = free_port()
        e = self.entry(port=port)
        key1 = self.state / "srvkey1"
        keygen(key1)
        proc = spawn_sshd(self.state, key1, port, self.d / "authorized_keys")
        try:
            self.trust(port)
            self.assertIn("user", self.runner.test_ssh(e, self.key, ""))       # trusted explicitly, then it works
            self.assertTrue((self.state / "known_hosts").read_text().strip())
        finally:
            stop_sshd(proc)
        key2 = self.state / "srvkey2"                                           # same address, different key: a MITM or a rebuild
        keygen(key2)
        proc = spawn_sshd(self.state, key2, port, self.d / "authorized_keys")
        try:
            res = self.runner.test_ssh(e, self.key, "")
            self.assertFalse(res["ok"])
            self.assertNotIn("user", res)
            self.assertIn("host key changed", res["message"])
            self.runner.forget_host_key("127.0.0.1", port)
            self.assertFalse(self.runner.test_ssh(e, self.key, "")["ok"])      # forgetting does not auto-trust the new key
            self.trust(port)
            self.assertIn("user", self.runner.test_ssh(e, self.key, ""))      # trusted again after an explicit confirmation
        finally:
            stop_sshd(proc)

    def test_gate_connection_is_strict_once_the_proxmox_key_is_known(self):
        self.runner.host = "10.10.56.5"
        self.assertIn("StrictHostKeyChecking=accept-new", self.runner._gate_ssh("x"))     # never seeded: first use
        pub = Path(str(self.hostkey) + ".pub").read_text().split()
        (self.state / "known_hosts").write_text(f"10.10.56.5 {pub[0]} {pub[1]}\n")        # what the builder seeds
        self.runner._gate_strict_at = 0
        argv = self.runner._gate_ssh("x")
        self.assertIn("StrictHostKeyChecking=yes", argv)
        self.assertNotIn("StrictHostKeyChecking=accept-new", argv)

    def test_argv_for_each_auth_mode(self):
        pw = self.runner._direct_argv(self.entry("password"), "cmd", None, False)
        self.assertIn("PreferredAuthentications=password", pw)
        self.assertNotIn("-i", pw)
        env = self.runner._direct_env("s3")
        self.assertEqual((env["SSH_ASKPASS_REQUIRE"], env["UPDATEDASH_ASKPASS_VALUE"]), ("force", "s3"))
        k = self.runner._direct_argv(self.entry("key"), "cmd", "/tmp/k", False)
        self.assertIn("BatchMode=yes", k)
        self.assertIn("PasswordAuthentication=no", k)
        self.assertNotIn("BatchMode=yes", self.runner._direct_argv(self.entry("key"), "cmd", "/tmp/k", True))
        self.assertEqual(k[-2], f"{self.user}@127.0.0.1")
        self.assertIn("StrictHostKeyChecking=yes", pw)                         # never accept-new / never "no"
        self.assertNotIn("StrictHostKeyChecking=no", " ".join(pw + k))


if __name__ == "__main__":
    unittest.main()
