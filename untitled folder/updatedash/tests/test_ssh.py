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


@unittest.skipUnless(SSHD and KEYGEN, "sshd not available")
class TestRealSsh(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = Path(tempfile.mkdtemp(prefix="udssh-"))
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        cls.port = s.getsockname()[1]
        s.close()
        cls.hostkey = cls.d / "hostkey"
        keygen(cls.hostkey)
        cls.key, pub1 = keygen(cls.d / "client")
        cls.pkey, pub2 = keygen(cls.d / "client_pp", "pass phrase 1")
        (cls.d / "authorized_keys").write_text(pub1 + pub2)
        os.chmod(cls.d / "authorized_keys", 0o600)
        cls.cfg = cls.d / "sshd_config"
        cls.start_sshd()

    @classmethod
    def start_sshd(cls, hostkey=None):
        cls.cfg.write_text(f"""Port {cls.port}
ListenAddress 127.0.0.1
HostKey {hostkey or cls.hostkey}
PidFile {cls.d}/sshd.pid
AuthorizedKeysFile {cls.d}/authorized_keys
PasswordAuthentication yes
KbdInteractiveAuthentication no
PubkeyAuthentication yes
UsePAM no
StrictModes no
LogLevel ERROR
""")
        cls.proc = subprocess.Popen([SSHD, "-D", "-e", "-f", str(cls.cfg)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for _ in range(50):
            if cls.proc.poll() is not None:
                raise unittest.SkipTest("sshd could not start here: " + cls.proc.stdout.read().decode()[:200])
            try:
                socket.create_connection(("127.0.0.1", cls.port), 0.2).close()
                return
            except OSError:
                time.sleep(0.1)
        raise unittest.SkipTest("sshd did not start in time")

    @classmethod
    def stop_sshd(cls):
        cls.proc.terminate()
        cls.proc.wait(5)
        cls.proc.stdout.close()

    @classmethod
    def tearDownClass(cls):
        cls.stop_sshd()
        shutil.rmtree(cls.d, True)

    def setUp(self):
        self.state = Path(tempfile.mkdtemp(prefix="udstate-"))
        self.addCleanup(shutil.rmtree, self.state, True)
        self.access = AccessStore(self.state / "access.json", FakeVault())
        self.runner = Runner({"transport": "pve", "pve": {"host": "unused"}}, self.state, self.access, ROOT)
        self.user = os.environ.get("USER") or subprocess.run(["id", "-un"], capture_output=True, text=True).stdout.strip()

    def entry(self, auth="key", **kw):
        return clean_access(dict({"host": "127.0.0.1", "port": self.port, "user": self.user, "auth": auth}, **kw))

    def test_key_login_and_exec(self):
        e = self.entry()
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
        self.assertEqual(self.runner.test_ssh(e, self.pkey, "pass phrase 1")["user"], self.user)
        bad = self.runner.test_ssh(e, self.pkey, "wrong passphrase")
        self.assertFalse(bad["ok"])
        self.assertNotIn("user", bad)
        self.assertNotIn("wrong passphrase", bad["message"])

    def test_wrong_key_is_rejected_with_a_hint(self):
        other, _ = keygen(self.state / "other")
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
        res = self.runner.test_ssh(self.entry("password"), "Sup3r-Secret-pw", "")
        self.assertFalse(res["ok"])
        self.assertEqual(seen.read_text(), "Sup3r-Secret-pw")
        self.assertNotIn("Sup3r-Secret-pw", res["message"])

    def test_host_key_is_pinned_until_forgotten(self):
        e = self.entry()
        self.assertIn("user", self.runner.test_ssh(e, self.key, ""))          # first contact: trusted and remembered
        self.assertTrue((self.state / "known_hosts").read_text().strip())
        type(self).stop_sshd()
        other_hostkey = self.state / "hostkey2"
        keygen(other_hostkey)
        type(self).start_sshd(other_hostkey)
        try:
            res = self.runner.test_ssh(e, self.key, "")
            self.assertFalse(res["ok"])
            self.assertIn("host key changed", res["message"])
            self.runner.forget_host_key("127.0.0.1", self.port)
            self.assertIn("user", self.runner.test_ssh(e, self.key, ""))      # accepted again after forgetting
        finally:
            type(self).stop_sshd()
            type(self).start_sshd()

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


if __name__ == "__main__":
    unittest.main()
