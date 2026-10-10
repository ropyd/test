"""Running commands: through the Proxmox gate (pct exec) or directly over SSH with per-container credentials."""
import base64
import binascii
import contextlib
import hashlib
import json
import os
import re
import shlex
import signal
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from .util import ANSI, find_tool

SSH, SSH_KEYGEN, SSH_KEYSCAN = find_tool("ssh"), find_tool("ssh-keygen"), find_tool("ssh-keyscan")

TEST_SCRIPT = (
    'echo "UD_USER=$(id -un)"; echo "UD_UID=$(id -u)"; echo "UD_HOST=$(hostname)"; '
    '( . /etc/os-release 2>/dev/null && echo "UD_OS=$PRETTY_NAME" ); '
    'command -v update >/dev/null 2>&1 && echo "UD_UPDATE=1"; '
    'command -v apt-get >/dev/null 2>&1 && echo "UD_APT=1"; true'
)


KEY_TYPES = {"ssh-ed25519": "ED25519", "ssh-rsa": "RSA", "ecdsa-sha2-nistp256": "ECDSA",
             "ecdsa-sha2-nistp384": "ECDSA", "ecdsa-sha2-nistp521": "ECDSA"}


def key_fingerprint(line, expected_host_token):
    """Parse one `ssh-keyscan` line ("<host> <type> <base64 key>") into {"type", "fingerprint"}, or None.
    The fingerprint is OpenSSH's: SHA256 of the raw key blob, base64 without padding."""
    parts = line.split()
    if len(parts) != 3 or parts[0] != expected_host_token or parts[1] not in KEY_TYPES:
        return None
    try:
        blob = base64.b64decode(parts[2], validate=True)
    except (binascii.Error, ValueError):
        return None
    digest = base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    return {"type": KEY_TYPES[parts[1]], "fingerprint": "SHA256:" + digest}


def kill_tree(p):
    """Kill a child and everything it started (they share a process group)."""
    try:
        os.killpg(p.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            p.kill()
        except OSError:
            pass


def run_argv(argv, timeout, on_line=None, holder=None, env=None, scrub=()):
    """Run argv, stream cleaned output lines, return (rc, [lines]).

    holder['p'] receives the Popen (for cancel); `scrub` strings are masked in output."""
    scrub = [s for s in scrub if s]
    try:
        p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             text=True, errors="replace", start_new_session=True, env=env)
    except OSError as e:
        return 127, [str(e)]
    if holder is not None:
        holder["p"] = p
    fired = threading.Event()

    def kill():
        fired.set()
        kill_tree(p)

    timer = threading.Timer(timeout, kill)
    timer.start()
    lines = []
    try:
        for raw in p.stdout:
            line = ANSI.sub("", raw).rstrip("\n")
            for s in scrub:
                line = line.replace(s, "***")
            lines.append(line)
            if on_line:
                on_line(line)
        rc = p.wait()
    finally:
        timer.cancel()
        try:
            p.stdout.close()
        except OSError:
            pass
    if fired.is_set():
        msg = f"timed out after {timeout}s"
        lines.append(msg)
        if on_line:
            on_line(msg)
        rc = 124
    return rc, lines


class Runner:
    def __init__(self, cfg, state_dir, access, base_dir):
        self.local = cfg["transport"] == "local"
        pve = cfg.get("pve") or {}
        self.host = pve.get("host")
        self.user = pve.get("user", "root")
        self.key = pve.get("key", "/etc/updatedash/id_ed25519")
        self.state_dir = Path(state_dir)
        self.known_hosts = str(self.state_dir / "known_hosts")
        self._kh_lock = threading.Lock()
        self._gate_strict_at, self._gate_strict_val = 0, False
        self.access = access
        self.askpass = str(Path(base_dir) / "askpass.sh")
        try:
            os.chmod(self.askpass, 0o755)  # nosec B103 - a root-owned script that must be executable; it holds no secret
        except OSError:
            pass
        self.keydir = Path(os.environ.get("RUNTIME_DIRECTORY") or tempfile.gettempdir()) / "updatedash-keys"
        self.keydir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.keydir, 0o700)
        self.gate_configured = self.local or bool(self.host)

    # ---------------------------------------------------------------- Proxmox gate
    def _gate_strict(self):
        """Once the Proxmox host's key is in known_hosts (the builder pre-seeds it) a changed key is refused;
        only if it was never seeded does the first connection trust it."""
        now = time.time()
        if now - self._gate_strict_at > 60:
            self._gate_strict_val = self.hostkey_known(self.host, 22)
            self._gate_strict_at = now
        return self._gate_strict_val

    def _gate_ssh(self, remote):
        mode = "yes" if self._gate_strict() else "accept-new"
        return [SSH, "-i", self.key, "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
                "-o", f"UserKnownHostsFile={self.known_hosts}",
                "-o", f"StrictHostKeyChecking={mode}", "-o", "ConnectTimeout=8",
                "-o", "ServerAliveInterval=15", f"{self.user}@{self.host}", remote]

    # local-transport test hooks: UPDATEDASH_FAKE_LIST is a `pct list` dump; the allow list is a JSON file
    def _local_allow(self):
        try:
            return set(json.loads((self.state_dir / "local_allow.json").read_text()))
        except (OSError, ValueError):
            return None

    def _local_gate(self, args):
        allow = self._local_allow()
        if args == ("allow", "list"):
            return 0, [str(i) for i in sorted(allow or [])]
        if args == ("allow", "protected"):
            return 0, [x for x in os.environ.get("UPDATEDASH_FAKE_PROTECTED", "").split(",") if x]
        if args[:1] == ("allow",) and len(args) == 3:
            cur = set(allow or [])
            (cur.add if args[1] == "add" else cur.discard)(int(args[2]))
            (self.state_dir / "local_allow.json").write_text(json.dumps(sorted(cur)))
            return 0, [f"ok {args[1]} {args[2]}"]
        return 1, ["unsupported"]

    def pct(self, *args, timeout=120, on_line=None):
        if not self.gate_configured:
            return 1, ["Proxmox host is not configured (pve.host)"]
        if self.local:
            fake = os.environ.get("UPDATEDASH_FAKE_LIST")
            if args[:1] == ("list",) and fake:
                lines = Path(fake).read_text().splitlines()
                allow = self._local_allow()
                if "--all" in args or allow is None:
                    return 0, lines
                keep = {str(a) for a in allow}
                return 0, [x for i, x in enumerate(lines) if i == 0 or (x.split() or [""])[0] in keep]
            return 0, ["(local transport: skipped pct " + " ".join(args) + ")"]
        return run_argv(self._gate_ssh(shlex.join(["pct", *args])), timeout, on_line)

    def gate(self, *args, timeout=30):
        """Non-pct gate requests: `allow list|add|remove|protected`."""
        if not self.gate_configured:
            return 1, ["Proxmox host is not configured (pve.host)"]
        if self.local:
            return self._local_gate(args)
        return run_argv(self._gate_ssh(shlex.join(args)), timeout)

    # ---------------------------------------------------------------- direct SSH
    @contextlib.contextmanager
    def _keyfile(self, key_text):
        fd, path = tempfile.mkstemp(dir=str(self.keydir), prefix="k-")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(key_text.replace("\r\n", "\n").strip() + "\n")
            os.chmod(path, 0o600)
            yield path
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

    def _direct_argv(self, e, remote, keyfile, passphrase_given):
        argv = [SSH, "-p", str(e["port"]), "-o", "ConnectTimeout=8", "-o", "ServerAliveInterval=15",
                "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={self.known_hosts}",
                "-o", "LogLevel=ERROR", "-o", "IdentityAgent=none", "-o", "NumberOfPasswordPrompts=1"]
        if e["auth"] == "password":
            argv += ["-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no"]
        else:
            argv += ["-i", keyfile, "-o", "IdentitiesOnly=yes", "-o", "PasswordAuthentication=no",
                     "-o", "KbdInteractiveAuthentication=no"]
            if not passphrase_given:
                argv += ["-o", "BatchMode=yes"]
        return argv + [f"{e['user']}@{e['host']}", remote]

    def _direct_env(self, value):
        env = dict(os.environ)
        env.update(SSH_ASKPASS=self.askpass, SSH_ASKPASS_REQUIRE="force", UPDATEDASH_ASKPASS_VALUE=value or "")
        env.pop("DISPLAY", None)
        return env

    def _direct_run(self, e, secret, passphrase, cmd, timeout, on_line=None, holder=None):
        remote = shlex.join((["sudo", "-n"] if e.get("sudo") else []) + ["bash", "-c", cmd])
        scrub = (secret, passphrase) if e["auth"] == "password" else (passphrase,)
        if e["auth"] == "password":
            return run_argv(self._direct_argv(e, remote, None, False), timeout, on_line, holder,
                            self._direct_env(secret), scrub)
        with self._keyfile(secret) as kf:
            return run_argv(self._direct_argv(e, remote, kf, bool(passphrase)), timeout, on_line, holder,
                            self._direct_env(passphrase), scrub)

    def uses_ssh(self, ctid):
        return self.access.has(ctid)

    def exec(self, ctid, cmd, timeout=60, on_line=None, holder=None):
        if self.access.has(ctid):
            e = self.access.entries[str(ctid)]
            try:
                secret, passphrase = self.access.secrets(ctid)
            except ValueError as err:
                return 1, [str(err)]
            return self._direct_run(e, secret, passphrase, cmd, timeout, on_line, holder)
        if self.local:
            return run_argv(["bash", "-c", cmd], timeout, on_line, holder)
        if not self.gate_configured:
            return 1, ["no access configured for this container (Proxmox host or SSH credentials)"]
        remote = shlex.join(["pct", "exec", str(ctid), "--", "bash", "-c", cmd])
        return run_argv(self._gate_ssh(remote), timeout, on_line, holder)

    def test_ssh(self, e, secret, passphrase):
        """Try a login with the given (unsaved) credentials. Returns a dict for the UI."""
        rc, out = self._direct_run(e, secret, passphrase, TEST_SCRIPT, 25)
        info = {}
        for ln in out:
            m = re.match(r"^UD_([A-Z]+)=(.*)$", ln)
            if m:
                info[m.group(1)] = m.group(2).strip()
        text = " ".join(x for x in out if not x.startswith("UD_")).strip()
        if rc != 0 or "USER" not in info:
            hint = ""
            if "REMOTE HOST IDENTIFICATION HAS CHANGED" in text:
                hint = " The host key changed: if that is expected (rebuilt server), tick 'Forget the saved host key', check the new fingerprint and trust it again."
            elif "host key is known" in text or "Host key verification failed" in text:
                hint = " The server's host key is not trusted yet: use 'Check host key', compare the fingerprint, and confirm it."
            elif "Permission denied" in text:
                hint = " Check the user, password/key, and that the server allows this login (PermitRootLogin, PasswordAuthentication)."
            elif "Connection refused" in text:
                hint = " Nothing is listening on that port: is sshd installed and running in the container?"
            elif "sudo" in text and e.get("sudo"):
                hint = " Passwordless sudo (sudo -n) is required when 'Use sudo' is on."
            return {"ok": False, "message": (text or f"ssh exited with code {rc}")[:300] + hint}
        root = info.get("UID") == "0"
        res = {"ok": True, "user": info.get("USER"), "uid": info.get("UID"), "hostname": info.get("HOST"),
               "os": info.get("OS"), "root": root, "apt": info.get("APT") == "1",
               "community_update": info.get("UPDATE") == "1",
               "fingerprint": self.host_fingerprint(e["host"], e["port"])}
        if root:
            res["message"] = f"Connected as {info.get('USER')} on {info.get('HOST')}."
        else:
            res["ok"] = False
            res["message"] = (f"Connected as {info.get('USER')} (not root). Updates need root: log in as root "
                              "or turn on 'Use sudo' with passwordless sudo for this user.")
        return res

    # -- host keys: nothing is trusted automatically; the user compares a fingerprint and confirms it
    def _token(self, host, port):
        return host if int(port) == 22 else f"[{host}]:{port}"

    def hostkey_known(self, host, port):
        if not os.path.exists(self.known_hosts):
            return False
        try:
            return subprocess.run([SSH_KEYGEN, "-F", self._token(host, port), "-f", self.known_hosts],
                                  capture_output=True, timeout=5).returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    def scan_hostkeys(self, host, port):
        """Ask the server for its host keys (nothing is saved). Returns [{type, fingerprint, line}]."""
        try:
            out = subprocess.run([SSH_KEYSCAN, "-T", "5", "-p", str(int(port)), "-t", "ed25519,ecdsa,rsa", host],
                                 capture_output=True, text=True, timeout=20).stdout
        except (OSError, subprocess.SubprocessError):
            return []
        keys = []
        for line in out.splitlines():
            parsed = key_fingerprint(line, self._token(host, port))
            if parsed:
                keys.append(dict(parsed, line=line))
        return keys

    def trust_hostkey(self, host, port, fingerprint):
        """Save the server's key to known_hosts, but only if it matches the fingerprint the user confirmed."""
        for k in self.scan_hostkeys(host, port):
            if k["fingerprint"] == fingerprint:
                with self._kh_lock:
                    fd = os.open(self.known_hosts, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
                    with os.fdopen(fd, "a") as f:
                        f.write(k["line"] + "\n")
                return True
        return False

    def host_fingerprint(self, host, port):
        token = host if int(port) == 22 else f"[{host}]:{port}"
        try:
            out = subprocess.run([SSH_KEYGEN, "-F", token, "-l", "-f", self.known_hosts], capture_output=True,
                                 text=True, timeout=5).stdout
        except (OSError, subprocess.SubprocessError):
            return None
        m = re.search(r"(SHA256:\S+)", out)
        return m.group(1) if m else None

    def forget_host_key(self, host, port):
        token = host if int(port) == 22 else f"[{host}]:{port}"
        try:
            subprocess.run([SSH_KEYGEN, "-R", token, "-f", self.known_hosts], capture_output=True, timeout=5)
        except (OSError, subprocess.SubprocessError):
            pass
