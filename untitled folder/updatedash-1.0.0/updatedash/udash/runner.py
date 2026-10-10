"""Running commands: through the Proxmox gate (pct exec) or directly over SSH with per-container credentials."""
import contextlib
import json
import os
import re
import shlex
import signal
import subprocess
import tempfile
import threading
from pathlib import Path

from .util import ANSI

TEST_SCRIPT = (
    'echo "UD_USER=$(id -un)"; echo "UD_UID=$(id -u)"; echo "UD_HOST=$(hostname)"; '
    '( . /etc/os-release 2>/dev/null && echo "UD_OS=$PRETTY_NAME" ); '
    'command -v update >/dev/null 2>&1 && echo "UD_UPDATE=1"; '
    'command -v apt-get >/dev/null 2>&1 && echo "UD_APT=1"; true'
)


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
        self.access = access
        self.askpass = str(Path(base_dir) / "askpass.sh")
        try:
            os.chmod(self.askpass, 0o755)
        except OSError:
            pass
        self.keydir = Path(os.environ.get("RUNTIME_DIRECTORY") or tempfile.gettempdir()) / "updatedash-keys"
        self.keydir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.keydir, 0o700)
        self.gate_configured = self.local or bool(self.host)

    # ---------------------------------------------------------------- Proxmox gate
    def _gate_ssh(self, remote):
        return ["ssh", "-i", self.key, "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
                "-o", f"UserKnownHostsFile={self.known_hosts}",
                "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=8",
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
        argv = ["ssh", "-p", str(e["port"]), "-o", "ConnectTimeout=8", "-o", "ServerAliveInterval=15",
                "-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={self.known_hosts}",
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
            if "REMOTE HOST IDENTIFICATION HAS CHANGED" in text or "Host key verification failed" in text:
                hint = " The host key changed: tick 'Forget the saved host key' and test again if that is expected."
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

    def host_fingerprint(self, host, port):
        token = host if int(port) == 22 else f"[{host}]:{port}"
        try:
            out = subprocess.run(["ssh-keygen", "-F", token, "-l", "-f", self.known_hosts], capture_output=True,
                                 text=True, timeout=5).stdout
        except (OSError, subprocess.SubprocessError):
            return None
        m = re.search(r"(SHA256:\S+)", out)
        return m.group(1) if m else None

    def forget_host_key(self, host, port):
        token = host if int(port) == 22 else f"[{host}]:{port}"
        try:
            subprocess.run(["ssh-keygen", "-R", token, "-f", self.known_hosts], capture_output=True, timeout=5)
        except (OSError, subprocess.SubprocessError):
            pass
