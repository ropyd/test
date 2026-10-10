#!/usr/bin/env python3
"""SSH forced-command gate for updatedash. Runs on the Proxmox HOST, as root.

Install as /usr/local/sbin/updatedash-gate and reference it from authorized_keys:

  command="/usr/local/sbin/updatedash-gate",from="<dashboard-ip>",restrict ssh-ed25519 AAAA... updatedash

The dashboard's key can do exactly this, and nothing else:

  pct exec <ctid> -- bash -c <command>   only for CT IDs in /etc/updatedash-gate.allow, and only for a command
                                         on the built-in list below or in /etc/updatedash-gate.commands
  pct snapshot|delsnapshot <ctid> pre-update-YYYYMMDD-HHMMSS   (at most MAX_SNAPSHOTS exist per container)
  pct listsnapshot <ctid>
  pct list                      read-only; filtered to the allowed CT IDs
  allow list | allow protected  read-only

With /etc/updatedash-gate.manage present (its content is the dashboard's own CT ID) it may also:

  pct list --all                read-only list of every container on this node
  allow add <ctid> | allow remove <ctid>      (never a CT ID listed in /etc/updatedash-gate.protected)

Every request, allowed or refused, is written to the host's syslog (tag updatedash-gate), which the dashboard cannot edit.
Anything else (other pct subcommands, other CT IDs, other commands, a shell) is refused.
"""
import os
import re
import shlex
import shutil
import subprocess
import sys
import syslog

ALLOW_FILE = "/etc/updatedash-gate.allow"
MANAGE_FLAG = "/etc/updatedash-gate.manage"
PROTECTED_FILE = "/etc/updatedash-gate.protected"
COMMANDS_FILE = "/etc/updatedash-gate.commands"
SNAP = re.compile(r"pre-update-\d{8}-\d{6}")
MAX_SNAPSHOTS = 10
MAX_COMMAND = 2000

# ---- commands the dashboard may run inside an allowed container (kept in step with udash/core.py by a test)
PKG = r"[a-z0-9][a-z0-9.+-]{0,60}"
SLUGS = ("sonarr", "radarr", "prowlarr", "lidarr", "jackett", "autobrr", "flaresolverr", "vaultwarden",
         "homarr", "heimdall", "traefik", "nginxproxymanager")
APT_ENV = "export DEBIAN_FRONTEND=noninteractive;"
OS_COUNT = "apt-get -s upgrade 2>/dev/null | grep -c '^Inst' || true"
BUILTIN_EXACT = frozenset({
    APT_ENV + " apt-get update -qq && apt-get -y -o Dpkg::Options::=--force-confold upgrade",
    "export PHS_SILENT=1 TERM=xterm; update",
    OS_COUNT,
    "apt-get update -qq >/dev/null 2>&1; " + OS_COUNT,
})
BUILTIN_PATTERNS = (
    re.compile(r"apt-get update -qq >/dev/null 2>&1; apt-cache policy " + PKG),
    re.compile(re.escape(APT_ENV) + r" apt-get update -qq && apt-get install -y --only-upgrade " + PKG),
    re.compile(r"cat /root/\.(?:" + "|".join(SLUGS) + r") 2>/dev/null \|\| cat /opt/\*_version\.txt 2>/dev/null"),
)


def _log(level, msg):
    try:
        syslog.openlog("updatedash-gate", syslog.LOG_PID, syslog.LOG_AUTH)
        syslog.syslog(level, re.sub(r"[^\x20-\x7e]", "?", msg)[:300])
    except Exception:  # noqa: BLE001 - logging must never break the gate
        pass


def deny(msg, detail=""):
    sys.stderr.write(f"updatedash-gate: {msg}\n")
    _log(syslog.LOG_WARNING, f"DENIED {msg} :: {detail or os.environ.get('SSH_ORIGINAL_COMMAND', '')}")
    sys.exit(126)


def _read_lines(path):
    try:
        with open(path) as f:
            return [ln.rstrip("\n") for ln in f]
    except FileNotFoundError:
        return []
    except OSError:
        deny(f"cannot read {path}")


def read_ids(path=None):
    return {ln.split("#")[0].strip() for ln in _read_lines(path or ALLOW_FILE) if ln.split("#")[0].strip()}


def read_protected():
    try:
        return read_ids(PROTECTED_FILE)
    except SystemExit:
        return set()


def custom_commands():
    """Exact command lines the host owner approved in addition to the built-ins ('#' lines are comments)."""
    try:
        return {ln.strip() for ln in _read_lines(COMMANDS_FILE) if ln.strip() and not ln.lstrip().startswith("#")}
    except SystemExit:
        return set()


def command_allowed(cmd):
    if not cmd or len(cmd) > MAX_COMMAND or "\n" in cmd or "\r" in cmd or "\0" in cmd:
        return False
    if cmd in BUILTIN_EXACT or any(p.fullmatch(cmd) for p in BUILTIN_PATTERNS):
        return True
    return cmd in custom_commands()


def write_ids(ids):
    tmp = ALLOW_FILE + ".tmp"
    with open(tmp, "w") as f:
        f.write("# CT IDs updatedash may manage. Edited by hand or by the dashboard (see updatedash-gate).\n")
        for i in sorted(ids, key=int):
            f.write(i + "\n")
    os.chmod(tmp, 0o644)
    os.replace(tmp, ALLOW_FILE)


def manage_self():
    """None when GUI management is off, else the dashboard's own CT id ('' if unknown)."""
    try:
        with open(MANAGE_FLAG) as f:
            return f.read().strip()
    except OSError:
        return None


def pct_bin():
    return "/usr/sbin/pct" if os.path.exists("/usr/sbin/pct") else (shutil.which("pct") or "/usr/sbin/pct")


def pct_list(only):
    out = subprocess.run([pct_bin(), "list"], capture_output=True, text=True)
    rows = out.stdout.splitlines()
    keep = [r for i, r in enumerate(rows) if i == 0 or only is None or (r.split() or [""])[0] in only]
    sys.stdout.write("\n".join(keep) + "\n")
    sys.stderr.write(out.stderr)
    sys.exit(out.returncode)


def snapshot_count(ctid):
    out = subprocess.run([pct_bin(), "listsnapshot", ctid], capture_output=True, text=True)
    return len(set(SNAP.findall(out.stdout)))


def main():
    raw = os.environ.get("SSH_ORIGINAL_COMMAND", "")
    try:
        argv = shlex.split(raw)
    except ValueError:
        deny("unparseable command")
    ids = read_ids()

    if argv == ["pct", "list"]:
        _log(syslog.LOG_INFO, "ok pct list")
        pct_list(ids)
    if argv == ["allow", "list"]:
        _log(syslog.LOG_INFO, "ok allow list")
        sys.stdout.write("".join(i + "\n" for i in sorted(ids, key=int)))
        sys.exit(0)
    if argv == ["allow", "protected"]:
        _log(syslog.LOG_INFO, "ok allow protected")
        sys.stdout.write("".join(i + "\n" for i in sorted(read_protected())))
        sys.exit(0)

    me = manage_self()
    if argv == ["pct", "list", "--all"]:
        if me is None:
            deny("GUI management is disabled on this host")
        _log(syslog.LOG_INFO, "ok pct list --all")
        pct_list(None)
    if len(argv) == 3 and argv[0] == "allow" and argv[1] in ("add", "remove"):
        if me is None:
            deny("GUI management is disabled on this host")
        cid = argv[2]
        if not (cid.isdigit() and len(cid) <= 9):
            deny("bad CT id")
        if cid in read_protected():
            deny(f"container {cid} is protected on the host; edit {ALLOW_FILE} by hand")
        if argv[1] == "add":
            if cid == me:
                deny("the dashboard's own container cannot be added")
            if subprocess.run([pct_bin(), "status", cid], capture_output=True).returncode != 0:
                deny(f"container {cid} does not exist")
            ids.add(cid)
        else:
            ids.discard(cid)
        write_ids(ids)
        _log(syslog.LOG_NOTICE, f"ok allow {argv[1]} {cid}")
        sys.stdout.write(f"ok {argv[1]} {cid}\n")
        sys.exit(0)

    ok = False
    why = "request not permitted"
    if len(argv) >= 3 and argv[0] == "pct" and argv[2] in ids and argv[2].isdigit():
        sub = argv[1]
        if sub == "exec":
            ok = len(argv) == 7 and argv[3] == "--" and argv[4:6] == ["bash", "-c"]
            if ok and not command_allowed(argv[6]):
                ok, why = False, "command is not on the allow list (see /etc/updatedash-gate.commands)"
        elif sub == "snapshot":
            ok = len(argv) == 4 and bool(SNAP.fullmatch(argv[3]))
            if ok and snapshot_count(argv[2]) >= MAX_SNAPSHOTS:
                ok, why = False, f"container {argv[2]} already has {MAX_SNAPSHOTS} pre-update snapshots; remove old ones"
        elif sub == "delsnapshot":
            ok = len(argv) == 4 and bool(SNAP.fullmatch(argv[3]))
        elif sub == "listsnapshot":
            ok = len(argv) == 3
    if not ok:
        deny(why)
    _log(syslog.LOG_INFO, f"ok {argv[1]} {argv[2]} " + (argv[6][:80] if argv[1] == "exec" else " ".join(argv[3:])))
    os.execv(pct_bin(), argv)


if __name__ == "__main__":
    main()
