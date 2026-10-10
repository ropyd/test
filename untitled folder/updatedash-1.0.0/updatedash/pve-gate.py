#!/usr/bin/env python3
"""SSH forced-command gate for updatedash. Runs on the Proxmox HOST.

Install as /usr/local/sbin/updatedash-gate and reference it from authorized_keys:

  command="/usr/local/sbin/updatedash-gate",from="<dashboard-ip>",no-pty,no-port-forwarding,no-X11-forwarding,no-agent-forwarding ssh-ed25519 AAAA... updatedash

Container work is only allowed for CT IDs listed in /etc/updatedash-gate.allow (one per line):

  pct exec <ctid> -- bash -c <command>
  pct snapshot <ctid> pre-update-YYYYMMDD-HHMMSS
  pct listsnapshot <ctid>
  pct delsnapshot <ctid> pre-update-YYYYMMDD-HHMMSS
  pct list                      read-only; filtered to the allowed CT IDs
  allow list                    prints the allowed CT IDs

If the file /etc/updatedash-gate.manage exists, the dashboard may also manage the allow list itself
(the file's content is the dashboard's own CT ID, which can never be added):

  pct list --all                read-only list of every container on this node
  allow add <ctid>              only existing containers
  allow remove <ctid>
  allow protected               prints the protected CT IDs (always allowed)

CT IDs listed in /etc/updatedash-gate.protected can NEVER be added or removed through the dashboard, even
with GUI management on; change those by editing the allow file by hand. Use it for Tailscale, your password
manager, reverse proxies and anything else a compromised dashboard must not be able to reach.

Delete /etc/updatedash-gate.manage to turn GUI management off. Edit the allow file by hand any time.
Anything else (other pct subcommands, other CTIDs, a shell) is refused.
"""
import os
import re
import shlex
import shutil
import subprocess
import sys

ALLOW_FILE = "/etc/updatedash-gate.allow"
MANAGE_FLAG = "/etc/updatedash-gate.manage"
PROTECTED_FILE = "/etc/updatedash-gate.protected"
SNAP = re.compile(r"pre-update-\d{8}-\d{6}")


def deny(msg):
    sys.stderr.write(f"updatedash-gate: {msg}\n")
    sys.exit(126)


def read_ids():
    try:
        with open(ALLOW_FILE) as f:
            return {ln.split("#")[0].strip() for ln in f if ln.split("#")[0].strip()}
    except FileNotFoundError:
        return set()
    except OSError:
        deny(f"cannot read {ALLOW_FILE}")


def read_protected():
    try:
        with open(PROTECTED_FILE) as f:
            return {ln.split("#")[0].strip() for ln in f if ln.split("#")[0].strip()}
    except OSError:
        return set()


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
    return shutil.which("pct") or "/usr/sbin/pct"


def pct_list(only):
    out = subprocess.run([pct_bin(), "list"], capture_output=True, text=True)
    rows = out.stdout.splitlines()
    keep = [r for i, r in enumerate(rows) if i == 0 or only is None or (r.split() or [""])[0] in only]
    sys.stdout.write("\n".join(keep) + "\n")
    sys.stderr.write(out.stderr)
    sys.exit(out.returncode)


def main():
    try:
        argv = shlex.split(os.environ.get("SSH_ORIGINAL_COMMAND", ""))
    except ValueError:
        deny("unparseable command")
    ids = read_ids()

    if argv == ["pct", "list"]:
        pct_list(ids)
    if argv == ["allow", "list"]:
        sys.stdout.write("".join(i + "\n" for i in sorted(ids, key=int)))
        sys.exit(0)

    if argv == ["allow", "protected"]:
        sys.stdout.write("".join(i + "\n" for i in sorted(read_protected())))
        sys.exit(0)

    me = manage_self()
    if argv == ["pct", "list", "--all"]:
        if me is None:
            deny("GUI management is disabled on this host")
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
        sys.stdout.write(f"ok {argv[1]} {cid}\n")
        sys.exit(0)

    ok = False
    if len(argv) >= 3 and argv[0] == "pct" and argv[2] in ids and argv[2].isdigit():
        sub = argv[1]
        if sub == "exec":
            ok = len(argv) == 7 and argv[3] == "--" and argv[4:6] == ["bash", "-c"]
        elif sub in ("snapshot", "delsnapshot"):
            ok = len(argv) == 4 and bool(SNAP.fullmatch(argv[3]))
        elif sub == "listsnapshot":
            ok = len(argv) == 3
    if not ok:
        deny("request not permitted")
    os.execv(pct_bin(), argv)


if __name__ == "__main__":
    main()
