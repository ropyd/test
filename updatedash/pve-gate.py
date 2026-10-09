#!/usr/bin/env python3
"""SSH forced-command gate for updatedash. Runs on the Proxmox HOST.

Install as /usr/local/sbin/updatedash-gate and reference it from authorized_keys:

  command="/usr/local/sbin/updatedash-gate",from="<dashboard-ip>",no-pty,no-port-forwarding,no-X11-forwarding,no-agent-forwarding ssh-ed25519 AAAA... updatedash

Only these requests are allowed, and only for container IDs listed in
/etc/updatedash-gate.allow (one CTID per line):

  pct exec <ctid> -- bash -c <command>
  pct snapshot <ctid> pre-update-YYYYMMDD-HHMMSS
  pct listsnapshot <ctid>
  pct delsnapshot <ctid> pre-update-YYYYMMDD-HHMMSS

Anything else (other pct subcommands, other CTIDs, a shell) is refused.
"""
import os
import re
import shlex
import shutil
import sys

ALLOW_FILE = "/etc/updatedash-gate.allow"
SNAP = re.compile(r"pre-update-\d{8}-\d{6}")


def deny(msg):
    sys.stderr.write(f"updatedash-gate: {msg}\n")
    sys.exit(126)


def allowed_ids():
    try:
        with open(ALLOW_FILE) as f:
            return {ln.split("#")[0].strip() for ln in f if ln.split("#")[0].strip()}
    except OSError:
        deny(f"cannot read {ALLOW_FILE}")


def main():
    try:
        argv = shlex.split(os.environ.get("SSH_ORIGINAL_COMMAND", ""))
    except ValueError:
        deny("unparseable command")
    ids = allowed_ids()
    ok = False
    if len(argv) >= 3 and argv[0] == "pct" and argv[2] in ids and argv[2].isdigit():
        sub = argv[1]
        if sub == "exec":
            ok = len(argv) == 7 and argv[3] == "--" and argv[4:6] == ["bash", "-c"]
        elif sub == "snapshot" or sub == "delsnapshot":
            ok = len(argv) == 4 and bool(SNAP.fullmatch(argv[3]))
        elif sub == "listsnapshot":
            ok = len(argv) == 3
    if not ok:
        deny("request not permitted")
    pct = shutil.which("pct") or "/usr/sbin/pct"
    os.execv(pct, argv)


if __name__ == "__main__":
    main()
