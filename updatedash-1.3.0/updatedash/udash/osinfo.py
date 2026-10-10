"""Reading a container's operating system and pending package updates from fixed, read-only commands."""
import re

# These exact strings are the only OS commands the Proxmox gate accepts (pve-gate.py keeps the same list).
OS_INFO = ('. /etc/os-release 2>/dev/null; echo "UD_NAME=$PRETTY_NAME"; echo "UD_ID=$ID"; echo "UD_VERSION=$VERSION_ID"; '
           'echo "UD_CODENAME=$VERSION_CODENAME"; echo "UD_DEBIAN=$(cat /etc/debian_version 2>/dev/null)"; '
           'command -v apt-get >/dev/null 2>&1 && echo "UD_APT=1"; true')
OS_PENDING = "apt-get -s upgrade 2>/dev/null | grep '^Inst' || true"
APT_REFRESH = "apt-get update -qq >/dev/null 2>&1; "

MAX_PACKAGES = 300
INST = re.compile(r"^Inst (\S+)(?: \[([^\]]*)\])? \((\S+) (.*)\)\s*$")
DEB_POINT = re.compile(r"\+deb(\d+)u(\d+)")


def cmd_os_info():
    return OS_INFO


def cmd_os_pending(update_first):
    return (APT_REFRESH if update_first else "") + OS_PENDING


def parse_os_info(lines):
    """-> {name, id, version, codename, debian, apt} (missing values are None)."""
    kv = {}
    for ln in lines:
        m = re.match(r"^UD_([A-Z]+)=(.*)$", ln)
        if m:
            kv[m.group(1)] = m.group(2).strip()
    return {"name": kv.get("NAME") or None, "id": kv.get("ID") or None, "version": kv.get("VERSION") or None,
            "codename": kv.get("CODENAME") or None, "debian": kv.get("DEBIAN") or None, "apt": kv.get("APT") == "1"}


def parse_pending(lines):
    """Parse `apt-get -s upgrade` "Inst ..." lines.

    Returns {"total", "security", "packages": [{pkg, from, to, security}], "point": (from, to) | None}.
    Packages are listed security first, then by name, capped at MAX_PACKAGES (the counts stay exact)."""
    pkgs = []
    for ln in lines:
        m = INST.match(ln.strip())
        if not m:
            continue
        name, old, new, origin = m.groups()
        pkgs.append({"pkg": name, "from": old or "", "to": new, "security": bool(re.search(r"security", origin, re.I))})
    point = None
    for p in pkgs:
        if p["pkg"] == "base-files":
            a, b = DEB_POINT.search(p["from"]), DEB_POINT.search(p["to"])
            if a and b and a.group(1) == b.group(1):
                point = (f"{a.group(1)}.{a.group(2)}", f"{b.group(1)}.{b.group(2)}")
    pkgs.sort(key=lambda p: (not p["security"], p["pkg"]))
    return {"total": len(pkgs), "security": sum(p["security"] for p in pkgs), "packages": pkgs[:MAX_PACKAGES],
            "point": point}
