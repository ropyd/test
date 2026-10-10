"""Small shared helpers (no project imports)."""
import json
import os
import re
import shutil
import tempfile
from pathlib import Path

ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07|\r")


def atomic_write(path, data, mode=0o600):
    """Write a file atomically (temp file in the same dir + rename) with the given permissions."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data if isinstance(data, bytes) else data.encode())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def read_json(path, default):
    try:
        with open(path, "rb") as f:
            return json.loads(f.read().decode() or "null")
    except (OSError, ValueError):
        return default


def find_tool(name):
    """Absolute path of a helper binary, resolved once (so a later change to PATH can't swap it)."""
    for d in ("/usr/bin", "/bin", "/usr/local/bin", "/opt/homebrew/bin"):
        p = os.path.join(d, name)
        if os.access(p, os.X_OK):
            return p
    return shutil.which(name) or name


def safe_link(u):
    """Only https links are ever rendered as links."""
    return u if isinstance(u, str) and u.startswith("https://") and len(u) < 500 else None


def norm(v):
    return (v or "").strip().lstrip("vV")


def same(a, b):
    """Version equality that tolerates a leading v and build suffixes (1.2 vs 1.2.0-ubuntu1)."""
    a, b = norm(a), norm(b)
    if not a or not b:
        return False
    return a == b or any(a.startswith(b + s) or b.startswith(a + s) for s in ".-+")


def first_line(lines):
    for ln in lines:
        if ln.strip():
            return ln.strip()
    return None
