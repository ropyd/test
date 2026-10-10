"""Latest-version lookups."""
import json
import re
import threading
import time
import urllib.request

from .util import safe_link

REPO_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
_cache = {}
_lock = threading.Lock()


def github_latest(repo, token=""):  # nosec B107 - an empty token means "unauthenticated", not a password
    """Latest release as {"tag", "url", "body"} (cached 30 minutes)."""
    if not REPO_RE.match(repo or "") or ".." in repo:
        raise ValueError(f"not a valid GitHub repository name: {repo!r}")
    with _lock:
        c = _cache.get(repo)
        if c and time.time() - c[0] < 1800:
            return c[1]
    headers = {"User-Agent": "updatedash", "Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(f"https://api.github.com/repos/{repo}/releases/latest", headers=headers)
    with urllib.request.urlopen(req, timeout=15) as r:  # nosec B310 - fixed https://api.github.com prefix, validated repo
        rel = json.load(r)
    info = {"tag": rel["tag_name"], "url": safe_link(rel.get("html_url")),
            "body": (rel.get("body") or "").replace("\r", "").strip()[:1500]}
    with _lock:
        _cache[repo] = (time.time(), info)
    return info
