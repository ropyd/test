"""Browse the community-scripts library and prepare (never run) install commands.

The catalog is read from the project's GitHub repository: one `ct/<name>.sh` per app, whose first lines declare the
defaults (CPU, RAM, disk, OS). Nothing from the repository is executed or sourced here; headers are parsed with
strict patterns, and every value is validated before it can appear in a command."""
import hashlib
import json
import re
import shlex
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .store import ValidationError
from .util import atomic_write, read_json

REPO = "community-scripts/ProxmoxVE"
CORE_REPO = "community-scripts/core"
RAW = "https://raw.githubusercontent.com"
API = "https://api.github.com"
ALLOWED_HOSTS = ("https://api.github.com/", "https://raw.githubusercontent.com/")
CACHE_SECONDS = 24 * 3600
MAX_APPS_PER_PLAN = 12
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,60}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")

_ASSIGN = re.compile(r'^(var_[a-z_]+)="\$\{var_[a-z_]+:-([^}"]*)\}"\s*$')
_APP = re.compile(r'^APP="([^"\n]{1,80})"\s*$')
_APP_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._+()-]{0,59}$")
_SOURCE = re.compile(r"^#\s*Source:\s*(https://\S+)")


def default_fetch(url, limit=8 * 1024 * 1024, token="", range_bytes=None):
    """GET a GitHub URL (https only, GitHub hosts only) and return at most `limit` bytes."""
    if not url.startswith(ALLOWED_HOSTS):
        raise ValueError(f"refusing to fetch {url!r}")
    headers = {"User-Agent": "updatedash", "Accept": "application/vnd.github+json" if "api.github" in url else "*/*"}
    if token and "api.github" in url:
        headers["Authorization"] = f"Bearer {token}"
    if range_bytes:
        headers["Range"] = f"bytes=0-{range_bytes - 1}"
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=20) as r:  # nosec B310 - host allowlist above
        return r.read(limit)


def _int(v, lo, hi, default):
    try:
        n = int(v)
    except (TypeError, ValueError):
        return default
    return n if lo <= n <= hi else default


def parse_ct_header(slug, text):
    """-> entry dict from the top of a ct script (pure text parsing, nothing is sourced)."""
    kv, app, source = {}, None, None
    for ln in text.splitlines()[:80]:
        m = _ASSIGN.match(ln.strip())
        if m:
            kv[m.group(1)] = m.group(2)
            continue
        m = _APP.match(ln.strip())
        if m and app is None:
            app = m.group(1)
            continue
        m = _SOURCE.match(ln.strip())
        if m and source is None:
            source = m.group(1)[:200]
    tags = [t for t in re.split(r"[;,]", kv.get("var_tags", "")) if re.fullmatch(r"[a-z0-9_-]{1,24}", t)]
    os_ = kv.get("var_os", "debian")
    return {
        # the app name is shown in the UI and echoed by the plan, so it must be plain text
        "slug": slug, "app": app if app and _APP_OK.match(app) else slug, "tags": tags[:8],
        "cpu": _int(kv.get("var_cpu"), 1, 64, 1), "ram": _int(kv.get("var_ram"), 128, 262144, 512),
        "disk": _int(kv.get("var_disk"), 1, 8192, 4), "os": os_ if re.fullmatch(r"[a-z]{3,12}", os_) else "debian",
        "version": kv.get("var_version", "") if re.fullmatch(r"[0-9.]{1,8}", kv.get("var_version", "")) else "",
        "unprivileged": kv.get("var_unprivileged", "1") != "0", "source": source,
        "page": f"https://community-scripts.org/scripts/{slug}",
    }


class ScriptCatalog:
    def __init__(self, path, token="", fetch=None):
        self.path = Path(path)
        self.token = token
        self._fetch = fetch or default_fetch
        self.lock = threading.Lock()
        d = read_json(self.path, {}) or {}
        self.entries = d.get("entries", []) if isinstance(d, dict) else []
        self.commit, self.core_commit = d.get("commit"), d.get("core_commit")
        self.updated = d.get("updated", 0)
        self.loading, self.progress, self.error = False, (0, 0), None

    # -- status and search
    def status(self):
        return {"count": len(self.entries), "commit": self.commit, "updated": self.updated, "loading": self.loading,
                "progress": list(self.progress), "error": self.error, "stale": time.time() - self.updated > CACHE_SECONDS}

    def search(self, q="", tag="", limit=30, offset=0):
        q, tag = (q or "").strip().lower(), (tag or "").strip().lower()
        words = q.split()
        with self.lock:
            rows = list(self.entries)
        out = []
        for e in rows:
            hay = f"{e['slug']} {e['app']} {' '.join(e['tags'])}".lower()
            if tag and tag not in e["tags"]:
                continue
            if all(w in hay for w in words):
                score = (0 if e["slug"] == q or e["app"].lower() == q else 1 if e["slug"].startswith(q) else 2, e["app"].lower())
                out.append((score, e))
        out.sort(key=lambda x: x[0])
        res = [e for _, e in out]
        return {"total": len(res), "results": res[offset:offset + max(1, min(limit, 100))]}

    def tags(self, top=24):
        counts = {}
        with self.lock:
            for e in self.entries:
                for t in e["tags"]:
                    counts[t] = counts.get(t, 0) + 1
        return [t for t, _ in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:top]]

    def get(self, slug):
        with self.lock:
            return next((dict(e) for e in self.entries if e["slug"] == slug), None)

    # -- loading
    def refresh_async(self, force=False):
        with self.lock:
            if self.loading or (not force and self.entries and time.time() - self.updated < CACHE_SECONDS):
                return False
            self.loading = True
        threading.Thread(target=self.refresh, daemon=True).start()
        return True

    def _json(self, url):
        return json.loads(self._fetch(url, 8 * 1024 * 1024, self.token))

    def refresh(self):
        """Fetch the list of scripts at the current commit, then each script's header."""
        try:
            self.error = None
            commit = self._json(f"{API}/repos/{REPO}/commits/main")["sha"]
            core_commit = self._json(f"{API}/repos/{CORE_REPO}/commits/main")["sha"]
            if not (SHA_RE.match(commit) and SHA_RE.match(core_commit)):
                raise ValueError("unexpected commit id from GitHub")
            root = self._json(f"{API}/repos/{REPO}/git/trees/{commit}")
            ct_sha = next(t["sha"] for t in root["tree"] if t["path"] == "ct" and t["type"] == "tree")
            tree = self._json(f"{API}/repos/{REPO}/git/trees/{ct_sha}")
            slugs = sorted(t["path"][:-3] for t in tree["tree"] if t["type"] == "blob" and t["path"].endswith(".sh")
                           and SLUG_RE.match(t["path"][:-3]))
            if not slugs:
                raise ValueError("no scripts found in the repository listing")
            old = {e["slug"]: e for e in self.entries}
            self.progress = (0, len(slugs))
            done = [0]

            def one(slug):
                try:
                    text = self._fetch(f"{RAW}/{REPO}/{commit}/ct/{slug}.sh", 16384, "", 8192).decode("utf-8", "replace")
                    e = parse_ct_header(slug, text)
                except Exception:  # noqa: BLE001 - keep the previous entry (or a bare one) if one script can't be read
                    e = old.get(slug) or parse_ct_header(slug, "")
                done[0] += 1
                self.progress = (done[0], len(slugs))
                return e

            with ThreadPoolExecutor(max_workers=6) as pool:
                entries = list(pool.map(one, slugs))
            with self.lock:
                self.entries, self.commit, self.core_commit, self.updated = entries, commit, core_commit, int(time.time())
            atomic_write(self.path, json.dumps({"commit": commit, "core_commit": core_commit, "updated": self.updated,
                                                "entries": entries}), 0o600)
        except Exception as e:  # noqa: BLE001
            self.error = f"{type(e).__name__}: {str(e)[:160]}"
        finally:
            self.loading = False

    # -- plans
    def script_sha256(self, slug):
        data = self._fetch(f"{RAW}/{REPO}/{self.commit}/ct/{slug}.sh", 512 * 1024, "")
        return hashlib.sha256(data).hexdigest(), data.count(b"\n")


# ---------------------------------------------------------------- the plan (text only; never executed here)
_HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,40}$")
_CIDR_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})$")
_IP_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")


def _ipv4_ok(parts):
    return all(0 <= int(p) <= 255 for p in parts)


def clean_app_request(req, entry):
    """Validate one app's overrides. Returns {var_name: value}; anything not given keeps the script's own default."""
    out = {}

    def num(key, var, lo, hi):
        v = req.get(key)
        if v in (None, ""):
            return
        if isinstance(v, bool) or not str(v).isdigit() or not lo <= int(v) <= hi:
            raise ValidationError(f"{key} must be a number from {lo} to {hi}")
        out[var] = str(int(v))

    num("ctid", "var_ctid", 100, 999_999_999)
    num("cpu", "var_cpu", 1, 64)
    num("ram", "var_ram", 128, 262_144)
    num("disk", "var_disk", 1, 8192)
    host = str(req.get("hostname") or "").strip().lower()
    if host:
        if not _HOST_RE.match(host):
            raise ValidationError("hostname: lowercase letters, numbers and dashes only")
        out["var_hostname"] = host
    net = str(req.get("net") or "").strip().lower()
    if net and net != "dhcp":
        m = _CIDR_RE.match(net)
        if not (m and _ipv4_ok(m.groups()[:4]) and 1 <= int(m.group(5)) <= 32):
            raise ValidationError("net: use dhcp or an address like 10.10.56.30/24")
    if net:
        out["var_net"] = net
    gw = str(req.get("gateway") or "").strip()
    if gw:
        m = _IP_RE.match(gw)
        if not (m and _ipv4_ok(m.groups())):
            raise ValidationError("gateway must be an IPv4 address")
        if net in ("", "dhcp"):
            raise ValidationError("a gateway only makes sense with a static address")
        out["var_gateway"] = gw
    if net not in ("", "dhcp") and "var_gateway" not in out:
        raise ValidationError("a static address needs a gateway")
    for key, var in (("bridge", "var_brg"), ("storage", "var_container_storage"), ("template_storage", "var_template_storage")):
        v = str(req.get(key) or "").strip()
        if v:
            if not _NAME_RE.match(v):
                raise ValidationError(f"{key}: letters, numbers, dots, dashes and underscores only")
            out[var] = v
    return out


def build_plan(catalog, apps, node_name="", opt_out_diagnostics=True):
    """-> {"commit", "core_commit", "apps": [...], "script": "<bash text>", "warnings": [...]}. Executes nothing."""
    if not apps or not isinstance(apps, list):
        raise ValidationError("choose at least one app")
    if len(apps) > MAX_APPS_PER_PLAN:
        raise ValidationError(f"at most {MAX_APPS_PER_PLAN} apps per plan")
    if not (catalog.commit and SHA_RE.match(catalog.commit) and catalog.core_commit and SHA_RE.match(catalog.core_commit)):
        raise ValidationError("the catalog has not been loaded yet")
    node_name = re.sub(r"[^A-Za-z0-9._ -]", "", str(node_name or ""))[:40]
    base = f"{RAW}/{REPO}/{catalog.commit}"
    core = f"{RAW}/{CORE_REPO}/{catalog.core_commit}"
    seen, items, warnings, blocks = set(), [], [], []
    for i, req in enumerate(apps, 1):
        if not isinstance(req, dict):
            raise ValidationError("bad app entry")
        slug = str(req.get("slug") or "")
        entry = catalog.get(slug) if SLUG_RE.match(slug) else None
        if not entry:
            raise ValidationError(f"unknown app: {slug[:40]!r}")
        overrides = clean_app_request(req, entry)
        for key in ("var_ctid", "var_hostname"):
            if key in overrides:
                ident = (key, overrides[key])
                if ident in seen:
                    raise ValidationError(f"{key[4:]} {overrides[key]} is used twice in this plan")
                seen.add(ident)
        digest, lines = catalog.script_sha256(slug)
        env = [("PHS_SILENT", "1"), ("mode", "default"), ("COMMUNITY_SCRIPTS_URL", base), ("COMMUNITY_SCRIPTS_CORE_URL", core),
               *sorted(overrides.items())]
        assigns = " ".join(f"{k}={shlex.quote(v)}" for k, v in env)
        url = f"{base}/ct/{slug}.sh"
        cmd = f'{assigns} bash -c "$(curl -fsSL {shlex.quote(url)})"'
        items.append({"slug": slug, "app": entry["app"], "command": cmd, "sha256": digest, "lines": lines, "url": url,
                      "review": f"https://github.com/{REPO}/blob/{catalog.commit}/ct/{slug}.sh", "page": entry["page"],
                      "overrides": overrides, "defaults": {k: entry[k] for k in ("cpu", "ram", "disk", "os", "unprivileged")}})
        label = shlex.quote(f"==> [{i}/{len(apps)}] {entry['app']}")
        failed = shlex.quote(f"{entry['app']} failed; stopping.")
        blocks.append(f"printf '%s\\n' {label}\n{cmd} || {{ printf '%s\\n' {failed} >&2; exit 1; }}")
    if len({a["slug"] for a in items}) < len(items):
        warnings.append("The same app appears more than once; give each copy its own hostname and CT id.")
    header = [
        "#!/usr/bin/env bash",
        f"# updatedash install plan{f' for {node_name}' if node_name else ''}. Prepared by the dashboard, NOT run by it.",
        "# Run as root in the Proxmox shell of the node you chose. Each app below is a script from the community-scripts",
        "# project that creates a container, pinned to one reviewed commit:",
        f"#   scripts {catalog.commit}   core {catalog.core_commit}",
        "# Review each script first (links in the dashboard), or check one with:  curl -fsSL <url> | sha256sum",
        "set -u",
        '[ "$(id -u)" = 0 ] || { echo "Run as root on the Proxmox node." >&2; exit 1; }',
    ]
    if opt_out_diagnostics:
        header += ["# The scripts ask once whether to send install diagnostics (app, size, Proxmox version) to the project.",
                   "# This records 'no' unless you already made a choice on this node:",
                   "mkdir -p /usr/local/community-scripts",
                   "[ -f /usr/local/community-scripts/diagnostics ] || printf 'DIAGNOSTICS=no\\n' > /usr/local/community-scripts/diagnostics"]
    return {"commit": catalog.commit, "core_commit": catalog.core_commit, "apps": items, "warnings": warnings,
            "script": "\n".join(header + [""] + blocks) + "\n"}
