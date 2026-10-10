#!/usr/bin/env python3
"""updatedash: a small web dashboard that shows which self-hosted LXC services have
updates available and can run the update on request.

It talks to the Proxmox host over SSH (restricted key, see pve-gate.py) and runs
`pct exec` inside each container. Only dependency besides the stdlib is PyYAML.

Every container the gate allows is discovered automatically and listed. Known apps get a
preset (see CATALOG); anything in `services:` in the config overrides the preset for that CT.
"""
import base64
import copy
import hmac
import json
import mimetypes
import os
import re
import shlex
import signal
import subprocess
import sys
import threading
import time
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import yaml

BASE = Path(__file__).resolve().parent
STATIC = BASE / "static"
CONFIG_PATH = os.environ.get("UPDATEDASH_CONFIG", "/etc/updatedash/config.yaml")
STATE_DIR = Path(os.environ.get("UPDATEDASH_STATE", "/var/lib/updatedash"))
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07|\r")
SNAP_RE = re.compile(r"pre-update-\d{8}-\d{6}")

# Community-scripts containers ship an `update` command. PHS_SILENT=1 is its supported unattended mode: it
# skips the whiptail menu and runs the silent update (it does the same when there is no terminal).
COMMUNITY_UPDATE = "export PHS_SILENT=1 TERM=dumb; update"
APT_ENV = "export DEBIAN_FRONTEND=noninteractive;"
OS_UPGRADE = APT_ENV + " apt-get update -qq && apt-get -y -o Dpkg::Options::=--force-confold upgrade"


def _gh(repo, slug):
    # community-scripts store the installed release tag in ~/.<app>, older ones in /opt/*_version.txt
    return {"latest": {"type": "github", "repo": repo},
            "current": f"cat /root/.{slug} 2>/dev/null || cat /opt/*_version.txt 2>/dev/null"}


def _apt(pkg, link=None):
    d = {"latest": {"type": "apt", "package": pkg}}
    if link:
        d["link"] = link
    return d


# Presets matched against the container's hostname (first match wins). Verify the `current`
# file for your apps; a wrong guess only shows "Unknown" for the installed version.
CATALOG = [
    (r"jellyfin", _apt("jellyfin", "https://github.com/jellyfin/jellyfin/releases")),
    (r"plex", _apt("plexmediaserver", "https://forums.plex.tv/t/plex-media-server/30447")),
    (r"tailscale", _apt("tailscale", "https://tailscale.com/changelog")),
    (r"cloudflared", _apt("cloudflared", "https://github.com/cloudflare/cloudflared/releases")),
    (r"sonarr", _gh("Sonarr/Sonarr", "sonarr")),
    (r"radarr", _gh("Radarr/Radarr", "radarr")),
    (r"prowlarr", _gh("Prowlarr/Prowlarr", "prowlarr")),
    (r"lidarr", _gh("Lidarr/Lidarr", "lidarr")),
    (r"jackett", _gh("Jackett/Jackett", "jackett")),
    (r"autobrr", _gh("autobrr/autobrr", "autobrr")),
    (r"flaresolverr", _gh("FlareSolverr/FlareSolverr", "flaresolverr")),
    (r"vaultwarden", _gh("dani-garcia/vaultwarden", "vaultwarden")),
    (r"homarr", _gh("homarr-labs/homarr", "homarr")),
    (r"heimdall", _gh("linuxserver/Heimdall", "heimdall")),
    (r"traefik", _gh("traefik/traefik", "traefik")),
    (r"nginx.?proxy", _gh("NginxProxyManager/nginx-proxy-manager", "nginxproxymanager")),
]


def auto_service(ctid, name):
    svc = {"name": name, "ctid": ctid, "auto": True}
    for pat, extra in CATALOG:
        if re.search(pat, name.lower()):
            svc.update(copy.deepcopy(extra))
            break
    return svc


def load_config():
    with open(CONFIG_PATH) as f:
        cfg = yaml.safe_load(f) or {}
    cfg.setdefault("listen", "127.0.0.1:8099")
    cfg.setdefault("username", "admin")
    cfg.setdefault("transport", "pve")
    cfg.setdefault("snapshot_before_update", True)
    cfg.setdefault("keep_snapshots", 2)
    cfg.setdefault("check_interval_minutes", 360)
    cfg.setdefault("github_token", "")
    cfg["services"] = cfg.get("services") or []
    cfg.setdefault("discover", cfg["transport"] == "pve")
    cfg["password"] = os.environ.get("UPDATEDASH_PASSWORD", cfg.get("password") or "")
    if not cfg["password"] or cfg["password"] == "CHANGE-ME":
        sys.exit("Set a real `password` in the config (or UPDATEDASH_PASSWORD).")
    if cfg["transport"] not in ("pve", "local"):
        sys.exit("transport must be 'pve' or 'local'")
    seen = set()
    for s in cfg["services"]:
        if not s.get("name") or s.get("ctid") is None:
            sys.exit("every entry in `services` needs a name and a ctid")
        s["ctid"] = int(s["ctid"])
        if s["ctid"] in seen:
            sys.exit(f"duplicate ctid {s['ctid']} in services")
        seen.add(s["ctid"])
    return cfg


# ---------------------------------------------------------------- command running

def kill_tree(p):
    """Kill a child and everything it started (they share a process group)."""
    try:
        os.killpg(p.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        p.kill()


def run_argv(argv, timeout, on_line=None, holder=None):
    """Run argv, stream cleaned output lines, return (rc, [lines]). holder['p'] gets the Popen (for cancel)."""
    try:
        p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True, errors="replace",
                             start_new_session=True)
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
            lines.append(line)
            if on_line:
                on_line(line)
        rc = p.wait()
    finally:
        timer.cancel()
    if fired.is_set():
        msg = f"timed out after {timeout}s"
        lines.append(msg)
        if on_line:
            on_line(msg)
        rc = 124
    return rc, lines


class Runner:
    def __init__(self, cfg):
        self.local = cfg["transport"] == "local"
        pve = cfg.get("pve") or {}
        self.host = pve.get("host")
        self.user = pve.get("user", "root")
        self.key = pve.get("key", "/etc/updatedash/id_ed25519")
        self.known_hosts = str(STATE_DIR / "known_hosts")
        if not self.local and not self.host:
            sys.exit("pve.host is required when transport is 'pve'")

    def _ssh(self, remote):
        return ["ssh", "-i", self.key, "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
                "-o", f"UserKnownHostsFile={self.known_hosts}",
                "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=8",
                "-o", "ServerAliveInterval=15", f"{self.user}@{self.host}", remote]

    def exec(self, ctid, cmd, timeout=60, on_line=None, holder=None):
        if self.local:
            return run_argv(["bash", "-c", cmd], timeout, on_line, holder)
        remote = shlex.join(["pct", "exec", str(ctid), "--", "bash", "-c", cmd])
        return run_argv(self._ssh(remote), timeout, on_line, holder)

    # -- local transport test hooks: UPDATEDASH_FAKE_LIST is a `pct list` dump; the allow list is a JSON file
    def _local_allow(self):
        try:
            return set(json.loads((STATE_DIR / "local_allow.json").read_text()))
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
            (STATE_DIR / "local_allow.json").write_text(json.dumps(sorted(cur)))
            return 0, [f"ok {args[1]} {args[2]}"]
        return 1, ["unsupported"]

    def pct(self, *args, timeout=120, on_line=None):
        if self.local:
            fake = os.environ.get("UPDATEDASH_FAKE_LIST")
            if args[:1] == ("list",) and fake:
                lines = Path(fake).read_text().splitlines()
                allow = self._local_allow()
                if "--all" in args or allow is None:
                    return 0, lines
                return 0, [l for i, l in enumerate(lines) if i == 0 or (l.split() or [""])[0] in {str(a) for a in allow}]
            return 0, ["(local transport: skipped pct " + " ".join(args) + ")"]
        return run_argv(self._ssh(shlex.join(["pct", *args])), timeout, on_line)

    def gate(self, *args, timeout=30):
        """Non-pct gate requests: `allow list|add|remove`."""
        if self.local:
            return self._local_gate(args)
        return run_argv(self._ssh(shlex.join(args)), timeout)


# ---------------------------------------------------------------- version logic

_gh_cache = {}


def safe_link(u):
    return u if isinstance(u, str) and u.startswith("https://") and len(u) < 500 else None


def github_latest(repo, token):
    """Latest release as {"tag", "url", "body"} (cached 30 min)."""
    c = _gh_cache.get(repo)
    if c and time.time() - c[0] < 1800:
        return c[1]
    headers = {"User-Agent": "updatedash", "Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(f"https://api.github.com/repos/{repo}/releases/latest", headers=headers)
    with urllib.request.urlopen(req, timeout=15) as r:
        rel = json.load(r)
    info = {"tag": rel["tag_name"], "url": safe_link(rel.get("html_url")),
            "body": (rel.get("body") or "").replace("\r", "").strip()[:1500]}
    _gh_cache[repo] = (time.time(), info)
    return info


def norm(v):
    return (v or "").strip().lstrip("vV")


def same(a, b):
    a, b = norm(a), norm(b)
    if not a or not b:
        return False
    return a == b or any(a.startswith(b + s) or b.startswith(a + s) for s in ".-+")


def first_line(lines):
    for ln in lines:
        if ln.strip():
            return ln.strip()
    return None


def transport_error(rc, lines):
    text = " ".join(lines[-3:]).strip()
    if rc in (255, 126, 127, 124) or "Permission denied" in text or "updatedash-gate" in text:
        return text or f"exit code {rc}"
    return None


def app_check_type(svc):
    lat = svc.get("latest") or {}
    return lat.get("type") or ("github" if lat.get("repo") else None)


def can_app_update(svc):
    return bool(svc.get("update") or app_check_type(svc))


# ---------------------------------------------------------------- core

def new_state():
    return {"status": "unknown", "installed": None, "latest": None, "os_updates": None, "error": None,
            "checked_at": None, "checking": False, "job": None, "ct_status": None,
            "link": None, "notes": None, "installed_hint": None}


class Dash:
    def __init__(self, cfg):
        self.cfg = cfg
        self.runner = Runner(cfg)
        self.explicit = {s["ctid"]: s for s in cfg["services"]}
        self.services = dict(self.explicit)      # ctid -> service definition
        self.order = sorted(self.services)
        self.state = {c: new_state() for c in self.order}
        self.inventory_error = None
        self.jobs = {}
        self.lock = threading.Lock()
        self.pool = ThreadPoolExecutor(max_workers=4)
        self.last_sweep = 0

    # -- discovery
    def sync_inventory(self):
        if not self.cfg["discover"]:
            return
        rc, out = self.runner.pct("list", timeout=30)
        inv = {}
        if rc == 0:
            for ln in out:
                t = ln.split()
                if len(t) >= 3 and t[0].isdigit():
                    inv[int(t[0])] = (t[1], t[-1])
        if rc != 0:
            self.inventory_error = "Could not list containers: " + " ".join(out[-2:])[:200]
            return
        with self.lock:
            self.inventory_error = None
            services = {}
            for cid, (_status, name) in inv.items():
                svc = copy.deepcopy(self.explicit.get(cid) or auto_service(cid, name))
                services[cid] = svc
            for cid, svc in self.explicit.items():
                services.setdefault(cid, svc)
            self.services = services
            self.order = sorted(services)
            for cid in services:
                st = self.state.setdefault(cid, new_state())
                st["ct_status"] = inv[cid][0] if cid in inv else None
            for cid in list(self.state):
                if cid not in services:
                    del self.state[cid]

    def inventory(self):
        """Every container on the node with a `managed` flag (needs GUI management on the host)."""
        rc, out = self.runner.pct("list", "--all", timeout=30)
        if rc != 0:
            msg = " ".join(out[-2:])
            return {"manage": False, "message": msg[:300] or "the gate refused the request", "containers": []}
        rc2, allowed = self.runner.gate("allow", "list")
        managed = {int(x) for x in allowed if x.strip().isdigit()} if rc2 == 0 else set()
        rc3, prot = self.runner.gate("allow", "protected")
        locked = {int(x) for x in prot if x.strip().isdigit()} if rc3 == 0 else set()
        rows = []
        for ln in out:
            t = ln.split()
            if len(t) >= 3 and t[0].isdigit():
                rows.append({"ctid": int(t[0]), "status": t[1], "name": t[-1], "managed": int(t[0]) in managed,
                             "locked": int(t[0]) in locked})
        return {"manage": True, "containers": sorted(rows, key=lambda r: r["ctid"])}

    def set_allowed(self, ctid, add):
        rc, out = self.runner.gate("allow", "add" if add else "remove", str(ctid))
        if rc != 0:
            return False, (" ".join(out[-2:]) or "the gate refused the request")[:300]
        self.sync_inventory()
        if add and ctid in self.services:
            self.check_async(ctid)
        return True, "ok"

    # -- checking
    def check(self, ctid):
        svc = self.services.get(ctid)
        if not svc:
            return
        with self.lock:
            st = self.state[ctid]
            if st["checking"]:
                return
            st["checking"] = True
            stopped = st["ct_status"] == "stopped"
        res = {"installed": None, "latest": None, "os_updates": None, "error": None,
               "link": safe_link(svc.get("link")), "notes": None, "installed_hint": None}
        if stopped:
            status = "stopped"
        else:
            try:
                self._check_into(svc, res)
            except Exception as e:  # noqa: BLE001 - surface any failure in the UI
                res["error"] = f"{type(e).__name__}: {e}"
            if res["error"]:
                status = "error"
            elif app_check_type(svc):
                if res["installed"] and res["latest"]:
                    status = "current" if same(res["installed"], res["latest"]) else "update"
                else:
                    status = "unknown"
            else:
                status = "os" if (res["os_updates"] or 0) > 0 else "nocheck"
        with self.lock:
            if ctid in self.state:
                self.state[ctid].update(res, status=status, checking=False, checked_at=time.time())

    def _check_into(self, svc, res):
        ctid, run = svc["ctid"], self.runner.exec
        typ = app_check_type(svc)
        lat = svc.get("latest") or {}
        prefix = "apt-get update -qq >/dev/null 2>&1; "
        if typ == "apt":
            pkg = shlex.quote(lat["package"])
            rc, out = run(ctid, f"apt-get update -qq >/dev/null 2>&1; apt-cache policy {pkg}", 120)
            err = transport_error(rc, out)
            if err:
                res["error"] = err
                return
            text = "\n".join(out)
            m_i = re.search(r"Installed:\s*(\S+)", text)
            m_c = re.search(r"Candidate:\s*(\S+)", text)
            inst = m_i.group(1) if m_i else None
            res["installed"] = None if inst in (None, "(none)") else inst
            res["latest"] = m_c.group(1) if m_c and m_c.group(1) != "(none)" else None
            if res["installed"] is None:
                res["installed_hint"] = f"apt package {lat['package']} is not installed"
            prefix = ""
        else:
            if svc.get("current"):
                rc, out = run(ctid, svc["current"], 30)
                err = transport_error(rc, out)
                if err:
                    res["error"] = err
                    return
                res["installed"] = first_line(out) if rc == 0 else None
                if res["installed"] is None:
                    res["installed_hint"] = "no version found by: " + svc["current"][:100]
            elif typ in ("github", "command"):
                res["installed_hint"] = "no `current` command configured for this app"
            if typ == "github":
                info = github_latest(lat["repo"], self.cfg["github_token"])
                res["latest"] = info["tag"]
                res["link"] = res["link"] or info["url"]
                res["notes"] = info["body"] or None
            elif typ == "command":
                rc, out = run(ctid, lat["cmd"], 30)
                res["latest"] = first_line(out) if rc == 0 else None
        if svc.get("os_updates", True):
            rc, out = run(ctid, prefix + "apt-get -s upgrade 2>/dev/null | grep -c '^Inst' || true", 90)
            err = transport_error(rc, out)
            if err:
                res["error"] = err
                return
            n = first_line(out)
            res["os_updates"] = int(n) if n and n.isdigit() else None

    def check_all(self):
        self.last_sweep = time.time()
        self.sync_inventory()
        list(self.pool.map(self.check, list(self.order)))

    def check_async(self, ctid=None):
        if ctid is not None:
            self.pool.submit(self.check, ctid)
        else:
            threading.Thread(target=self.check_all, daemon=True).start()

    # -- updating
    def start_update(self, ctid, kind):
        svc = self.services[ctid]
        if kind == "app" and not can_app_update(svc):
            raise ValueError("no application update is defined for this container (OS upgrade only)")
        with self.lock:
            if self.state[ctid]["ct_status"] == "stopped":
                raise ValueError("the container is stopped")
            cur = self.state[ctid]["job"]
            if cur and self.jobs[cur]["status"] == "running":
                raise ValueError("an update is already running for this container")
            jid = uuid.uuid4().hex[:12]
            self.jobs[jid] = {"id": jid, "service": svc["name"], "kind": kind, "status": "running",
                              "lines": [], "started": time.time(), "ended": None,
                              "holder": {}, "cancelled": False}
            self.state[ctid]["job"] = jid
            for old in sorted(self.jobs.values(), key=lambda j: j["started"])[:-40]:
                if old["status"] != "running":
                    self.jobs.pop(old["id"], None)
        threading.Thread(target=self._run_update, args=(self.jobs[jid], svc, kind), daemon=True).start()
        return jid

    def cancel(self, ctid):
        with self.lock:
            jid = self.state[ctid]["job"]
            job = self.jobs.get(jid) if jid else None
            if not job or job["status"] != "running":
                raise ValueError("nothing is running for this container")
            job["cancelled"] = True
            p = job["holder"].get("p")
        if p:
            kill_tree(p)

    def _update_command(self, svc, kind):
        if kind == "os":
            return OS_UPGRADE
        if svc.get("update"):
            return svc["update"]
        if app_check_type(svc) == "apt":
            pkg = (svc.get("latest") or {})["package"]
            return f"{APT_ENV} apt-get update -qq && apt-get install -y --only-upgrade {shlex.quote(pkg)}"
        return COMMUNITY_UPDATE

    def _run_update(self, job, svc, kind):
        log = job["lines"].append
        ctid, ok = svc["ctid"], False
        try:
            if self.cfg["snapshot_before_update"] and not self.runner.local:
                snap = time.strftime("pre-update-%Y%m%d-%H%M%S")
                log(f"Creating snapshot {snap} of CT {ctid} ({svc['name']}) ...")
                rc, _ = self.runner.pct("snapshot", str(ctid), snap, timeout=300, on_line=log)
                if rc != 0:
                    log("Snapshot failed, so the update was NOT run. "
                        "(Set snapshot_before_update: false to skip snapshots.)")
                    return
                log("Snapshot created.")
            cmd = self._update_command(svc, kind)
            log(f"$ {cmd}")
            rc, _ = self.runner.exec(ctid, cmd, int(svc.get("update_timeout", 1800)), log, job["holder"])
            if job["cancelled"]:
                log("Cancelled. The SSH session was closed, but a command already started inside the container "
                    "may still be running (check with `pct exec " + str(ctid) + " -- ps aux`).")
                return
            log(f"Finished with exit code {rc}")
            ok = rc == 0
            if ok:
                self._prune(ctid, log)
        except Exception as e:  # noqa: BLE001
            log(f"Error: {type(e).__name__}: {e}")
        finally:
            job["status"] = "ok" if ok else "failed"
            job["ended"] = time.time()
            self.check(ctid)

    def _prune(self, ctid, log):
        keep = int(self.cfg["keep_snapshots"])
        if self.runner.local or not self.cfg["snapshot_before_update"]:
            return
        rc, out = self.runner.pct("listsnapshot", str(ctid), timeout=60)
        if rc != 0:
            return
        names = sorted(set(SNAP_RE.findall("\n".join(out))))
        for old in names[:-keep] if keep > 0 else names:
            rc, _ = self.runner.pct("delsnapshot", str(ctid), old, timeout=300)
            log(f"Removed old snapshot {old}" if rc == 0 else f"Could not remove snapshot {old}")

    # -- views
    def view(self):
        with self.lock:
            items = []
            for cid in self.order:
                s, st = self.services[cid], self.state[cid]
                job = self.jobs.get(st["job"]) if st["job"] else None
                items.append({"name": s["name"], "ctid": cid, "can_app_update": can_app_update(s),
                              **{k: st[k] for k in ("status", "installed", "latest", "os_updates", "error",
                                                    "checked_at", "checking", "ct_status", "link",
                                                    "installed_hint")},
                              "notes": st["notes"] if st["status"] == "update" else None,
                              "job": st["job"], "running": bool(job and job["status"] == "running"),
                              "job_status": job["status"] if job else None})
            return {"services": items,
                    "total": len(items),
                    "updates": sum(i["status"] == "update" for i in items),
                    "os_pending": sum((i["os_updates"] or 0) > 0 for i in items),
                    "errors": sum(i["status"] == "error" for i in items),
                    "stopped": sum(i["status"] == "stopped" for i in items),
                    "inventory_error": self.inventory_error,
                    "last_sweep": self.last_sweep or None,
                    "interval": self.cfg["check_interval_minutes"]}

    def job_view(self, jid, since):
        j = self.jobs.get(jid)
        if not j:
            return None
        return {"id": jid, "service": j["service"], "kind": j["kind"], "status": j["status"],
                "lines": j["lines"][since:], "next": len(j["lines"])}


# ---------------------------------------------------------------- http

def make_handler(dash):
    cfg = dash.cfg
    user_b, pw_b = cfg["username"].encode(), cfg["password"].encode()

    class H(BaseHTTPRequestHandler):
        server_version = "updatedash"

        def log_message(self, fmt, *args):
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

        def _send(self, code, body, ctype="application/json", extra=None):
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'none'")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def _authed(self):
            h = self.headers.get("Authorization", "")
            ok = False
            if h.startswith("Basic "):
                try:
                    u, _, p = base64.b64decode(h[6:]).decode().partition(":")
                    ok = hmac.compare_digest(u.encode(), user_b) & hmac.compare_digest(p.encode(), pw_b)
                except Exception:  # noqa: BLE001
                    ok = False
            if not ok:
                time.sleep(1)
                self._send(401, {"error": "authentication required"},
                           extra={"WWW-Authenticate": 'Basic realm="updatedash"'})
            return ok

        def do_GET(self):
            url = urlparse(self.path)
            if url.path == "/healthz":
                return self._send(200, b"ok", "text/plain")
            if not self._authed():
                return
            if url.path == "/api/services":
                return self._send(200, dash.view())
            if url.path == "/api/inventory":
                return self._send(200, dash.inventory())
            m = re.fullmatch(r"/api/jobs/([0-9a-f]{12})", url.path)
            if m:
                since = int(parse_qs(url.query).get("since", ["0"])[0] or 0)
                v = dash.job_view(m.group(1), since)
                return self._send(200, v) if v else self._send(404, {"error": "unknown job"})
            path = "index.html" if url.path == "/" else url.path.removeprefix("/static/")
            if path in ("index.html", "app.js", "style.css") and (url.path == "/" or url.path.startswith("/static/")):
                f = STATIC / path
                ctype = mimetypes.guess_type(path)[0] or "application/octet-stream"
                return self._send(200, f.read_bytes(), ctype + "; charset=utf-8")
            self._send(404, {"error": "not found"})

        def do_POST(self):
            if not self._authed():
                return
            # Custom header blocks cross-site form posts (browsers re-send Basic auth automatically).
            if self.headers.get("X-Requested-With") != "updatedash":
                return self._send(403, {"error": "missing X-Requested-With header"})
            try:
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(min(n, 10000)) or b"{}")
            except (ValueError, json.JSONDecodeError):
                return self._send(400, {"error": "invalid JSON"})
            ctid = body.get("ctid")
            if self.path == "/api/allow":
                action = body.get("action")
                if not isinstance(ctid, int) or isinstance(ctid, bool) or not 0 < ctid < 10**9 \
                        or action not in ("add", "remove"):
                    return self._send(400, {"error": "bad container or action"})
                ok, msg = dash.set_allowed(ctid, action == "add")
                return self._send(200 if ok else 409, {"ok": ok, "message": msg})
            if ctid is not None and (isinstance(ctid, bool) or not isinstance(ctid, int) or ctid not in dash.services):
                return self._send(404, {"error": "unknown container"})
            if self.path == "/api/check":
                dash.check_async(ctid)
                return self._send(202, {"ok": True})
            if self.path == "/api/cancel":
                if ctid is None:
                    return self._send(400, {"error": "bad container"})
                try:
                    dash.cancel(ctid)
                    return self._send(202, {"ok": True})
                except ValueError as e:
                    return self._send(409, {"error": str(e)})
            if self.path == "/api/update":
                kind = body.get("kind", "app")
                if ctid is None or kind not in ("app", "os"):
                    return self._send(400, {"error": "bad container or kind"})
                try:
                    return self._send(202, {"job": dash.start_update(ctid, kind)})
                except ValueError as e:
                    return self._send(409, {"error": str(e)})
            self._send(404, {"error": "not found"})

    return H


def main():
    cfg = load_config()
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    dash = Dash(cfg)
    host, _, port = cfg["listen"].rpartition(":")
    srv = ThreadingHTTPServer((host or "127.0.0.1", int(port)), make_handler(dash))
    srv.daemon_threads = True

    def scheduler():
        dash.check_all()
        while True:
            time.sleep(60)
            if time.time() - dash.last_sweep >= cfg["check_interval_minutes"] * 60:
                dash.check_all()

    threading.Thread(target=scheduler, daemon=True).start()
    print(f"updatedash listening on {cfg['listen']} (transport={cfg['transport']}, "
          f"discover={cfg['discover']}, {len(dash.explicit)} configured overrides)", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
