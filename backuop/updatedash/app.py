#!/usr/bin/env python3
"""updatedash: a small web dashboard that shows which self-hosted LXC services have
updates available and can run the update on request.

It talks to the Proxmox host over SSH (restricted key, see pve-gate.py) and runs
`pct exec` inside each container. Only dependency besides the stdlib is PyYAML.
"""
import base64
import hmac
import json
import mimetypes
import os
import re
import shlex
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

# Community-scripts containers ship an interactive `update` command (a whiptail menu).
# Run it inside a pty and press Enter on the default choice ("YES (Silent Mode)").
COMMUNITY_UPDATE = r"export TERM=xterm; (sleep 5; printf '\n') | script -qec update /dev/null"
APT_ENV = "export DEBIAN_FRONTEND=noninteractive;"
OS_UPGRADE = APT_ENV + " apt-get update -qq && apt-get -y -o Dpkg::Options::=--force-confold upgrade"


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
    cfg.setdefault("services", [])
    cfg["password"] = os.environ.get("UPDATEDASH_PASSWORD", cfg.get("password") or "")
    if not cfg["password"] or cfg["password"] == "CHANGE-ME":
        sys.exit("Set a real `password` in the config (or UPDATEDASH_PASSWORD).")
    if cfg["transport"] not in ("pve", "local"):
        sys.exit("transport must be 'pve' or 'local'")
    names = set()
    for s in cfg["services"]:
        if not s.get("name") or s["name"] in names:
            sys.exit("every service needs a unique name")
        names.add(s["name"])
        s["ctid"] = int(s["ctid"])
    return cfg


# ---------------------------------------------------------------- command running

def run_argv(argv, timeout, on_line=None):
    """Run argv, stream cleaned output lines, return (rc, [lines])."""
    try:
        p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True, errors="replace")
    except OSError as e:
        return 127, [str(e)]
    fired = threading.Event()

    def kill():
        fired.set()
        p.kill()

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

    def exec(self, ctid, cmd, timeout=60, on_line=None):
        if self.local:
            return run_argv(["bash", "-c", cmd], timeout, on_line)
        remote = shlex.join(["pct", "exec", str(ctid), "--", "bash", "-c", cmd])
        return run_argv(self._ssh(remote), timeout, on_line)

    def pct(self, *args, timeout=120, on_line=None):
        if self.local:
            return 0, ["(local transport: skipped pct " + " ".join(args) + ")"]
        return run_argv(self._ssh(shlex.join(["pct", *args])), timeout, on_line)


# ---------------------------------------------------------------- version logic

_gh_cache = {}


def github_latest(repo, token):
    c = _gh_cache.get(repo)
    if c and time.time() - c[0] < 1800:
        return c[1]
    headers = {"User-Agent": "updatedash", "Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(f"https://api.github.com/repos/{repo}/releases/latest", headers=headers)
    with urllib.request.urlopen(req, timeout=15) as r:
        tag = json.load(r)["tag_name"]
    _gh_cache[repo] = (time.time(), tag)
    return tag


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


# ---------------------------------------------------------------- core

class Dash:
    def __init__(self, cfg):
        self.cfg = cfg
        self.runner = Runner(cfg)
        self.services = {s["name"]: s for s in cfg["services"]}
        self.order = [s["name"] for s in cfg["services"]]
        self.state = {n: {"status": "unknown", "installed": None, "latest": None, "os_updates": None,
                          "error": None, "checked_at": None, "checking": False, "job": None}
                      for n in self.order}
        self.jobs = {}
        self.lock = threading.Lock()
        self.pool = ThreadPoolExecutor(max_workers=4)
        self.last_sweep = 0

    # -- checking
    def check(self, name):
        svc = self.services[name]
        with self.lock:
            if self.state[name]["checking"]:
                return
            self.state[name]["checking"] = True
        res = {"installed": None, "latest": None, "os_updates": None, "error": None}
        try:
            self._check_into(svc, res)
        except Exception as e:  # noqa: BLE001 - surface any failure in the UI
            res["error"] = f"{type(e).__name__}: {e}"
        if res["error"]:
            status = "error"
        elif res["installed"] and res["latest"]:
            status = "current" if same(res["installed"], res["latest"]) else "update"
        else:
            status = "unknown"
        with self.lock:
            self.state[name].update(res, status=status, checking=False, checked_at=time.time())

    def _check_into(self, svc, res):
        ctid, run = svc["ctid"], self.runner.exec
        lat = svc.get("latest") or {}
        typ = lat.get("type", "github")
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
            prefix = ""
        else:
            if svc.get("current"):
                rc, out = run(ctid, svc["current"], 30)
                err = transport_error(rc, out)
                if err:
                    res["error"] = err
                    return
                res["installed"] = first_line(out) if rc == 0 else None
            if typ == "github":
                res["latest"] = github_latest(lat["repo"], self.cfg["github_token"])
            elif typ == "command":
                rc, out = run(ctid, lat["cmd"], 30)
                res["latest"] = first_line(out) if rc == 0 else None
            prefix = "apt-get update -qq >/dev/null 2>&1; "
        if svc.get("os_updates", True):
            rc, out = run(ctid, prefix + "apt-get -s upgrade 2>/dev/null | grep -c '^Inst' || true", 90)
            n = first_line(out)
            res["os_updates"] = int(n) if n and n.isdigit() else None

    def check_all(self):
        self.last_sweep = time.time()
        list(self.pool.map(self.check, self.order))

    def check_async(self, name=None):
        if name:
            self.pool.submit(self.check, name)
        else:
            threading.Thread(target=self.check_all, daemon=True).start()

    # -- updating
    def start_update(self, name, kind):
        svc = self.services[name]
        with self.lock:
            cur = self.state[name]["job"]
            if cur and self.jobs[cur]["status"] == "running":
                raise ValueError("an update is already running for this service")
            jid = uuid.uuid4().hex[:12]
            self.jobs[jid] = {"id": jid, "service": name, "kind": kind, "status": "running",
                              "lines": [], "started": time.time(), "ended": None}
            self.state[name]["job"] = jid
            for old in sorted(self.jobs.values(), key=lambda j: j["started"])[:-40]:
                if old["status"] != "running":
                    self.jobs.pop(old["id"], None)
        threading.Thread(target=self._run_update, args=(self.jobs[jid], svc, kind), daemon=True).start()
        return jid

    def _update_command(self, svc, kind):
        if kind == "os":
            return OS_UPGRADE
        if svc.get("update"):
            return svc["update"]
        lat = svc.get("latest") or {}
        if lat.get("type") == "apt":
            return f"{APT_ENV} apt-get update -qq && apt-get install -y --only-upgrade {shlex.quote(lat['package'])}"
        return COMMUNITY_UPDATE

    def _run_update(self, job, svc, kind):
        log = job["lines"].append
        ctid, ok = svc["ctid"], False
        try:
            if self.cfg["snapshot_before_update"] and not self.runner.local:
                snap = time.strftime("pre-update-%Y%m%d-%H%M%S")
                log(f"Creating snapshot {snap} of CT {ctid} ...")
                rc, _ = self.runner.pct("snapshot", str(ctid), snap, timeout=300, on_line=log)
                if rc != 0:
                    log("Snapshot failed, so the update was NOT run. "
                        "(Set snapshot_before_update: false to skip snapshots.)")
                    return
                log("Snapshot created.")
            cmd = self._update_command(svc, kind)
            log(f"$ {cmd}")
            rc, _ = self.runner.exec(ctid, cmd, int(svc.get("update_timeout", 1800)), log)
            log(f"Finished with exit code {rc}")
            ok = rc == 0
            if ok:
                self._prune(ctid, log)
        except Exception as e:  # noqa: BLE001
            log(f"Error: {type(e).__name__}: {e}")
        finally:
            job["status"] = "ok" if ok else "failed"
            job["ended"] = time.time()
            self.check(svc["name"])

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
            for n in self.order:
                s, st = self.services[n], self.state[n]
                job = self.jobs.get(st["job"]) if st["job"] else None
                items.append({"name": n, "ctid": s["ctid"], **{k: st[k] for k in (
                    "status", "installed", "latest", "os_updates", "error", "checked_at", "checking")},
                    "job": st["job"], "running": bool(job and job["status"] == "running"),
                    "job_status": job["status"] if job else None})
            return {"services": items, "updates": sum(i["status"] == "update" for i in items),
                    "os_updates": sum((i["os_updates"] or 0) > 0 for i in items),
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
            name = body.get("name")
            if self.path == "/api/check":
                if name and name not in dash.services:
                    return self._send(404, {"error": "unknown service"})
                dash.check_async(name)
                return self._send(202, {"ok": True})
            if self.path == "/api/update":
                kind = body.get("kind", "app")
                if name not in dash.services or kind not in ("app", "os"):
                    return self._send(400, {"error": "bad service or kind"})
                try:
                    return self._send(202, {"job": dash.start_update(name, kind)})
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
    print(f"updatedash listening on {cfg['listen']} ({len(dash.order)} services, transport={cfg['transport']})",
          flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
