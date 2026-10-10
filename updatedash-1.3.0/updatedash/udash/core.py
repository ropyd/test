"""The engine: inventory, version checks, updates, logs."""
import copy
import importlib.util
import logging
import re
import shlex
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .catalog import auto_service
from .hostsetup import build_setup_script
from .osinfo import cmd_os_info, cmd_os_pending, parse_os_info, parse_pending
from .runner import Runner
from .store import HostRegistry, ValidationError, clean_access, is_custom_uid, make_uid, split_uid
from .util import first_line, safe_link, same
from .versions import github_latest

log = logging.getLogger("updatedash")
SNAP_RE = re.compile(r"pre-update-\d{8}-\d{6}")

# Community-scripts containers ship an `update` command. PHS_SILENT=1 is its supported unattended mode.
# TERM must not be "dumb": the scripts call `clear`, which exits 1 there and trips their error handler.
COMMUNITY_UPDATE = "export PHS_SILENT=1 TERM=xterm; update"
APT_ENV = "export DEBIAN_FRONTEND=noninteractive;"
OS_UPGRADE = APT_ENV + " apt-get update -qq && apt-get -y -o Dpkg::Options::=--force-confold upgrade"


# Every command run inside a container is built here. The Proxmox gate only accepts this exact vocabulary
# (pve-gate.py), and a test keeps the two in step; custom commands from the config need host approval.
def cmd_apt_policy(pkg):
    return f"apt-get update -qq >/dev/null 2>&1; apt-cache policy {shlex.quote(pkg)}"


def cmd_apt_install(pkg):
    return f"{APT_ENV} apt-get update -qq && apt-get install -y --only-upgrade {shlex.quote(pkg)}"


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


def new_state():
    return {"status": "unknown", "installed": None, "latest": None, "os_updates": None, "error": None,
            "os_security": None, "os_info": None, "os_point": None, "os_packages": [],
            "checked_at": None, "checking": False, "job": None, "job_meta": None, "ct_status": None,
            "link": None, "notes": None, "installed_hint": None}


class Dash:
    def __init__(self, cfg, state_dir, vault, access, logs, settings, audit, base_dir, hosts=None):
        self.cfg = cfg
        self.base_dir = Path(base_dir)
        self.access, self.logs, self.settings, self.audit = access, logs, settings, audit
        self.hosts = hosts or HostRegistry(None, cfg.get("pve"))
        self.runner = Runner(cfg, state_dir, access, base_dir, self.hosts)
        self.explicit = self._explicit_services(cfg["services"])
        self.services = dict(self.explicit)
        self.order = sorted(self.services)
        self.state = {c: new_state() for c in self.order}
        self.inv = {}                      # uid -> (status, name) from the gates of all nodes
        self.inv_by_host = {}              # host index -> {uid: (status, name)} (kept when a node can't be reached)
        self.host_errors = {}              # host index -> message
        self.gate_managed = set()
        self.inventory_error = None
        self.jobs = {}
        self.lock = threading.RLock()
        self.pool = ThreadPoolExecutor(max_workers=4)
        self.slots = threading.BoundedSemaphore(cfg["max_parallel_updates"])
        self.last_sweep = 0
        self.on_sweep = None                # set by Automation: called after every full sweep
        self.auto_uids = lambda: set()
        self.stopping = False
        self.logs.mark_interrupted()
        self._rebuild()
        for cid, meta in self.logs.latest_per_ctid().items():
            if cid in self.state:
                self.state[cid]["job"], self.state[cid]["job_meta"] = meta["id"], meta

    def _explicit_services(self, services):
        """Config overrides keyed by uid. `host: <name>` selects a node other than the primary one."""
        out = {}
        for s in services:
            hidx = 0
            if s.get("host"):
                h = self.hosts.by_name(s["host"])
                if not h:
                    log.warning("service %r names an unknown host %r; ignored", s.get("name"), s["host"])
                    continue
                hidx = h["idx"]
            d = dict(s)
            d["ctid"] = make_uid(hidx, s["ctid"])
            out[d["ctid"]] = d
        return out

    # -- assembling the list of things we manage
    def _rebuild(self):
        with self.lock:
            services = {}
            for cid, (_st, name) in self.inv.items():
                services[cid] = copy.deepcopy(self.explicit.get(cid) or auto_service(cid, name))
            for cid, svc in self.explicit.items():
                services.setdefault(cid, copy.deepcopy(svc))
            for cid, entry in self.access.customs():
                base = self.explicit.get(cid) or auto_service(cid, entry["name"])
                services[cid] = dict(copy.deepcopy(base), name=entry["name"], custom=True)
            self.services = services
            self.order = sorted(services)
            for cid in services:
                st = self.state.setdefault(cid, new_state())
                st["ct_status"] = self.inv[cid][0] if cid in self.inv else None
            for cid in list(self.state):
                if cid not in services:
                    del self.state[cid]

    def sync_inventory(self):
        self.explicit = self._explicit_services(self.cfg["services"])
        if self.cfg["discover"]:
            known = {h["idx"] for h in self.hosts.all()}
            for hidx in [i for i in self.inv_by_host if i not in known]:
                del self.inv_by_host[hidx]
                self.host_errors.pop(hidx, None)
            for h in self.hosts.all():
                if not self.runner.gate_ok(h["idx"]):
                    continue
                rc, out = self.runner.pct("list", host=h["idx"], timeout=30)
                if rc != 0:
                    self.host_errors[h["idx"]] = f"{h['name']}: could not list containers: " + " ".join(out[-2:])[:160]
                    continue
                self.host_errors.pop(h["idx"], None)
                inv = {}
                for ln in out:
                    t = ln.split()
                    if len(t) >= 3 and t[0].isdigit():
                        inv[make_uid(h["idx"], int(t[0]))] = (t[1], t[-1])
                self.inv_by_host[h["idx"]] = inv
            self.inv = {uid: v for d in self.inv_by_host.values() for uid, v in d.items()}
            self.gate_managed = set(self.inv)
            self.inventory_error = " | ".join(self.host_errors.values()) or None
        self._rebuild()

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
               "os_security": None, "os_info": None, "os_point": None, "os_packages": [],
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
        refresh_apt = True
        if typ == "apt":
            rc, out = run(ctid, cmd_apt_policy(lat["package"]), 120)
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
            refresh_apt = False
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
            rc, out = run(ctid, cmd_os_info(), 30)
            err = transport_error(rc, out)
            if err:
                res["error"] = err
                return
            res["os_info"] = parse_os_info(out)
            if res["os_info"]["apt"]:
                rc, out = run(ctid, cmd_os_pending(refresh_apt), 90)
                err = transport_error(rc, out)
                if err:
                    res["error"] = err
                    return
                pend = parse_pending(out)
                res.update(os_updates=pend["total"], os_security=pend["security"], os_packages=pend["packages"],
                           os_point=pend["point"])

    def check_all(self):
        self.last_sweep = time.time()
        self.sync_inventory()
        list(self.pool.map(self.check, list(self.order)))
        if self.on_sweep:
            self.on_sweep()

    def check_async(self, ctid=None):
        if ctid is not None:
            self.pool.submit(self.check, ctid)
        else:
            threading.Thread(target=self.check_all, daemon=True).start()

    # -- updating
    def snapshot_plan(self, ctid):
        """(will_snapshot, reason). Snapshots go through the Proxmox gate, so they need the CT to be gate-managed."""
        if not self.cfg["snapshot_before_update"]:
            return False, "snapshots are turned off in the config"
        if self.runner.local:
            return False, "local transport"
        if is_custom_uid(ctid):
            return False, "this host is not a Proxmox container"
        if ctid not in self.gate_managed:
            return False, "the container is not managed through the Proxmox host"
        return True, ""

    def start_update(self, ctid, kind, actor="?"):
        svc = self.services[ctid]
        if kind == "app" and not can_app_update(svc):
            raise ValueError("no application update is defined for this container (OS upgrade only)")
        with self.lock:
            if self.stopping:
                raise ValueError("the dashboard is shutting down")
            if self.state[ctid]["ct_status"] == "stopped":
                raise ValueError("the container is stopped")
            cur = self.jobs.get(self.state[ctid]["job"] or "")
            if cur and cur["status"] in ("running", "queued"):
                raise ValueError("an update is already running for this container")
            jid = uuid.uuid4().hex[:12]
            job = {"id": jid, "ctid": ctid, "service": svc["name"], "kind": kind, "status": "queued", "lines": [],
                   "started": time.time(), "ended": None, "by": actor, "holder": {}, "cancelled": False}
            self.jobs[jid] = job
            self.state[ctid]["job"] = jid
            self.state[ctid]["job_meta"] = None
            finished = sorted((j for j in self.jobs.values() if j["status"] not in ("running", "queued")),
                              key=lambda j: j["started"])
            for old in finished[:-20]:
                self.jobs.pop(old["id"], None)
        self.logs.save(job)
        self.audit.append(actor, "", f"update.{kind}", f"CT {ctid} {svc['name']} job {jid}")
        threading.Thread(target=self._run_update, args=(job, svc, kind), daemon=True).start()
        return jid

    def _update_command(self, svc, kind):
        if kind == "os":
            return OS_UPGRADE
        if svc.get("update"):
            return svc["update"]
        if app_check_type(svc) == "apt":
            return cmd_apt_install((svc.get("latest") or {})["package"])
        return COMMUNITY_UPDATE

    def _run_update(self, job, svc, kind):
        count = [0]

        def log(line):
            job["lines"].append(line)
            count[0] += 1
            if count[0] % 25 == 0:
                self.logs.save(job)

        ctid, ok, got_slot = svc["ctid"], False, False
        try:
            if not self.slots.acquire(blocking=False):
                log("Waiting for a free update slot ...")
                while not self.slots.acquire(timeout=1):
                    if job["cancelled"]:
                        log("Cancelled while waiting.")
                        return
            got_slot = True
            job["status"] = "running"
            self.logs.save(job)
            will_snap, why = self.snapshot_plan(ctid)
            if will_snap:
                snap = time.strftime("pre-update-%Y%m%d-%H%M%S")
                log(f"Creating snapshot {snap} of CT {ctid} ({svc['name']}) ...")
                hidx, real = split_uid(ctid)
                rc, _ = self.runner.pct("snapshot", str(real), snap, host=hidx, timeout=300, on_line=log)
                if rc != 0:
                    log("Snapshot failed, so the update was NOT run. (Set snapshot_before_update: false to skip snapshots.)")
                    return
                log("Snapshot created.")
            elif self.cfg["snapshot_before_update"] and not self.runner.local:
                log(f"No snapshot taken: {why}.")
            cmd = self._update_command(svc, kind)
            log(f"$ {cmd}")
            rc, _ = self.runner.exec(ctid, cmd, int(svc.get("update_timeout", 1800)), log, job["holder"])
            if job["cancelled"]:
                log("Cancelled. The SSH session was closed, but a command already started inside the container "
                    "may still be running (check with `ps aux` in it).")
                return
            log(f"Finished with exit code {rc}")
            ok = rc == 0
            if will_snap:
                self._prune_snapshots(ctid, log)
        except Exception as e:  # noqa: BLE001
            log(f"Error: {type(e).__name__}: {e}")
        finally:
            if got_slot:
                self.slots.release()
            job["status"] = "ok" if ok else "failed"
            job["ended"] = time.time()
            self.logs.save(job)
            self.logs.prune(ctid, self.settings.get("log_retention"))
            with self.lock:
                if ctid in self.state:
                    self.state[ctid]["job_meta"] = {k: job[k] for k in ("id", "status", "kind", "ended")}
            self.audit.append(job["by"], "", f"update.{kind}.{job['status']}", f"CT {ctid} {svc['name']} job {job['id']}")
            self.check(ctid)

    def _prune_snapshots(self, ctid, log):
        keep = int(self.cfg["keep_snapshots"])
        hidx, real = split_uid(ctid)
        rc, out = self.runner.pct("listsnapshot", str(real), host=hidx, timeout=60)
        if rc != 0:
            return
        names = sorted(set(SNAP_RE.findall("\n".join(out))))
        for old in (names[:-keep] if keep > 0 else names):
            rc, _ = self.runner.pct("delsnapshot", str(real), old, host=hidx, timeout=300)
            log(f"Removed old snapshot {old}" if rc == 0 else f"Could not remove snapshot {old}")

    def cancel(self, ctid, actor="?"):
        with self.lock:
            jid = self.state[ctid]["job"]
            job = self.jobs.get(jid) if jid else None
            if not job or job["status"] not in ("running", "queued"):
                raise ValueError("nothing is running for this container")
            job["cancelled"] = True
            p = job["holder"].get("p")
        if p:
            from .runner import kill_tree
            kill_tree(p)
        self.audit.append(actor, "", "update.cancel", f"CT {ctid} job {jid}")

    def running_jobs(self):
        with self.lock:
            return [j for j in self.jobs.values() if j["status"] in ("running", "queued")]

    def shutdown(self, wait=60):
        self.stopping = True
        deadline = time.time() + wait
        while self.running_jobs() and time.time() < deadline:
            time.sleep(0.5)
        for j in self.running_jobs():  # out of time: don't leave half-saved logs
            j["lines"].append("The dashboard stopped before this finished.")
            j["status"] = "interrupted"
            j["ended"] = time.time()
            self.logs.save(j)

    # -- inventory management through the gate (GUI add/remove)
    def inventory(self, host=0):
        """Every container on one node, with managed/locked flags (needs GUI management on that node)."""
        if not self.runner.gate_ok(host):
            return {"manage": False, "message": "That Proxmox host is not configured.", "containers": []}
        rc, out = self.runner.pct("list", "--all", host=host, timeout=30)
        if rc != 0:
            return {"manage": False, "message": (" ".join(out[-2:]) or "the gate refused the request")[:300],
                    "containers": []}
        rc2, allowed = self.runner.gate("allow", "list", host=host)
        managed = {int(x) for x in allowed if x.strip().isdigit()} if rc2 == 0 else set()
        rc3, prot = self.runner.gate("allow", "protected", host=host)
        locked = {int(x) for x in prot if x.strip().isdigit()} if rc3 == 0 else set()
        rows = []
        for ln in out:
            t = ln.split()
            if len(t) >= 3 and t[0].isdigit():
                c = int(t[0])
                rows.append({"ctid": c, "host": host, "status": t[1], "name": t[-1], "managed": c in managed,
                             "locked": c in locked})
        return {"manage": True, "host": host, "containers": sorted(rows, key=lambda r: r["ctid"])}

    def node_info(self, host=0):
        """Storages and bridges on a node, for suggestions in the install form. Failure just means no suggestions."""
        out = {"rootdir": [], "vztmpl": [], "bridges": []}
        if not self.runner.gate_ok(host):
            return out
        rc, lines = self.runner.gate("node", "info", host=host, timeout=40)
        if rc != 0:
            return out
        for ln in lines:
            t = ln.split()
            if len(t) == 3 and t[0] == "storage" and t[1] in ("rootdir", "vztmpl"):
                out[t[1]].append(t[2])
            elif len(t) == 2 and t[0] == "bridge":
                out["bridges"].append(t[1])
        return out

    def local_ip_for(self, host):
        """The address of this machine that the node would see (used to prefill the node setup form)."""
        import socket
        try:
            infos = socket.getaddrinfo(host, 22, type=socket.SOCK_DGRAM)
            fam, _, _, _, addr = infos[0]
            s = socket.socket(fam, socket.SOCK_DGRAM)
            s.settimeout(2)
            s.connect(addr)                                   # UDP connect sends nothing; it only selects a route
            ip = s.getsockname()[0]
            s.close()
            return ip
        except OSError:
            return ""

    def set_allowed(self, ctid, add, host=0):
        rc, out = self.runner.gate("allow", "add" if add else "remove", str(ctid), host=host)
        if rc != 0:
            return False, (" ".join(out[-2:]) or "the gate refused the request")[:300]
        self.sync_inventory()
        uid = make_uid(host, ctid)
        if add and uid in self.services:
            self.check_async(uid)
        return True, "ok"

    # -- Proxmox nodes
    def hosts_view(self):
        out = []
        for h in self.hosts.all():
            if h["primary"] and not h["host"]:
                continue                                   # SSH-only install: no primary node configured
            n = sum(1 for uid in self.inv if split_uid(uid)[0] == h["idx"])
            out.append({"idx": h["idx"], "name": h["name"], "host": h["host"], "primary": h["primary"],
                        "containers": n, "error": self.host_errors.get(h["idx"])})
        return out

    def host_hostkeys(self, body):
        host = str(body.get("host") or "").strip()
        fields = clean_access({"host": host, "port": 22, "user": "root", "auth": "password"})
        known = self.runner.hostkey_known(fields["host"], 22)
        keys = self.runner.scan_hostkeys(fields["host"], 22)
        return {"known": known, "keys": [{"type": k["type"], "fingerprint": k["fingerprint"]} for k in keys],
                "message": "" if keys else "No SSH host key was returned. Is sshd running on that node?"}

    def add_host(self, body, actor="?"):
        name, host = str(body.get("name") or "").strip(), str(body.get("host") or "").strip()
        user = str(body.get("user") or "updatedash-gate").strip()
        # validate everything first (registry.add re-checks while holding its lock)
        probe = HostRegistry(None, self.cfg.get("pve"))
        probe.extra = [dict(h) for h in self.hosts.extra]
        probe.next_idx = self.hosts.next_idx
        probe.add(name, host, user)
        self._ensure_hostkey({"host": host, "port": 22}, body)
        ok, msg = self.runner.gate_ping({"host": host, "user": user})
        if not ok:
            raise ValidationError(msg)
        idx = self.hosts.add(name, host, user)
        self.audit.append(actor, "", "host.add", f"{name} ({host}) as host {idx}")
        self.sync_inventory()
        self.check_async()
        return {"idx": idx, "message": msg}

    def remove_host(self, idx, actor="?"):
        if idx == 0:
            raise ValidationError("the primary node is set in the config file (pve:), not here")
        h = self.hosts.get(idx)
        if not h:
            raise ValidationError("unknown host")
        self.hosts.remove(idx)
        self.audit.append(actor, "", "host.remove", f"{h['name']} (host {idx})")
        self.sync_inventory()

    def host_setup_script(self, dashboard_ips, allow="", protected="", manage=True):
        key_path = Path(str((self.cfg.get("pve") or {}).get("key") or "/etc/updatedash/id_ed25519") + ".pub")
        try:
            pub = key_path.read_text().strip()
        except OSError:
            raise ValidationError(f"cannot read the dashboard's public key ({key_path})")
        gate = (self.base_dir / "pve-gate.py").read_bytes()
        try:
            return build_setup_script(gate, pub, dashboard_ips, allow, protected, manage)
        except ValueError as e:
            raise ValidationError(str(e))

    # -- per-container SSH access
    def _params(self, body, custom=False):
        fields = clean_access(body, custom=custom)
        secret = body.get("secret")
        passphrase = body.get("passphrase")
        for v in (secret, passphrase):
            if v is not None and (not isinstance(v, str) or len(v) > 16384):
                raise ValidationError("secret is too long")
        return fields, secret, passphrase

    def _ensure_hostkey(self, fields, body):
        """Direct SSH never trusts a host key by itself. Unknown host -> the user must have confirmed a fingerprint."""
        host, port = fields["host"], fields["port"]
        if body.get("forget_host_key"):
            self.runner.forget_host_key(host, port)
        if self.runner.hostkey_known(host, port):
            return
        fp = str(body.get("trust_fingerprint") or "")
        if not fp:
            raise ValidationError("The server's SSH host key is not trusted yet. Click 'Check host key', compare the "
                                  "fingerprint with the one on the server, and tick 'I verified it'.")
        if not self.runner.trust_hostkey(host, port, fp):
            raise ValidationError("The server no longer presents that host key (or is unreachable): nothing was trusted. "
                                  "Check the host and port, and fetch the key again.")

    def access_hostkeys(self, body):
        fields = clean_access(dict(body, user="root", auth="password"))
        known = self.runner.hostkey_known(fields["host"], fields["port"])
        keys = self.runner.scan_hostkeys(fields["host"], fields["port"])
        return {"known": known, "keys": [{"type": k["type"], "fingerprint": k["fingerprint"]} for k in keys],
                "message": "" if keys else "No SSH host key was returned. Is sshd running on that host and port?"}

    def commands_needing_approval(self):
        """Custom commands from the config that the Proxmox gate will refuse until the host owner approves them."""
        if not hasattr(self, "_gate_mod"):
            spec = importlib.util.spec_from_file_location("udash_gate", self.base_dir / "pve-gate.py")
            self._gate_mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(self._gate_mod)
        g, found = self._gate_mod, []
        for cid, svc in self.explicit.items():
            if self.access.has(cid):
                continue                                     # reached over SSH, not through the gate
            for cmd in (svc.get("current"), (svc.get("latest") or {}).get("cmd"), svc.get("update")):
                if cmd and cmd not in g.BUILTIN_EXACT and not any(p.fullmatch(cmd) for p in g.BUILTIN_PATTERNS) \
                        and cmd not in found:
                    found.append(cmd)
        return found

    def access_test(self, body):
        ctid = body.get("ctid")
        fields, secret, passphrase = self._params(body, custom=bool(body.get("custom")) or
                                                  (isinstance(ctid, int) and is_custom_uid(ctid)))
        if (not secret) and isinstance(ctid, int) and self.access.has(ctid):
            secret, saved_pp = self.access.secrets(ctid)
            passphrase = saved_pp if passphrase is None else passphrase
        if not secret:
            raise ValidationError("enter a password or private key to test")
        if fields["auth"] == "key" and "PRIVATE KEY" not in secret:
            raise ValidationError("that does not look like a private key (expected a PEM/OpenSSH key block)")
        self._ensure_hostkey(fields, body)
        res = self.runner.test_ssh(fields, secret, passphrase or "")
        if isinstance(ctid, int) and self.access.has(ctid):
            self.access.mark_tested(ctid, res["ok"], res["message"])
        return res

    def access_save(self, body, actor="?"):
        ctid = body.get("ctid")
        custom = bool(body.get("custom"))
        if custom:
            ctid = None
        elif not isinstance(ctid, int) or isinstance(ctid, bool) or ctid not in self.services:
            raise ValidationError("unknown container")
        fields, secret, passphrase = self._params(body, custom=custom or (ctid is not None and is_custom_uid(ctid)))
        if fields["auth"] == "key" and secret is not None and secret != "" and "PRIVATE KEY" not in secret:
            raise ValidationError("that does not look like a private key (expected a PEM/OpenSSH key block)")
        self._ensure_hostkey(fields, body)
        if custom:
            ctid = self.access.add_custom(fields, secret or "", passphrase)
        else:
            if is_custom_uid(ctid):
                fields["custom"], fields["name"] = True, self.access.entries[str(ctid)]["name"]
            self.access.set(ctid, fields, secret, passphrase)
        self.audit.append(actor, "", "access.save", f"CT {ctid} {fields['user']}@{fields['host']}:{fields['port']} ({fields['auth']})")
        self._rebuild()
        res = self.runner.test_ssh(fields, *self._secrets_for_test(ctid))
        self.access.mark_tested(ctid, res["ok"], res["message"])
        self.check_async(ctid)
        return {"ctid": ctid, "test": res, "access": self.access.public(ctid)}

    def _secrets_for_test(self, ctid):
        s, p = self.access.secrets(ctid)
        return s, p

    def access_remove(self, ctid, actor="?"):
        was_custom = is_custom_uid(ctid)
        if not self.access.remove(ctid):
            raise ValidationError("no saved credentials for this container")
        self.audit.append(actor, "", "access.remove", f"CT {ctid}{' (host removed)' if was_custom else ''}")
        self._rebuild()
        if not was_custom:
            self.check_async(ctid)

    # -- views
    def view(self):
        with self.lock:
            items = []
            for cid in self.order:
                s, st = self.services[cid], self.state[cid]
                job = self.jobs.get(st["job"] or "")
                meta = ({k: job[k] for k in ("id", "status", "kind", "ended")} if job else st["job_meta"])
                acc = self.access.public(cid)
                running = bool(job and job["status"] in ("running", "queued"))
                hidx, real = split_uid(cid)
                custom = is_custom_uid(cid)
                hcfg = None if custom else self.hosts.get(hidx)
                items.append({
                    "name": s["name"], "ctid": cid, "custom": custom, "real_ctid": real,
                    "host_idx": None if custom else hidx, "host": None if custom else (hcfg["name"] if hcfg else None),
                    "can_app_update": can_app_update(s),
                    "os_security": st["os_security"], "os_point": st["os_point"], "auto_system": cid in self.auto_uids(),
                    "os_info": ({k: st["os_info"][k] for k in ("name", "debian", "codename", "apt")} if st["os_info"] else None),
                    **{k: st[k] for k in ("status", "installed", "latest", "os_updates", "error", "checked_at",
                                          "checking", "ct_status", "link", "installed_hint")},
                    "notes": st["notes"] if st["status"] == "update" else None,
                    "access": (acc or {"mode": "gate"}),
                    "snapshot": self.snapshot_plan(cid)[0],
                    "job": meta["id"] if meta else None, "running": running,
                    "job_status": meta["status"] if meta else None,
                })
            return {"services": items, "total": len(items),
                    "updates": sum(i["status"] == "update" for i in items),
                    "os_pending": sum((i["os_updates"] or 0) > 0 for i in items),
                    "security": sum((i["os_security"] or 0) > 0 for i in items),
                    "errors": sum(i["status"] == "error" for i in items),
                    "stopped": sum(i["status"] == "stopped" for i in items),
                    "inventory_error": self.inventory_error,
                    "gate": any(self.runner.gate_ok(h["idx"]) for h in self.hosts.all()),
                    "hosts": [{"idx": h["idx"], "name": h["name"], "error": self.host_errors.get(h["idx"])}
                              for h in self.hosts.all() if self.runner.gate_ok(h["idx"])],
                    "last_sweep": self.last_sweep or None, "interval": self.cfg["check_interval_minutes"],
                    "log_retention": self.settings.get("log_retention")}

    def summary(self, detail=False):
        """Flat counts for other dashboards. Names and hosts only when the token was created with detail."""
        v = self.view()
        items = v["services"]
        running = sum(1 for i in items if i["ct_status"] == "running")
        stopped = sum(1 for i in items if i["ct_status"] == "stopped" or i["status"] == "stopped")
        out = {
            "generated_at": int(time.time()), "last_check": int(v["last_sweep"]) if v["last_sweep"] else None,
            "stale": bool(not v["last_sweep"] or time.time() - v["last_sweep"] > 2 * 60 * v["interval"]),
            "total": v["total"], "running": running, "stopped": stopped,
            "unknown": v["total"] - running - stopped,
            "app_updates": v["updates"], "system_updates": v["os_pending"], "security_updates": v["security"],
            "needs_attention": sum(1 for i in items if i["status"] in ("update", "os", "error") or (i["os_updates"] or 0) > 0),
            "unreachable": v["errors"], "hosts": max(1, len(v["hosts"])),
        }
        if detail:
            out["containers"] = [{"name": i["name"], "host": i["host"], "state": i["ct_status"] or "unknown",
                                  "app_update": i["status"] == "update", "system_updates": i["os_updates"] or 0,
                                  "security_updates": i["os_security"] or 0, "status": i["status"]} for i in items]
        return out

    def system_view(self, uid):
        """Pending packages and OS details for one container (loaded on demand, not on every poll)."""
        with self.lock:
            st = self.state.get(uid)
            if st is None:
                return None
            info = st["os_info"] or {}
            return {"ctid": uid, "name": self.services[uid]["name"], "os_info": info or None,
                    "point": list(st["os_point"]) if st["os_point"] else None,
                    "total": st["os_updates"], "security": st["os_security"],
                    "packages": list(st["os_packages"]), "checked_at": st["checked_at"]}

    def job_view(self, jid, since):
        j = self.jobs.get(jid)
        if j:
            return {"id": jid, "ctid": j["ctid"], "service": j["service"], "kind": j["kind"], "status": j["status"],
                    "started": j["started"], "ended": j["ended"], "lines": j["lines"][since:],
                    "next": len(j["lines"])}
        d = self.logs.load(jid)
        if not d:
            return None
        lines = d.pop("lines")
        return dict(d, lines=lines[since:], next=len(lines))
