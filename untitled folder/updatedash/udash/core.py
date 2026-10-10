"""The engine: inventory, version checks, updates, logs."""
import copy
import logging
import re
import shlex
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from .catalog import auto_service
from .runner import Runner
from .store import CUSTOM_BASE, ValidationError, clean_access
from .util import first_line, safe_link, same
from .versions import github_latest

log = logging.getLogger("updatedash")
SNAP_RE = re.compile(r"pre-update-\d{8}-\d{6}")

# Community-scripts containers ship an `update` command. PHS_SILENT=1 is its supported unattended mode.
# TERM must not be "dumb": the scripts call `clear`, which exits 1 there and trips their error handler.
COMMUNITY_UPDATE = "export PHS_SILENT=1 TERM=xterm; update"
APT_ENV = "export DEBIAN_FRONTEND=noninteractive;"
OS_UPGRADE = APT_ENV + " apt-get update -qq && apt-get -y -o Dpkg::Options::=--force-confold upgrade"


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
            "checked_at": None, "checking": False, "job": None, "job_meta": None, "ct_status": None,
            "link": None, "notes": None, "installed_hint": None}


class Dash:
    def __init__(self, cfg, state_dir, vault, access, logs, settings, audit, base_dir):
        self.cfg = cfg
        self.access, self.logs, self.settings, self.audit = access, logs, settings, audit
        self.runner = Runner(cfg, state_dir, access, base_dir)
        self.explicit = {s["ctid"]: s for s in cfg["services"]}
        self.services = dict(self.explicit)
        self.order = sorted(self.services)
        self.state = {c: new_state() for c in self.order}
        self.inv = {}                      # ctid -> (status, name) from the gate
        self.gate_managed = set()
        self.inventory_error = None
        self.jobs = {}
        self.lock = threading.RLock()
        self.pool = ThreadPoolExecutor(max_workers=4)
        self.slots = threading.BoundedSemaphore(cfg["max_parallel_updates"])
        self.last_sweep = 0
        self.stopping = False
        self.logs.mark_interrupted()
        self._rebuild()
        for cid, meta in self.logs.latest_per_ctid().items():
            if cid in self.state:
                self.state[cid]["job"], self.state[cid]["job_meta"] = meta["id"], meta

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
        if self.cfg["discover"] and self.runner.gate_configured:
            rc, out = self.runner.pct("list", timeout=30)
            if rc != 0:
                self.inventory_error = "Could not list containers: " + " ".join(out[-2:])[:200]
            else:
                inv = {}
                for ln in out:
                    t = ln.split()
                    if len(t) >= 3 and t[0].isdigit():
                        inv[int(t[0])] = (t[1], t[-1])
                self.inventory_error = None
                self.inv = inv
                self.gate_managed = set(inv)
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
    def snapshot_plan(self, ctid):
        """(will_snapshot, reason). Snapshots go through the Proxmox gate, so they need the CT to be gate-managed."""
        if not self.cfg["snapshot_before_update"]:
            return False, "snapshots are turned off in the config"
        if self.runner.local:
            return False, "local transport"
        if ctid >= CUSTOM_BASE:
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
            pkg = (svc.get("latest") or {})["package"]
            return f"{APT_ENV} apt-get update -qq && apt-get install -y --only-upgrade {shlex.quote(pkg)}"
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
                rc, _ = self.runner.pct("snapshot", str(ctid), snap, timeout=300, on_line=log)
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
            if ok and will_snap:
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
        rc, out = self.runner.pct("listsnapshot", str(ctid), timeout=60)
        if rc != 0:
            return
        names = sorted(set(SNAP_RE.findall("\n".join(out))))
        for old in (names[:-keep] if keep > 0 else names):
            rc, _ = self.runner.pct("delsnapshot", str(ctid), old, timeout=300)
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
    def inventory(self):
        rc, out = self.runner.pct("list", "--all", timeout=30)
        if rc != 0:
            return {"manage": False, "message": (" ".join(out[-2:]) or "the gate refused the request")[:300],
                    "containers": []}
        rc2, allowed = self.runner.gate("allow", "list")
        managed = {int(x) for x in allowed if x.strip().isdigit()} if rc2 == 0 else set()
        rc3, prot = self.runner.gate("allow", "protected")
        locked = {int(x) for x in prot if x.strip().isdigit()} if rc3 == 0 else set()
        rows = []
        for ln in out:
            t = ln.split()
            if len(t) >= 3 and t[0].isdigit():
                c = int(t[0])
                rows.append({"ctid": c, "status": t[1], "name": t[-1], "managed": c in managed, "locked": c in locked})
        return {"manage": True, "containers": sorted(rows, key=lambda r: r["ctid"])}

    def set_allowed(self, ctid, add):
        rc, out = self.runner.gate("allow", "add" if add else "remove", str(ctid))
        if rc != 0:
            return False, (" ".join(out[-2:]) or "the gate refused the request")[:300]
        self.sync_inventory()
        if add and ctid in self.services:
            self.check_async(ctid)
        return True, "ok"

    # -- per-container SSH access
    def _params(self, body, custom=False):
        fields = clean_access(body, custom=custom)
        secret = body.get("secret")
        passphrase = body.get("passphrase")
        for v in (secret, passphrase):
            if v is not None and (not isinstance(v, str) or len(v) > 16384):
                raise ValidationError("secret is too long")
        return fields, secret, passphrase

    def access_test(self, body):
        ctid = body.get("ctid")
        fields, secret, passphrase = self._params(body, custom=bool(body.get("custom")) or
                                                  (isinstance(ctid, int) and ctid >= CUSTOM_BASE))
        if (not secret) and isinstance(ctid, int) and self.access.has(ctid):
            secret, saved_pp = self.access.secrets(ctid)
            passphrase = saved_pp if passphrase is None else passphrase
        if not secret:
            raise ValidationError("enter a password or private key to test")
        if fields["auth"] == "key" and "PRIVATE KEY" not in secret:
            raise ValidationError("that does not look like a private key (expected a PEM/OpenSSH key block)")
        if body.get("forget_host_key"):
            self.runner.forget_host_key(fields["host"], fields["port"])
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
        fields, secret, passphrase = self._params(body, custom=custom or (ctid is not None and ctid >= CUSTOM_BASE))
        if fields["auth"] == "key" and secret is not None and secret != "" and "PRIVATE KEY" not in secret:
            raise ValidationError("that does not look like a private key (expected a PEM/OpenSSH key block)")
        if body.get("forget_host_key"):
            self.runner.forget_host_key(fields["host"], fields["port"])
        if custom:
            ctid = self.access.add_custom(fields, secret or "", passphrase)
        else:
            if ctid >= CUSTOM_BASE:
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
        was_custom = ctid >= CUSTOM_BASE
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
                items.append({
                    "name": s["name"], "ctid": cid, "custom": cid >= CUSTOM_BASE,
                    "can_app_update": can_app_update(s),
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
                    "errors": sum(i["status"] == "error" for i in items),
                    "stopped": sum(i["status"] == "stopped" for i in items),
                    "inventory_error": self.inventory_error,
                    "gate": self.runner.gate_configured,
                    "last_sweep": self.last_sweep or None, "interval": self.cfg["check_interval_minutes"],
                    "log_retention": self.settings.get("log_retention")}

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
