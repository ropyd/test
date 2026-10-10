"""Notifications and opt-in automatic system updates.

Both are driven by the normal sweep and add no new way to run commands: an automatic update is exactly the "Update system"
button (snapshot first, same gate command), started by the scheduler instead of a person, and recorded in the audit log
as `schedule`. Nothing is automatic until you tick a container."""
import ipaddress
import json
import logging
import socket
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

from .store import ValidationError
from .util import atomic_write, read_json

log = logging.getLogger("updatedash.automation")
KINDS = ("ntfy", "webhook")
MAX_AUTO = 200


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def clean_notify(d):
    d = d or {}
    kind = d.get("kind", "ntfy")
    if kind not in KINDS:
        raise ValidationError("kind must be ntfy or webhook")
    url = str(d.get("url") or "").strip()
    enabled = bool(d.get("enabled"))
    if url or enabled:
        u = urlparse(url)
        if u.scheme not in ("http", "https") or not u.hostname or len(url) > 300:
            raise ValidationError("the address must be a full http:// or https:// URL")
        if u.username or u.password:
            raise ValidationError("do not put a user name or password in the URL")
        _check_host(u.hostname)
    return {"kind": kind, "url": url, "enabled": enabled and bool(url)}


def _check_host(host):
    """Local services (a LAN ntfy) are fine; link-local addresses (cloud metadata) and 'any' are not."""
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        raise ValidationError("that host name does not resolve")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if ip.is_link_local or ip.is_unspecified or ip.is_multicast:
            raise ValidationError("that address is not allowed")


class Automation:
    def __init__(self, path, dash, audit, clock=time.time):
        self.path, self.dash, self.audit, self.clock = Path(path), dash, audit, clock
        self.lock = threading.Lock()
        d = read_json(self.path, {}) or {}
        try:
            self.notify = clean_notify(d.get("notify"))
        except ValidationError:
            self.notify = {"kind": "ntfy", "url": "", "enabled": False}
        auto = d.get("auto") or {}
        self.auto = {"uids": sorted({int(u) for u in auto.get("uids", []) if isinstance(u, int) and u > 0})[:MAX_AUTO],
                     "hour": auto.get("hour") if isinstance(auto.get("hour"), int) and 0 <= auto["hour"] <= 23 else 3}
        self.sent = set(d.get("sent", []))               # alert keys already sent, so one problem is announced once
        self.last_auto = dict(d.get("last_auto", {}))    # uid -> "YYYY-MM-DD" of the last automatic run
        dash.on_sweep = self.after_sweep
        dash.auto_uids = lambda: set(self.auto["uids"])

    def _save(self):
        atomic_write(self.path, json.dumps({"notify": self.notify, "auto": self.auto, "sent": sorted(self.sent),
                                            "last_auto": self.last_auto}, indent=1))

    def public(self):
        with self.lock:
            return {"notify": dict(self.notify), "auto": {"uids": list(self.auto["uids"]), "hour": self.auto["hour"]}}

    def set_notify(self, body):
        n = clean_notify(body)
        with self.lock:
            self.notify = n
            self._save()
        return n

    def set_auto(self, body):
        uids, hour = body.get("uids", []), body.get("hour", 3)
        if (not isinstance(uids, list) or len(uids) > MAX_AUTO
                or not all(isinstance(u, int) and not isinstance(u, bool) and u > 0 for u in uids)):
            raise ValidationError("uids must be a list of container numbers")
        if isinstance(hour, bool) or not isinstance(hour, int) or not 0 <= hour <= 23:
            raise ValidationError("hour must be 0-23")
        known = set(self.dash.services)
        if any(u not in known for u in uids):
            raise ValidationError("unknown container")
        with self.lock:
            self.auto = {"uids": sorted(set(uids)), "hour": hour}
            self._save()
        return self.public()["auto"]

    # -- sending
    def send(self, title, text, extra=None):
        """Returns (ok, message). Never follows redirects; short timeout; no credentials are sent."""
        n = self.notify
        if not n["url"]:
            return False, "no address set"
        try:
            _check_host(urlparse(n["url"]).hostname)
            if n["kind"] == "ntfy":
                req = urllib.request.Request(n["url"], data=text.encode(), method="POST",
                                             headers={"Title": title.encode("ascii", "replace").decode(), "Tags": "package"})
            else:
                body = json.dumps({"title": title, "text": f"{title}\n{text}", "content": f"{title}\n{text}", "summary": extra or {}})
                req = urllib.request.Request(n["url"], data=body.encode(), method="POST", headers={"Content-Type": "application/json"})
            opener = urllib.request.build_opener(_NoRedirect)
            with opener.open(req, timeout=8) as r:    # nosec B310 - scheme checked (http/https) in clean_notify
                return 200 <= r.status < 300, f"HTTP {r.status}"
        except urllib.error.HTTPError as e:
            return False, f"HTTP {e.code}"
        except (urllib.error.URLError, OSError, ValidationError) as e:
            return False, str(getattr(e, "reason", e))[:120]

    def test(self):
        ok, msg = self.send("updatedash test", "If you can read this, notifications work.")
        return {"ok": ok, "message": msg}

    # -- the sweep hook
    def after_sweep(self):
        try:
            self._notify_new()
        except Exception:                                  # a broken webhook must never break the sweep
            log.exception("notification step failed")
        try:
            self.run_auto(self.clock())
        except Exception:
            log.exception("automatic update step failed")

    def _alerts(self):
        out = {}
        for s in self.dash.view()["services"]:
            who = s["name"] + (f" ({s['host']})" if s.get("host") and len(self.dash.hosts.all()) > 1 else "")
            if (s["os_security"] or 0) > 0:
                out[f"{s['ctid']}:sec:{s['os_security']}"] = f"{who}: {s['os_security']} security update(s)"
            if s["status"] == "update":
                out[f"{s['ctid']}:app:{s['latest']}"] = f"{who}: {s['installed'] or '?'} → {s['latest']}"
        return out

    def _notify_new(self):
        if not self.notify["enabled"]:
            return
        current = self._alerts()
        with self.lock:
            fresh = {k: v for k, v in current.items() if k not in self.sent}
            self.sent = set(current)                      # keys that vanished may be announced again later
            self._save()
        if fresh:
            ok, msg = self.send(f"{len(fresh)} update{'s' if len(fresh) != 1 else ''} available", "\n".join(sorted(fresh.values()))[:1500],
                                self.dash.summary())
            if not ok:
                log.warning("notification failed: %s", msg)

    # -- opt-in automatic system updates
    def run_auto(self, now):
        with self.lock:
            uids, hour = list(self.auto["uids"]), self.auto["hour"]
        if not uids:
            return []
        lt = time.localtime(now)
        if lt.tm_hour < hour:
            return []
        today = time.strftime("%Y-%m-%d", lt)
        started = []
        for uid in uids:
            if self.last_auto.get(str(uid)) == today or uid not in self.dash.state:
                continue
            st = self.dash.state[uid]
            if not (st["os_security"] or 0) > 0 or st["ct_status"] == "stopped" or st["status"] == "error":
                continue
            try:
                self.dash.start_update(uid, "os", actor="schedule")
                started.append(uid)
            except ValueError as e:
                log.info("automatic update of %s skipped: %s", uid, e)
                continue
            with self.lock:
                self.last_auto[str(uid)] = today
                self._save()
        return started
