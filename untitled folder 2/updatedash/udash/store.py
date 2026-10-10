"""Persistent state: encrypted credentials, per-container access, update logs, audit trail, settings."""
import hashlib
import json
import logging
import os
import re
import threading
import time
from pathlib import Path

from .util import atomic_write, read_json

log = logging.getLogger("updatedash")
CUSTOM_BASE = 10_000_000            # CT ids >= this are non-Proxmox hosts added by SSH
MAX_LOG_LINES = 5000
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,252}$")
USER_RE = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}$")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,39}$")


class ValidationError(ValueError):
    pass


# ---------------------------------------------------------------- secrets at rest
class Vault:
    """Fernet encryption for stored credentials; the same key also signs session cookies (derived)."""

    def __init__(self, key_file, fallback_dir):
        try:
            from cryptography.fernet import Fernet
        except ImportError as e:  # pragma: no cover
            raise RuntimeError("python3-cryptography is required (apt install python3-cryptography)") from e
        path = Path(key_file)
        if not path.is_file():
            path = Path(fallback_dir) / "secret.key"
            if not path.is_file():
                atomic_write(path, Fernet.generate_key(), 0o600)
                log.warning("created %s; for better separation keep the key in /etc/updatedash/secret.key", path)
        self.key = path.read_bytes().strip()
        self._f = Fernet(self.key)

    def encrypt(self, text):
        return self._f.encrypt(text.encode()).decode()

    def decrypt(self, token):
        from cryptography.fernet import InvalidToken
        try:
            return self._f.decrypt(token.encode()).decode()
        except InvalidToken as e:
            raise ValueError("stored secret cannot be decrypted (secret.key changed?)") from e

    def derive(self, label):
        import hashlib
        import hmac
        return hmac.new(self.key, label, hashlib.sha256).digest()


# ---------------------------------------------------------------- settings
class Settings:
    LIMITS = {"log_retention": (1, 200)}

    def __init__(self, path, defaults):
        self.path = Path(path)
        self.lock = threading.Lock()
        self.data = dict(defaults)
        for k, v in (read_json(self.path, {}) or {}).items():
            if k in self.LIMITS and isinstance(v, int) and self.LIMITS[k][0] <= v <= self.LIMITS[k][1]:
                self.data[k] = v

    def get(self, key):
        return self.data[key]

    def public(self):
        return {"log_retention": self.data["log_retention"], "limits": {k: list(v) for k, v in self.LIMITS.items()}}

    def update(self, changes):
        clean = {}
        for k, v in changes.items():
            if k not in self.LIMITS:
                raise ValidationError(f"unknown setting: {k}")
            if isinstance(v, bool) or not isinstance(v, int):
                raise ValidationError(f"{k} must be a whole number")
            lo, hi = self.LIMITS[k]
            if not lo <= v <= hi:
                raise ValidationError(f"{k} must be between {lo} and {hi}")
            clean[k] = v
        with self.lock:
            self.data.update(clean)
            atomic_write(self.path, json.dumps({k: self.data[k] for k in self.LIMITS}, indent=1))
        return clean


# ---------------------------------------------------------------- per-container access (SSH credentials)
PUBLIC_FIELDS = ("mode", "host", "port", "user", "auth", "sudo", "custom", "name",
                 "tested_at", "tested_ok", "tested_msg")


def clean_access(d, custom=False):
    """Validate user-supplied SSH access fields; returns a clean dict (no secrets)."""
    host = str(d.get("host") or "").strip()
    user = str(d.get("user") or "").strip()
    auth = d.get("auth")
    raw_port = d.get("port")
    try:
        port = 22 if raw_port in (None, "") else int(raw_port)
    except (TypeError, ValueError):
        raise ValidationError("port must be a number")
    if not HOST_RE.match(host):
        raise ValidationError("host must be a hostname or IP address")
    if not 1 <= port <= 65535:
        raise ValidationError("port must be 1-65535")
    if not USER_RE.match(user):
        raise ValidationError("user name has unsupported characters")
    if auth not in ("password", "key"):
        raise ValidationError("auth must be 'password' or 'key'")
    out = {"mode": "ssh", "host": host, "port": port, "user": user, "auth": auth, "sudo": bool(d.get("sudo"))}
    if custom:
        name = str(d.get("name") or "").strip()
        if not NAME_RE.match(name):
            raise ValidationError("name must be 1-40 letters, numbers, spaces, dots, dashes")
        out["name"] = name
        out["custom"] = True
    return out


class AccessStore:
    """access.json: public fields in clear, secrets encrypted with the Vault."""

    def __init__(self, path, vault):
        self.path = Path(path)
        self.vault = vault
        self.lock = threading.RLock()
        data = read_json(self.path, {}) or {}
        self.entries = data.get("entries", {}) if isinstance(data, dict) else {}
        self.next_custom = max(int(data.get("next_custom", CUSTOM_BASE)) if isinstance(data, dict) else CUSTOM_BASE,
                               CUSTOM_BASE)

    def _save(self):
        atomic_write(self.path, json.dumps({"version": 1, "next_custom": self.next_custom, "entries": self.entries},
                                           indent=1))

    def has(self, ctid):
        return str(ctid) in self.entries

    def public(self, ctid):
        e = self.entries.get(str(ctid))
        if not e:
            return None
        out = {k: e[k] for k in PUBLIC_FIELDS if k in e}
        out["has_secret"] = bool(e.get("secret"))
        out["has_passphrase"] = bool(e.get("passphrase"))
        return out

    def customs(self):
        return [(int(k), v) for k, v in self.entries.items() if v.get("custom")]

    def secrets(self, ctid):
        e = self.entries.get(str(ctid)) or {}
        sec = self.vault.decrypt(e["secret"]) if e.get("secret") else ""
        pp = self.vault.decrypt(e["passphrase"]) if e.get("passphrase") else ""
        return sec, pp

    def set(self, ctid, fields, secret=None, passphrase=None):
        """Create/replace an entry. secret/passphrase None = keep the stored one, '' = clear it."""
        with self.lock:
            old = self.entries.get(str(ctid)) or {}
            e = dict(fields)
            for key, new in (("secret", secret), ("passphrase", passphrase)):
                if new is None:
                    if old.get(key):
                        e[key] = old[key]
                elif new != "":
                    e[key] = self.vault.encrypt(new)
            if e["auth"] == "password":
                e.pop("passphrase", None)
            if not e.get("secret"):
                raise ValidationError("a password or private key is required")
            for k in ("tested_at", "tested_ok", "tested_msg"):
                if k in old and k not in e:
                    e[k] = old[k]
            self.entries[str(ctid)] = e
            self._save()

    def add_custom(self, fields, secret, passphrase):
        with self.lock:
            ctid = self.next_custom
            self.next_custom += 1
            try:
                self.set(ctid, fields, secret, passphrase)
            except Exception:
                self.next_custom -= 1
                raise
            return ctid

    def mark_tested(self, ctid, ok, msg):
        with self.lock:
            e = self.entries.get(str(ctid))
            if e is not None:
                e.update(tested_at=int(time.time()), tested_ok=bool(ok), tested_msg=(msg or "")[:200])
                self._save()

    def remove(self, ctid):
        with self.lock:
            existed = self.entries.pop(str(ctid), None) is not None
            if existed:
                self._save()
            return existed


# ---------------------------------------------------------------- update logs
JID_RE = re.compile(r"^[0-9a-f]{12}$")


class LogStore:
    """One JSON file per run: logs/<ctid>/<startedms>-<id>.json. Retention is per container."""

    def __init__(self, root):
        self.root = Path(root)
        self.lock = threading.Lock()

    def _path(self, job):
        return self.root / str(job["ctid"]) / f"{int(job['started'] * 1000):013d}-{job['id']}.json"

    def save(self, job):
        lines = job["lines"]
        if len(lines) > MAX_LOG_LINES:
            lines = lines[:200] + [f"... {len(lines) - MAX_LOG_LINES - 200} lines omitted ..."] + lines[-(MAX_LOG_LINES - 200):]
        meta = {k: job.get(k) for k in ("id", "ctid", "service", "kind", "status", "started", "ended", "by")}
        with self.lock:
            atomic_write(self._path(job), json.dumps({"meta": meta, "lines": lines}), 0o600)

    def _files(self, ctid):
        d = self.root / str(ctid)
        return sorted(d.glob("*.json"), reverse=True) if d.is_dir() else []

    def list(self, ctid):
        out = []
        for p in self._files(ctid):
            d = read_json(p, None)
            if isinstance(d, dict) and "meta" in d:
                out.append(dict(d["meta"], line_count=len(d.get("lines", []))))
        return out

    def load(self, jid):
        if not JID_RE.match(jid or ""):
            return None
        for p in self.root.glob(f"*/*-{jid}.json"):
            d = read_json(p, None)
            if isinstance(d, dict) and "meta" in d:
                return dict(d["meta"], lines=d.get("lines", []))
        return None

    def prune(self, ctid, keep):
        """Keep the newest `keep` runs for this container; never delete one that is still running."""
        removed = 0
        kept = 0
        for p in self._files(ctid):
            d = read_json(p, None) or {}
            if (d.get("meta") or {}).get("status") == "running":
                continue
            kept += 1
            if kept > keep:
                try:
                    p.unlink()
                    removed += 1
                except OSError:
                    pass
        return removed

    def prune_all(self, keep):
        total = 0
        if self.root.is_dir():
            for d in self.root.iterdir():
                if d.is_dir() and d.name.isdigit():
                    total += self.prune(int(d.name), keep)
        return total

    def latest_per_ctid(self):
        out = {}
        if self.root.is_dir():
            for d in self.root.iterdir():
                if d.is_dir() and d.name.isdigit():
                    files = self._files(int(d.name))
                    if files:
                        m = (read_json(files[0], None) or {}).get("meta")
                        if m:
                            out[int(d.name)] = m
        return out

    def mark_interrupted(self):
        """After a crash/restart, runs still marked 'running' can no longer be running."""
        n = 0
        if not self.root.is_dir():
            return n
        for p in self.root.glob("*/*.json"):
            d = read_json(p, None)
            if isinstance(d, dict) and (d.get("meta") or {}).get("status") == "running":
                d["meta"]["status"] = "interrupted"
                d["meta"]["ended"] = time.time()
                d.setdefault("lines", []).append("The dashboard restarted while this was running; the outcome is unknown.")
                atomic_write(p, json.dumps(d), 0o600)
                n += 1
        return n


# ---------------------------------------------------------------- audit
GENESIS = "0" * 64


def _chain_hash(rec):
    body = {k: v for k, v in rec.items() if k != "h"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class Audit:
    """Append-only JSON lines. Each record carries the hash of the previous one, so editing or deleting a record in
    the middle is detectable. The same events also go to the system journal; a copy off the box (remote syslog)
    is what makes the trail trustworthy if the dashboard itself is compromised."""

    def __init__(self, path, max_bytes=1_000_000, keep=3):
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.keep = keep
        self.lock = threading.Lock()
        self._last = GENESIS
        for p in (self.path, self.path.with_name(self.path.name + ".1")):
            last = self._last_hash_in(p)
            if last:
                self._last = last
                break

    @staticmethod
    def _last_hash_in(p):
        try:
            with open(p) as f:
                for ln in reversed(f.readlines()):
                    try:
                        h = json.loads(ln).get("h")
                    except ValueError:
                        continue
                    if h:
                        return h
        except OSError:
            pass
        return None

    def _files_oldest_first(self):
        files = [self.path.with_name(f"{self.path.name}.{i}") for i in range(self.keep, 0, -1)] + [self.path]
        return [p for p in files if p.exists()]

    def verify(self):
        """(ok, index of the first record that breaks the chain or None). Records from before chaining are skipped."""
        prev, n = None, 0
        for p in self._files_oldest_first():
            try:
                lines = p.read_text().splitlines()
            except OSError:
                continue
            for ln in lines:
                try:
                    rec = json.loads(ln)
                except ValueError:
                    return False, n
                if "h" not in rec:
                    continue
                if rec["h"] != _chain_hash(rec) or (prev is not None and rec.get("p") != prev):
                    return False, n
                prev, n = rec["h"], n + 1
        return True, None

    def append(self, actor, ip, action, detail=""):
        rec = {"t": int(time.time()), "user": actor, "ip": ip, "action": action, "detail": str(detail)[:300]}
        with self.lock:
            rec["p"] = self._last
            rec["h"] = _chain_hash(rec)
            self._last = rec["h"]
            self.path.parent.mkdir(parents=True, exist_ok=True)
            try:
                if self.path.exists() and self.path.stat().st_size > self.max_bytes:
                    for i in range(self.keep - 1, 0, -1):
                        src = self.path.with_name(f"{self.path.name}.{i}")
                        if src.exists():
                            os.replace(src, self.path.with_name(f"{self.path.name}.{i + 1}"))
                    os.replace(self.path, self.path.with_name(self.path.name + ".1"))
                fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
                with os.fdopen(fd, "a") as f:
                    f.write(json.dumps(rec) + "\n")
            except OSError as e:  # never let auditing break a request
                log.error("audit write failed: %s", e)
        log.info("audit %s %s %s %s", actor, ip, action, rec["detail"])

    def tail(self, n=50):
        """Newest first. Files are read oldest to newest so events from the same second keep their order."""
        rows = []
        for p in self._files_oldest_first():
            try:
                with open(p) as f:
                    for ln in f:
                        try:
                            rows.append(json.loads(ln))
                        except ValueError:
                            pass
            except OSError:
                pass
        return list(reversed(rows))[:n]
