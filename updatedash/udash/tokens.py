"""Read-only API tokens for other dashboards (e.g. Homarr). Only a hash of each token is stored; the token itself
is shown once, when it is created. A token can read the summary endpoint and nothing else."""
import hashlib
import hmac
import json
import secrets
import threading
import time
from pathlib import Path

from .store import NAME_RE, ValidationError
from .util import atomic_write, read_json

PREFIX = "udt_"
MAX_TOKENS = 10
RATE_LIMIT = 60          # requests per token per minute


class TokenStore:
    def __init__(self, path):
        self.path = Path(path)
        self.lock = threading.Lock()
        data = read_json(self.path, {}) or {}
        self.tokens = data.get("tokens", []) if isinstance(data, dict) else []
        self._hits = {}
        self._flushed = 0

    @staticmethod
    def _hash(token):
        return hashlib.sha256(token.encode()).hexdigest()

    def _save(self):
        atomic_write(self.path, json.dumps({"tokens": self.tokens}, indent=1), 0o600)

    def create(self, name, detail=False):
        name = str(name or "").strip()
        if not NAME_RE.match(name):
            raise ValidationError("name must be 1-40 letters, numbers, spaces, dots, dashes")
        with self.lock:
            if len(self.tokens) >= MAX_TOKENS:
                raise ValidationError(f"at most {MAX_TOKENS} tokens; revoke one first")
            if any(t["name"].lower() == name.lower() for t in self.tokens):
                raise ValidationError("a token with that name already exists")
            token = PREFIX + secrets.token_urlsafe(30)
            rec = {"id": secrets.token_hex(6), "name": name, "hash": self._hash(token), "created": int(time.time()),
                   "last_used": None, "detail": bool(detail)}
            self.tokens.append(rec)
            self._save()
        return token, self.public(rec)

    @staticmethod
    def public(rec):
        return {k: rec[k] for k in ("id", "name", "created", "last_used", "detail")}

    def list(self):
        with self.lock:
            return [self.public(t) for t in self.tokens]

    def revoke(self, tid):
        with self.lock:
            n = len(self.tokens)
            self.tokens = [t for t in self.tokens if t["id"] != tid]
            if len(self.tokens) != n:
                self._save()
                return True
            return False

    def verify(self, token):
        """-> the token record, or None. Compares against every stored hash in constant time."""
        if not token or not token.startswith(PREFIX) or len(token) > 200:
            return None
        h = self._hash(token)
        found = None
        with self.lock:
            for t in self.tokens:
                if hmac.compare_digest(h, t["hash"]):
                    found = t
            if found:
                now = time.time()
                if not found["last_used"] or now - found["last_used"] > 60:      # don't write the file on every poll
                    found["last_used"] = int(now)
                    self._save()
        return dict(found) if found else None

    def allow(self, tid):
        """Sliding-window rate limit per token. Returns seconds to wait (0 = go ahead)."""
        now = time.time()
        with self.lock:
            hits = [t for t in self._hits.get(tid, []) if now - t < 60]
            if len(hits) >= RATE_LIMIT:
                self._hits[tid] = hits
                return int(60 - (now - hits[0])) + 1
            hits.append(now)
            self._hits[tid] = hits
            return 0
