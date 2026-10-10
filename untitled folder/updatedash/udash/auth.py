"""Password hashing, signed session cookies and login throttling."""
import base64
import hashlib
import hmac
import json
import logging
import os
import threading
import time

from .util import atomic_write, read_json

log = logging.getLogger("updatedash")
MIN_PASSWORD = 10


def _b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


PBKDF2_ITERATIONS = 600_000


def hash_password(pw, n=2 ** 14, r=8, p=1):
    """scrypt where the Python build has it, PBKDF2-SHA256 otherwise. The scheme is stored in the hash."""
    salt = os.urandom(16)
    if hasattr(hashlib, "scrypt"):
        h = hashlib.scrypt(pw.encode(), salt=salt, n=n, r=r, p=p, dklen=32)
        return f"scrypt${n}${r}${p}${_b64(salt)}${_b64(h)}"
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, PBKDF2_ITERATIONS, 32)
    return f"pbkdf2${PBKDF2_ITERATIONS}${_b64(salt)}${_b64(h)}"


def verify_password(pw, stored):
    try:
        parts = stored.split("$")
        if parts[0] == "scrypt" and len(parts) == 6 and hasattr(hashlib, "scrypt"):
            _, n, r, p, salt, h = parts
            calc = hashlib.scrypt(pw.encode(), salt=_unb64(salt), n=int(n), r=int(r), p=int(p), dklen=32)
        elif parts[0] == "pbkdf2" and len(parts) == 4:
            _, iters, salt, h = parts
            calc = hashlib.pbkdf2_hmac("sha256", pw.encode(), _unb64(salt), int(iters), 32)
        else:
            return False
        return hmac.compare_digest(calc, _unb64(h))
    except (ValueError, TypeError):
        return False


class Locked(Exception):
    def __init__(self, retry_after):
        super().__init__("too many failed logins")
        self.retry_after = retry_after


class AuthError(Exception):
    pass


class Auth:
    WINDOW = 300          # seconds in which failures are counted
    MAX_PER_IP = 5
    MAX_GLOBAL = 40

    def __init__(self, cfg, state_dir, vault):
        self.username = cfg["username"]
        self.state_file = state_dir / "auth.json"
        self.session_seconds = int(cfg["session_hours"]) * 3600
        self._key = vault.derive(b"session")
        self._lock = threading.Lock()
        self._fail = {}
        self._global = []
        self.plaintext_in_config = False
        stored = (read_json(self.state_file, {}) or {}).get("password_hash")
        self._fp_material = stored          # what sessions are bound to: changes only when the password changes
        if not stored and cfg.get("password_hash"):
            stored = cfg["password_hash"]
        if not stored and cfg.get("password"):
            if cfg["password"] == "CHANGE-ME":
                raise AuthError("set a real password in the config (password_hash or password)")
            stored = hash_password(cfg["password"])      # re-salted on every start, so bind sessions to the password
            self._fp_material = "plain:" + cfg["password"]
            self.plaintext_in_config = True
        if not stored:
            raise AuthError("no password configured: set password_hash (or password) in the config")
        self.hash = stored
        self._fp_material = self._fp_material or stored

    # -- throttling
    def _prune(self, now):
        for ip in list(self._fail):
            self._fail[ip] = [t for t in self._fail[ip] if now - t < self.WINDOW]
            if not self._fail[ip]:
                del self._fail[ip]
        self._global = [t for t in self._global if now - t < self.WINDOW]

    def _retry_after(self, ip, now):
        mine = self._fail.get(ip, [])
        if len(mine) >= self.MAX_PER_IP:
            return int(self.WINDOW - (now - mine[0])) + 1
        if len(self._global) >= self.MAX_GLOBAL:
            return int(self.WINDOW - (now - self._global[0])) + 1
        return 0

    def login(self, ip, username, password):
        now = time.time()
        with self._lock:
            self._prune(now)
            wait = self._retry_after(ip, now)
            if wait:
                raise Locked(wait)
        # Always run the hash so a wrong user name costs the same as a wrong password.
        ok_pw = verify_password(password or "", self.hash)
        ok_user = hmac.compare_digest((username or "").encode(), self.username.encode())
        if ok_pw and ok_user:
            with self._lock:
                self._fail.pop(ip, None)
            return self.make_session()
        with self._lock:
            self._fail.setdefault(ip, []).append(time.time())
            self._global.append(time.time())
        return None

    # -- sessions
    def _fingerprint(self):
        return hmac.new(self._key, self._fp_material.encode(), hashlib.sha256).hexdigest()[:16]

    def make_session(self):
        now = int(time.time())
        payload = json.dumps({"u": self.username, "iat": now, "exp": now + self.session_seconds,
                              "pv": self._fingerprint()}, separators=(",", ":")).encode()
        sig = hmac.new(self._key, payload, hashlib.sha256).digest()
        return _b64(payload) + "." + _b64(sig)

    def check_session(self, token):
        try:
            p, s = (token or "").split(".")
            payload = _unb64(p)
            if not hmac.compare_digest(hmac.new(self._key, payload, hashlib.sha256).digest(), _unb64(s)):
                return None
            d = json.loads(payload)
            if d.get("exp", 0) < time.time() or d.get("pv") != self._fingerprint() or d.get("u") != self.username:
                return None
            return d["u"]
        except (ValueError, TypeError, KeyError):
            return None

    # -- password change (stored in the state dir so the service never needs to write its config)
    def change_password(self, current, new):
        if not verify_password(current or "", self.hash):
            raise AuthError("current password is wrong")
        if len(new or "") < MIN_PASSWORD:
            raise AuthError(f"the new password must be at least {MIN_PASSWORD} characters")
        if new == current:
            raise AuthError("the new password must be different")
        h = hash_password(new)
        atomic_write(self.state_file, json.dumps({"password_hash": h}), 0o600)
        self.hash = h
        self._fp_material = h
        self.plaintext_in_config = False
        return self.make_session()
