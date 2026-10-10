"""Password hashing, server-side sessions, TOTP two-factor and login throttling."""
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import struct
import threading
import time
from urllib.parse import quote

from .util import atomic_write, read_json

log = logging.getLogger("updatedash")
MIN_PASSWORD = 10
MAX_PASSWORD = 256          # refuse absurd inputs before spending CPU on hashing them
PBKDF2_ITERATIONS = 600_000
TOTP_STEP = 30
RECOVERY_CODES = 10


def _b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ---------------------------------------------------------------- passwords
def hash_password(pw, n=2 ** 14, r=8, p=5):
    """scrypt (OWASP minimum n=2^14, r=8, p=5) where Python has it, PBKDF2-SHA256 otherwise.
    The scheme and parameters are stored in the hash, so older hashes keep verifying."""
    salt = os.urandom(16)
    if hasattr(hashlib, "scrypt"):
        h = hashlib.scrypt(pw.encode(), salt=salt, n=n, r=r, p=p, dklen=32, maxmem=256 * 1024 * 1024)
        return f"scrypt${n}${r}${p}${_b64(salt)}${_b64(h)}"
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, PBKDF2_ITERATIONS, 32)
    return f"pbkdf2${PBKDF2_ITERATIONS}${_b64(salt)}${_b64(h)}"


def verify_password(pw, stored):
    try:
        parts = stored.split("$")
        if parts[0] == "scrypt" and len(parts) == 6 and hasattr(hashlib, "scrypt"):
            _, n, r, p, salt, h = parts
            calc = hashlib.scrypt(pw.encode(), salt=_unb64(salt), n=int(n), r=int(r), p=int(p), dklen=32,
                                  maxmem=256 * 1024 * 1024)
        elif parts[0] == "pbkdf2" and len(parts) == 4:
            _, iters, salt, h = parts
            calc = hashlib.pbkdf2_hmac("sha256", pw.encode(), _unb64(salt), int(iters), 32)
        else:
            return False
        return hmac.compare_digest(calc, _unb64(h))
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------------- TOTP (RFC 4226 / 6238)
def hotp(secret, counter, digits=6):
    h = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    return f"{(struct.unpack('>I', h[o:o + 4])[0] & 0x7FFFFFFF) % 10 ** digits:0{digits}d}"


def totp_match(secret_b32, code, now=None, last=0, window=1):
    """Returns the matching time-step counter, or None. Steps at or before `last` are refused (no replay)."""
    if not (code.isdigit() and len(code) == 6):
        return None
    secret = base64.b32decode(secret_b32)
    t = int((time.time() if now is None else now) // TOTP_STEP)
    found = None
    for c in range(t - window, t + window + 1):
        if hmac.compare_digest(hotp(secret, c), code) and c > last:
            found = c
    return found


def new_totp_secret():
    return base64.b32encode(os.urandom(20)).decode()


def otpauth_uri(secret, account, issuer="Update Dashboard"):
    return (f"otpauth://totp/{quote(issuer)}:{quote(account)}?secret={secret}&issuer={quote(issuer)}"
            f"&algorithm=SHA1&digits=6&period={TOTP_STEP}")


def _norm_recovery(code):
    return "".join(ch for ch in code.upper() if ch.isalnum())


def _recovery_hash(code):
    return hashlib.sha256(b"updatedash-recovery:" + _norm_recovery(code).encode()).hexdigest()


# ---------------------------------------------------------------- sessions
class SessionStore:
    """Server-side sessions: random ids (only their hashes are stored), so a session can be revoked.
    Sessions end after an absolute lifetime or after being idle too long."""

    def __init__(self, path, absolute, idle, max_sessions=20):
        self.path, self.absolute, self.idle, self.max = path, absolute, idle, max_sessions
        self.lock = threading.Lock()
        data = read_json(path, {}) or {}
        self.data = data if isinstance(data, dict) else {}
        self._last_flush = 0
        self._prune(time.time())

    @staticmethod
    def _id(token):
        return hashlib.sha256((token or "").encode()).hexdigest()

    def _prune(self, now):
        for sid in [k for k, v in self.data.items()
                    if now - v.get("created", 0) > self.absolute or now - v.get("last", 0) > self.idle]:
            del self.data[sid]

    def _flush(self, force=False):
        now = time.time()
        if force or now - self._last_flush > 60:
            atomic_write(self.path, json.dumps(self.data), 0o600)
            self._last_flush = now

    def create(self, user, ip, ua):
        now = time.time()
        token = secrets.token_urlsafe(32)
        with self.lock:
            self._prune(now)
            while len(self.data) >= self.max:                    # drop the least recently used
                del self.data[min(self.data, key=lambda k: self.data[k]["last"])]
            self.data[self._id(token)] = {"created": now, "last": now, "ip": ip, "ua": (ua or "")[:120], "user": user}
            self._flush(True)
        return token

    def validate(self, token):
        if not token:
            return None
        now = time.time()
        with self.lock:
            s = self.data.get(self._id(token))
            if not s:
                return None
            if now - s["created"] > self.absolute or now - s["last"] > self.idle:
                del self.data[self._id(token)]
                self._flush(True)
                return None
            s["last"] = now
            self._flush()
            return dict(s, id=self._id(token))

    def revoke(self, sid):
        with self.lock:
            existed = self.data.pop(sid, None) is not None
            if existed:
                self._flush(True)
            return existed

    def revoke_all(self, keep=None):
        with self.lock:
            for sid in [k for k in self.data if k != keep]:
                del self.data[sid]
            self._flush(True)

    def list(self, current_id):
        with self.lock:
            self._prune(time.time())
            rows = [{"id": k, "created": v["created"], "last": v["last"], "ip": v.get("ip"), "ua": v.get("ua"),
                     "current": k == current_id} for k, v in self.data.items()]
        return sorted(rows, key=lambda r: -r["last"])


# ---------------------------------------------------------------- the authenticator
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
        self.vault = vault
        self.state_file = state_dir / "auth.json"
        self._lock = threading.Lock()
        self._hash_slots = threading.BoundedSemaphore(2)     # a login flood can't exhaust CPU/memory
        self._fail = {}
        self._global = []
        self.plaintext_in_config = False
        st = read_json(self.state_file, {}) or {}
        stored = st.get("password_hash")
        if not stored and cfg.get("password_hash") and cfg["password_hash"] != "CHANGE-ME":
            stored = cfg["password_hash"]
        if not stored and cfg.get("password"):
            if cfg["password"] == "CHANGE-ME":
                raise AuthError("set a real password in the config (password_hash or password)")
            stored = hash_password(cfg["password"])
            self.plaintext_in_config = True
        if not stored:
            raise AuthError("no password configured: set password_hash (or password) in the config")
        self.hash = stored
        self.totp = st.get("totp") if isinstance(st.get("totp"), dict) else {}
        self.sessions = SessionStore(state_dir / "sessions.json",
                                     int(cfg["session_hours"]) * 3600,
                                     int(cfg.get("session_idle_minutes", 480)) * 60)

    # -- persistence
    def _save(self):
        atomic_write(self.state_file, json.dumps({"password_hash": None if self.plaintext_in_config else self.hash,
                                                  "totp": self.totp}), 0o600)

    def _verify_pw(self, pw):
        with self._hash_slots:
            return verify_password(pw, self.hash)

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

    def _fail_now(self, ip):
        with self._lock:
            self._fail.setdefault(ip, []).append(time.time())
            self._global.append(time.time())

    # -- second factor
    @property
    def totp_enabled(self):
        return bool(self.totp.get("enabled"))

    def two_factor_status(self):
        return {"enabled": self.totp_enabled, "recovery_left": len(self.totp.get("recovery", []))}

    def _check_second_factor(self, code):
        code = (code or "").strip().replace(" ", "")
        with self._lock:
            secret = self.vault.decrypt(self.totp["secret"])
            counter = totp_match(secret, code, last=int(self.totp.get("last", 0)))
            if counter is not None:
                self.totp["last"] = counter
                self._save()
                return True
            h = _recovery_hash(code) if len(_norm_recovery(code)) >= 8 else None
            if h and h in self.totp.get("recovery", []):
                self.totp["recovery"].remove(h)
                self._save()
                return True
        return False

    # -- login
    def login(self, ip, username, password, code="", ua=""):
        """Returns a session token, or None for bad credentials. Raises Locked when throttled."""
        now = time.time()
        with self._lock:
            self._prune(now)
            wait = self._retry_after(ip, now)
        if wait:
            raise Locked(wait)
        if len(password or "") > MAX_PASSWORD or len(username or "") > 64:
            self._fail_now(ip)
            return None
        # Always run the hash so a wrong user name costs the same as a wrong password.
        ok_pw = self._verify_pw(password or "")
        ok_user = hmac.compare_digest((username or "").encode(), self.username.encode())
        ok_2fa = (not self.totp_enabled) or self._check_second_factor(code)
        if ok_pw and ok_user and ok_2fa:
            with self._lock:
                self._fail.pop(ip, None)
            return self.sessions.create(self.username, ip, ua)
        self._fail_now(ip)
        return None

    def throttle_check(self, ip):
        """Raises Locked if this address has failed too often (logins and bad API tokens share the allowance)."""
        now = time.time()
        with self._lock:
            self._prune(now)
            wait = self._retry_after(ip, now)
        if wait:
            raise Locked(wait)

    def throttle_fail(self, ip):
        self._fail_now(ip)

    def check_session(self, token):
        s = self.sessions.validate(token)
        return s["user"] if s else None

    def session_id(self, token):
        return SessionStore._id(token)

    # -- password change: ends every other session and issues a fresh one
    def change_password(self, current, new, ip="", ua=""):
        if len(new or "") > MAX_PASSWORD:
            raise AuthError(f"the password must be at most {MAX_PASSWORD} characters")
        if not self._verify_pw(current or ""):
            raise AuthError("current password is wrong")
        if len(new or "") < MIN_PASSWORD:
            raise AuthError(f"the new password must be at least {MIN_PASSWORD} characters")
        if new == current:
            raise AuthError("the new password must be different")
        with self._hash_slots:
            h = hash_password(new)
        self.hash = h
        self.plaintext_in_config = False
        self._save()
        self.sessions.revoke_all()
        return self.sessions.create(self.username, ip, ua)

    # -- two-factor setup (needs the password; the secret is stored encrypted)
    def totp_begin(self, password):
        if not self._verify_pw(password or ""):
            raise AuthError("password is wrong")
        if self.totp_enabled:
            raise AuthError("two-factor is already on; turn it off first to set it up again")
        secret = new_totp_secret()
        self.totp = {"pending": self.vault.encrypt(secret)}
        self._save()
        return {"secret": secret, "uri": otpauth_uri(secret, self.username)}

    def totp_enable(self, code):
        if not self.totp.get("pending"):
            raise AuthError("start the setup first")
        secret = self.vault.decrypt(self.totp["pending"])
        counter = totp_match(secret, (code or "").strip().replace(" ", ""))
        if counter is None:
            raise AuthError("that code is not valid; check the time on your phone and try again")
        codes = [f"{secrets.token_hex(3)}-{secrets.token_hex(3)}" for _ in range(RECOVERY_CODES)]
        self.totp = {"secret": self.vault.encrypt(secret), "enabled": True, "last": counter,
                     "recovery": [_recovery_hash(c) for c in codes]}
        self._save()
        return codes

    def totp_disable(self, password, code):
        if not self._verify_pw(password or ""):
            raise AuthError("password is wrong")
        if not self.totp_enabled:
            self.totp = {}
            self._save()
            return
        if not self._check_second_factor(code):
            raise AuthError("the code is not valid")
        self.totp = {}
        self._save()

