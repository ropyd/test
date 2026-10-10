# Changelog

## 1.1.0 (security release)
* **Gate command allowlist**: the Proxmox gate runs only an exact list of update/check commands (extras approved in
  `/etc/updatedash-gate.commands`); host-side syslog of every decision; snapshot cap; absolute `pct` path; `restrict`.
* **Two-factor sign-in** (TOTP + recovery codes), **server-side revocable sessions** with idle timeout and a sessions list,
  `__Host-` cookies, `allow_from` network allowlist, stronger password hashing and login-flood limits.
* **HTTPS by default for new installs** (`tls: auto`), HSTS, warnings for unencrypted use and for a proxy without `trust_proxy`.
* **SSH host keys are trusted only after you confirm a fingerprint** (direct SSH); the builder pre-seeds the Proxmox host key.
* Hash-chained audit log with an integrity check; socket timeouts and a connection cap; extra response headers.
* Bandit and pip-audit in CI; Dependabot; `SECURITY.md`; `docs/SECURITY-REVIEW.md`; optional systemd hardening drop-in.
* Fixed during verification: a keep-alive session bug in the new code (never released), port 0 treated as 22 earlier.
* **Upgrade notes:** everyone is signed out once; in Nginx Proxy Manager set the scheme to **https** if you turn on `tls: auto`;
  re-run the builder with `CTID=<id> SETUP_GATE=1` to install the new gate.

## 1.0.0
* Rebuilt as a package (`udash/`) with a test suite (52 tests incl. real sshd) and CI.
* Per-container direct SSH access (password or key) with a Test button; add non-Proxmox hosts by SSH. Credentials are
  encrypted at rest.
* Update logs stored on disk with a retention setting (per container) in the GUI; log history per container.
* "Update" only when relevant; version arrows and release links; release-notes preview.
* Sign-in page with signed sessions, hashed passwords, lockout, password change, audit log; HTTPS option.
* GUI management of the Proxmox allow list, protected-container list, queued/cancellable updates, graceful shutdown.
* Fixes: community-script updates run unattended (`PHS_SILENT=1`, `TERM=xterm`); port 0 was treated as 22; sessions
  survived restarts; same-second audit entries were reordered.
