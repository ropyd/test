# Security review (1.0.0 → 1.1.0)

Method: re-read all code paths that handle credentials, commands, sessions and network input; wrote tests for each
finding before and after fixing it (including tests that fail against the old behaviour); ran Bandit (static analysis);
used the real UI and a real `sshd` to check the flows end to end. **Not done:** an independent penetration test, a
fuzzing campaign, or testing on a real Proxmox host / systemd (the unit and gate were checked with mocks and by reading).

## Threat model
| Attacker | Goal | Main defences |
|---|---|---|
| Someone on your LAN | Reach the login, guess the password, steal a session | `allow_from`, TLS, two-factor, lockout, hashed password, `__Host-` cookies |
| Someone who steals a session cookie or password | Act as the admin | Server-side sessions (revocable), idle timeout, two-factor, audit log |
| Someone who gets code execution **in the dashboard process** | Run commands as root in your containers | Gate command allowlist + allow list + protected list; they can still update allowed containers, not run arbitrary code there |
| Someone who gets root **on the dashboard container** | Everything the dashboard can do | Limited by what it was given; stored credentials and the key are readable by them (see R1) |
| A malicious or compromised update source | Run code via an update | Out of scope for the dashboard; see R2 |

## Findings and what changed

| # | Finding | Severity | Status |
|---|---|---|---|
| F1 | The Proxmox gate ran **any** command in an allowed container (`pct exec N -- bash -c <anything>`), so code execution in the dashboard meant arbitrary root commands in every allowed container. | High | **Fixed.** The gate runs only an exact list of update/check commands (plus lines you approve in `/etc/updatedash-gate.commands`). A test keeps the list in step with the code that generates commands. Found while designing the list: a generic `cat /root/.<name>` pattern would also have exposed `.bash_history` and `.ssh`, so the app names are whitelisted. |
| F2 | Password-only sign-in on a tool that can run root commands. | High | **Fixed.** TOTP two-factor (RFC 6238, tested against the RFC vectors), one-time recovery codes, replay protection, optional `allow_from` network allowlist. |
| F3 | Plain HTTP by default; credentials and the session cookie crossed the LAN in clear text. | High | **Fixed for new installs / mitigated.** `tls: auto` serves HTTPS with a generated certificate; `Secure`, `__Host-`, HSTS; a warning banner while the connection is unencrypted. Existing installs keep their setting until changed. |
| F4 | Sessions were stateless signed cookies: logging out or a stolen cookie could not be revoked. | Medium | **Fixed.** Server-side sessions (only hashes stored), idle and absolute expiry, per-session revoke, sign out everywhere, password change ends all other sessions. |
| F5 | Trust-on-first-use for SSH host keys (direct SSH and the Proxmox hop). | Medium | **Fixed.** Direct SSH is always `StrictHostKeyChecking=yes`: you check a fingerprint and confirm it before anything is trusted; a changed key is refused until forgotten and re-confirmed. The builder pre-seeds the Proxmox host key and the dashboard becomes strict once it is known. |
| F6 | No limits on logins: very long passwords, parallel hashing, and a small scrypt cost. | Medium | **Fixed.** 256-character cap, at most two concurrent hashes, OWASP-minimum scrypt (n=2^14, r=8, p=5; PBKDF2-600k fallback), old hashes keep verifying. |
| F7 | Slow or numerous connections could exhaust threads; the TLS handshake ran on the accept loop. | Medium | **Fixed.** Socket timeout, connection cap, handshake in the worker thread. Tested with a stalled client and a flood. |
| F8 | The audit log could be edited unnoticed; the dashboard was the only record. | Medium | **Mitigated.** Hash-chained entries with a verify check shown in Settings (detects edits and deletions in the middle); the gate also writes every allow/deny to the host's syslog, which the dashboard cannot edit. Not tamper-proof against someone who can rewrite the whole file (R6). |
| F9 | Gate hygiene: `pct` found via `PATH`, no cap on snapshots (disk fill), SSH key options listed one by one. | Low–Med | **Fixed.** Absolute path, at most 10 pre-update snapshots per container (and pruning after every run), `restrict` in `authorized_keys`. |
| F10 | Missing browser hardening headers; Sec-Fetch-Site not checked; Python version in the `Server` header. | Low | **Fixed.** COOP/CORP/Permissions-Policy, cross-site fetches rejected, no version disclosure. Strict CSP (no inline script/style) was already in place. |
| F11 | Running behind a reverse proxy without `trust_proxy` silently makes every visitor look like the proxy (lockout and audit become useless, and one attacker could lock everyone out). | Low | **Mitigated.** The dashboard detects forwarded headers from an untrusted peer and shows a warning; `trust_proxy` uses the right-most untrusted address so spoofed entries don't help. |
| F12 | State directory permissions depended on the installer. | Low | **Fixed.** Enforced to 0700 at startup; secrets and sessions files are 0600. |
| F13 | GitHub API URL built from a configured repo name. | Low | **Fixed.** Strict `owner/name` validation before use (Bandit finding). |
| F14 | **Found while verifying this release in the UI:** the new session lookup was cached on the connection handler, but one handler serves many requests on a keep-alive connection. A request without a cookie could reuse the previous request's result (sign-in loops; and the reverse, a signed-in state leaking to a later cookie-less request, which would matter behind a proxy that shares connections). | High (had it shipped) | **Fixed before release.** The lookup is now per request, with three regression tests that fail against the old code. The earlier test client opened a new connection per request and could not see this. |

Bandit: no high or medium findings; the remaining low findings are argv-list `subprocess` calls (no shell) and one
false positive on an empty-string default.

## Known limitations (accepted for now) and what would fix them
| # | Limitation | Suggested improvement |
|---|---|---|
| R1 | Someone with root on the dashboard container can read `secret.key` and decrypt stored SSH credentials (the key sits next to the data so the service can start unattended). | Optional **unlock on start**: keep the key encrypted with a passphrase typed after each restart; or avoid stored passwords by installing a forced-command key (like the Proxmox gate) on each target instead of root credentials. |
| R2 | Community-script `update` downloads and runs code from GitHub as root. Compromise of that source compromises the container. | Pin to reviewed commits or a mirror you control; don't auto-update security-critical containers; read release notes first (the dashboard links them). |
| R3 | A stored SSH password reaches `ssh` in an environment variable for the duration of one connection (visible to root and the service user on that host); key files exist briefly on tmpfs. | Prefer key auth. Could pass secrets over an inherited file descriptor. |
| R4 | One admin account, no roles, no second-person approval for sensitive containers. | Roles (view/update/admin) and an approval step for "protected" containers. |
| R5 | The lockout can be used to keep the real admin out (global cap). | `allow_from` (implemented) limits who can try; an out-of-band unlock (`systemctl restart`) exists. |
| R6 | The hash chain detects partial edits, not a full rewrite. | Ship logs off the box: remote syslog from the gate and the dashboard. |
| R7 | A self-signed certificate means the browser trusts it on first use. | Pin the fingerprint shown in Settings, or use a certificate from your own CA / the reverse proxy. |
| R8 | The default systemd unit is a moderate sandbox, and I could not test a stricter one here. | `docs/hardening.conf` is provided; check with `systemd-analyze security updatedash`. |
| R9 | Supply chain: Python dependencies come from Debian packages; CI runs Bandit and `pip-audit`, Dependabot watches the workflow actions. | Pin action versions by commit SHA; consider signed releases of this project. |

## Recommended next steps, in order
1. Turn on two-factor, TLS and `allow_from`; fill in `/etc/updatedash-gate.protected`.
2. Remote syslog for the Proxmox host and the dashboard.
3. Replace stored root passwords with per-target forced-command keys (removes R1/R3 for those hosts).
4. Unlock-on-start for the credential key (R1).
5. An external penetration test / ZAP scan of the running dashboard behind your proxy, and a review of the gate on a real host.
