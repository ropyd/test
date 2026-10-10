# Changelog

## 1.3.0
* **The dashboard no longer holds a root login on Proxmox.** The builder (and the second-node setup script) create an unprivileged
  host user `updatedash-gate` with no password. Its key can only run the gate, and only through one sudo rule
  (`NOPASSWD` for that single file; validated with `visudo`). The user's key file is root-owned. On upgrade the builder proves the new
  login works from the dashboard container before it removes the old root key line. `GATE_USER=root` keeps the old behaviour.
* **Phone layout:** compact header grid, collapsible notices, stacked cards with labels above values, compact package list, bottom-sheet
  dialogs, 16px inputs (no iOS zoom), larger touch targets.
* **Notifications** (Settings → Automation): ntfy or a JSON webhook, sent once per *new* security/application update, names and versions only;
  link-local addresses refused, redirects not followed, no credentials stored.
* **Optional automatic system updates:** per container, once a day after a chosen hour, only when a security update is pending. Same action as the
  button (snapshot first, no reboot), recorded as `schedule`. Off unless you tick a container.
* **Install form suggestions:** storage and bridge names come from the node through a new read-only gate request (`node info`).
* **Second node:** the dashboard's own address (as the node sees it) is filled in for you.
* **Browser smoke test** (`tests/ui_smoke.py`, Playwright) in CI; a missing favicon no longer logs an error.
* **Upgrade notes:** re-run the builder with `CTID=<id> SETUP_GATE=1` (installs sudo on the host if it is missing, creates the user, switches the
  dashboard to it). Existing extra nodes keep logging in as root until you re-run their setup script (it is safe to repeat).

## 1.2.0
* **System vs application, separated.** Each row has an Application pane (installed → available, release link) and a System pane
  (OS release, point-release arrow such as Debian 12.9 → 12.10, security vs other counts, expandable package list with from → to).
  Security updates sort first; the confirmation lists the packages. Containers without apt show "not checked" instead of "0".
* **Multiple independent Proxmox nodes.** Settings → Proxmox hosts generates a self-contained setup script per node (gate plus the
  dashboard's key), shows the node's SSH fingerprint for you to confirm, and checks the gate before adding. CT numbers may repeat across nodes.
  Existing single-node installs are unchanged.
* **Homarr / other dashboards.** Read-only `GET /api/v1/summary` with a bearer token (hash-only storage, rate-limited, counts only unless the
  token was created with container names). Settings → Integrations.
* **Install apps (plan only).** Search the community-scripts library, pick apps, set options, and get one commit-pinned script to run yourself in
  the Proxmox shell. The dashboard never runs an installer. Script hashes and review links are shown; diagnostics can be opted out.
* **Themes.** Presets, light/dark/auto, accent colour, solid or gradient backgrounds (linear/radial, 2–3 colours), live preview. Values are
  validated; the stylesheet is generated, so the strict CSP is unchanged.
* **Reverse proxy guide** for Nginx Proxy Manager and Traefik (`docs/REVERSE-PROXY.md`) with tests for forwarded-host handling.
* Gate: allows the new OS info/pending commands (old ones still accepted). Drift test keeps dashboard and gate in sync.
* **Upgrade notes:** re-run the builder with `CTID=<id> SETUP_GATE=1` so the host gate learns the new check commands. Until then, system
  details show as an error for that node while application checks keep working.

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
