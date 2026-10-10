# updatedash

A small, self-hosted dashboard that shows which of your containers and hosts have updates, what version they would
move to (with a link to the release notes), and updates them on request. It runs in its own LXC.

```
browser ─► updatedash LXC ─┬─ ssh (restricted key) ─► Proxmox host gate ─► pct exec / snapshot ─► your LXCs
                           └─ ssh (per-container credentials) ───────────────────────────────► any host with sshd
```

* **Two ways to reach a container**, chosen per container: through a locked-down gate on the Proxmox host (also gives
  you snapshots), or directly over SSH with a password or key you supply. Each has a **Test** button.
* **Nothing runs unless you click it** (or you add your own schedule). Every update takes a snapshot first when the
  container is managed through Proxmox.
* Stdlib Python plus PyYAML and `cryptography`. No database, no Docker, no outbound calls except GitHub's release API.

## Install

Keep this folder and `ct/updatedash.sh` in your git repo (layout below), then on the Proxmox host as root:

```
REPO_URL=https://github.com/<you>/<repo>.git \
IP=10.10.56.16/24 GW=10.10.56.1 \
ALLOW_CTIDS="113 114 116 117" PROTECTED_CTIDS="119 122 123 124" \
bash -c "$(curl -fsSL https://raw.githubusercontent.com/<you>/<repo>/main/ct/updatedash.sh)"
```

```
repo/
  ct/updatedash.sh              builds the LXC and runs install.sh
  updatedash/                   the application (app.py, udash/, static/, install.sh, pve-gate.py, tests/, docs/)
  .github/workflows/test.yml    CI
```

The builder creates a Debian 13 LXC, installs the app, and (after asking) installs the Proxmox gate. It prints a
first-login password once; only a hash is stored. **Upgrade** by re-running the same command with `CTID=<dashboard CT>`.
Useful variables: `GUI_MANAGE=0` (no web-UI management of the allow list), `SETUP_GATE=1` (redo the host step on an
existing container), `ASSUME_YES=1`, `BRIDGE=`, `STORAGE=`, `BRANCH=`, `SUBDIR=`, `GIT_TOKEN=`. See the top of the script.

Then open `http://<dashboard-ip>:8099`, sign in, and use **Manage containers** and **Access**.
Put it behind HTTPS (Nginx Proxy Manager / Traefik) and set `trust_proxy` in the config to the proxy's IP.

## Using it

| Want to… | Do this |
|---|---|
| See what needs updating | The table sorts "needs action" first; the chips summarise. Filters and search are remembered. |
| Add or remove Proxmox containers | **Manage containers**, tick/untick (or edit `/etc/updatedash-gate.allow` on the host). |
| Reach a container directly | Row → **Access**: host, user, password or private key → **Test connection** → **Save**. |
| Manage a non-Proxmox machine | **Manage containers → Add a host by SSH**. |
| See what changed in an update | The version links to the release page; the confirmation shows the notes. |
| Read or copy a log | Row → **Logs** (history) or the log panel → **Copy log**. |
| Keep fewer logs | **Settings → Log retention** (per container; `1` keeps only the latest). |
| Change the password | **Settings → Password**. |

The **Update** button appears only when there is something to update (or the installed version can't be read, which is
shown). **Upgrade OS** appears when apt has pending packages.

### Direct SSH access: what the dashboard needs from the target
* sshd reachable from the dashboard, and a login that is **root**, or a user with **passwordless sudo** (tick "Use sudo").
  Many LXC templates disable root password login; use a key, or set `PermitRootLogin prohibit-password`.
* The first connection trusts and remembers the host key; a **changed key is refused** until you tick "Forget the saved
  host key". Test shows the fingerprint so you can compare it.
* Credentials are encrypted (Fernet) with `/etc/updatedash/secret.key`, are never sent back to the browser, are written
  to a private temp file only for the duration of a connection, and are masked in any output.
* Direct SSH cannot take Proxmox snapshots. If the container is also managed through the gate, snapshots still happen.

## Security model

What a compromised dashboard (someone with the login) can and can't do:

| Control | Effect |
|---|---|
| Gate on the Proxmox host (`pve-gate.py`, forced command, `from=` the dashboard's IP) | The dashboard's host key can only run `pct exec/snapshot/listsnapshot/delsnapshot` and read-only `pct list`, and only for CT IDs in `/etc/updatedash-gate.allow`. No shell, no other `pct` command. |
| `/etc/updatedash-gate.manage` (created by the builder unless `GUI_MANAGE=0`) | Lets the web UI add/remove IDs in the allow list. **Delete the file to turn it off.** |
| `/etc/updatedash-gate.protected` | IDs here can never be added or removed through the dashboard (put Tailscale, your password manager, proxies here). |
| Per-container credentials | Only reach what you gave credentials for; encrypted at rest. |
| Login | Hashed password (scrypt/PBKDF2), signed `HttpOnly`/`SameSite=Strict` session cookie, lockout after 5 failures per IP (and a global cap), sessions end on password change. |
| Requests | Custom-header + `Origin` checks against cross-site requests; strict CSP, no inline scripts; request size limits; all inputs validated. |
| Audit log | Logins, updates, cancels, access/credential changes, allow-list changes, settings: *Settings → Recent activity*. |
| Service | Runs as an unprivileged user with a hardened systemd unit; graceful shutdown waits for running updates. |

Not protected against: someone with root on the dashboard container (they can read the secret key and decrypt stored
credentials), or on the Proxmox host. Back up and update the dashboard like any other privileged service.

## Operations

* **Logs** (service): `journalctl -u updatedash`. **Update logs**: `/var/lib/updatedash/logs/<ctid>/`, retention per container.
* **Backup**: take a Proxmox backup of the dashboard container (it contains the data and `/etc/updatedash/secret.key`
  together). Copying `/var/lib/updatedash` alone is not enough to restore stored credentials without the secret key.
* **Upgrade**: re-run the builder with `CTID=`; config, key, secret key and data are kept. **Rollback** of an app: `pct rollback <CTID> pre-update-<time>`.
* **Uninstall**: `/opt/updatedash/uninstall.sh [--purge]`, then remove the `updatedash` line from the host's
  `/root/.ssh/authorized_keys` and the files `/usr/local/sbin/updatedash-gate`, `/etc/updatedash-gate.*`.
* **Health**: `GET /healthz` (no login) returns `ok`.
* **Tests**: `python -m unittest discover -s tests -t .` (52 tests, including a real `sshd` on localhost); CI runs them on 3.9 and 3.13.

## Configuration
See `config.example.yaml`; every key is documented there. Changes made in the UI (log retention, password) are stored in
`/var/lib/updatedash` and take precedence over the file.

## Troubleshooting
* **A row says "Unreachable: updatedash-gate: request not permitted"**: the container isn't in the allow list (or has no SSH access).
* **"Version unknown"**: the preset couldn't read the installed version. Find the file with the command in `config.example.yaml`
  and add an override in `services:`; the Update button still works.
* **Community-script update fails**: the log shows the script's own error; **Copy log** and look at the last lines.
* **Locked out**: wait 5 minutes, or on the dashboard container `systemctl restart updatedash` (clears the lockout).
  Lost password: `printf '%s' 'new-password' | python3 /opt/updatedash/app.py hash-password`, put the output in
  `password_hash:` in `/etc/updatedash/config.yaml`, delete `/var/lib/updatedash/auth.json`, restart.
