# updatedash

A small dashboard that runs in its own LXC. It shows, per service, the installed version, the latest
version, and whether an update is available, with a button to run the update.

```
browser ──► updatedash LXC ──ssh (restricted key)──► Proxmox host ──pct exec──► service LXCs
```

The dashboard LXC never gets a shell on the host. The SSH key is locked to `pve-gate.py`, which only
allows `pct exec / snapshot / listsnapshot / delsnapshot` for the CT IDs you list.

## Deploy (one command, from your own git repo)

Keep this folder and `ct/updatedash.sh` in your repo:

```
your-repo/
  ct/updatedash.sh
  updatedash/        (app.py, install.sh, pve-gate.py, config.example.yaml, static/)
```

Then, as root in the **Proxmox host** shell:

```
REPO_URL=https://git.example.com/you/homelab.git \
  bash -c "$(curl -fsSL https://git.example.com/you/homelab/raw/branch/main/ct/updatedash.sh)"
```

* `REPO_URL` can also be a git repo on the Proxmox host itself (e.g. `/root/homelab`); the script packs it
  with `git archive` and pushes it in, so no network access to a git server is needed.
* Private https repo: add `GIT_TOKEN=...` (and `GIT_USER=...` if your server needs a specific user name).
  For a private raw URL, use `curl -fsSL -H "Authorization: token <T>" <url>`, or download the script first.
* It creates a Debian 13 LXC (1 core, 256 MB, 2 GB, DHCP by default), pulls the repo, runs `install.sh`,
  and then, after showing you exactly what it will change and asking, installs the SSH gate on the host,
  allows the CT IDs you give it, and points the dashboard at the host.
* Useful options: `CTID=`, `IP=10.10.56.50/24 GW=10.10.56.1`, `BRIDGE=`, `STORAGE=`, `BRANCH=`, `SUBDIR=`,
  `ALLOW_CTIDS="110 111 112"`, `ASSUME_YES=1`. The full list is at the top of `ct/updatedash.sh`.
* **Update later:** run the same command with `CTID=<dashboard CT id>`. It pulls the latest code into the
  existing container, re-runs `install.sh` (your config and key are kept) and restarts the service.

Every container listed in `/etc/updatedash-gate.allow` on the host is **discovered automatically** and shown,
whether it is up to date, stopped or has an update. Known apps are recognised by hostname (Sonarr, Radarr,
Prowlarr, Lidarr, Jackett, autobrr, Vaultwarden, Flaresolverr, Homarr, Heimdall, Traefik, Nginx Proxy Manager,
Jellyfin, Plex, Tailscale, cloudflared). Other containers still show their OS package updates and can be
OS-upgraded. You only need `services:` in `/etc/updatedash/config.yaml` to override a preset or add checks for
an app it doesn't know (matched by CT ID).

## Adding and removing containers

**From the web UI:** click **Manage containers**, then tick or untick a container. Ticking adds its CT ID to the
host's allow list and checks it straight away.

**From the terminal (optional, good for automation):** the allow list is just a file on the Proxmox host,
`/etc/updatedash-gate.allow`, one CT ID per line. Edit it by hand or script it; the dashboard picks changes up on
the next check. Both methods edit the same file.

### Security model (what a compromised dashboard can and can't do)
* The dashboard's SSH key only runs the gate (`updatedash-gate`), locked to the dashboard's IP. It can only
  `pct exec`/snapshot containers listed in the allow file, plus read-only `pct list`. It never gets a host shell.
* Web-UI management is switched on by the file `/etc/updatedash-gate.manage` on the host. With it on, someone who
  gets into the dashboard could add *other* containers to the allow list. Two limits stay in force:
  * CT IDs in `/etc/updatedash-gate.protected` (put Tailscale, your password manager and reverse proxies here)
    can **never** be added or removed through the dashboard, and the dashboard's own container can't be added.
  * Only containers that exist can be added; nothing else about the host can be changed.
* To turn web-UI management off: `rm /etc/updatedash-gate.manage` on the host (or re-run the builder with
  `GUI_MANAGE=0`). The allow list is then hand-edited only. Protected IDs are edited only by hand.
* Every update takes a snapshot first, the login uses basic auth (use it behind HTTPS), and POSTs need a custom
  header to block cross-site requests.

## Versions and release notes
Each row shows the installed version, and when an update exists, `→ newer version ↗`. The link opens the release
notes or changelog (GitHub release page for GitHub-hosted apps; Jellyfin, Plex, Tailscale and cloudflared link to their
changelogs; set `link:` in a config override for anything else). The update confirmation shows
`installed → new` with the release notes preview for GitHub apps. "unknown" installed means the preset couldn't
read the version; hover it for the command that was tried.

### Manual deploy (no script)
1. Create a Debian 13 LXC, copy this folder in (`pct push`), and run `bash updatedash/install.sh`.
2. On the Proxmox host:
   ```
   pct pull <CTID> /opt/updatedash/pve-gate.py /usr/local/sbin/updatedash-gate
   chmod 755 /usr/local/sbin/updatedash-gate
   printf '110\n111\n' > /etc/updatedash-gate.allow     # CT IDs the dashboard may touch
   echo 'command="/usr/local/sbin/updatedash-gate",from="<DASHBOARD-IP>",no-pty,no-port-forwarding,no-X11-forwarding,no-agent-forwarding <PUBLIC KEY LINE>' >> /root/.ssh/authorized_keys
   ```
3. Edit `/etc/updatedash/config.yaml` and restart the service.

## Find the version file for community-script apps
Community-script apps record the installed release in `/root/.<appname>` (lowercase), older ones in
`/opt/*_version.txt`. The presets read those. Check one with:
```
pct exec <CTID> -- sh -c 'ls -A /root | grep "^\\."; ls /opt/*_version.txt 2>/dev/null'
```
If a preset can't read the version it shows "Version unknown"; add an override in `services:` with the right
`current:` command. You can still use "Update anyway".

## Notes
* Check the first update on a non-critical container (Sonarr), not Vaultwarden.
* Community-script apps are updated with their own `update` command in its supported unattended mode (`PHS_SILENT=1`). A running update can be stopped with **Cancel**; if a command had already started inside the container it may keep running, so check it with `pct exec <CTID> -- ps aux`.
* A snapshot `pre-update-YYYYMMDD-HHMMSS` is taken before each update, and old ones are pruned after a
  successful update. Roll back with `pct rollback <CTID> <snapshot>`.
* Put it behind NPM (`http` → dashboard IP : 8099) with your wildcard cert, and don't expose it publicly.
  Basic-auth credentials travel in clear text over plain HTTP, so use HTTPS.
* Re-running `install.sh` upgrades the app and keeps your config and key.
