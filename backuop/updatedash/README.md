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

Finish by editing the services in `/etc/updatedash/config.yaml` inside the container, then
`systemctl restart updatedash`.

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
Many community-script containers record the installed version in a file. Find it with:
```
pct exec <CTID> -- sh -c 'ls /opt/*_version.txt /opt/*/version* ~/.*version* 2>/dev/null; cat /opt/*_version.txt 2>/dev/null'
```
Put the matching `cat <file>` in `current:`. A service with no readable version shows "Unknown", but you can
still use "Update anyway".

## Notes
* Check the first update on a non-critical container (Sonarr), not Vaultwarden.
* The community `update` menu is interactive. updatedash runs it in a pty and presses Enter on the default
  item. If a particular app hangs, set `update:` for it to a command that works non-interactively. Jobs are
  killed after `update_timeout` (default 1800 s).
* A snapshot `pre-update-YYYYMMDD-HHMMSS` is taken before each update, and old ones are pruned after a
  successful update. Roll back with `pct rollback <CTID> <snapshot>`.
* Put it behind NPM (`http` → dashboard IP : 8099) with your wildcard cert, and don't expose it publicly.
  Basic-auth credentials travel in clear text over plain HTTP, so use HTTPS.
* Re-running `install.sh` upgrades the app and keeps your config and key.
