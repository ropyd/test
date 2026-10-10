# Security

## What this tool is
A web UI that can run commands **as root inside your containers** (the dashboard itself runs as an unprivileged user, and its Proxmox login is an unprivileged user that can only run the gate through sudo) (through the Proxmox gate or direct SSH). Treat the
dashboard like a privileged admin host: anyone who can sign in can change the software on everything it manages.

## Quick hardening checklist
1. Turn on **two-factor sign-in** (Settings). Keep the recovery codes offline.
2. Serve **HTTPS**: `tls: auto` (new installs) or an HTTPS reverse proxy with `trust_proxy` set.
3. Set **`allow_from`** to your admin LAN/VPN so nothing else can reach the login page.
4. List sensitive containers (Tailscale, password manager, proxies) in `/etc/updatedash-gate.protected` on the Proxmox host.
   Turn GUI management off (`rm /etc/updatedash-gate.manage`) once the list is set, if you don't need to change it often.
5. Prefer the Proxmox gate over stored SSH credentials where you can: the gate only runs a fixed list of update commands.
6. Send syslog off the Proxmox host and the dashboard (remote syslog); the gate and the dashboard both log there.
7. Back up the dashboard container to encrypted storage (its backup contains the stored credentials and the key).
8. Keep it updated (re-run the builder with `CTID=`), and read release notes for sensitive services before updating them.

## Reporting a problem
Open a private security advisory on the repository, or contact the maintainer directly. Please don't post exploit
details in a public issue. See `docs/SECURITY-REVIEW.md` for the threat model and known limitations.
