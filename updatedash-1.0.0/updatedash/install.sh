#!/usr/bin/env bash
# Install or upgrade updatedash inside a Debian/Ubuntu LXC. Safe to re-run: it upgrades the program files and
# keeps /etc/updatedash/config.yaml, the SSH key, the secret key and all data in /var/lib/updatedash.
set -euo pipefail

[ "$(id -u)" = 0 ] || { echo "Run as root." >&2; exit 1; }
SRC="$(cd "$(dirname "$0")" && pwd)"
APP=/opt/updatedash

echo "==> Installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends python3 python3-yaml python3-cryptography openssh-client ca-certificates >/dev/null

echo "==> Creating service user and directories"
id updatedash >/dev/null 2>&1 || useradd --system --home-dir /var/lib/updatedash --create-home --shell /usr/sbin/nologin updatedash
install -d -o updatedash -g updatedash -m 0700 /var/lib/updatedash
install -d -m 0755 "$APP" "$APP/udash" "$APP/static"
rm -f "$APP"/udash/*.py "$APP"/static/*          # drop files from older versions
install -m 0644 "$SRC/app.py" "$APP/app.py"
install -m 0755 "$SRC/askpass.sh" "$APP/askpass.sh"
install -m 0755 "$SRC/uninstall.sh" "$APP/uninstall.sh"
install -m 0644 "$SRC/pve-gate.py" "$APP/pve-gate.py"
install -m 0644 "$SRC"/udash/*.py "$APP/udash/"
install -m 0644 "$SRC"/static/* "$APP/static/"
install -d -o root -g updatedash -m 0750 /etc/updatedash

NEWPASS=""
if [ ! -f /etc/updatedash/config.yaml ]; then
  install -m 0640 -o root -g updatedash "$SRC/config.example.yaml" /etc/updatedash/config.yaml
  NEWPASS="$(python3 -c 'import secrets; print(secrets.token_urlsafe(18))')"
  HASH="$(printf '%s' "$NEWPASS" | python3 "$APP/app.py" hash-password)"
  sed -i "s|^password_hash:.*|password_hash: \"$HASH\"|" /etc/updatedash/config.yaml
fi

# key that encrypts stored credentials and signs sessions (kept apart from the data directory)
if [ ! -f /etc/updatedash/secret.key ]; then
  python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())' > /etc/updatedash/secret.key
fi
chown root:updatedash /etc/updatedash/secret.key
chmod 0640 /etc/updatedash/secret.key

# key used to reach the Proxmox host gate
if [ ! -f /etc/updatedash/id_ed25519 ]; then
  ssh-keygen -q -t ed25519 -N '' -C updatedash -f /etc/updatedash/id_ed25519
fi
chown root:updatedash /etc/updatedash/id_ed25519 /etc/updatedash/id_ed25519.pub
chmod 0640 /etc/updatedash/id_ed25519
chmod 0644 /etc/updatedash/id_ed25519.pub

cat >/etc/systemd/system/updatedash.service <<'UNIT'
[Unit]
Description=Update dashboard
After=network-online.target
Wants=network-online.target

[Service]
User=updatedash
Group=updatedash
Environment=UPDATEDASH_CONFIG=/etc/updatedash/config.yaml
Environment=UPDATEDASH_STATE=/var/lib/updatedash
ExecStartPre=/usr/bin/python3 /opt/updatedash/app.py check-config
ExecStart=/usr/bin/python3 /opt/updatedash/app.py
Restart=on-failure
RestartSec=5
TimeoutStopSec=90
UMask=0077
RuntimeDirectory=updatedash
RuntimeDirectoryMode=0700
NoNewPrivileges=yes
CapabilityBoundingSet=
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/updatedash

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable updatedash >/dev/null 2>&1
systemctl is-active --quiet updatedash && systemctl restart updatedash || true

IP="$(hostname -I | awk '{print $1}')"
cat <<MSG

==> Installed. Next steps
1. On the PROXMOX HOST, install the gate (the builder script does this for you; manual steps are in the README).
   Public key to authorise:

   $(cat /etc/updatedash/id_ed25519.pub)

2. Open http://$IP:8099 (put it behind HTTPS before exposing it beyond your LAN).
MSG
if [ -n "$NEWPASS" ]; then
  echo
  echo "   First login:  admin / $NEWPASS"
  echo "   Shown once. Only a hash is stored. Change it any time under Settings."
fi
