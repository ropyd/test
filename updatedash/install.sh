#!/usr/bin/env bash
# Install updatedash inside a Debian/Ubuntu LXC. Safe to re-run: it upgrades the app
# files and leaves /etc/updatedash/config.yaml and the SSH key alone.
set -euo pipefail

[ "$(id -u)" = 0 ] || { echo "Run as root." >&2; exit 1; }
SRC="$(cd "$(dirname "$0")" && pwd)"

echo "==> Installing packages"
apt-get update -qq
apt-get install -y --no-install-recommends python3 python3-yaml openssh-client ca-certificates >/dev/null

echo "==> Creating service user and directories"
id updatedash >/dev/null 2>&1 || useradd --system --home-dir /var/lib/updatedash --create-home --shell /usr/sbin/nologin updatedash
install -d -m 0755 /opt/updatedash/static
install -m 0644 "$SRC/app.py" /opt/updatedash/app.py
install -m 0644 "$SRC"/static/* /opt/updatedash/static/
install -m 0644 "$SRC/pve-gate.py" /opt/updatedash/pve-gate.py
install -d -o root -g updatedash -m 0750 /etc/updatedash

NEWPASS=""
if [ ! -f /etc/updatedash/config.yaml ]; then
  install -m 0640 -o root -g updatedash "$SRC/config.example.yaml" /etc/updatedash/config.yaml
  NEWPASS="$(python3 -c 'import secrets; print(secrets.token_urlsafe(18))')"
  sed -i "s|^password:.*|password: \"$NEWPASS\"|" /etc/updatedash/config.yaml
fi

if [ ! -f /etc/updatedash/id_ed25519 ]; then
  ssh-keygen -q -t ed25519 -N '' -C updatedash -f /etc/updatedash/id_ed25519
fi
chown root:updatedash /etc/updatedash/id_ed25519 /etc/updatedash/id_ed25519.pub
chmod 0640 /etc/updatedash/id_ed25519
chmod 0644 /etc/updatedash/id_ed25519.pub

cat >/etc/systemd/system/updatedash.service <<'EOF'
[Unit]
Description=Update dashboard
After=network-online.target
Wants=network-online.target

[Service]
User=updatedash
Group=updatedash
Environment=UPDATEDASH_CONFIG=/etc/updatedash/config.yaml
Environment=UPDATEDASH_STATE=/var/lib/updatedash
ExecStart=/usr/bin/python3 /opt/updatedash/app.py
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/updatedash

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable updatedash >/dev/null 2>&1

IP="$(hostname -I | awk '{print $1}')"
cat <<EOF

==> Installed. Next steps
1. On the PROXMOX HOST, install the gate (see README step 3). Public key to authorise:

   $(cat /etc/updatedash/id_ed25519.pub)

2. Edit /etc/updatedash/config.yaml (pve.host, your services and their CT IDs), then:
     systemctl restart updatedash
3. Open http://$IP:8099
EOF
if [ -n "$NEWPASS" ]; then
  echo
  echo "   Login:  admin / $NEWPASS    (also stored in /etc/updatedash/config.yaml)"
fi
