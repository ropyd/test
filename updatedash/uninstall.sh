#!/usr/bin/env bash
# Remove updatedash from this container. Add --purge to also delete its data and secrets.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "Run as root." >&2; exit 1; }
systemctl disable --now updatedash 2>/dev/null || true
rm -f /etc/systemd/system/updatedash.service
systemctl daemon-reload
rm -rf /opt/updatedash
if [ "${1:-}" = "--purge" ]; then
  rm -rf /var/lib/updatedash /etc/updatedash
  userdel updatedash 2>/dev/null || true
  echo "Removed, including configuration, credentials, logs and the secret key."
else
  echo "Removed the program. Kept /etc/updatedash and /var/lib/updatedash (use --purge to delete them)."
fi
echo "On the Proxmox host, also remove the user: userdel updatedash-gate; rm -rf /var/lib/updatedash-gate /etc/sudoers.d/updatedash-gate (and any updatedash line in /root/.ssh/authorized_keys from older installs), plus /usr/local/sbin/updatedash-gate and /etc/updatedash-gate.*"
