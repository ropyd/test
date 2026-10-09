#!/usr/bin/env bash
# Build (or update) the updatedash LXC from your own git repository.
# Run on the Proxmox VE host as root:
#
#   REPO_URL=https://git.example.com/you/homelab.git \
#     bash -c "$(curl -fsSL https://git.example.com/you/homelab/raw/branch/main/ct/updatedash.sh)"
#
# REPO_URL may be an https/ssh git URL, or a path to a git repo on this Proxmox host.
# Re-run with CTID=<existing id> to pull the latest code into an existing container.
#
# Optional environment variables (defaults in brackets):
#   REPO_URL      git URL or local path (prompted if unset)
#   BRANCH        [main]            SUBDIR   folder in the repo holding install.sh [updatedash]
#   GIT_TOKEN     token for a private https repo   GIT_USER [git]   (sent as HTTP basic auth)
#   CTID          [next free id]    CT_HOSTNAME [updatedash]
#   CORES [1]  RAM [256]  DISK [2] (GB)  BRIDGE [vmbr0]
#   IP [dhcp] or e.g. 10.10.56.50/24      GW  (required with a static IP)
#   STORAGE / TEMPLATE_STORAGE  [first active rootdir / vztmpl storage]
#   PVE_HOST      address of this host as seen by the container [auto]
#   ALLOW_CTIDS   space-separated CT IDs the dashboard may manage [prompted]
#   ASSUME_YES=1  don't ask before changing host files
set -Eeuo pipefail
trap 'printf "\033[1;31mxx\033[0m failed on line %s\n" "$LINENO" >&2' ERR

msg()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mxx\033[0m %s\n' "$*" >&2; exit 1; }
tty_ok() { [ -t 0 ] && [ -t 1 ]; }

[ "$(id -u)" = 0 ] || die "Run as root on the Proxmox host."
command -v pct >/dev/null && command -v pveam >/dev/null || die "This script must run on a Proxmox VE host."

REPO_URL="${REPO_URL:-}"; BRANCH="${BRANCH:-main}"; SUBDIR="${SUBDIR-updatedash}"
GIT_TOKEN="${GIT_TOKEN:-}"; GIT_USER="${GIT_USER:-git}"
CTID="${CTID:-}"; CT_HOSTNAME="${CT_HOSTNAME:-updatedash}"
CORES="${CORES:-1}"; RAM="${RAM:-256}"; DISK="${DISK:-2}"; BRIDGE="${BRIDGE:-vmbr0}"
IP="${IP:-dhcp}"; GW="${GW:-}"
STORAGE="${STORAGE:-}"; TEMPLATE_STORAGE="${TEMPLATE_STORAGE:-}"
PVE_HOST="${PVE_HOST:-}"; ALLOW_CTIDS="${ALLOW_CTIDS:-}"; ASSUME_YES="${ASSUME_YES:-0}"
SRC_DIR=/root/updatedash-src
GATE_BIN="${GATE_BIN:-/usr/local/sbin/updatedash-gate}"
ALLOW_FILE="${ALLOW_FILE:-/etc/updatedash-gate.allow}"
AUTH_KEYS="${AUTH_KEYS:-/root/.ssh/authorized_keys}"

if [ -z "$REPO_URL" ]; then
  tty_ok || die "Set REPO_URL (git URL or a local repo path on this host)."
  read -rp "Git repository URL or local path: " REPO_URL
fi
[ -n "$REPO_URL" ] || die "REPO_URL is empty."
[[ "$BRANCH" =~ ^[A-Za-z0-9._/-]+$ ]] || die "Unsafe BRANCH value."
[[ "$SUBDIR" =~ ^[A-Za-z0-9._/-]*$ ]] || die "Unsafe SUBDIR value."

# ---------------------------------------------------------------- create the container
create_container() {
  [ -n "$CTID" ] || CTID="$(pvesh get /cluster/nextid)"
  [ -n "$STORAGE" ] || STORAGE="$(pvesm status --content rootdir | awk 'NR>1 && $3=="active" {print $1; exit}')"
  [ -n "$TEMPLATE_STORAGE" ] || TEMPLATE_STORAGE="$(pvesm status --content vztmpl | awk 'NR>1 && $3=="active" {print $1; exit}')"
  [ -n "$STORAGE" ] && [ -n "$TEMPLATE_STORAGE" ] || die "Could not find storage; set STORAGE and TEMPLATE_STORAGE."

  msg "Looking for a Debian 13 template"
  pveam update >/dev/null 2>&1 || warn "pveam update failed; using the cached template list"
  local tpl arch
  case "$(dpkg --print-architecture)" in
    amd64) arch=amd64 ;;
    arm64) arch=arm64 ;;
    *) die "Unsupported host architecture: $(dpkg --print-architecture)" ;;
  esac
  tpl="$(pveam available --section system | awk -v a="$arch" '$2 ~ ("^debian-13-standard_.*_" a "\\.tar") {print $2}' | sort -V | tail -1)"
  [ -n "$tpl" ] || die "No debian-13-standard ($arch) template found. Try: pveam update"
  pveam list "$TEMPLATE_STORAGE" | grep -qF "$tpl" || { msg "Downloading $tpl"; pveam download "$TEMPLATE_STORAGE" "$tpl"; }

  local net="name=eth0,bridge=${BRIDGE}"
  if [ "$IP" = dhcp ]; then net+=",ip=dhcp"; else
    [ -n "$GW" ] || die "A static IP needs GW=<gateway>."
    net+=",ip=${IP},gw=${GW}"
  fi

  msg "Creating CT $CTID ($CT_HOSTNAME) on $STORAGE"
  pct create "$CTID" "${TEMPLATE_STORAGE}:vztmpl/${tpl}" \
    --hostname "$CT_HOSTNAME" --unprivileged 1 --onboot 1 --tags updatedash \
    --cores "$CORES" --memory "$RAM" --swap 0 --rootfs "${STORAGE}:${DISK}" \
    --net0 "$net" --features nesting=1 --start 1

  msg "Waiting for the container network"
  local i
  for i in $(seq 1 40); do
    pct exec "$CTID" -- getent hosts deb.debian.org >/dev/null 2>&1 && return 0
    sleep 2
  done
  die "CT $CTID has no network/DNS after 80s. Check BRIDGE, IP/GW and DNS. To start over: pct stop $CTID; pct destroy $CTID --purge"
}

# ---------------------------------------------------------------- get the code in
fetch_source() {
  pct exec "$CTID" -- rm -rf "$SRC_DIR"
  if [ -d "$REPO_URL" ]; then
    command -v git >/dev/null || die "git is needed on the host to use a local repo path."
    msg "Packing $REPO_URL @ $BRANCH from this host"
    local tmp; tmp="$(mktemp)"
    git -C "$REPO_URL" archive --format=tar.gz -o "$tmp" "$BRANCH"
    pct push "$CTID" "$tmp" /root/src.tar.gz
    rm -f "$tmp"
    pct exec "$CTID" -- sh -c "mkdir -p '$SRC_DIR' && tar xzf /root/src.tar.gz -C '$SRC_DIR' && rm -f /root/src.tar.gz"
  else
    msg "Cloning $REPO_URL @ $BRANCH inside the container"
    pct exec "$CTID" -- sh -c 'command -v git >/dev/null || { apt-get update -qq && apt-get install -y -qq --no-install-recommends git ca-certificates >/dev/null; }'
    local gitcmd=(git)
    if [ -n "$GIT_TOKEN" ]; then
      gitcmd+=(-c "http.extraHeader=Authorization: Basic $(printf '%s:%s' "$GIT_USER" "$GIT_TOKEN" | base64 -w0)")
    fi
    pct exec "$CTID" -- "${gitcmd[@]}" clone --quiet --depth 1 --branch "$BRANCH" "$REPO_URL" "$SRC_DIR"
  fi
  INSTALL_DIR="$SRC_DIR${SUBDIR:+/$SUBDIR}"
  pct exec "$CTID" -- test -f "$INSTALL_DIR/install.sh" \
    || die "install.sh not found at ${SUBDIR:-<repo root>} in the repo (set SUBDIR=...)."
}

# ---------------------------------------------------------------- host-side SSH gate
setup_gate() {
  local ct_ip pub keyblob entry
  ct_ip="$(pct exec "$CTID" -- hostname -I | awk '{print $1}')"
  [ -n "$ct_ip" ] || die "Could not read the container's IP."
  pub="$(pct exec "$CTID" -- cat /etc/updatedash/id_ed25519.pub)"
  keyblob="$(awk '{print $2}' <<<"$pub")"

  if [ -z "$ALLOW_CTIDS" ] && tty_ok; then
    echo; pct list; echo
    read -rp "CT IDs the dashboard may update (space separated, e.g. 110 111 112): " ALLOW_CTIDS
  fi
  local id ids=()
  for id in $ALLOW_CTIDS; do
    [[ "$id" =~ ^[0-9]+$ ]] || die "Bad CT id: $id"
    [ "$id" != "$CTID" ] || continue
    pct status "$id" >/dev/null 2>&1 || die "CT $id does not exist."
    ids+=("$id")
  done

  entry="command=\"${GATE_BIN}\",from=\"${ct_ip}\",no-pty,no-port-forwarding,no-X11-forwarding,no-agent-forwarding ${pub}"
  echo
  msg "About to change this Proxmox host:"
  echo "   - install ${GATE_BIN} (restricts the key to pct exec/snapshot)"
  echo "   - allow CT IDs: ${ids[*]:-<none yet>}   (${ALLOW_FILE})"
  echo "   - add this line to ${AUTH_KEYS}:"
  echo "     ${entry:0:150}..."
  if [ "$ASSUME_YES" != 1 ]; then
    tty_ok || { warn "Not interactive and ASSUME_YES!=1: skipping host changes. Do README step 3 by hand."; return 0; }
    read -rp "Proceed? [y/N] " ans
    [[ "$ans" =~ ^[Yy]$ ]] || { warn "Skipped host changes."; return 0; }
  fi

  pct pull "$CTID" /opt/updatedash/pve-gate.py "$GATE_BIN"
  chmod 755 "$GATE_BIN"
  touch "$ALLOW_FILE"
  for id in "${ids[@]}"; do grep -qx "$id" "$ALLOW_FILE" || echo "$id" >> "$ALLOW_FILE"; done
  mkdir -p "$(dirname "$AUTH_KEYS")"; touch "$AUTH_KEYS"
  grep -qF "$keyblob" "$AUTH_KEYS" || echo "$entry" >> "$AUTH_KEYS"
  msg "Gate installed."

  [ -n "$PVE_HOST" ] || PVE_HOST="$(ip -4 route get "$ct_ip" 2>/dev/null | grep -oP 'src \K\S+' | head -1 || true)"
  [ -n "$PVE_HOST" ] || PVE_HOST="$(hostname -I | awk '{print $1}')"
  pct exec "$CTID" -- sed -i "s|^  host: .*|  host: ${PVE_HOST}|" /etc/updatedash/config.yaml
  pct exec "$CTID" -- systemctl restart updatedash
  CT_IP="$ct_ip"
}

# ---------------------------------------------------------------- main
if [ -n "$CTID" ] && pct status "$CTID" >/dev/null 2>&1; then
  msg "CT $CTID exists: updating updatedash in place"
  MODE=update
else
  MODE=create
  create_container
fi

fetch_source
msg "Running install.sh inside CT $CTID"
pct exec "$CTID" -- bash "$INSTALL_DIR/install.sh"
pct exec "$CTID" -- rm -rf "$SRC_DIR"

CT_IP="$(pct exec "$CTID" -- hostname -I | awk '{print $1}')"
[ "$MODE" = create ] && setup_gate
pct exec "$CTID" -- systemctl restart updatedash

echo
msg "Done."
echo "   Dashboard : http://${CT_IP}:8099   (CT $CTID)"
echo "   Login     : admin / $(pct exec "$CTID" -- awk -F'"' '/^password:/ {print $2}' /etc/updatedash/config.yaml)"
echo "   Next      : edit your services in the container: pct exec $CTID -- nano /etc/updatedash/config.yaml"
echo "               then: pct exec $CTID -- systemctl restart updatedash"
