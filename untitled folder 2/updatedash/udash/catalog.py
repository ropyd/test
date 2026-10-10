"""Presets for well-known apps, matched against the container hostname."""
import copy
import re


def _gh(repo, slug):
    # community-scripts store the installed release tag in ~/.<app>; older ones in /opt/*_version.txt
    return {"latest": {"type": "github", "repo": repo},
            "current": f"cat /root/.{slug} 2>/dev/null || cat /opt/*_version.txt 2>/dev/null"}


def _apt(pkg, link=None):
    d = {"latest": {"type": "apt", "package": pkg}}
    if link:
        d["link"] = link
    return d


CATALOG = [
    (r"jellyfin", _apt("jellyfin", "https://github.com/jellyfin/jellyfin/releases")),
    (r"plex", _apt("plexmediaserver", "https://forums.plex.tv/t/plex-media-server/30447")),
    (r"tailscale", _apt("tailscale", "https://tailscale.com/changelog")),
    (r"cloudflared", _apt("cloudflared", "https://github.com/cloudflare/cloudflared/releases")),
    (r"sonarr", _gh("Sonarr/Sonarr", "sonarr")),
    (r"radarr", _gh("Radarr/Radarr", "radarr")),
    (r"prowlarr", _gh("Prowlarr/Prowlarr", "prowlarr")),
    (r"lidarr", _gh("Lidarr/Lidarr", "lidarr")),
    (r"jackett", _gh("Jackett/Jackett", "jackett")),
    (r"autobrr", _gh("autobrr/autobrr", "autobrr")),
    (r"flaresolverr", _gh("FlareSolverr/FlareSolverr", "flaresolverr")),
    (r"vaultwarden", _gh("dani-garcia/vaultwarden", "vaultwarden")),
    (r"homarr", _gh("homarr-labs/homarr", "homarr")),
    (r"heimdall", _gh("linuxserver/Heimdall", "heimdall")),
    (r"traefik", _gh("traefik/traefik", "traefik")),
    (r"nginx.?proxy", _gh("NginxProxyManager/nginx-proxy-manager", "nginxproxymanager")),
]


def auto_service(ctid, name):
    svc = {"name": name, "ctid": ctid, "auto": True}
    for pat, extra in CATALOG:
        if re.search(pat, name.lower()):
            svc.update(copy.deepcopy(extra))
            break
    return svc
