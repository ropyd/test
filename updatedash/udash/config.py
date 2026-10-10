"""Configuration loading and validation."""
import ipaddress
import os
from pathlib import Path

import yaml

CONFIG_PATH = os.environ.get("UPDATEDASH_CONFIG", "/etc/updatedash/config.yaml")
STATE_DIR = Path(os.environ.get("UPDATEDASH_STATE", "/var/lib/updatedash"))

DEFAULTS = {
    "listen": "127.0.0.1:8099",
    "username": "admin",
    "session_hours": 12,
    "allow_from": [],           # if set, only these IPs/CIDRs may reach the dashboard at all (else 403)
    "trust_proxy": [],          # IPs/CIDRs of reverse proxies whose X-Forwarded-* headers are trusted
    "tls": "off",               # "auto" = generate and use a self-signed certificate (see tls_names)
    "tls_names": [],            # extra DNS names/IPs for the self-signed certificate
    "tls_cert": "",
    "tls_key": "",
    "session_idle_minutes": 480,
    "max_connections": 64,
    "socket_timeout": 30,
    "transport": "pve",
    "snapshot_before_update": True,
    "keep_snapshots": 2,
    "check_interval_minutes": 360,
    "github_token": "",
    "log_retention": 5,         # default; changeable at runtime in Settings
    "max_parallel_updates": 2,
    "secret_key_file": "/etc/updatedash/secret.key",
}


class ConfigError(Exception):
    pass


def load_config(path=None):
    path = path or CONFIG_PATH
    try:
        with open(path) as f:
            cfg = yaml.safe_load(f) or {}
    except OSError as e:
        raise ConfigError(f"cannot read {path}: {e}")
    except yaml.YAMLError as e:
        raise ConfigError(f"invalid YAML in {path}: {e}")
    if not isinstance(cfg, dict):
        raise ConfigError("the config must be a YAML mapping")
    for k, v in DEFAULTS.items():
        cfg.setdefault(k, v)
    cfg["services"] = cfg.get("services") or []
    cfg.setdefault("discover", cfg["transport"] == "pve")
    if os.environ.get("UPDATEDASH_PASSWORD"):
        cfg["password"] = os.environ["UPDATEDASH_PASSWORD"]
    if cfg["transport"] not in ("pve", "local"):
        raise ConfigError("transport must be 'pve' or 'local'")
    if cfg["transport"] == "pve" and not (cfg.get("pve") or {}).get("host"):
        # Direct-SSH-only installs are fine, but the gate needs a host.
        cfg["pve"] = dict(cfg.get("pve") or {})
    if cfg["tls"] not in ("off", "auto"):
        raise ConfigError("tls must be 'off' or 'auto' (or set tls_cert and tls_key)")
    for key, lo, hi in (("session_idle_minutes", 5, 10080), ("max_connections", 8, 1024), ("socket_timeout", 1, 300), ("session_hours", 1, 720), ("log_retention", 1, 200), ("max_parallel_updates", 1, 8),
                        ("keep_snapshots", 0, 20), ("check_interval_minutes", 5, 10080)):
        try:
            cfg[key] = int(cfg[key])
        except (TypeError, ValueError):
            raise ConfigError(f"{key} must be a number")
        if not lo <= cfg[key] <= hi:
            raise ConfigError(f"{key} must be between {lo} and {hi}")
    nets = []
    for item in cfg["trust_proxy"] or []:
        try:
            nets.append(ipaddress.ip_network(str(item), strict=False))
        except ValueError:
            raise ConfigError(f"trust_proxy entry is not an IP or CIDR: {item}")
    cfg["_trusted_nets"] = nets
    allow = []
    for item in cfg["allow_from"] or []:
        try:
            allow.append(ipaddress.ip_network(str(item), strict=False))
        except ValueError:
            raise ConfigError(f"allow_from entry is not an IP or CIDR: {item}")
    cfg["_allow_nets"] = allow
    seen = set()
    for s in cfg["services"]:
        if not isinstance(s, dict) or not s.get("name") or s.get("ctid") is None:
            raise ConfigError("every entry in `services` needs a name and a ctid")
        s["ctid"] = int(s["ctid"])
        if s["ctid"] in seen:
            raise ConfigError(f"duplicate ctid {s['ctid']} in services")
        seen.add(s["ctid"])
    return cfg


def is_allowed_client(cfg, ip):
    """True when no allowlist is configured, or the client address is inside it."""
    if not cfg["_allow_nets"]:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in cfg["_allow_nets"])


def is_trusted_proxy(cfg, ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in cfg["_trusted_nets"])
