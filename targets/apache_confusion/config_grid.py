"""Apache Confusion config grid — discrete dimension definitions.

Each config is a curated combination of Apache module settings that
creates different request processing behaviour.  The grid is NOT
a free-form grammar — it's a fixed set of interesting combinations
designed to trigger module-interaction confusion patterns.

Usage:
    from config_grid import CONFIGS, get_port
    for cfg in CONFIGS:
        port = get_port(cfg["id"])
        print(f"Config {cfg['id']}: port={port}, {cfg['description']}")
"""

from __future__ import annotations

# ── Dimension definitions ────────────────────────────────────────

CONFIG_DIMENSIONS = {
    "rewrite": ["off", "simple", "proxy_passthrough", "per_dir"],
    "backend": ["static", "cgi", "proxy_http", "proxy_ajp"],
    "authz": ["none", "location", "directory", "files"],
    "path_norm": ["default", "merge_slashes_off", "allow_encoded"],
    "extra": ["none", "mod_negotiation", "mod_autoindex", "htaccess_override"],
}

# ── Curated configs (12+1 baseline) ─────────────────────────────

CONFIGS: list[dict] = [
    {
        "id": 0,
        "description": "Baseline: static, location authz, no rewrite",
        "rewrite": "off", "backend": "static", "authz": "location",
        "path_norm": "default", "extra": "none",
        "config_file": "configs/00_baseline.conf",
    },
    {
        "id": 1,
        "description": "RewriteRule proxy passthrough (filename confusion)",
        "rewrite": "proxy_passthrough", "backend": "proxy_http", "authz": "location",
        "path_norm": "default", "extra": "none",
        "config_file": "configs/01_rewrite_proxy.conf",
    },
    {
        "id": 2,
        "description": "Simple rewrite + CGI + directory authz",
        "rewrite": "simple", "backend": "cgi", "authz": "directory",
        "path_norm": "default", "extra": "none",
        "config_file": "configs/02_rewrite_cgi.conf",
    },
    {
        "id": 3,
        "description": "Per-dir rewrite + proxy + Files authz + encoded slashes",
        "rewrite": "per_dir", "backend": "proxy_http", "authz": "files",
        "path_norm": "allow_encoded", "extra": "none",
        "config_file": "configs/03_perdir_proxy_files.conf",
    },
    {
        "id": 4,
        "description": "Proxy AJP + location authz + MergeSlashes off",
        "rewrite": "proxy_passthrough", "backend": "proxy_ajp", "authz": "location",
        "path_norm": "merge_slashes_off", "extra": "none",
        "config_file": "configs/04_proxy_ajp_location.conf",
    },
    {
        "id": 5,
        "description": "Per-dir rewrite + static + directory authz + encoded slashes",
        "rewrite": "per_dir", "backend": "static", "authz": "directory",
        "path_norm": "allow_encoded", "extra": "none",
        "config_file": "configs/05_perdir_static_directory.conf",
    },
    {
        "id": 6,
        "description": "mod_negotiation MultiViews + location authz",
        "rewrite": "off", "backend": "static", "authz": "location",
        "path_norm": "default", "extra": "mod_negotiation",
        "config_file": "configs/06_negotiation.conf",
    },
    {
        "id": 7,
        "description": "Rewrite + proxy + directory authz + autoindex",
        "rewrite": "simple", "backend": "proxy_http", "authz": "directory",
        "path_norm": "default", "extra": "mod_autoindex",
        "config_file": "configs/07_rewrite_proxy_directory.conf",
    },
    {
        "id": 8,
        "description": "Proxy passthrough + no authz (permissive baseline)",
        "rewrite": "proxy_passthrough", "backend": "proxy_http", "authz": "none",
        "path_norm": "default", "extra": "none",
        "config_file": "configs/08_proxy_noauth.conf",
    },
    {
        "id": 9,
        "description": "Per-dir rewrite + CGI + location authz + encoded slashes",
        "rewrite": "per_dir", "backend": "cgi", "authz": "location",
        "path_norm": "allow_encoded", "extra": "none",
        "config_file": "configs/09_perdir_cgi_location.conf",
    },
    {
        "id": 10,
        "description": "Negotiation + Files authz + MergeSlashes off",
        "rewrite": "simple", "backend": "static", "authz": "files",
        "path_norm": "merge_slashes_off", "extra": "mod_negotiation",
        "config_file": "configs/10_negotiation_files.conf",
    },
    {
        "id": 11,
        "description": "AJP proxy + directory authz",
        "rewrite": "off", "backend": "proxy_ajp", "authz": "directory",
        "path_norm": "default", "extra": "none",
        "config_file": "configs/11_proxy_ajp_directory.conf",
    },
    {
        "id": 12,
        "description": ".htaccess AllowOverride + location authz",
        "rewrite": "off", "backend": "static", "authz": "location",
        "path_norm": "default", "extra": "htaccess_override",
        "config_file": "configs/12_htaccess_override.conf",
    },
]

# ── Port mapping ─────────────────────────────────────────────────

BASE_PORT = 9100


def get_port(config_id: int) -> int:
    """Return the Docker host port for a given config ID."""
    return BASE_PORT + config_id


def get_config(config_id: int) -> dict:
    """Look up config by ID."""
    for cfg in CONFIGS:
        if cfg["id"] == config_id:
            return cfg
    raise ValueError(f"Unknown config_id: {config_id}")
