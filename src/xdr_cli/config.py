"""Config management for ~/.xdr-cli/config.toml."""

from __future__ import annotations

import os
import stat
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path

import tomli_w

from xdr_cli.secret_files import atomic_write_secret


@dataclass
class Config:
    """XDR CLI configuration."""

    tenant_id: str = ""
    client_id: str = ""
    auth_mode: str = "device_code"  # "device_code" or "client_credentials"
    client_secret: str = ""
    default_limit: int = 25
    # 120s default tuned for library hunts: r1/r2 queries with joins +
    # aggregations routinely run 30-90s against Defender. The previous 30s
    # default reflected single-event lookups and caused summary-mode hunts
    # to look like "empty results" when in fact the API was just slow.
    # Override per-call with `xdr hunt run --timeout` / `library-run --timeout`.
    api_timeout: int = 120
    # Optional investigation telemetry expires after 30 minutes of inactivity.
    session_timeout_seconds: int = 1800
    schema_stale_seconds: int = 86400
    # A full semantic collection is advisory-only and due weekly by default.
    schema_collection_stale_seconds: int = 604800


# Allowed keys for serialization (skip unknown keys on load)
_CONFIG_FIELDS = {f.name for f in Config.__dataclass_fields__.values()}


def get_config_home() -> Path:
    """Return the XDR CLI config directory path."""
    env = os.environ.get("XDR_CLI_HOME")
    if env:
        return Path(env)
    return Path.home() / ".xdr-cli"


def ensure_config_dir() -> Path:
    """Create config directory and subdirectories if they don't exist."""
    config_home = get_config_home()
    config_home.mkdir(mode=0o700, parents=True, exist_ok=True)
    queries_home = config_home / "queries"
    queries_home.mkdir(mode=0o700, exist_ok=True)
    if os.name == "posix":
        # Avoid a needless metadata write on read-only mounts when the privacy
        # boundary is already correct; repair only directories that are wider.
        if stat.S_IMODE(config_home.stat().st_mode) != 0o700:
            config_home.chmod(0o700)
        if stat.S_IMODE(queries_home.stat().st_mode) != 0o700:
            queries_home.chmod(0o700)
    return config_home


def load_config() -> Config:
    """Load config from TOML file. Returns defaults if file doesn't exist."""
    config_file = get_config_home() / "config.toml"
    if not config_file.exists():
        return Config()
    with open(config_file, "rb") as f:
        data = tomllib.load(f)
    if (
        os.name == "posix"
        and data.get("client_secret")
        and stat.S_IMODE(config_file.stat().st_mode) != 0o600
    ):
        # Upgrade credential-bearing files created by older releases before
        # returning the secret to any caller.
        config_file.chmod(0o600)
    # Filter to known fields only
    known = {k: v for k, v in data.items() if k in _CONFIG_FIELDS}
    return Config(**known)


def save_config(config: Config) -> None:
    """Save config to TOML file."""
    config_home = ensure_config_dir()
    config_file = config_home / "config.toml"
    data = asdict(config)
    # Don't persist empty secrets
    if not data.get("client_secret"):
        data.pop("client_secret", None)
    atomic_write_secret(config_file, tomli_w.dumps(data))
