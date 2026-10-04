"""Config management for ~/.xdr-cli/config.toml."""

from __future__ import annotations

import json
import math
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

    api_backend: str = "auto"
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
    schema_collect_on_session_end: bool = True
    schema_refresh_on_session_end: bool = True
    schema_explore_on_session_end: bool = True
    schema_explore_max_queries: int = 5
    schema_maintenance_timeout_seconds: float = 90
    schema_stale_seconds: int = 86400
    # A full semantic collection is advisory-only and due weekly by default.
    schema_collection_stale_seconds: int = 604800

    def __post_init__(self) -> None:
        from xdr_cli.exceptions import ConfigError

        if self.api_backend not in ("auto", "official", "portal-cookie"):
            raise ConfigError("api_backend must be auto, official, or portal-cookie.")

        for name in (
            "schema_collect_on_session_end",
            "schema_refresh_on_session_end",
            "schema_explore_on_session_end",
        ):
            if type(getattr(self, name)) is not bool:
                raise ConfigError(f"{name} must be a TOML boolean.")
        if type(self.schema_explore_max_queries) is not int or not (
            1 <= self.schema_explore_max_queries <= 1000
        ):
            raise ConfigError("schema_explore_max_queries must be an integer between 1 and 1000.")
        age = self.schema_stale_seconds
        if (
            type(age) not in (int, float)
            or age < 0
            or (type(age) is float and (not math.isfinite(age) or not age.is_integer()))
        ):
            raise ConfigError("schema_stale_seconds must be finite nonnegative whole seconds.")
        self.schema_stale_seconds = int(age)
        deadline = self.schema_maintenance_timeout_seconds
        if (
            type(deadline) not in (int, float)
            or deadline <= 0
            or deadline > 3600
            or (type(deadline) is float and not math.isfinite(deadline))
        ):
            raise ConfigError(
                "schema_maintenance_timeout_seconds must be finite positive seconds, at most 3600."
            )

    def list_limit(self, override: int | None) -> int:
        """Resolve a list command's --limit, defaulting to `default_limit`.

        Validated here rather than in __post_init__ so a bad value fails only
        the list commands that use it, not every command's config load.
        """
        from xdr_cli.exceptions import ConfigError

        if override is not None:
            return override
        value = self.default_limit
        if type(value) is not int or value < 1:
            raise ConfigError("default_limit must be a positive integer.")
        return value

    def check_maintenance_config(self) -> None:
        """Reject deferred upkeep errors at the upkeep boundary, not CLI startup."""
        error = getattr(self, "_maintenance_config_error", None)
        if error is not None:
            raise error


# Allowed keys for serialization. Unknown keys are diagnosed on load.
_CONFIG_FIELDS = {f.name for f in Config.__dataclass_fields__.values()}
_MAINTENANCE_FIELDS = {name for name in _CONFIG_FIELDS if name.startswith("schema_")}


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


def load_config(*, validate_maintenance: bool = False) -> Config:
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
    from xdr_cli.exceptions import ConfigError
    from xdr_cli.output import err_console

    unknown = sorted(set(data) - _CONFIG_FIELDS)
    if unknown:
        err_console.print(
            "Warning: unknown config keys " + json.dumps(unknown) + "; check config.toml.",
            markup=False,
        )
    known = {k: v for k, v in data.items() if k in _CONFIG_FIELDS}
    error = None
    try:
        config = Config(**known)
    except ConfigError as exc:
        # Keep authentication and local recovery available. These fallback
        # defaults cannot authorize upkeep: its entry point checks the error.
        config = Config(**{k: v for k, v in known.items() if k not in _MAINTENANCE_FIELDS})
        error = exc
    if any(name.startswith("schema_") for name in unknown):
        error = ConfigError("Unknown schema config keys; correct config.toml before schema upkeep.")
    if error is not None:
        error.help_command = "xdr auth status"
        config._maintenance_config_error = error
        config._maintenance_config_values = {
            name: value for name, value in data.items() if name.startswith("schema_")
        }
        err_console.print(
            "Warning: config schema upkeep disabled until corrected: " + error.message,
            markup=False,
        )
        if validate_maintenance:
            raise error
    return config


def save_config(config: Config) -> None:
    """Save config to TOML file."""
    config_home = ensure_config_dir()
    config_file = config_home / "config.toml"
    data = asdict(config)
    data["api_backend"] = getattr(config, "_api_backend_preference", config.api_backend)
    # Auth login must still save credentials during upkeep-config recovery.
    # Preserve the rejected settings instead of replacing them with defaults
    # that would silently enable queries on the next invocation.
    data.update(getattr(config, "_maintenance_config_values", {}))
    # Don't persist empty secrets
    if not data.get("client_secret"):
        data.pop("client_secret", None)
    atomic_write_secret(config_file, tomli_w.dumps(data))
