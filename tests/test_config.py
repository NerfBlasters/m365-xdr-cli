"""Tests for config management."""

import sys
from pathlib import Path

import pytest

from xdr_cli.config import Config, ensure_config_dir, load_config, save_config


@pytest.fixture()
def config_dir(tmp_path, monkeypatch):
    """Use a temp dir instead of ~/.xdr-cli/."""
    config_path = tmp_path / ".xdr-cli"
    monkeypatch.setenv("XDR_CLI_HOME", str(config_path))
    return config_path


def test_default_config():
    cfg = Config()
    assert cfg.tenant_id == ""
    assert cfg.client_id == ""
    assert cfg.auth_mode == "device_code"
    assert cfg.default_limit == 25


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Unix directory permissions not enforced on Windows",
)
def test_ensure_config_dir_creates_directory(config_dir):
    assert not config_dir.exists()
    ensure_config_dir()
    assert config_dir.exists()
    assert config_dir.stat().st_mode & 0o777 == 0o700


def test_ensure_config_dir_creates_queries_subdir(config_dir):
    ensure_config_dir()
    queries_dir = config_dir / "queries"
    assert queries_dir.exists()


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX file mode bits are not the Windows privacy boundary",
)
def test_ensure_config_dir_does_not_rechmod_already_private_directories(
    config_dir, monkeypatch
):
    config_dir.mkdir(mode=0o700)
    queries_dir = config_dir / "queries"
    queries_dir.mkdir(mode=0o700)

    def unexpected_chmod(*_args, **_kwargs):
        raise AssertionError("already-private directories must not be rewritten")

    monkeypatch.setattr(Path, "chmod", unexpected_chmod)
    assert ensure_config_dir() == config_dir


def test_save_and_load_config(config_dir):
    ensure_config_dir()
    cfg = Config(tenant_id="test-tenant", client_id="test-client")
    save_config(cfg)

    loaded = load_config()
    assert loaded.tenant_id == "test-tenant"
    assert loaded.client_id == "test-client"
    assert loaded.auth_mode == "device_code"


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX file mode bits are not the Windows privacy boundary",
)
def test_save_config_with_secret_repairs_private_modes(config_dir):
    config_dir.mkdir(mode=0o755)
    config_dir.chmod(0o755)

    previous_umask = __import__("os").umask(0o002)
    try:
        save_config(
            Config(
                tenant_id="test-tenant",
                client_id="test-client",
                auth_mode="client_credentials",
                client_secret="fabricated-secret",
            )
        )
    finally:
        __import__("os").umask(previous_umask)

    assert config_dir.stat().st_mode & 0o777 == 0o700
    assert (config_dir / "config.toml").stat().st_mode & 0o777 == 0o600
    assert 'client_secret = "fabricated-secret"' in (
        config_dir / "config.toml"
    ).read_text()


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX file mode bits are not the Windows privacy boundary",
)
def test_load_config_repairs_legacy_secret_file_mode(config_dir):
    config_dir.mkdir(mode=0o700)
    config_file = config_dir / "config.toml"
    config_file.write_text(
        'tenant_id = "tenant"\nclient_id = "client"\nclient_secret = "legacy-secret"\n'
    )
    config_file.chmod(0o644)

    loaded = load_config()

    assert loaded.client_secret == "legacy-secret"
    assert config_file.stat().st_mode & 0o777 == 0o600


def test_load_config_returns_default_when_no_file(config_dir):
    ensure_config_dir()
    cfg = load_config()
    assert cfg.tenant_id == ""


def test_load_config_preserves_unknown_keys(config_dir):
    """Unknown keys in TOML should not crash loading."""
    ensure_config_dir()
    config_file = config_dir / "config.toml"
    config_file.write_text('tenant_id = "t"\nfuture_key = "value"\n')
    cfg = load_config()
    assert cfg.tenant_id == "t"


def test_get_config_home_respects_env_var(tmp_path, monkeypatch):
    custom_path = tmp_path / "custom"
    monkeypatch.setenv("XDR_CLI_HOME", str(custom_path))
    from xdr_cli.config import get_config_home
    assert get_config_home() == custom_path


def test_load_config_ignores_legacy_default_format(tmp_path, monkeypatch):
    """A config.toml with default_format (now-removed) loads cleanly."""
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    (tmp_path / "config.toml").write_text(
        'tenant_id = "t"\nclient_id = "c"\ndefault_format = "table"\n'
    )
    cfg = load_config()
    assert cfg.tenant_id == "t"
    assert not hasattr(cfg, "default_format")


def test_session_collection_default_and_opt_out(config_dir):
    assert load_config().schema_collect_on_session_end is True
    save_config(Config(schema_collect_on_session_end=False))
    assert load_config().schema_collect_on_session_end is False


def test_session_collection_requires_boolean(config_dir):
    from xdr_cli.exceptions import ConfigError

    config_dir.mkdir()
    (config_dir / "config.toml").write_text('schema_collect_on_session_end = "false"\n')
    with pytest.raises(ConfigError, match="TOML boolean"):
        load_config(validate_maintenance=True)


def test_session_schema_defaults_and_configured_round_trip(config_dir):
    default = load_config()
    assert default.schema_collect_on_session_end is True
    assert default.schema_refresh_on_session_end is True
    assert default.schema_explore_on_session_end is True
    assert default.schema_explore_max_queries == 5
    assert default.schema_maintenance_timeout_seconds == 90
    save_config(Config(
        schema_refresh_on_session_end=False,
        schema_explore_on_session_end=False,
        schema_explore_max_queries=17,
        schema_stale_seconds=0,
    ))
    configured = load_config()
    assert configured.schema_collect_on_session_end is True
    assert configured.schema_refresh_on_session_end is False
    assert configured.schema_explore_on_session_end is False
    assert configured.schema_explore_max_queries == 17
    assert configured.schema_stale_seconds == 0


@pytest.mark.parametrize("key", [
    "schema_collect_on_session_end", "schema_refresh_on_session_end",
    "schema_explore_on_session_end",
])
@pytest.mark.parametrize("value", ['"false"', "0", "1", "[]"])
def test_session_schema_toggles_reject_non_booleans_in_toml(config_dir, key, value):
    from xdr_cli.exceptions import ConfigError

    config_dir.mkdir()
    (config_dir / "config.toml").write_text(f"{key} = {value}\n")
    with pytest.raises(ConfigError, match=key):
        load_config(validate_maintenance=True)


@pytest.mark.parametrize("value", ["true", "false", "0", "-1", "1001", '"5"', "5.0"])
def test_session_explore_budget_rejects_invalid_toml(config_dir, value):
    from xdr_cli.exceptions import ConfigError

    config_dir.mkdir()
    (config_dir / "config.toml").write_text(f"schema_explore_max_queries = {value}\n")
    with pytest.raises(ConfigError, match="schema_explore_max_queries"):
        load_config(validate_maintenance=True)


@pytest.mark.parametrize("value", [
    "true", "false", "-1", '"86400"', "1.5", "inf", "-inf", "nan",
])
def test_schema_refresh_age_rejects_invalid_toml(config_dir, value):
    from xdr_cli.exceptions import ConfigError

    config_dir.mkdir()
    (config_dir / "config.toml").write_text(f"schema_stale_seconds = {value}\n")
    with pytest.raises(ConfigError, match="schema_stale_seconds"):
        load_config(validate_maintenance=True)


@pytest.mark.parametrize("value", [1, 5, 1000])
def test_session_explore_budget_accepts_inclusive_bounds(config_dir, value):
    save_config(Config(schema_explore_max_queries=value))
    assert load_config().schema_explore_max_queries == value


@pytest.mark.parametrize("value", [0, 86400, 3600.0, 0.0])
def test_schema_refresh_age_accepts_zero_and_positive_seconds(config_dir, value):
    save_config(Config(schema_stale_seconds=value))
    assert load_config().schema_stale_seconds == value
    assert type(load_config().schema_stale_seconds) is int


@pytest.mark.parametrize("value", [0.05, 90, 3600.0])
def test_session_maintenance_deadline_round_trip(config_dir, value):
    save_config(Config(schema_maintenance_timeout_seconds=value))
    assert load_config().schema_maintenance_timeout_seconds == value


@pytest.mark.parametrize("value", [
    True, False, 0, -1, 3600.01, 3601, 1e308, float("inf"), float("nan"), "90",
])
def test_session_maintenance_deadline_rejects_invalid_values(value):
    from xdr_cli.exceptions import ConfigError

    with pytest.raises(ConfigError, match="schema_maintenance_timeout_seconds"):
        Config(schema_maintenance_timeout_seconds=value)


@pytest.mark.parametrize("options", [
    {"schema_refresh_on_session_end": 1},
    {"schema_explore_on_session_end": "true"},
    {"schema_explore_max_queries": True},
    {"schema_explore_max_queries": 0},
    {"schema_stale_seconds": False},
    {"schema_stale_seconds": -1},
])
def test_direct_config_construction_enforces_schema_option_types(options):
    from xdr_cli.exceptions import ConfigError

    with pytest.raises(ConfigError):
        Config(**options)
