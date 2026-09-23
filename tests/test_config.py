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
