"""Microsoft 365 Defender XDR investigation CLI."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("xdr-cli")
except PackageNotFoundError:
    # Fallback for source-tree execution without an editable install
    # (e.g., PYTHONPATH=src). "0.0.0+unknown" is SemVer-valid build
    # metadata and makes broken installs visible in `xdr --version`.
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
