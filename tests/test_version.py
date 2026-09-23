"""Verify the version source-of-truth: pyproject.toml is canonical,
xdr_cli.__version__ reads from package metadata.

This test catches regressions where someone re-hardcodes __version__
instead of letting it load dynamically from the installed package.
"""
import tomllib
from pathlib import Path

import pytest

import xdr_cli


def test_version_matches_pyproject():
    """xdr_cli.__version__ must match the version in pyproject.toml.

    Skipped when __version__ ends in '+unknown' — that's the
    PackageNotFoundError fallback (no installed metadata to compare
    against), which is a legitimate state for source-tree-only
    execution but doesn't have a meaningful comparison value.
    """
    if xdr_cli.__version__.endswith("+unknown"):
        pytest.skip(
            "Package not installed (no metadata to compare against). "
            "Run `pip install -e .` to enable this test."
        )

    pyproject = Path(__file__).parent.parent / "pyproject.toml"
    with pyproject.open("rb") as f:
        data = tomllib.load(f)
    expected = data["project"]["version"]
    assert xdr_cli.__version__ == expected, (
        f"Version drift: pyproject.toml says {expected!r}, "
        f"xdr_cli.__version__ says {xdr_cli.__version__!r}. "
        "If you bumped pyproject.toml, ensure __init__.py reads it "
        "dynamically via importlib.metadata.version('xdr-cli')."
    )
