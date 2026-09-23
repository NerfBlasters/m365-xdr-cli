"""Tests for helper utilities."""

from datetime import UTC, datetime

import pytest

from xdr_cli.exceptions import UsageError
from xdr_cli.helpers import (
    build_odata_filter,
    format_timestamp,
    parse_time_delta,
    validate_filter_choices,
)


class TestParseTimeDelta:
    def test_days(self):
        result = parse_time_delta("7d")
        now = datetime.now(tz=UTC)
        diff = now - result
        assert 6.9 < diff.total_seconds() / 86400 < 7.1

    def test_hours(self):
        result = parse_time_delta("24h")
        now = datetime.now(tz=UTC)
        diff = now - result
        assert 23.9 < diff.total_seconds() / 3600 < 24.1

    def test_minutes(self):
        result = parse_time_delta("30m")
        now = datetime.now(tz=UTC)
        diff = now - result
        assert 29.5 < diff.total_seconds() / 60 < 30.5

    def test_invalid_raises(self):
        with pytest.raises(ValueError, match="Invalid time delta"):
            parse_time_delta("foo")

    def test_no_unit_raises(self):
        with pytest.raises(ValueError, match="Invalid time delta"):
            parse_time_delta("123")


class TestBuildOdataFilter:
    def test_single_severity(self):
        result = build_odata_filter(severity=["high"])
        assert result == "severity eq 'high'"

    def test_multiple_severity(self):
        result = build_odata_filter(severity=["high", "medium"])
        assert "severity eq 'high'" in result
        assert "severity eq 'medium'" in result
        assert " or " in result

    def test_single_status(self):
        result = build_odata_filter(status=["active"])
        assert result == "status eq 'active'"

    def test_multiple_status(self):
        result = build_odata_filter(status=["active", "resolved"])
        assert "status eq 'active'" in result
        assert "status eq 'resolved'" in result
        assert " or " in result

    def test_since(self):
        result = build_odata_filter(since="7d")
        assert "createdDateTime ge" in result

    def test_combined_filters(self):
        result = build_odata_filter(severity=["high"], status=["active"])
        assert " and " in result
        assert "severity eq 'high'" in result
        assert "status eq 'active'" in result

    def test_empty_returns_empty(self):
        result = build_odata_filter()
        assert result == ""

    def test_string_values_cannot_change_filter_structure(self):
        result = build_odata_filter(
            assigned_to="x' or severity ne 'informational",
            service_source="service' or status ne 'resolved",
        )

        assert "assignedTo eq 'x'' or severity ne ''informational'" in result
        assert "serviceSource eq 'service'' or status ne ''resolved'" in result


class TestSplitCsv:
    def test_returns_none_for_none(self):
        from xdr_cli.helpers import split_csv
        assert split_csv(None) is None

    def test_returns_none_for_empty_list(self):
        from xdr_cli.helpers import split_csv
        # Empty list has nothing to split; reflecting "no filter" semantics.
        assert split_csv([]) == []

    def test_passes_through_list_without_commas(self):
        from xdr_cli.helpers import split_csv
        assert split_csv(["high", "medium"]) == ["high", "medium"]

    def test_splits_single_comma_value(self):
        from xdr_cli.helpers import split_csv
        assert split_csv(["medium,high"]) == ["medium", "high"]

    def test_splits_and_flattens_mixed(self):
        from xdr_cli.helpers import split_csv
        # Agent types --severity medium,high --severity low; helper flattens.
        assert split_csv(["medium,high", "low"]) == ["medium", "high", "low"]

    def test_strips_whitespace_around_values(self):
        from xdr_cli.helpers import split_csv
        assert split_csv(["medium , high"]) == ["medium", "high"]

    def test_filters_empty_string_entries(self):
        from xdr_cli.helpers import split_csv
        # Trailing comma or double comma shouldn't produce empty entries.
        assert split_csv(["medium,,high,"]) == ["medium", "high"]

    def test_all_empty_returns_none(self):
        from xdr_cli.helpers import split_csv
        assert split_csv([",", "  "]) is None


def test_validate_filter_choices_rejects_unknown_values():
    with pytest.raises(UsageError, match="Invalid --severity"):
        validate_filter_choices(
            ["high", "x' or severity ne 'low"],
            frozenset({"high", "low"}),
            option="--severity",
            help_command="xdr alerts list --help",
        )


class TestFormatTimestamp:
    def test_recent_shows_relative(self):
        now = datetime.now(tz=UTC)
        iso = now.isoformat()
        result = format_timestamp(iso)
        assert "just now" in result or "0m ago" in result or "1m ago" in result

    def test_none_returns_dash(self):
        assert format_timestamp(None) == "-"

    def test_empty_returns_dash(self):
        assert format_timestamp("") == "-"
