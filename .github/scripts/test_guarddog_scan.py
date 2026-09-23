"""Security regressions for order-independent binary-finding fingerprints."""

import copy

from guarddog_scan import fingerprint


def report(binary_text):
    return {"results": {"bundled_binary": binary_text}, "risk_score": {"label": "high_risk"}}


def test_binary_inventory_order_does_not_change_exception_identity():
    header = "Binary file/s detected in package:\n"
    a, b = "a" * 64, "b" * 64
    original = report(f"{header}{a}: cli.exe (exe), cli-32.exe (exe)\n{b}: gui.exe (exe)")
    reordered = report(f"{header}{b}: gui.exe (exe)\n{a}: cli-32.exe (exe), cli.exe (exe)")
    assert fingerprint(original) == fingerprint(reordered)
    assert original["results"]["bundled_binary"].endswith("gui.exe (exe)")


def test_changed_hash_filename_or_added_binary_never_matches_exception():
    header = "Binary file/s detected in package:\n"
    original = report(f"{header}{'a' * 64}: cli.exe (exe)")
    for text in (
        f"{header}{'b' * 64}: cli.exe (exe)",
        f"{header}{'a' * 64}: payload.exe (exe)",
        f"{header}{'a' * 64}: cli.exe (exe), payload.exe (exe)",
        f"{header}{'a' * 64}: cli.exe (exe), cli.exe (exe)",
        f"{header}{'a' * 64}: cli.exe (exe)\nunknown format",
    ):
        assert fingerprint(original) != fingerprint(report(text))
    changed = copy.deepcopy(original)
    changed["results"]["new-threat"] = [{"code": "new suspicious code"}]
    assert fingerprint(original) != fingerprint(changed)
