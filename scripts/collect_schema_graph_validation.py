#!/usr/bin/env python3
"""Collect a live validation bundle for semantic graph probing.

The installed ``xdr`` command keeps seed-bearing source/target stage artifacts
in its normal private result store. This collector copies only the physical
schema result, cache-only target plans, final aggregate observation reports,
and their sidecars into the requested bundle. Sensitive seed/query diagnostics
are available only through an explicit option.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

DEFAULT_SOURCES = (
    "DeviceNetworkEvents.DeviceId",
    "EntraIdSignInEvents.AccountUpn",
    "EntraIdSignInEvents.AccountObjectId",
    "DeviceFileEvents.SHA256",
    "EmailEvents.NetworkMessageId",
    "CloudAppEvents.RawEventData#/UserId",
)


def _safe_name(value: str) -> str:
    return "".join(character if character.isalnum() else "_" for character in value).strip("_")


def _receipt(stdout: str) -> dict[str, Any] | None:
    for line in stdout.splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and value.get("status") == "success" and value.get("run_id"):
            return value
    return None


_PRIVATE_METADATA_KEYS = {
    "alert_id",
    "anchors",
    "data_path",
    "incident_id",
    "meta_path",
    "query",
    "request_ids",
    "request-id",
    "client-request-id",
    "client_request_id",
    "command",
    "request_id",
    "resolved_parameters",
    "session",
    "session_id",
    "session_label",
    "stage_run_ids",
    "tenant_key",
    "tenant_binding",
    "message",
    "detail",
    "original",
    "invalid",
    "allowed",
    "suggestions",
    "corrected_argv",
    "help_command",
}


def _timestamp() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _append_debug(path: Path, event: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(_sanitized(event), separators=(",", ":")) + "\n")
        handle.flush()


def _error_summary(records: list[dict[str, Any]]) -> dict[str, Any] | None:
    for record in records:
        error = record.get("error")
        if record.get("status") != "error" or not isinstance(error, dict):
            continue
        original = error.get("original")
        summary = {
            "type": error.get("type"),
            "code": error.get("code"),
            "exit_code": error.get("exit_code"),
            "retryable": error.get("retryable"),
        }
        if isinstance(original, dict):
            summary["original_type"] = original.get("type")
        return _sanitized(summary)
    return None


def _progress(index: int, total: int, state: str, label: str, detail: str = "") -> None:
    suffix = f" — {detail}" if detail else ""
    print(f"[{index:02d}/{total:02d}] {state:<4} {label}{suffix}", file=sys.stderr, flush=True)


def _public_argv(argv: list[str]) -> list[str]:
    public = list(argv)
    if "--private-debug-output" in public:
        index = public.index("--private-debug-output") + 1
        if index < len(public):
            public[index] = "<private-debug-path>"
    return public


def _sanitized(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _sanitized(item)
            for key, item in value.items()
            if key not in _PRIVATE_METADATA_KEYS
        }
    if isinstance(value, list):
        return [_sanitized(item) for item in value]
    return value


def _copy_artifact(receipt: dict[str, Any], destination: Path) -> None:
    data_source = Path(str(receipt["data_path"])).resolve()
    meta_source = Path(str(receipt["meta_path"])).resolve()
    if not data_source.is_file() or not meta_source.is_file():
        raise RuntimeError("reported result artifact is incomplete")
    shutil.copyfile(data_source, destination.with_suffix(".jsonl"))
    metadata = json.loads(meta_source.read_text(encoding="utf-8"))
    destination.with_suffix(".meta.json").write_text(
        json.dumps(_sanitized(metadata), separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def _run(
    argv: list[str],
    *,
    destination: Path,
    environment: dict[str, str],
    debug_path: Path,
    progress_index: int,
    progress_total: int,
    include_private_debug: bool = False,
) -> dict[str, Any]:
    label = " ".join(argv[1:4])
    public_argv = _public_argv(argv)
    _progress(progress_index, progress_total, "RUN", label)
    _append_debug(
        debug_path,
        {
            "event": "command-start",
            "at": _timestamp(),
            "index": progress_index,
            "argv": public_argv,
        },
    )
    started = time.monotonic()
    try:
        completed = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
    except OSError as exc:
        completed = subprocess.CompletedProcess(
            argv,
            1,
            stdout="",
            stderr=f"{type(exc).__name__}: {exc}\n",
        )
    duration_ms = round((time.monotonic() - started) * 1000)
    public_records = []
    for line in completed.stdout.splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        public_records.append(_sanitized(value))
    destination.with_suffix(".stdout.jsonl").write_text(
        "".join(json.dumps(item, separators=(",", ":")) + "\n" for item in public_records),
        encoding="utf-8",
    )
    stderr_text = (
        completed.stderr
        if include_private_debug
        else "[omitted from value-free validation bundle]\n"
    )
    destination.with_suffix(".stderr.txt").write_text(stderr_text, encoding="utf-8")
    receipt = _receipt(completed.stdout)
    if receipt is not None:
        _copy_artifact(receipt, destination)
    error = _error_summary(public_records)
    result = {
        "argv": public_argv,
        "exit_code": completed.returncode,
        "receipt_run_id": receipt.get("run_id") if receipt else None,
        "duration_ms": duration_ms,
        "error": error,
    }
    state = "OK" if completed.returncode in {0, 14} else "FAIL"
    detail = f"exit={completed.returncode}, {duration_ms / 1000:.1f}s"
    if receipt is not None:
        detail += f", receipt={receipt['run_id']}"
    if error and error.get("code"):
        detail += f", {error['code']}"
    _progress(progress_index, progress_total, state, label, detail)
    _append_debug(
        debug_path,
        {
            "event": "command-end",
            "at": _timestamp(),
            "index": progress_index,
            **result,
        },
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--xdr", default="xdr", help="Path to the installed xdr executable")
    parser.add_argument("--source", action="append", dest="sources")
    parser.add_argument("--lookback", default="30d")
    parser.add_argument("--samples", type=int, default=5)
    parser.add_argument("--batch-size", type=int, default=20)
    parser.add_argument(
        "--timeout",
        type=int,
        default=120,
        help="Per-query HTTP timeout passed to schema observe",
    )
    parser.add_argument(
        "--target-limit",
        type=int,
        default=40,
        help="Targets per source for validation; use 0 for exhaustive coverage",
    )
    parser.add_argument(
        "--include-private-debug",
        action="store_true",
        help="Include sensitive sampled values and compiled KQL; protect the bundle",
    )
    args = parser.parse_args()
    if args.target_limit < 0:
        parser.error("--target-limit must be zero or greater")
    if args.timeout < 1:
        parser.error("--timeout must be one or greater")

    output = args.output_dir.expanduser().resolve()
    output.mkdir(parents=True, exist_ok=False)
    if os.name == "posix":
        output.chmod(0o700)
    environment = dict(os.environ)
    sources = tuple(args.sources or DEFAULT_SOURCES)
    progress_total = 2 + (2 * len(sources))
    debug_path = output / "collector.debug.jsonl"
    commands: list[dict[str, Any]] = []

    commands.append(
        _run(
            [args.xdr, "schema", "refresh"],
            destination=output / "00_schema_refresh",
            environment=environment,
            debug_path=debug_path,
            progress_index=1,
            progress_total=progress_total,
            include_private_debug=args.include_private_debug,
        )
    )
    if commands[-1]["exit_code"] != 0:
        print(f"schema refresh failed; inspect {output}", file=sys.stderr)
        return int(commands[-1]["exit_code"])

    for ordinal, source in enumerate(sources, start=1):
        stem = f"{ordinal:02d}_{_safe_name(source)}"
        target_limit_args = (
            ["--max-targets", str(args.target_limit)]
            if args.target_limit > 0
            else ["--exhaustive"]
        )
        plan = _run(
            [
                args.xdr,
                "schema",
                "observe",
                source,
                "--plan-only",
                "--batch-size",
                str(args.batch_size),
                *target_limit_args,
            ],
            destination=output / f"{stem}_plan",
            environment=environment,
            debug_path=debug_path,
            progress_index=ordinal * 2,
            progress_total=progress_total,
            include_private_debug=args.include_private_debug,
        )
        commands.append(plan)
        if plan["exit_code"] != 0:
            _progress(
                (ordinal * 2) + 1,
                progress_total,
                "SKIP",
                f"schema observe {source}",
                "plan failed",
            )
            continue
        private_debug_args = []
        if args.include_private_debug:
            private_debug_args = [
                "--private-debug-output",
                str(output / f"{stem}_private_debug.jsonl"),
            ]
        commands.append(
            _run(
                [
                    args.xdr,
                    "schema",
                    "observe",
                    source,
                    "--lookback",
                    args.lookback,
                    "--samples",
                    str(args.samples),
                    "--batch-size",
                    str(args.batch_size),
                    "--timeout",
                    str(args.timeout),
                    *target_limit_args,
                    *private_debug_args,
                ],
                destination=output / f"{stem}_observe",
                environment=environment,
                debug_path=debug_path,
                progress_index=(ordinal * 2) + 1,
                progress_total=progress_total,
                include_private_debug=args.include_private_debug,
            )
        )

    commands.append(
        _run(
            [args.xdr, "schema", "candidates"],
            destination=output / "99_candidates",
            environment=environment,
            debug_path=debug_path,
            progress_index=progress_total,
            progress_total=progress_total,
            include_private_debug=args.include_private_debug,
        )
    )

    manifest = {
        "schema_version": 1,
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "contains_seed_values": args.include_private_debug,
        "collection_scope": "schema-graph-live-validation",
        "sources": list(sources),
        "lookback": args.lookback,
        "samples": args.samples,
        "batch_size": args.batch_size,
        "timeout": args.timeout,
        "target_limit": args.target_limit or None,
        "commands": commands,
        "private_debug": args.include_private_debug,
        "excluded": (
            ["authentication material", "unrelated private result artifacts"]
            if args.include_private_debug
            else [
                "schema observe source-sample artifacts",
                "schema observe target-batch metadata containing literal KQL",
                "tenant identifiers and authentication material",
            ]
        ),
    }
    (output / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if os.name == "posix":
        for path in output.iterdir():
            path.chmod(0o600)
        output.chmod(0o700)
    failures = [item for item in commands if item["exit_code"] not in {0, 14}]
    sensitivity = "SENSITIVE" if args.include_private_debug else "value-free"
    print(f"wrote {sensitivity} validation bundle to {output}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
