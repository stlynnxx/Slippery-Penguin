"""Reusable filesystem inventory helpers for Slippery Penguin."""

from __future__ import annotations

import os
import re
import stat
import subprocess
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

Runner = Callable[..., subprocess.CompletedProcess[Any]]


@dataclass(frozen=True)
class ScanInventory:
    """All discovery results that can be reused throughout one scan."""

    privileged_files: list[str]
    capabilities_by_file: dict[str, list[str]]
    file_metadata: dict[str, dict[str, int | bool]]
    warnings: list[str]
    timings: dict[str, float | int]


def normalise_path(path: str) -> str:
    return os.path.normpath(os.path.abspath(path))


def _decode_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value


def _decode_getcap_path(path: str) -> str:
    path = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), path)
    path = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), path)
    return path.replace(r"\ ", " ")


def deduplicate_paths(paths: Iterable[str]) -> list[str]:
    unique: dict[str, None] = {}
    for path in paths:
        if path:
            unique.setdefault(normalise_path(path), None)
    return list(unique)


def parse_find_output(output: str | bytes | None) -> list[str]:
    """Parse find -print0 output, including paths with spaces or newlines."""
    if output is None:
        return []
    if isinstance(output, bytes):
        paths = [os.fsdecode(part) for part in output.split(b"\0") if part]
    else:
        paths = [part for part in output.split("\0") if part]
    return deduplicate_paths(paths)


def parse_getcap_output(output: str | bytes | None) -> dict[str, list[str]]:
    """Parse getcap output into normalised path -> capability expressions."""
    capabilities: dict[str, list[str]] = {}
    for line in _decode_output(output).splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.rsplit(None, 1)
        if len(parts) != 2:
            continue
        path, expression = parts
        if "=" not in expression:
            continue
        key = normalise_path(_decode_getcap_path(path))
        values = capabilities.setdefault(key, [])
        if expression not in values:
            values.append(expression)
    return capabilities


def _run_command(
    command: list[str],
    *,
    runner: Runner,
    timeout: float | None,
    text: bool = False,
) -> tuple[str, str, int, str | None]:
    kwargs: dict[str, Any] = {"capture_output": True, "check": False}
    if text:
        kwargs.update(text=True, errors="replace")
    if timeout is not None:
        kwargs["timeout"] = timeout
    try:
        completed = runner(command, **kwargs)
    except subprocess.TimeoutExpired as exc:
        warning = f"Command timed out after {timeout}s: {' '.join(command)}"
        return _decode_output(exc.stdout), _decode_output(exc.stderr), -1, warning
    except OSError as exc:
        return "", "", -1, f"Could not run {' '.join(command)}: {exc}"

    stdout = _decode_output(completed.stdout)
    stderr = _decode_output(completed.stderr)
    warning = None
    if completed.returncode:
        warning = f"{' '.join(command)} exited with status {completed.returncode}"
    if stderr.strip():
        detail = stderr.strip()
        if len(detail) > 2000:
            detail = detail[:2000] + "… [stderr truncated]"
        warning = f"{warning}: {detail}" if warning else detail
    return stdout, stderr, completed.returncode, warning


def discover_privileged_files(
    root: str = "/",
    *,
    runner: Runner | None = None,
    timeout: float | None = 300,
) -> tuple[list[str], list[str]]:
    """Find regular SUID and SGID files in a single filesystem traversal."""
    run = runner or subprocess.run
    command = [
        "find",
        root,
        "-type",
        "f",
        "(",
        "-perm",
        "-4000",
        "-o",
        "-perm",
        "-2000",
        ")",
        "-print0",
    ]
    stdout, _stderr, _returncode, warning = _run_command(
        command, runner=run, timeout=timeout
    )
    return parse_find_output(stdout), [warning] if warning else []


def scan_file_capabilities(
    root: str = "/",
    *,
    runner: Runner | None = None,
    timeout: float | None = 300,
) -> tuple[dict[str, list[str]], list[str]]:
    """Run one recursive getcap scan and keep any stdout returned on failure."""
    run = runner or subprocess.run
    stdout, _stderr, _returncode, warning = _run_command(
        ["getcap", "-r", root], runner=run, timeout=timeout, text=True
    )
    return parse_getcap_output(stdout), [warning] if warning else []


def collect_file_metadata(
    paths: Iterable[str],
    *,
    stat_func: Callable[[str], os.stat_result] | None = None,
) -> tuple[dict[str, dict[str, int | bool]], list[str]]:
    """Cache stat metadata once per unique relevant file path."""
    get_stat = stat_func or os.stat
    metadata: dict[str, dict[str, int | bool]] = {}
    warnings: list[str] = []
    for path in deduplicate_paths(paths):
        try:
            info = get_stat(path)
        except OSError as exc:
            warnings.append(f"Could not stat {path}: {exc}")
            continue
        mode = info.st_mode
        metadata[path] = {
            "mode": stat.S_IMODE(mode),
            "uid": info.st_uid,
            "gid": info.st_gid,
            "size": info.st_size,
            "mtime_ns": getattr(info, "st_mtime_ns", int(info.st_mtime * 1e9)),
            "suid": bool(mode & stat.S_ISUID),
            "sgid": bool(mode & stat.S_ISGID),
        }
    return metadata, warnings


def collect_scan_inventory(
    root: str = "/",
    *,
    runner: Runner | None = None,
    stat_func: Callable[[str], os.stat_result] | None = None,
    command_timeout: float | None = 300,
) -> ScanInventory:
    """Collect find, getcap, and reusable metadata once per scan."""
    run = runner or subprocess.run
    total_started = time.perf_counter()

    started = time.perf_counter()
    privileged_files, find_warnings = discover_privileged_files(
        root, runner=run, timeout=command_timeout
    )
    find_seconds = time.perf_counter() - started

    started = time.perf_counter()
    capabilities, getcap_warnings = scan_file_capabilities(
        root, runner=run, timeout=command_timeout
    )
    getcap_seconds = time.perf_counter() - started

    started = time.perf_counter()
    file_metadata, metadata_warnings = collect_file_metadata(
        [*privileged_files, *capabilities.keys()], stat_func=stat_func
    )
    metadata_seconds = time.perf_counter() - started

    timings: dict[str, float | int] = {
        "find_seconds": round(find_seconds, 6),
        "getcap_seconds": round(getcap_seconds, 6),
        "metadata_seconds": round(metadata_seconds, 6),
        "total_seconds": round(time.perf_counter() - total_started, 6),
        "find_commands": 1,
        "getcap_commands": 1,
    }
    return ScanInventory(
        privileged_files=privileged_files,
        capabilities_by_file=capabilities,
        file_metadata=file_metadata,
        warnings=find_warnings + getcap_warnings + metadata_warnings,
        timings=timings,
    )
