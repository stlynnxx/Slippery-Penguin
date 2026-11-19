"""Opt-in, evidence-driven runtime tracing for Slippery Penguin.

Tracing executes the selected binary. It is diagnostic instrumentation, not a
sandbox and must only be used on systems the operator is authorised to assess.
"""

from __future__ import annotations

import asyncio
import os
import signal
import tempfile
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class RuntimeTraceResult:
    """Outcome of one runtime tracing attempt."""

    status: str
    returncode: int | None
    observations: list[str]
    diagnostics: list[str]
    timed_out: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _normalise(path: str) -> str:
    return os.path.normpath(os.path.abspath(path))


def select_trace_candidates(
    privileged_binaries: Iterable[str],
    findings_by_binary: Mapping[str, Mapping[str, Any]],
) -> dict[str, list[str]]:
    """Select privileged binaries with strong, documented static evidence.

    Eligibility requires a discovered SUID/SGID path and at least one of:
    - a HIGH or CRITICAL configured-string finding; or
    - a GTFOBins match explicitly marked for the SUID context.
    """
    privileged = {_normalise(path) for path in privileged_binaries}
    selected: dict[str, list[str]] = {}

    for binary, findings in findings_by_binary.items():
        if _normalise(binary) not in privileged:
            continue

        reasons: list[str] = []
        for finding in findings.get("flags", []) or []:
            if not isinstance(finding, Mapping):
                continue
            severity = str(finding.get("severity", "")).strip()
            severity_level = severity.upper().split(maxsplit=1)[0] if severity else ""
            if severity_level in {"HIGH", "CRITICAL"}:
                label = str(finding.get("string", "")).strip() or "unnamed finding"
                reasons.append(f"{severity}: {label}")

        for match in findings.get("gtfo", []) or []:
            if not isinstance(match, Mapping):
                continue
            if str(match.get("context", "")).lower() == "suid":
                match_type = str(match.get("type", "unknown"))
                reasons.append(f"GTFOBins SUID match: {match_type}")

        if reasons:
            selected[binary] = sorted(set(reasons))

    return dict(sorted(selected.items()))


def _signal_process_group(process: asyncio.subprocess.Process, sig: int) -> None:
    """Signal only the isolated session created for this trace."""
    try:
        os.killpg(process.pid, sig)
    except ProcessLookupError:
        pass
    except PermissionError:
        try:
            process.kill() if sig == signal.SIGKILL else process.terminate()
        except ProcessLookupError:
            pass


async def _stop_process_group(
    process: asyncio.subprocess.Process,
    communicate_task: asyncio.Task[tuple[bytes, bytes]],
    grace_period: float,
) -> None:
    """Terminate the isolated trace session and reap the strace process."""
    _signal_process_group(process, signal.SIGTERM)
    try:
        await asyncio.wait_for(asyncio.shield(communicate_task), timeout=grace_period)
    except TimeoutError:
        _signal_process_group(process, signal.SIGKILL)
        await communicate_task


def read_trace_output(trace_path: str) -> list[str]:
    with open(trace_path, "r", encoding="utf-8", errors="replace") as trace_file:
        return [line.rstrip("\n") for line in trace_file if line.strip()]


async def trace_binary(
    binary: str,
    *,
    timeout: float = 2.0,
    grace_period: float = 0.5,
    strace_executable: str = "strace",
) -> RuntimeTraceResult:
    """Trace execve activity for one selected binary with bounded cleanup.

    A new session is created for each trace so timeout/cancellation signals can
    only target this trace's process group, never the scanner's own group.
    Application stdout is discarded; strace observations and diagnostics are
    captured separately.
    """
    if timeout <= 0:
        raise ValueError("timeout must be greater than zero")
    if grace_period <= 0:
        raise ValueError("grace_period must be greater than zero")

    fd, trace_path = tempfile.mkstemp(prefix="slippery-penguin-strace-", suffix=".log")
    os.close(fd)
    process: asyncio.subprocess.Process | None = None
    communicate_task: asyncio.Task[tuple[bytes, bytes]] | None = None

    try:
        try:
            process = await asyncio.create_subprocess_exec(
                strace_executable,
                "-f",
                "-qq",
                "-e",
                "trace=execve",
                "-o",
                trace_path,
                binary,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
        except OSError as exc:
            return RuntimeTraceResult(
                status="unavailable",
                returncode=None,
                observations=[],
                diagnostics=[f"Could not start strace: {exc}"],
            )

        communicate_task = asyncio.create_task(process.communicate())
        timed_out = False
        diagnostics: list[str] = []

        try:
            _stdout, stderr = await asyncio.wait_for(
                asyncio.shield(communicate_task), timeout=timeout
            )
        except TimeoutError:
            timed_out = True
            await _stop_process_group(process, communicate_task, grace_period)
            _stdout, stderr = communicate_task.result()
        except asyncio.CancelledError:
            await _stop_process_group(process, communicate_task, grace_period)
            raise
        except OSError as exc:
            await _stop_process_group(process, communicate_task, grace_period)
            diagnostics.append(f"Trace communication failed: {exc}")
            stderr = b""

        if stderr:
            decoded = stderr.decode(errors="replace").strip()
            if decoded:
                diagnostics.extend(line for line in decoded.splitlines() if line)

        try:
            observations = await asyncio.to_thread(read_trace_output, trace_path)
        except OSError as exc:
            observations = []
            diagnostics.append(f"Could not read trace output: {exc}")

        returncode = process.returncode
        if timed_out:
            status = "timed_out"
        elif not observations and returncode not in (0, None):
            status = "failed"
        elif returncode not in (0, None):
            status = "completed_nonzero_exit"
        else:
            status = "completed"

        return RuntimeTraceResult(
            status=status,
            returncode=returncode,
            observations=observations,
            diagnostics=diagnostics,
            timed_out=timed_out,
        )
    finally:
        if process is not None and process.returncode is None:
            if communicate_task is not None and not communicate_task.done():
                await _stop_process_group(process, communicate_task, grace_period)
            else:
                _signal_process_group(process, signal.SIGKILL)
                await process.wait()
        try:
            os.unlink(trace_path)
        except FileNotFoundError:
            pass


def confirm_runtime_trace(input_func=input) -> bool:
    """Require an explicit affirmative response before executing any target.

    EOF and every response other than the exact word 'yes' fail closed.
    """
    try:
        return (
            input_func(
                "Type 'y' and press enter to execute the listed runtime traces, or anything else to cancel: "
            )
            .strip()
            .lower()
            == "y"
        )
    except (EOFError, KeyboardInterrupt):
        return False
