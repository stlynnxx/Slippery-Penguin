from __future__ import annotations

import asyncio
import signal
import unittest
from pathlib import Path
from unittest.mock import patch

from runtime_tracing import confirm_runtime_trace, select_trace_candidates, trace_binary


class ConfirmationTests(unittest.TestCase):
    def test_only_exact_yes_confirms_execution(self):
        self.assertTrue(confirm_runtime_trace(lambda _prompt: "yes"))
        self.assertTrue(confirm_runtime_trace(lambda _prompt: " YES "))
        self.assertFalse(confirm_runtime_trace(lambda _prompt: "y"))
        self.assertFalse(confirm_runtime_trace(lambda _prompt: "no"))
        self.assertFalse(confirm_runtime_trace(lambda _prompt: ""))

    def test_eof_and_keyboard_interrupt_fail_closed(self):
        def eof(_prompt):
            raise EOFError

        def interrupted(_prompt):
            raise KeyboardInterrupt

        self.assertFalse(confirm_runtime_trace(eof))
        self.assertFalse(confirm_runtime_trace(interrupted))


class CandidateSelectionTests(unittest.TestCase):
    def test_only_privileged_binaries_with_high_risk_evidence_are_selected(self):
        privileged = ["/usr/bin/high", "/usr/bin/gtfo", "/usr/bin/low"]
        findings = {
            "/usr/bin/high": {"flags": [{"severity": "HIGH WITH CONTEXT", "string": "marker"}]},
            "/usr/bin/gtfo": {"gtfo": [{"context": "suid", "type": "shell"}]},
            "/usr/bin/low": {"flags": [{"severity": "LOW", "string": "benign"}]},
            "/tmp/unprivileged": {"flags": [{"severity": "CRITICAL", "string": "marker"}]},
        }
        selected = select_trace_candidates(privileged, findings)
        self.assertEqual(set(selected), {"/usr/bin/high", "/usr/bin/gtfo"})
        self.assertIn("HIGH WITH CONTEXT: marker", selected["/usr/bin/high"])

    def test_sgid_inventory_entry_can_be_selected(self):
        selected = select_trace_candidates(
            ["/usr/bin/sgid-tool"],
            {"/usr/bin/sgid-tool": {"flags": [{"severity": "HIGH", "string": "marker"}]}},
        )
        self.assertIn("/usr/bin/sgid-tool", selected)


class FakeProcess:
    def __init__(self, pid=98765, returncode=0, stderr=b""):
        self.pid = pid
        self.returncode = returncode
        self.stderr = stderr

    async def communicate(self):
        return b"", self.stderr

    async def wait(self):
        return self.returncode

    def kill(self):
        self.returncode = -signal.SIGKILL

    def terminate(self):
        self.returncode = -signal.SIGTERM


class RuntimeTraceTests(unittest.IsolatedAsyncioTestCase):
    async def test_observations_are_separate_from_diagnostics(self):
        process = FakeProcess(stderr=b"strace diagnostic\n")

        async def spawn(*command, **kwargs):
            trace_path = command[command.index("-o") + 1]
            Path(trace_path).write_text('execve("/fixture", ["/fixture"], 0x0) = 0\n')
            self.assertTrue(kwargs["start_new_session"])
            return process

        with patch("runtime_tracing.asyncio.create_subprocess_exec", side_effect=spawn):
            result = await trace_binary("/fixture", timeout=1)

        self.assertEqual(result.status, "completed")
        self.assertEqual(len(result.observations), 1)
        self.assertEqual(result.diagnostics, ["strace diagnostic"])

    async def test_nonzero_target_exit_is_preserved_with_observations(self):
        process = FakeProcess(returncode=7)

        async def spawn(*command, **kwargs):
            trace_path = command[command.index("-o") + 1]
            Path(trace_path).write_text('execve("/fixture", ["/fixture"], 0x0) = 0\\n')
            return process

        with patch("runtime_tracing.asyncio.create_subprocess_exec", side_effect=spawn):
            result = await trace_binary("/fixture", timeout=1)

        self.assertEqual(result.status, "completed_nonzero_exit")
        self.assertEqual(result.returncode, 7)
        self.assertTrue(result.observations)

    async def test_invalid_timeout_is_rejected_before_execution(self):
        with self.assertRaises(ValueError):
            await trace_binary("/fixture", timeout=0)

    async def test_missing_strace_is_not_reported_as_an_observation(self):
        async def missing(*args, **kwargs):
            raise FileNotFoundError("strace")

        with patch("runtime_tracing.asyncio.create_subprocess_exec", side_effect=missing):
            result = await trace_binary("/fixture", timeout=1)

        self.assertEqual(result.status, "unavailable")
        self.assertEqual(result.observations, [])
        self.assertIn("Could not start strace", result.diagnostics[0])

    async def test_timeout_signals_only_the_isolated_session(self):
        release = asyncio.Event()

        class HangingProcess(FakeProcess):
            async def communicate(self):
                await release.wait()
                self.returncode = -signal.SIGKILL
                return b"", b""

        process = HangingProcess()

        async def spawn(*args, **kwargs):
            self.assertTrue(kwargs["start_new_session"])
            return process

        def signal_group(pid, sig):
            self.assertEqual(pid, process.pid)
            if sig == signal.SIGKILL:
                release.set()

        with patch("runtime_tracing.asyncio.create_subprocess_exec", side_effect=spawn), patch(
            "runtime_tracing.os.killpg", side_effect=signal_group
        ) as killpg:
            result = await trace_binary("/fixture", timeout=0.01, grace_period=0.01)

        self.assertEqual(result.status, "timed_out")
        self.assertTrue(result.timed_out)
        self.assertEqual(killpg.call_count, 2)

    async def test_cancellation_cleans_up_process_session(self):
        release = asyncio.Event()

        class HangingProcess(FakeProcess):
            async def communicate(self):
                await release.wait()
                self.returncode = -signal.SIGTERM
                return b"", b""

        process = HangingProcess()

        async def spawn(*args, **kwargs):
            return process

        def signal_group(pid, sig):
            self.assertEqual(pid, process.pid)
            if sig == signal.SIGTERM:
                release.set()

        with patch("runtime_tracing.asyncio.create_subprocess_exec", side_effect=spawn), patch(
            "runtime_tracing.os.killpg", side_effect=signal_group
        ) as killpg:
            task = asyncio.create_task(trace_binary("/fixture", timeout=30, grace_period=0.1))
            await asyncio.sleep(0)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

        killpg.assert_called_once_with(process.pid, signal.SIGTERM)


if __name__ == "__main__":
    unittest.main()
