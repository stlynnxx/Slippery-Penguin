from __future__ import annotations

import os
import stat
import subprocess
import unittest
from unittest.mock import Mock

from scan_helpers import (
    collect_file_metadata,
    collect_scan_inventory,
    discover_privileged_files,
    match_flags,
    parse_find_output,
    parse_flag_config,
    parse_getcap_output,
    parse_strings_output,
    scan_file_capabilities,
)


class ScanHelperTests(unittest.TestCase):
    def test_find_output_is_nul_delimited_and_deduplicated(self) -> None:
        output = b"/usr/bin/passwd\0/opt/tool with space\0/usr/bin/passwd\0"
        self.assertEqual(
            parse_find_output(output),
            ["/usr/bin/passwd", "/opt/tool with space"],
        )

    def test_find_enumerates_suid_and_sgid_in_one_call(self) -> None:
        runner = Mock(return_value=subprocess.CompletedProcess(
            args=["find"], returncode=0, stdout=b"/usr/bin/a\0/usr/bin/b\0", stderr=b""
        ))
        paths, warnings = discover_privileged_files("/fixture", runner=runner)
        self.assertEqual(paths, ["/usr/bin/a", "/usr/bin/b"])
        self.assertFalse(warnings)
        runner.assert_called_once()
        self.assertIn("-4000", runner.call_args.args[0])
        self.assertIn("-2000", runner.call_args.args[0])
        self.assertIn("-print0", runner.call_args.args[0])

    def test_find_keeps_partial_results_when_a_directory_is_inaccessible(self) -> None:
        runner = Mock(return_value=subprocess.CompletedProcess(
            args=["find"], returncode=1, stdout=b"/usr/bin/known-suid\0",
            stderr=b"/root/private: Permission denied\n"
        ))
        paths, warnings = discover_privileged_files("/fixture", runner=runner)
        self.assertEqual(paths, ["/usr/bin/known-suid"])
        self.assertIn("Permission denied", warnings[0])

    def test_getcap_parser_preserves_spaces_and_multiple_paths(self) -> None:
        output = (
            "/usr/bin/ping cap_net_raw=ep\n"
            "/opt/my tool cap_net_bind_service=ep\n"
            "/opt/my tool cap_net_raw=ep\n"
            r"/opt/escaped\ path cap_net_raw=ep" "\n"
        )
        self.assertEqual(
            parse_getcap_output(output),
            {
                "/usr/bin/ping": ["cap_net_raw=ep"],
                "/opt/my tool": ["cap_net_bind_service=ep", "cap_net_raw=ep"],
                "/opt/escaped path": ["cap_net_raw=ep"],
            },
        )

    def test_capability_scan_runs_once_and_keeps_partial_output_on_error(self) -> None:
        runner = Mock(return_value=subprocess.CompletedProcess(
            args=["getcap"], returncode=1,
            stdout=b"/usr/bin/ping cap_net_raw=ep\n",
            stderr=b"/proc/1: Permission denied\n"
        ))
        capabilities, warnings = scan_file_capabilities("/fixture", runner=runner)
        runner.assert_called_once()
        self.assertEqual(capabilities["/usr/bin/ping"], ["cap_net_raw=ep"])
        self.assertIn("Permission denied", warnings[0])

    def test_missing_getcap_is_a_warning_not_a_crash(self) -> None:
        def missing_command(*_args: object, **_kwargs: object) -> None:
            raise FileNotFoundError("getcap")
        capabilities, warnings = scan_file_capabilities("/fixture", runner=missing_command)
        self.assertEqual(capabilities, {})
        self.assertIn("Could not run getcap", warnings[0])

    def test_metadata_is_cached_once_per_unique_path(self) -> None:
        info = os.stat_result(
            (stat.S_IFREG | stat.S_ISUID | 0o755, 123, 1, 1, 1000, 1000, 42, 10, 11, 12)
        )
        stat_func = Mock(return_value=info)
        metadata, warnings = collect_file_metadata(
            ["/tmp/example", "/tmp/example"], stat_func=stat_func
        )
        stat_func.assert_called_once_with("/tmp/example")
        self.assertFalse(warnings)
        self.assertTrue(metadata["/tmp/example"]["suid"])
        self.assertFalse(metadata["/tmp/example"]["sgid"])

    def test_metadata_permission_errors_are_reported(self) -> None:
        def denied(_path: str) -> os.stat_result:
            raise PermissionError("access denied")
        metadata, warnings = collect_file_metadata(["/root/private"], stat_func=denied)
        self.assertEqual(metadata, {})
        self.assertIn("access denied", warnings[0])

    def test_inventory_runs_one_find_one_getcap_and_caches_capability_only_metadata(self) -> None:
        calls: list[list[str]] = []

        def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
            calls.append(command)
            if command[0] == "find":
                return subprocess.CompletedProcess(command, 0, b"/usr/bin/ping\0", b"")
            return subprocess.CompletedProcess(
                command, 0,
                b"/usr/bin/ping cap_net_raw=ep\n/opt/cap-only cap_net_bind_service=ep\n",
                b"",
            )
        info = os.stat_result(
            (stat.S_IFREG | stat.S_ISUID | 0o755, 123, 1, 1, 1000, 1000, 42, 10, 11, 12)
        )
        stat_func = Mock(return_value=info)
        inventory = collect_scan_inventory(
            "/fixture", runner=runner, stat_func=stat_func
        )
        self.assertEqual([command[0] for command in calls], ["find", "getcap"])
        self.assertEqual(inventory.timings["find_commands"], 1)
        self.assertEqual(inventory.timings["getcap_commands"], 1)
        self.assertEqual(
            inventory.capabilities_by_file["/usr/bin/ping"], ["cap_net_raw=ep"]
        )
        self.assertIn("/opt/cap-only", inventory.file_metadata)
        self.assertEqual(stat_func.call_count, 2)


class StringsAndFlagsTests(unittest.TestCase):
    def test_strings_output_decodes_bytes_and_ignores_blank_lines(self) -> None:
        self.assertEqual(
            parse_strings_output(b"first\n\nsecond\n"),
            ["first", "second"],
        )

    def test_strings_output_handles_missing_output(self) -> None:
        self.assertEqual(parse_strings_output(None), [])

    def test_flag_matching_is_exact_and_deduplicated(self) -> None:
        flags = parse_flag_config(
            [
                {"string": "system", "severity": "HIGH", "context": "command"},
                {"string": "setuid", "severity": "MEDIUM"},
                {"string": "system", "severity": "CRITICAL"},
            ]
        )
        self.assertEqual(
            match_flags(["system", "systemd", "setuid"], flags),
            [
                {"string": "system", "severity": "HIGH", "context": "command"},
                {"string": "setuid", "severity": "MEDIUM", "context": ""},
            ],
        )

    def test_empty_flag_configuration_is_valid(self) -> None:
        self.assertEqual(parse_flag_config([]), [])

    def test_malformed_or_incomplete_flag_configuration_is_rejected(self) -> None:
        invalid_configs = [
            {},
            "not a list",
            [None],
            [{"severity": "HIGH"}],
            [{"string": "exec"}],
            [{"string": "exec", "severity": "HIGH", "context": 4}],
        ]
        for config in invalid_configs:
            with self.subTest(config=config):
                with self.assertRaises(ValueError):
                    parse_flag_config(config)


class CommandFailureTests(unittest.TestCase):
    def test_find_timeout_is_reported_without_raising(self) -> None:
        runner = Mock(
            side_effect=subprocess.TimeoutExpired(
                ["find"], 1, output=b""
            )
        )
        paths, warnings = discover_privileged_files(
            "/fixture", runner=runner, timeout=1
        )
        self.assertEqual(paths, [])
        self.assertIn("timed out", warnings[0])

    def test_empty_getcap_output_is_a_clean_empty_result(self) -> None:
        runner = Mock(
            return_value=subprocess.CompletedProcess(
                args=["getcap"], returncode=0, stdout="", stderr=""
            )
        )
        capabilities, warnings = scan_file_capabilities(
            "/fixture", runner=runner
        )
        self.assertEqual(capabilities, {})
        self.assertEqual(warnings, [])

    def test_sgid_mode_is_recorded(self) -> None:
        info = os.stat_result(
            (
                stat.S_IFREG | stat.S_ISGID | 0o755,
                123, 1, 1, 1000, 1000, 42, 10, 11, 12,
            )
        )
        metadata, warnings = collect_file_metadata(
            ["/tmp/group-tool"], stat_func=Mock(return_value=info)
        )
        self.assertTrue(metadata["/tmp/group-tool"]["sgid"])
        self.assertFalse(metadata["/tmp/group-tool"]["suid"])
        self.assertFalse(warnings)


if __name__ == "__main__":
    unittest.main()
