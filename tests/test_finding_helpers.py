from __future__ import annotations

import unittest

from finding_helpers import collect_findings, deduplicate_findings


class FindingDeduplicationTests(unittest.TestCase):
    def test_exact_duplicates_are_removed(self):
        findings = [
            {
                "binary_path": "/usr/bin/example",
                "finding_type": "flag",
                "rule": "system",
                "evidence": "system",
                "severity": "HIGH",
                "context": "command",
            },
            {
                "binary_path": "/usr/bin/example",
                "finding_type": "flag",
                "rule": "system",
                "evidence": "system",
                "severity": "HIGH",
                "context": "command",
            },
        ]

        self.assertEqual(len(deduplicate_findings(findings)), 1)

    def test_distinct_paths_rules_evidence_and_metadata_are_preserved(self):
        findings = [
            {
                "binary_path": "/usr/bin/first",
                "finding_type": "flag",
                "rule": "system",
                "evidence": "system",
                "severity": "HIGH",
                "context": "command",
            },
            {
                "binary_path": "/usr/bin/second",
                "finding_type": "flag",
                "rule": "system",
                "evidence": "system",
                "severity": "HIGH",
                "context": "command",
            },
            {
                "binary_path": "/usr/bin/first",
                "finding_type": "flag",
                "rule": "exec",
                "evidence": "exec",
                "severity": "MEDIUM",
                "context": "function",
            },
            {
                "binary_path": "/usr/bin/first",
                "finding_type": "flag",
                "rule": "system",
                "evidence": "system",
                "severity": "CRITICAL",
                "context": "shell",
            },
        ]

        result = deduplicate_findings(findings)
        self.assertEqual(len(result), 4)
        self.assertEqual({item["binary_path"] for item in result}, {
            "/usr/bin/first", "/usr/bin/second"
        })
        self.assertEqual(result[0]["evidence"], "system")
        self.assertEqual(result[0]["context"], "command")

    def test_collect_findings_deduplicates_across_scan_stages(self):
        results = {
            "/usr/bin/example": {
                "flags": [
                    {"string": "system", "severity": "HIGH", "context": "command"},
                    {"string": "system", "severity": "HIGH", "context": "command"},
                    {"string": "exec", "severity": "MEDIUM", "context": "function"},
                ],
                "gtfo": [
                    {"type": "shell", "context": "suid", "method": "python -c ..."},
                    {"type": "shell", "context": "suid", "method": "python -c ..."},
                    {"type": "file-write", "context": "suid", "method": "open('/tmp/x')"},
                ],
                "capabilities": ["cap_net_raw=ep", "cap_net_raw=ep"],
            }
        }

        findings = collect_findings(results)
        self.assertEqual(len(findings), 5)
        self.assertEqual(
            {item["finding_type"] for item in findings},
            {"flag", "gtfobins", "capability"},
        )
        self.assertTrue(all(item["binary_path"] == "/usr/bin/example" for item in findings))
        self.assertIn(
            ("flag", "system", "system"),
            {(item["finding_type"], item["rule"], item["evidence"]) for item in findings},
        )

    def test_empty_or_incomplete_records_are_ignored(self):
        self.assertEqual(
            deduplicate_findings([{}, {"binary_path": "/tmp/a", "finding_type": "flag"}]),
            [],
        )


if __name__ == "__main__":
    unittest.main()
