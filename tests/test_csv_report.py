from __future__ import annotations

import ast
import csv
import json
import tempfile
import unittest
from pathlib import Path


class CsvReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # slipperypenguin.py runs the scanner at import time, so load only the
        # report function's AST node to keep these tests isolated and safe.
        source = Path(__file__).resolve().parents[1] / "slipperypenguin.py"
        module = ast.parse(source.read_text(encoding="utf-8"))
        function = next(
            node for node in module.body
            if isinstance(node, ast.FunctionDef) and node.name == "write_csv_report"
        )
        namespace = {"csv": csv, "json": json}
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), "exec"), namespace)
        cls.write_csv_report = staticmethod(namespace["write_csv_report"])

    def read_rows(self, path):
        with path.open(newline="", encoding="utf-8") as report:
            return list(csv.DictReader(report))

    def test_directory_traversal_has_its_own_section(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.csv"
            self.write_csv_report(
                {"/usr/bin/example": {"flags": [{"string": "unsafe", "severity": "HIGH", "context": "test"}]}},
                output,
                {"/tmp/a": {"Subdirectories": ["nested"], "Files": ["one.txt", "two.txt"]}},
                [{
                    "path": "/tmp/a/world.txt",
                    "check": "world_writable",
                    "severity": "Needs manual review",
                    "permissions": "0o666",
                    "description": "File is writable by other users",
                }],
            )

            rows = self.read_rows(output)
            section = next(row for row in rows if row["binary"] == "Directory Traversal Results")
            traversal = next(row for row in rows if row["finding_type"] == "filepath_walk")
            security = next(row for row in rows if row["finding_type"] == "filepath_walk_security")
            existing = next(row for row in rows if row["finding_type"] == "flags")

            self.assertEqual(section["finding_type"], "")
            self.assertEqual(traversal["binary"], "/tmp/a")
            self.assertIn("nested", traversal["finding"])
            self.assertIn("one.txt", traversal["finding"])
            self.assertEqual(traversal["context"], "1 subdirectories; 2 files")
            self.assertEqual(security["binary"], "/tmp/a/world.txt")
            self.assertEqual(security["severity"], "Needs manual review")
            self.assertEqual(existing["finding"], "unsafe")

    def test_existing_call_signature_remains_compatible(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.csv"
            self.write_csv_report({"/usr/bin/example": {"strings": ["sample"]}}, output)
            rows = self.read_rows(output)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["finding_type"], "strings")
            self.assertEqual(rows[0]["finding"], "sample")

    def test_canonical_findings_replace_raw_security_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.csv"
            findings = [
                {
                    "binary_path": "/usr/bin/example",
                    "finding_type": "flag",
                    "rule": "unsafe",
                    "evidence": "unsafe",
                    "severity": "HIGH",
                    "context": "command",
                },
                {
                    "binary_path": "/usr/bin/example",
                    "finding_type": "gtfobins",
                    "rule": "shell",
                    "evidence": "python -c ...",
                    "severity": "",
                    "context": "suid",
                },
                {
                    "binary_path": "/usr/bin/example",
                    "finding_type": "capability",
                    "rule": "Linux file capability",
                    "evidence": "cap_net_raw=ep",
                    "severity": "",
                    "context": "",
                },
            ]
            self.write_csv_report(
                {
                    "/usr/bin/example": {
                        "flags": [{"string": "unsafe", "severity": "HIGH", "context": "command"}],
                        "gtfo": [{"type": "shell", "context": "suid", "method": "python -c ..."}],
                        "capabilities": ["cap_net_raw=ep"],
                    }
                },
                output,
                findings=findings,
            )

            rows = self.read_rows(output)
            self.assertEqual(len(rows), 3)
            self.assertEqual(
                {row["finding_type"] for row in rows},
                {"flag", "gtfobins", "capability"},
            )
            self.assertTrue(all(row["binary"] == "/usr/bin/example" for row in rows))
            self.assertEqual(
                next(row for row in rows if row["finding_type"] == "flag")["finding"],
                "unsafe",
            )

    def test_empty_traversal_does_not_add_an_empty_section(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.csv"
            self.write_csv_report({}, output, {}, [])
            rows = self.read_rows(output)
            self.assertEqual(rows, [])


if __name__ == "__main__":
    unittest.main()
