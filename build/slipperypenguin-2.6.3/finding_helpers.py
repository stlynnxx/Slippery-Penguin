"""Canonical finding construction and deduplication for scan results."""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any


def _evidence_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, sort_keys=True, ensure_ascii=False)
    return str(value).strip()


def deduplicate_findings(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Remove exact duplicate detections while retaining distinct rules and evidence."""
    unique: dict[tuple[str, ...], dict[str, Any]] = {}

    for finding in findings:
        binary_path = str(finding.get("binary_path") or "").strip()
        finding_type = str(finding.get("finding_type") or "").strip()
        rule = str(finding.get("rule") or "").strip()
        evidence = _evidence_text(finding.get("evidence"))
        if not binary_path or not finding_type or not rule or not evidence:
            continue

        key = (
            binary_path,
            finding_type,
            rule,
            evidence,
            str(finding.get("severity") or "").strip(),
            str(finding.get("context") or "").strip(),
        )
        unique.setdefault(
            key,
            {
                "binary_path": binary_path,
                "finding_type": finding_type,
                "rule": rule,
                "evidence": evidence,
                "severity": str(finding.get("severity") or "").strip(),
                "context": str(finding.get("context") or "").strip(),
            },
        )

    return list(unique.values())


def collect_findings(binary_results: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Build path-aware findings from all supported scan stages."""
    findings: list[dict[str, Any]] = []

    for binary_path, result in binary_results.items():
        for flag in result.get("flags", []) or []:
            if not isinstance(flag, dict):
                continue
            marker = str(flag.get("string") or "").strip()
            if not marker:
                continue
            findings.append(
                {
                    "binary_path": binary_path,
                    "finding_type": "flag",
                    "rule": marker,
                    "evidence": marker,
                    "severity": flag.get("severity", ""),
                    "context": flag.get("context", ""),
                }
            )

        for match in result.get("gtfo", []) or []:
            if not isinstance(match, dict):
                continue
            rule = str(match.get("type") or "GTFOBins match").strip()
            evidence = match.get("method")
            if not evidence:
                evidence = match
            findings.append(
                {
                    "binary_path": binary_path,
                    "finding_type": "gtfobins",
                    "rule": rule,
                    "evidence": evidence,
                    "severity": match.get("severity", ""),
                    "context": match.get("context", ""),
                }
            )

        for capability in result.get("capabilities", []) or []:
            findings.append(
                {
                    "binary_path": binary_path,
                    "finding_type": "capability",
                    "rule": "Linux file capability",
                    "evidence": capability,
                    "severity": "",
                    "context": "",
                }
            )

    return deduplicate_findings(findings)
