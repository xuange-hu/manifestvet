"""Renderers: text, JSON, SARIF.

The text form is the one a human reads, so it leads with the count and then one
block per finding: severity, rule, what happened, where (line + byte offset), the
bytes that prove it, and the fix.  ``why`` is behind ``--explain`` -- forty
paragraphs of rationale in a terminal is noise, and the same text is in
``docs/rules.md`` for the reader who wants it.
"""

from __future__ import annotations

import json

from .engine import Finding, Report

_COLORS = {
    "critical": "\x1b[1;91m",
    "high": "\x1b[91m",
    "medium": "\x1b[93m",
    "low": "\x1b[96m",
    "note": "\x1b[90m",
}
_RESET = "\x1b[0m"
_BOLD = "\x1b[1m"
_DIM = "\x1b[2m"


def _paint(text: str, severity: str, color: bool) -> str:
    if not color:
        return text
    return f"{_COLORS.get(severity, '')}{text}{_RESET}"


def _bar(report: Report) -> str:
    counts = report.counts
    order = ["critical", "high", "medium", "low", "note"]
    return "  ".join(f"{name}={counts.get(name, 0)}" for name in order if counts.get(name, 0) or name in
                     ("critical", "high", "medium"))


def text(report: Report, *, color: bool = True, explain: bool = False) -> str:
    lines: list[str] = []
    app = report.app
    lines.append(_paint(f"{report.target}", "high", color) if not color else f"{_BOLD}{report.target}{_RESET}")
    meta = report.to_dict()["meta"]
    lines.append(
        f"  package={app.package or '?'}  minSdk={app.min_sdk}  targetSdk={app.target_sdk}"
        f"  components={len(app.components)}  format={meta['format']}"
        + (f"  shift={meta['resource_map_shift']}" if meta["format"] == "axml" else "")
    )
    if meta["unresolved_ids"]:
        lines.append(
            f"  {_DIM}unresolved attribute ids: {', '.join(meta['unresolved_ids'])}{_RESET}"
            if color
            else f"  unresolved attribute ids: {', '.join(meta['unresolved_ids'])}"
        )
    if not report.findings:
        lines.append("  no findings (0 rules fired)")
        return "\n".join(lines)

    lines.append(
        f"  {len(report.findings)} findings  {_bar(report)}  risk={report.risk}/100"
        if not color
        else f"  {len(report.findings)} findings  {_bar(report)}  risk={_BOLD}{report.risk}/100{_RESET}"
    )
    lines.append("")
    for finding in report.findings:
        lines.extend(_finding_block(finding, color=color, explain=explain))
    return "\n".join(lines)


def _finding_block(finding: Finding, *, color: bool, explain: bool) -> list[str]:
    tag = _paint(f"[{finding.severity:8s}]", finding.severity, color)
    out = [f"{tag} {finding.rule}  {finding.title}"]
    out.append(f"           {finding.message}")
    out.append(
        f"           {_DIM}at line {finding.line}, offset 0x{finding.offset:x}{_RESET}"
        if color
        else f"           at line {finding.line}, offset 0x{finding.offset:x}"
    )
    if finding.evidence:
        out.append(f"           bytes: {finding.evidence}")
    if explain:
        out.append(f"           why:   {finding.why}")
    out.append(f"           fix:   {finding.fix}")
    out.append("")
    return out


def summary_line(report: Report) -> str:
    counts = report.counts
    parts = [f"{counts.get(k, 0)} {k}" for k in ("critical", "high", "medium", "low", "note") if counts.get(k)]
    return (
        f"{report.app.package or report.target}: {len(report.findings)} findings"
        + (f" ({', '.join(parts)})" if parts else "")
        + f", risk {report.risk}/100"
    )


def as_json(report: Report, indent: int = 2) -> str:
    return json.dumps(report.to_dict(), indent=indent, ensure_ascii=False, sort_keys=False)


def sarif(report: Report, *, tool_version: str = "0.0.0") -> str:
    """SARIF 2.1.0.  Every rule is declared once; findings reference it by index."""
    rules_seen: dict[str, dict] = {}
    results = []
    for finding in report.findings:
        if finding.rule not in rules_seen:
            rules_seen[finding.rule] = finding
        rules_seen[finding.rule]
        results.append(
            {
                "ruleId": finding.rule,
                "level": _sarif_level(finding.severity),
                "message": {"text": f"{finding.message} ({finding.evidence})"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": report.target.replace("\\", "/")},
                            "region": {"startLine": max(finding.line, 1)},
                        }
                    }
                ],
                "properties": {"severity": finding.severity, "fix": finding.fix},
            }
        )

    rule_descriptors = [
        {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.why},
            "help": {"text": finding.fix},
            "defaultConfiguration": {"level": _sarif_level(finding.severity)},
            "properties": {"severity": finding.severity, "tags": ["android", "manifest", "security"]},
        }
        for rule_id, finding in sorted(rules_seen.items())
    ]
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "manifestvet",
                        "informationUri": "https://github.com/xuange-hu/manifestvet",
                        "version": tool_version,
                        "rules": rule_descriptors,
                    }
                },
                "results": results,
                "properties": {
                    "package": report.app.package,
                    "minSdk": report.app.min_sdk,
                    "targetSdk": report.app.target_sdk,
                    "risk": report.risk,
                },
            }
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def _sarif_level(severity: str) -> str:
    return {"critical": "error", "high": "error", "medium": "warning", "low": "note", "note": "note"}.get(
        severity, "warning"
    )
