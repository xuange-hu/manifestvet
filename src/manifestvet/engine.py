"""Run the rules and shape the result.

One place converts :class:`manifestvet.rules.Issue` (what a rule says) into
:class:`Finding` (what a report prints): the rule's static title/severity/fix are
attached once, and the byte offset is narrowed from the element to the attribute
when the rule named one.  Keeping that mapping in one function is why the text,
JSON and SARIF renderers can never disagree about a finding's severity.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import rules
from .model import App
from .rules import SEVERITY_ORDER, Context, Issue, Rule


@dataclass
class Finding:
    rule: str
    title: str
    severity: str
    message: str
    where: str
    line: int
    offset: int
    evidence: str
    why: str
    fix: str

    def sort_key(self) -> tuple[int, str, int]:
        return (SEVERITY_ORDER.get(self.severity, 9), self.rule, self.offset)

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "title": self.title,
            "severity": self.severity,
            "message": self.message,
            "where": self.where,
            "line": self.line,
            "offset": self.offset,
            "offset_hex": f"0x{self.offset:x}",
            "evidence": self.evidence,
            "why": self.why,
            "fix": self.fix,
        }


@dataclass
class Report:
    target: str
    app: App
    findings: list[Finding] = field(default_factory=list)
    rules_run: int = 0
    rule_ids: list[str] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        out = {name: 0 for name in SEVERITY_ORDER}
        for finding in self.findings:
            out[finding.severity] = out.get(finding.severity, 0) + 1
        return out

    @property
    def worst(self) -> str:
        if not self.findings:
            return "none"
        return min(self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9)).severity

    @property
    def risk(self) -> int:
        """0-100, weighted so one critical dominates a pile of notes."""
        weights = {"critical": 40, "high": 14, "medium": 5, "low": 2, "note": 0}
        return min(100, sum(weights.get(f.severity, 0) for f in self.findings))

    def triggered(self) -> set[str]:
        return {f.rule for f in self.findings}

    def should_fail(self, threshold: str) -> bool:
        if threshold == "none":
            return False
        limit = SEVERITY_ORDER.get(threshold)
        if limit is None:
            return False
        return any(SEVERITY_ORDER.get(f.severity, 9) <= limit for f in self.findings)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "package": self.app.package,
            "min_sdk": self.app.min_sdk,
            "target_sdk": self.app.target_sdk,
            "components": len(self.app.components),
            "rules_run": self.rules_run,
            "counts": self.counts,
            "worst": self.worst,
            "risk": self.risk,
            "findings": [f.to_dict() for f in self.findings],
            "meta": meta(self.app),
        }


def meta(app: App) -> dict:
    """Facts about the parse itself, printed so the reader can trust the numbers."""
    doc = app.doc
    return {
        "format": "axml" if doc.resource_ids else "text",
        "bytes": doc.size,
        "elements": doc.element_count,
        "strings": len(doc.pool.strings) if doc.pool is not None else 0,
        "resource_map_entries": len(doc.resource_ids),
        "resource_map_shift": doc.shift,
        "unresolved_attributes": len(doc.unresolved),
        "unresolved_ids": sorted({f"0x{a.res_id:08x}" for a in doc.unresolved}),
        "declared_permissions": [p.name for p in app.declared],
        "used_permissions": [u.name for u in app.used],
    }


def _to_finding(rule: Rule, issue: Issue) -> Finding:
    element = issue.element
    offset = element.offset if element is not None else 0
    line = element.line if element is not None else 0
    if issue.attr and element is not None:
        attribute = element.get_attr(issue.attr)
        if attribute is not None:
            offset = attribute.offset
            line = attribute.line
    return Finding(
        rule=rule.id,
        title=rule.title,
        severity=rule.severity,
        message=issue.message,
        where=issue.where or (element.name if element is not None else ""),
        line=line,
        offset=offset,
        evidence=issue.evidence,
        why=rule.why,
        fix=rule.fix,
    )


def run(app: App, target: str = "<manifest>") -> Report:
    """Evaluate every rule against ``app`` and return the sorted report."""
    ctx = Context(app=app)
    executable = rules._executable()
    findings: list[Finding] = []
    for rule in executable:
        for issue in rule.check(ctx) or ():
            findings.append(_to_finding(rule, issue))
    findings.sort(key=lambda f: f.sort_key())
    return Report(
        target=target,
        app=app,
        findings=findings,
        rules_run=len(executable),
        rule_ids=[r.id for r in executable],
    )
