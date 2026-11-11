"""MCP surface -- optional extra, imported only when ``mcp`` is installed.

The module imports fine without `mcp`: the ImportError is deferred to
``build_server()``, so ``manifestvet --version`` and the CLI never need it.

Two tools exist only because the caller is a model, not a shell: 
``manifestvet_manifest`` takes the XML itself (no file needed) and
``manifestvet_components`` returns the exported surface as a table instead of a
list of findings -- the shape a model needs to reason about "what can another app
reach", which is a different question from "what is wrong".
"""

from __future__ import annotations

import json
import os

from . import __version__, engine, model, render
from .axml import AxmlError

TOOLS = (
    "manifestvet_scan",
    "manifestvet_manifest",
    "manifestvet_components",
    "manifestvet_explain",
    "manifestvet_rules",
    "manifestvet_sarif",
    "manifestvet_demo",
    "manifestvet_attrs",
)


def _error(message: str) -> str:
    return json.dumps({"error": message, "tool": "manifestvet"}, ensure_ascii=False)


def _audit(path: str, min_severity: str, max_findings: int) -> str:
    from pathlib import Path

    from . import apk

    if not os.path.exists(path):
        return _error(f"path not found: {path}")
    try:
        targets = apk.iter_targets(Path(path))
    except (OSError, FileNotFoundError) as exc:
        return _error(str(exc))
    if not targets:
        return _error(f"no AndroidManifest.xml under {path}")

    reports = []
    for name, data in targets:
        try:
            app = model.load(data)
        except AxmlError as exc:
            reports.append({"target": name, "error": str(exc)})
            continue
        report = engine.run(app, target=name)
        payload = report.to_dict()
        payload["summary"] = render.summary_line(report)
        reports.append(payload)

    merged = {
        "tool": "manifestvet",
        "version": __version__,
        "targets": len(reports),
        "worst": min(
            (r.get("worst", "none") for r in reports if "worst" in r),
            key=lambda w: render_level_rank(w),
            default="none",
        ),
        "reports": reports,
        "note": "offsets are byte offsets into the manifest chunk; 'line' is the line aapt recorded",
    }
    text = json.dumps(merged, indent=2, ensure_ascii=False)
    if max_findings and len(text) > 60_000:
        return json.dumps(
            {
                **{k: v for k, v in merged.items() if k != "reports"},
                "reports": [
                    {**r, "findings": r.get("findings", [])[: max(1, int(max_findings))]}
                    for r in reports
                ],
                "truncated": True,
            },
            indent=2,
            ensure_ascii=False,
        )
    return text


def render_level_rank(severity: str) -> int:
    from .rules import SEVERITY_ORDER

    return SEVERITY_ORDER.get(severity, 9)


def manifestvet_scan(path: str = ".", min_severity: str = "note", max_findings: int = 40) -> str:
    """Audit an APK, a compiled/source AndroidManifest.xml, or a directory tree.

    Every finding carries the rule id, the byte offset inside the manifest and the
    bytes that prove it. Use this when you can reach the filesystem.
    """
    return _audit(path, min_severity, max_findings)


def manifestvet_manifest(xml: str, max_findings: int = 40) -> str:
    """Audit AndroidManifest.xml text pasted inline -- no file on disk required.

    Accepts plain XML (what a developer has in the repo). For a compiled APK use
    manifestvet_scan instead.
    """
    try:
        app = model.load(xml.encode("utf-8"))
    except AxmlError as exc:
        return _error(f"could not parse the manifest: {exc}")
    report = engine.run(app, target="<inline>")
    payload = report.to_dict()
    payload["summary"] = render.summary_line(report)
    payload["findings"] = payload["findings"][: max(1, int(max_findings))]
    return json.dumps(payload, indent=2, ensure_ascii=False)


def manifestvet_components(path: str = ".") -> str:
    """List the attack surface: every component, whether it is reachable from another app, and its guard.

    Answers "what can another installed app reach" rather than "what is wrong" --
    the table a threat model starts from.
    """
    from pathlib import Path

    from . import apk

    if not os.path.exists(path):
        return _error(f"path not found: {path}")
    targets = apk.iter_targets(Path(path))
    if not targets:
        return _error(f"no AndroidManifest.xml under {path}")

    out = []
    for name, data in targets:
        try:
            app = model.load(data)
        except AxmlError as exc:
            out.append({"target": name, "error": str(exc)})
            continue
        components = []
        for component in app.components:
            exported = app.effective_exported(component)
            guard = component.permission or str(app.app_attrs.get("permission") or "")
            components.append(
                {
                    "kind": component.kind,
                    "name": component.name,
                    "exported": exported,
                    "exported_declared": component.exported_declared,
                    "guard": guard or None,
                    "guard_is_weak": bool(guard) and bool(engine.Context(app).weak_guard(guard)),
                    "authorities": component.sget("authorities") or None,
                    "launch_mode": component.sget("launchMode") or None,
                    "actions": component.all_actions(),
                    "deep_links": [d.describe() for d in component.all_deep_links()],
                    "line": component.line,
                    "offset": component.offset,
                }
            )
        out.append(
            {
                "target": name,
                "package": app.package,
                "min_sdk": app.min_sdk,
                "target_sdk": app.target_sdk,
                "exported_count": sum(1 for c in components if c["exported"]),
                "components": components,
            }
        )
    return json.dumps({"tool": "manifestvet", "targets": out}, indent=2, ensure_ascii=False)


def manifestvet_explain(rule_id: str) -> str:
    """Explain one rule: what it detects, why it matters, how to fix it, and which attack it maps to."""
    for rule in engine.rules.REGISTRY:
        if rule.id.upper() == rule_id.upper():
            return json.dumps(
                {
                    "id": rule.id,
                    "title": rule.title,
                    "severity": rule.severity,
                    "stage": rule.stage,
                    "why": rule.why,
                    "fix": rule.fix,
                    "docs": f"docs/rules.md#{rule.id.lower()}",
                },
                indent=2,
                ensure_ascii=False,
            )
    return _error(f"unknown rule {rule_id}; known: {', '.join(sorted(r.id for r in engine.rules.REGISTRY))}")


def manifestvet_rules(stage: int = 0, severity: str = "") -> str:
    """List the rule table, filterable by stage (1=element, 2=component, 3=app) and severity."""
    items = [
        rule
        for rule in sorted(engine.rules.REGISTRY, key=lambda r: r.id)
        if (not stage or rule.stage == stage) and (not severity or rule.severity == severity)
    ]
    return json.dumps(
        {
            "count": len(items),
            "rules": [
                {
                    "id": r.id,
                    "title": r.title,
                    "severity": r.severity,
                    "stage": r.stage,
                }
                for r in items
            ],
        },
        indent=2,
        ensure_ascii=False,
    )


def manifestvet_sarif(path: str = ".") -> str:
    """Scan and return SARIF 2.1.0, ready for GitHub code scanning."""
    from pathlib import Path

    from . import apk

    if not os.path.exists(path):
        return _error(f"path not found: {path}")
    targets = apk.iter_targets(Path(path))
    if not targets:
        return _error(f"no AndroidManifest.xml under {path}")
    runs = []
    for name, data in targets:
        try:
            app = model.load(data)
        except AxmlError as exc:
            return _error(f"{name}: {exc}")
        report = engine.run(app, target=name)
        runs.append(json.loads(render.sarif(report, tool_version=__version__))["runs"][0])
    return json.dumps(
        {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": runs,
        },
        indent=2,
        ensure_ascii=False,
    )


def manifestvet_demo() -> str:
    """Audit a generated three-manifest corpus that triggers every rule in the table.

    One call proves the reader, the model and all 40 rules work end to end.
    """
    from . import demo

    reports = []
    triggered: set[str] = set()
    for report in demo.reports():
        triggered |= report.triggered()
        payload = report.to_dict()
        payload["summary"] = render.summary_line(report)
        reports.append(payload)
    return json.dumps(
        {
            "tool": "manifestvet",
            "version": __version__,
            "rules_total": len(engine.rules.REGISTRY),
            "rules_triggered": len(triggered),
            "manifests": reports,
        },
        indent=2,
        ensure_ascii=False,
    )


def manifestvet_attrs(path: str = ".") -> str:
    """Dump every element and attribute with its byte offset: the evidence
    view of what the parser saw, where it sits in the file, and which resource
    id each attribute came from."""
    from pathlib import Path

    from . import apk, axml, srctext

    try:
        targets = list(apk.iter_targets(Path(path)))
    except (OSError, FileNotFoundError) as exc:
        return _error(str(exc))
    if not targets:
        return _error(f"no AndroidManifest.xml under {path}")

    lines: list[str] = []
    for name, data in targets:
        try:
            doc = axml.parse(data) if axml.looks_like_axml(data) else srctext.parse(data)
        except AxmlError as exc:
            lines.append(f"# {name}: {exc}")
            continue
        lines.append(f"# {name}  ({'axml' if doc.resource_ids else 'text'}, {doc.size} bytes)")
        for element in doc.walk():
            lines.append(f"{element.offset:#08x} L{element.line:<4d} <{element.name}>")
            for attribute in element.attributes:
                origin = f"0x{attribute.res_id:08x}" if attribute.res_id else "-"
                lines.append(
                    f"           {attribute.offset:#08x} {attribute.name}={attribute.value!r}  id={origin}"
                )
    return "\n".join(lines)


def build_server():
    """Construct the MCP server. Requires the optional `mcp` extra."""
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP(name="manifestvet")

    @mcp.tool(name="manifestvet_scan")
    def _scan_tool(path: str = ".", min_severity: str = "note", max_findings: int = 40) -> str:
        """Audit an APK, a compiled/source AndroidManifest.xml, or a directory tree."""
        return manifestvet_scan(path, min_severity, max_findings)

    @mcp.tool(name="manifestvet_manifest")
    def _manifest_tool(xml: str, max_findings: int = 40) -> str:
        """Audit AndroidManifest.xml text pasted inline -- no file on disk required."""
        return manifestvet_manifest(xml, max_findings)

    @mcp.tool(name="manifestvet_components")
    def _components_tool(path: str = ".") -> str:
        """List the attack surface: each component, whether it is exported, and its guard."""
        return manifestvet_components(path)

    @mcp.tool(name="manifestvet_explain")
    def _explain_tool(rule_id: str) -> str:
        """Explain one rule: what it detects, why it matters, how to fix it."""
        return manifestvet_explain(rule_id)

    @mcp.tool(name="manifestvet_rules")
    def _rules_tool(stage: int = 0, severity: str = "") -> str:
        """List the rule table, filterable by stage and severity."""
        return manifestvet_rules(stage, severity)

    @mcp.tool(name="manifestvet_sarif")
    def _sarif_tool(path: str = ".") -> str:
        """Scan and return SARIF 2.1.0 for GitHub code scanning."""
        return manifestvet_sarif(path)

    @mcp.tool(name="manifestvet_demo")
    def _demo_tool() -> str:
        """Audit a generated corpus that triggers every rule; one call proves the tool works."""
        return manifestvet_demo()

    @mcp.tool(name="manifestvet_attrs")
    def _attrs_tool(path: str = ".") -> str:
        """Dump every element and attribute with its byte offset - the evidence view."""
        return manifestvet_attrs(path)

    return mcp


def tool_manifest() -> list[dict[str, str]]:
    return [
        {"name": "manifestvet_scan", "description": manifestvet_scan.__doc__ or ""},
        {"name": "manifestvet_manifest", "description": manifestvet_manifest.__doc__ or ""},
        {"name": "manifestvet_components", "description": manifestvet_components.__doc__ or ""},
        {"name": "manifestvet_explain", "description": manifestvet_explain.__doc__ or ""},
        {"name": "manifestvet_rules", "description": manifestvet_rules.__doc__ or ""},
        {"name": "manifestvet_sarif", "description": manifestvet_sarif.__doc__ or ""},
        {"name": "manifestvet_demo", "description": manifestvet_demo.__doc__ or ""},
        {"name": "manifestvet_attrs", "description": manifestvet_attrs.__doc__ or ""},
    ]


def main() -> None:
    build_server().run()


if __name__ == "__main__":  # pragma: no cover
    main()
