"""Command line: scan, demo, rules, attrs, mcp.

Exit codes are part of the interface: 0 clean, 1 findings at or above
``--fail-on``, 2 the input could not be read or parsed.  CI wants that distinction
(a broken manifest is not a security finding) and so does anyone running this in a
pre-commit hook.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, apk, axml, engine, model, render, srctext
from .axml import AxmlError
from .rules import SEVERITY_ORDER

SEVERITY_CHOICES = ["critical", "high", "medium", "low", "note"]
FORMAT_CHOICES = ["text", "json", "sarif"]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="manifestvet",
        description="Android manifest security audit -- compiled AXML or source XML, byte-level evidence.",
    )
    parser.add_argument("--version", action="version", version=f"manifestvet {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="audit an APK, a manifest file, or a source tree")
    scan.add_argument("path", help=".apk/.aab/.zip, AndroidManifest.xml, or a directory to walk")
    scan.add_argument("-f", "--format", choices=FORMAT_CHOICES, default="text")
    scan.add_argument(
        "--fail-on",
        choices=["none", *SEVERITY_CHOICES],
        default="high",
        help="exit 1 when a finding at this severity or worse exists (default: high)",
    )
    scan.add_argument("--min-severity", choices=SEVERITY_CHOICES, default=None,
                      help="do not print findings below this severity")
    scan.add_argument("--explain", action="store_true", help="print the reasoning behind each rule")
    scan.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    scan.add_argument("--quiet", action="store_true", help="one summary line per manifest")

    demo = sub.add_parser("demo", help="audit a generated corpus that covers every rule")
    demo.add_argument("--explain", action="store_true")
    demo.add_argument("--no-color", action="store_true")

    rules_cmd = sub.add_parser("rules", help="list the rule table")
    rules_cmd.add_argument("--json", action="store_true")
    rules_cmd.add_argument("--markdown", action="store_true", help="print docs/rules.md")

    attrs = sub.add_parser("attrs", help="dump every element and attribute with its byte offset")
    attrs.add_argument("path")

    mcp_cmd = sub.add_parser("mcp", help="run the MCP server, or list what it exposes")
    mcp_cmd.add_argument("--check", action="store_true", help="print the tool manifest and exit")

    return parser


def _filter(report: engine.Report, threshold: str | None) -> engine.Report:
    if not threshold:
        return report
    limit = SEVERITY_ORDER[threshold]
    report.findings = [f for f in report.findings if SEVERITY_ORDER.get(f.severity, 9) <= limit]
    return report


def _targets(path: str) -> tuple[list[tuple[str, bytes]], int]:
    """Resolve inputs; returns the list plus an exit code (2 = nothing to read)."""
    try:
        targets = apk.iter_targets(Path(path))
    except (OSError, FileNotFoundError) as exc:
        print(f"manifestvet: {exc}", file=sys.stderr)
        return [], 2
    if not targets:
        print(f"manifestvet: no AndroidManifest.xml under {path}", file=sys.stderr)
        return [], 2
    return targets, 0


def _cmd_scan(args) -> int:
    targets, problem = _targets(args.path)
    if problem:
        return problem
    exit_code = 0
    json_reports: list[dict] = []
    sarif_runs: list[dict] = []
    for name, data in targets:
        try:
            app = model.load(data)
        except AxmlError as exc:
            print(f"manifestvet: {name}: {exc}", file=sys.stderr)
            exit_code = max(exit_code, 2)
            continue
        report = _filter(engine.run(app, target=name), args.min_severity)
        if report.should_fail(args.fail_on):
            exit_code = max(exit_code, 1)
        if args.format == "text":
            if args.quiet:
                print(render.summary_line(report))
            else:
                print(render.text(report, color=not args.no_color and sys.stdout.isatty(), explain=args.explain))
        elif args.format == "json":
            json_reports.append(report.to_dict())
        else:
            import json

            sarif_runs.append(json.loads(render.sarif(report, tool_version=__version__))["runs"][0])

    if args.format == "json":
        import json

        payload = json_reports[0] if len(json_reports) == 1 else {"reports": json_reports}
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    elif args.format == "sarif":
        import json

        payload = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": sarif_runs,
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    return exit_code


def _cmd_rules(args) -> int:
    table = sorted(engine.rules.REGISTRY, key=lambda r: r.id)
    if args.markdown:
        from .rulebook import full_markdown

        print(full_markdown())
        return 0
    if args.json:
        import json

        print(
            json.dumps(
                [
                    {
                        "id": r.id,
                        "title": r.title,
                        "severity": r.severity,
                        "stage": r.stage,
                        "why": r.why,
                        "fix": r.fix,
                    }
                    for r in table
                ],
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0
    for rule in table:
        print(f"{rule.id}  {rule.severity:8s}  stage{rule.stage}  {rule.title}")
    print(f"\n{len(table)} rules")
    return 0


def _cmd_attrs(args) -> int:
    targets, problem = _targets(args.path)
    if problem:
        return problem
    for name, data in targets:
        doc = axml.parse(data) if axml.looks_like_axml(data) else srctext.parse(data)
        print(f"# {name}  ({'axml' if doc.resource_ids else 'text'}, {doc.size} bytes)")
        for element in doc.walk():
            if not element.attributes:
                print(f"{element.offset:#08x} L{element.line:<4d} <{element.name}>")
                continue
            print(f"{element.offset:#08x} L{element.line:<4d} <{element.name}>")
            for attribute in element.attributes:
                origin = f"0x{attribute.res_id:08x}" if attribute.res_id else "-"
                print(f"           {attribute.offset:#08x} {attribute.name}={attribute.value!r}  id={origin}")
    return 0


def _cmd_mcp(args) -> int:
    from . import mcp_server

    if args.check:
        for tool in mcp_server.tool_manifest():
            print(f"{tool['name']:24s} {tool['description']}")
        print(f"\n{len(mcp_server.tool_manifest())} tools")
        return 0
    mcp_server.main()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "demo":
        from . import demo

        return demo.run(color=not args.no_color and sys.stdout.isatty(), explain=args.explain)
    if args.command == "rules":
        return _cmd_rules(args)
    if args.command == "attrs":
        return _cmd_attrs(args)
    if args.command == "mcp":
        return _cmd_mcp(args)
    parser.print_help()  # pragma: no cover
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
