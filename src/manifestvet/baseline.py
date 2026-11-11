"""Baseline: snapshot known findings so only *new* ones fail CI.

The identity of a finding is ``(rule, where, message)`` -- deliberately *not*
line or offset: those move with every recompile of the manifest, and a baseline
that invalidates itself on the next build is worse than none.  ``rule`` ids are
pinned by ``tests/test_entrypoints.py`` so a renumber cannot silently corrupt a
committed baseline.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import __version__
from .engine import Finding

DEFAULT_NAME = ".manifestvet-baseline.json"
FORMAT_VERSION = 1


class BaselineError(Exception):
    """The baseline file is missing, unreadable, or not a manifestvet baseline."""


def _entry(f: Finding) -> dict:
    return {"rule": f.rule, "where": f.where, "message": f.message, "severity": f.severity}


def storage_key(target: str, root: str) -> str:
    """Portability: key a target by its path relative to the scan root, falling
    back to the bare file name (single-file scans and archives)."""
    try:
        rel = Path(target).relative_to(root)
    except ValueError:
        return Path(target).name
    return Path(target).name if rel == Path(".") else rel.as_posix()


def _key(entry: dict) -> tuple[str, str, str]:
    return (entry["rule"], entry["where"], entry["message"])


def build(items: list[tuple[str, object]]) -> dict:
    """Assemble a baseline dict from ``(storage_key, report)`` pairs.

    The key must be checkout-portable (a path relative to the scan root, or a
    plain file name) -- absolute paths would invalidate the baseline on every
    CI machine whose workspace differs.
    """
    targets: dict[str, dict] = {}
    for key, report in items:
        targets[key] = {"findings": [_entry(f) for f in report.findings]}
    return {
        "version": FORMAT_VERSION,
        "generated_by": f"manifestvet {__version__}",
        "targets": targets,
    }


def load(path: str | Path) -> dict:
    p = Path(path)
    if not p.is_file():
        raise BaselineError(f"no baseline file at {p}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BaselineError(f"baseline {p}: {exc}") from exc
    if (
        not isinstance(data, dict)
        or data.get("version") != FORMAT_VERSION
        or not isinstance(data.get("targets"), dict)
    ):
        raise BaselineError(f"baseline {p}: not a manifestvet v{FORMAT_VERSION} baseline")
    return data


def save(path: str | Path, data: dict) -> None:
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def compare(findings: list[Finding], data: dict, key: str) -> tuple[list[Finding], list[Finding]]:
    """Split one report's findings into ``(persisted, new)``.

    Findings under a key the baseline does not know are all new -- a baseline
    covering ``app.apk`` must not silence ``lib.apk`` just because both ship the
    same debuggable flag.
    """
    entries = data.get("targets", {}).get(key, {}).get("findings", [])
    known = {_key(e) for e in entries if isinstance(e, dict)}
    persisted: list[Finding] = []
    new: list[Finding] = []
    for f in findings:
        (persisted if (f.rule, f.where, f.message) in known else new).append(f)
    return persisted, new
