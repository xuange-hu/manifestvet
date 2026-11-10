"""Entry points: the console scripts, the tool count, the version, the check path.

These are the surfaces a user hits before any rule runs, and they are the ones CI
never exercises (CI imports the package directly).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from manifestvet import __version__, cli, mcp_server
from manifestvet.__about__ import __version_info__
from manifestvet.rules import REGISTRY

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_version_is_three_parts():
    assert __version__ == ".".join(str(part) for part in __version_info__)
    assert len(__version_info__) == 3


def test_mcp_check_prints_every_tool(capsys):
    code = cli.main(["mcp", "--check"])
    out = capsys.readouterr().out
    assert code == 0
    for name in mcp_server.TOOLS:
        assert name in out
    assert "7 tools" in out


def test_mcp_tool_decorator_count_matches_the_manifest():
    path = os.path.join(REPO_ROOT, "src", "manifestvet", "mcp_server.py")
    with open(path, encoding="utf-8") as fh:
        source = fh.read()
    assert source.count("@mcp.tool(") == len(mcp_server.TOOLS)


def test_registry_ids_are_stable():
    # Findings are referenced by id in CI suppressions and in the docs; a renumber
    # would silently break every existing baseline.
    assert [rule.id for rule in sorted(REGISTRY, key=lambda r: r.id)][:3] == ["MVT001", "MVT002", "MVT003"]
    assert "MVT040" in {rule.id for rule in REGISTRY}


def test_rules_markdown_is_printable(capsys):
    code = cli.main(["rules", "--markdown"])
    out = capsys.readouterr().out
    assert code == 0
    assert out.startswith("# Rules")
    assert "MVT040" in out


def test_demo_command_returns_zero(capsys):
    assert cli.main(["demo", "--no-color"]) == 0


def test_console_script_entrypoint_is_importable():
    import manifestvet.cli as module

    assert callable(module.main)


def test_json_output_is_utf8_safe(capsys):
    """A manifest with a CJK label must not blow up the JSON writer on a cp936 console."""
    from _helpers import app_xml

    xml = app_xml(
        '<activity android:name=".A" android:exported="false" android:label="密钥"/>',
        application='android:allowBackup="false" android:usesCleartextTraffic="false"',
    )
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False, encoding="utf-8") as handle:
        handle.write(xml)
        path = handle.name
    try:
        code = cli.main(["scan", path, "-f", "json"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["package"] == "com.example.app"
        assert code == 0
    finally:
        os.unlink(path)


def test_help_exits_zero():
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--help"])
    assert excinfo.value.code == 0


def test_subcommand_without_arguments_is_a_usage_error(capsys):
    with pytest.raises(SystemExit) as excinfo:
        cli.main([])
    assert excinfo.value.code == 2


def test_version_string_is_reported_by_the_module():
    proc = subprocess.run(
        [sys.executable, "-c", "import manifestvet; print(manifestvet.__version__)"],
        cwd=REPO_ROOT,
        env={**os.environ, "PYTHONPATH": os.path.join(REPO_ROOT, "src")},
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert proc.stdout.strip() == __version__
