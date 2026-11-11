"""The MCP tools: same engine, model-shaped output, and a manifest that cannot drift
from what the server actually registers."""

from __future__ import annotations

import asyncio
import json

import pytest
from _helpers import app_xml

from manifestvet import mcp_server
from manifestvet.rules import REGISTRY

mcp = pytest.importorskip("mcp", reason="the mcp extra is optional")

NASTY = app_xml(
    '<activity android:name=".Open" android:exported="true"/>'
    '<provider android:name=".P" android:authorities="com.example.app.p" android:exported="true"/>',
    application='android:debuggable="true" android:allowBackup="true"',
)


def test_tool_manifest_lists_eight_tools():
    assert len(mcp_server.tool_manifest()) == 8
    assert {t["name"] for t in mcp_server.tool_manifest()} == set(mcp_server.TOOLS)


def test_every_tool_has_a_description():
    for tool in mcp_server.tool_manifest():
        assert len(tool["description"]) > 30, tool["name"]


def test_server_registers_exactly_the_manifest():
    server = mcp_server.build_server()
    tools = asyncio.run(server.list_tools())
    assert {tool.name for tool in tools} == set(mcp_server.TOOLS)


def test_server_tool_descriptions_are_not_empty():
    server = mcp_server.build_server()
    for tool in asyncio.run(server.list_tools()):
        assert tool.description


def test_scan_tool_on_a_directory(tmp_path):
    (tmp_path / "AndroidManifest.xml").write_text(NASTY, encoding="utf-8")
    payload = json.loads(mcp_server.manifestvet_scan(str(tmp_path)))
    assert payload["targets"] == 1
    report = payload["reports"][0]
    assert report["package"] == "com.example.app"
    assert any(f["rule"] == "MVT001" for f in report["findings"])
    assert report["summary"].startswith("com.example.app:")


def test_scan_tool_on_a_missing_path_reports_an_error():
    payload = json.loads(mcp_server.manifestvet_scan("no/such/path"))
    assert "path not found" in payload["error"]


def test_manifest_tool_takes_inline_xml():
    payload = json.loads(mcp_server.manifestvet_manifest(NASTY))
    assert payload["package"] == "com.example.app"
    assert payload["worst"] == "critical"


def test_manifest_tool_rejects_garbage():
    payload = json.loads(mcp_server.manifestvet_manifest("not a manifest"))
    assert "could not parse" in payload["error"]


def test_components_tool_lists_the_surface(tmp_path):
    (tmp_path / "AndroidManifest.xml").write_text(NASTY, encoding="utf-8")
    payload = json.loads(mcp_server.manifestvet_components(str(tmp_path)))
    target = payload["targets"][0]
    assert target["exported_count"] == 2
    exported = [c for c in target["components"] if c["exported"]]
    assert {c["kind"] for c in exported} == {"activity", "provider"}
    assert all(c["offset"] > 0 for c in target["components"])


def test_components_tool_flags_a_weak_guard(tmp_path):
    xml = app_xml(
        '<activity android:name=".A" android:exported="true" android:permission="android.permission.INTERNET"/>',
        application='android:allowBackup="false" android:usesCleartextTraffic="false"',
    )
    (tmp_path / "AndroidManifest.xml").write_text(xml, encoding="utf-8")
    payload = json.loads(mcp_server.manifestvet_components(str(tmp_path)))
    component = payload["targets"][0]["components"][0]
    assert component["guard"] == "android.permission.INTERNET"
    assert component["guard_is_weak"] is True


def test_explain_tool_is_case_insensitive():
    payload = json.loads(mcp_server.manifestvet_explain("mvt037"))
    assert payload["id"] == "MVT037"
    assert payload["severity"] == "critical"
    assert payload["docs"].endswith("#mvt037")


def test_explain_tool_lists_the_known_rules_on_a_typo():
    payload = json.loads(mcp_server.manifestvet_explain("MVT999"))
    assert "unknown rule" in payload["error"]
    assert "MVT001" in payload["error"]


def test_rules_tool_filters_by_stage():
    payload = json.loads(mcp_server.manifestvet_rules(stage=3))
    assert payload["count"] >= 1
    assert all(r["stage"] == 3 for r in payload["rules"])


def test_rules_tool_reports_the_full_table():
    payload = json.loads(mcp_server.manifestvet_rules())
    assert payload["count"] == len(REGISTRY)


def test_rules_tool_filters_by_severity():
    payload = json.loads(mcp_server.manifestvet_rules(severity="critical"))
    assert all(r["severity"] == "critical" for r in payload["rules"])


def test_sarif_tool_returns_one_run(tmp_path):
    (tmp_path / "AndroidManifest.xml").write_text(NASTY, encoding="utf-8")
    payload = json.loads(mcp_server.manifestvet_sarif(str(tmp_path)))
    assert len(payload["runs"]) == 1
    assert payload["runs"][0]["results"]


def test_demo_tool_covers_every_rule():
    payload = json.loads(mcp_server.manifestvet_demo())
    assert payload["rules_triggered"] == payload["rules_total"] == 40
    assert len(payload["manifests"]) == 3


def test_attrs_tool_dumps_offsets(tmp_path):
    """The evidence view must carry byte offsets, lines and resource ids -
    a dump without them proves nothing about where a value came from."""
    (tmp_path / "AndroidManifest.xml").write_text(NASTY, encoding="utf-8")
    out = mcp_server.manifestvet_attrs(str(tmp_path))
    assert "<manifest" in out or "<application" in out
    assert "0x" in out  # byte offsets are printed as hex
    assert "L1" in out or "L" in out  # line numbers
