"""Renderers must agree with the report and with each other."""

from __future__ import annotations

import json

from _helpers import app_xml, scan_text

from manifestvet import render

NASTY = app_xml(
    '<activity android:name=".Open" android:exported="true"/>',
    application='android:debuggable="true" android:allowBackup="true"',
)


def _report():
    return scan_text(NASTY, target="demo/AndroidManifest.xml")


def test_text_output_contains_the_header_and_findings():
    out = render.text(_report(), color=False)
    assert "package=com.example.app" in out
    assert "MVT001" in out
    assert "findings" in out
    assert "risk=" in out


def test_text_output_has_no_ansi_when_colour_is_off():
    out = render.text(_report(), color=False)
    assert "\x1b[" not in out


def test_text_output_has_ansi_when_colour_is_on():
    assert "\x1b[" in render.text(_report(), color=True)


def test_explain_adds_the_reasoning():
    plain = render.text(_report(), color=False)
    explained = render.text(_report(), color=False, explain=True)
    assert "why:" not in plain
    assert "why:" in explained
    assert len(explained) > len(plain)


def test_clean_report_says_so():
    from _helpers import app_xml as ax

    clean = ax(
        '<activity android:name=".A" android:exported="false"/>',
        application='android:allowBackup="false" android:usesCleartextTraffic="false"',
    )
    out = render.text(scan_text(clean), color=False)
    assert "no findings" in out


def test_offset_appears_in_the_text_block():
    out = render.text(_report(), color=False)
    assert "offset 0x" in out


def test_summary_line_is_one_line():
    line = render.summary_line(_report())
    assert "\n" not in line
    assert "findings" in line


def test_json_is_parseable_and_matches_the_report():
    payload = json.loads(render.as_json(_report()))
    assert payload["package"] == "com.example.app"
    assert len(payload["findings"]) == len(_report().findings)


def test_sarif_is_valid_shape():
    payload = json.loads(render.sarif(_report(), tool_version="0.1.0"))
    assert payload["version"] == "2.1.0"
    run = payload["runs"][0]
    assert run["tool"]["driver"]["name"] == "manifestvet"
    assert run["tool"]["driver"]["version"] == "0.1.0"
    assert run["results"]
    assert run["tool"]["driver"]["rules"]


def test_sarif_levels_map_from_severity():
    payload = json.loads(render.sarif(_report()))
    run = payload["runs"][0]
    by_rule = {rule["id"]: rule["defaultConfiguration"]["level"] for rule in run["tool"]["driver"]["rules"]}
    assert by_rule["MVT001"] == "error"
    assert all(result["level"] in {"error", "warning", "note"} for result in run["results"])


def test_sarif_uris_use_forward_slashes():
    report = scan_text(NASTY, target="a\\b\\AndroidManifest.xml")
    payload = json.loads(render.sarif(report))
    uri = payload["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert "\\" not in uri


def test_sarif_declares_each_rule_once():
    payload = json.loads(render.sarif(_report()))
    rules = payload["runs"][0]["tool"]["driver"]["rules"]
    ids = [rule["id"] for rule in rules]
    assert len(ids) == len(set(ids))


def test_sarif_region_line_is_at_least_one():
    payload = json.loads(render.sarif(_report()))
    for result in payload["runs"][0]["results"]:
        assert result["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1


def test_empty_report_renders_an_empty_sarif_run():
    clean = app_xml(
        '<activity android:name=".A" android:exported="false"/>',
        application='android:allowBackup="false" android:usesCleartextTraffic="false"',
    )
    payload = json.loads(render.sarif(scan_text(clean)))
    assert payload["runs"][0]["results"] == []
    assert payload["runs"][0]["tool"]["driver"]["rules"] == []
