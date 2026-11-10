"""The CLI contract: inputs, formats, exit codes."""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest
from _helpers import app_xml, manifest

from manifestvet import axmlwrite, cli

NASTY = app_xml(
    '<activity android:name=".Open" android:exported="true"/>',
    application='android:debuggable="true" android:allowBackup="true"',
)
CLEAN = app_xml(
    '<activity android:name=".A" android:exported="false"/>',
    application='android:allowBackup="false" android:usesCleartextTraffic="false"',
)


def _run(capsys, *argv) -> tuple[int, str]:
    code = cli.main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out + captured.err


def test_scan_a_text_manifest(tmp_path, capsys):
    path = tmp_path / "AndroidManifest.xml"
    path.write_text(NASTY, encoding="utf-8")
    code, out = _run(capsys, "scan", str(path), "--no-color")
    assert code == 1  # critical finding, default --fail-on high
    assert "MVT001" in out


def test_scan_clean_manifest_exits_zero(tmp_path, capsys):
    path = tmp_path / "AndroidManifest.xml"
    path.write_text(CLEAN, encoding="utf-8")
    code, out = _run(capsys, "scan", str(path), "--no-color")
    assert code == 0
    assert "no findings" in out


def test_scan_compiled_apk(compiled_apk, capsys):
    path = compiled_apk(NASTY)
    code, out = _run(capsys, "scan", path, "--no-color", "--quiet")
    assert code == 1
    assert "findings" in out


def test_scan_directory_finds_every_manifest(tmp_path, capsys):
    for name in ("a/AndroidManifest.xml", "b/AndroidManifest.xml"):
        target = tmp_path / name
        target.parent.mkdir(parents=True)
        target.write_text(CLEAN, encoding="utf-8")
    code, out = _run(capsys, "scan", str(tmp_path), "--no-color", "--quiet")
    assert code == 0
    assert out.count("findings") == 2


def test_scan_skips_build_directories(tmp_path, capsys):
    kept = tmp_path / "app/AndroidManifest.xml"
    kept.parent.mkdir(parents=True)
    kept.write_text(CLEAN, encoding="utf-8")
    skipped = tmp_path / "app/build/intermediates/AndroidManifest.xml"
    skipped.parent.mkdir(parents=True)
    skipped.write_text(CLEAN, encoding="utf-8")
    code, out = _run(capsys, "scan", str(tmp_path), "--no-color", "--quiet")
    assert out.count("findings") == 1


def test_json_format_is_parseable(tmp_path, capsys):
    path = tmp_path / "AndroidManifest.xml"
    path.write_text(NASTY, encoding="utf-8")
    code, out = _run(capsys, "scan", str(path), "-f", "json")
    payload = json.loads(out)
    assert payload["package"] == "com.example.app"
    assert code == 1


def test_json_format_over_a_directory_wraps_the_reports(tmp_path, capsys):
    for name in ("a/AndroidManifest.xml", "b/AndroidManifest.xml"):
        target = tmp_path / name
        target.parent.mkdir(parents=True)
        target.write_text(CLEAN, encoding="utf-8")
    _code, out = _run(capsys, "scan", str(tmp_path), "-f", "json")
    payload = json.loads(out)
    assert len(payload["reports"]) == 2


def test_sarif_format_is_parseable(tmp_path, capsys):
    path = tmp_path / "AndroidManifest.xml"
    path.write_text(NASTY, encoding="utf-8")
    _code, out = _run(capsys, "scan", str(path), "-f", "sarif")
    payload = json.loads(out)
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["results"]


def test_fail_on_none_makes_a_bad_manifest_exit_zero(tmp_path, capsys):
    path = tmp_path / "AndroidManifest.xml"
    path.write_text(NASTY, encoding="utf-8")
    code, _ = _run(capsys, "scan", str(path), "--fail-on", "none")
    assert code == 0


def test_fail_on_critical(tmp_path, capsys):
    path = tmp_path / "AndroidManifest.xml"
    path.write_text(NASTY, encoding="utf-8")
    assert _run(capsys, "scan", str(path), "--fail-on", "critical")[0] == 1


def test_min_severity_filters_output(tmp_path, capsys):
    path = tmp_path / "AndroidManifest.xml"
    path.write_text(
        manifest('<uses-permission android:name="android.permission.QUERY_ALL_PACKAGES"/>'),
        encoding="utf-8",
    )
    _code, out = _run(capsys, "scan", str(path), "--min-severity", "high", "--no-color")
    assert "MVT036" not in out
    assert "no findings" in out


def test_quiet_prints_one_line_per_manifest(tmp_path, capsys):
    path = tmp_path / "AndroidManifest.xml"
    path.write_text(NASTY, encoding="utf-8")
    _code, out = _run(capsys, "scan", str(path), "--quiet")
    assert out.strip().count("\n") == 0


def test_unreadable_input_exits_two(capsys):
    code, out = _run(capsys, "scan", "does/not/exist.apk", "--no-color")
    assert code == 2


def test_garbage_manifest_exits_two(tmp_path, capsys):
    path = tmp_path / "AndroidManifest.xml"
    path.write_bytes(b"\x00\x01\x02\x03")
    code, out = _run(capsys, "scan", str(path), "--no-color")
    assert code == 2
    assert "unrecognised" in out


def test_rules_command_lists_all_of_them(capsys):
    code, out = _run(capsys, "rules")
    assert code == 0
    assert "MVT001" in out
    assert "MVT040" in out
    assert "40 rules" in out


def test_rules_json(capsys):
    _code, out = _run(capsys, "rules", "--json")
    payload = json.loads(out)
    assert len(payload) == 40
    assert {"id", "title", "severity", "stage", "why", "fix"} <= set(payload[0])


def test_attrs_dumps_offsets(tmp_path, capsys):
    path = tmp_path / "AndroidManifest.xml"
    path.write_text(NASTY, encoding="utf-8")
    code, out = _run(capsys, "attrs", str(path))
    assert code == 0
    assert "debuggable" in out
    assert "0x" in out
    assert "id=-" in out  # text manifests have no resource ids


def test_attrs_on_a_compiled_manifest_shows_resource_ids(compiled_apk, capsys):
    code, out = _run(capsys, "attrs", compiled_apk(NASTY))
    assert code == 0
    assert "id=0x0101000f" in out  # debuggable


def test_demo_exits_zero_and_covers_the_table(capsys):
    code, out = _run(capsys, "demo", "--no-color")
    assert code == 0
    assert "40/40" in out


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--version"])
    assert excinfo.value.code == 0
    assert "manifestvet" in capsys.readouterr().out


def test_module_entrypoint_runs():
    """`python -m manifestvet` must work without the console script installed."""
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["PYTHONPATH"] = os.path.join(repo, "src")
    proc = subprocess.run(
        [sys.executable, "-m", "manifestvet", "rules"],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "MVT001" in proc.stdout


def test_demo_bytes_are_real_axml():
    from manifestvet import demo

    assert axmlwrite.compile_text(demo.MODERN)[:2] == b"\x03\x00"
