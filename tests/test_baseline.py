"""``--baseline`` / ``--save-baseline``: snapshot known findings, fail only on new ones."""

from __future__ import annotations

import json
import sys

import pytest
from _helpers import SRC  # noqa: F401  (sys.path side effect)

sys.path.insert(0, SRC)

from manifestvet import (
    baseline,  # noqa: E402
    cli,  # noqa: E402
)

VULNERABLE = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    '<manifest xmlns:android="http://schemas.android.com/apk/res/android"\n'
    '    package="com.example.app">\n'
    '    <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34"/>\n'
    '    <application android:debuggable="true" android:allowBackup="true">\n'
    '        <service android:name=".LoginService" android:exported="true"/>\n'
    "    </application>\n"
    "</manifest>\n"
)

CLEAN = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    '<manifest xmlns:android="http://schemas.android.com/apk/res/android"\n'
    '    package="com.example.app">\n'
    '    <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34"/>\n'
    "    <application/>\n"
    "</manifest>\n"
)


def _write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


# -- module level: build / save / load round trip -----------------------------

def test_build_groups_findings_by_target():
    data = baseline.build([("app.apk", _scan(VULNERABLE))])
    assert data["version"] == 1
    assert set(data["targets"]) == {"app.apk"}
    entries = data["targets"]["app.apk"]["findings"]
    assert entries, "a debuggable manifest must produce findings"
    assert all({"rule", "where", "message", "severity"} <= set(e) for e in entries)


def test_save_load_round_trip(tmp_path):
    data = baseline.build([("app.apk", _scan(VULNERABLE))])
    p = tmp_path / "bl.json"
    baseline.save(p, data)
    assert baseline.load(p) == data


def test_load_missing_file_raises(tmp_path):
    with pytest.raises(baseline.BaselineError):
        baseline.load(tmp_path / "nope.json")


def test_load_bad_json_raises(tmp_path):
    p = tmp_path / "bl.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(baseline.BaselineError):
        baseline.load(p)


def test_load_wrong_version_raises(tmp_path):
    p = tmp_path / "bl.json"
    p.write_text(json.dumps({"version": 99, "targets": {}}), encoding="utf-8")
    with pytest.raises(baseline.BaselineError):
        baseline.load(p)


def test_load_non_baseline_json_raises(tmp_path):
    p = tmp_path / "bl.json"
    p.write_text(json.dumps({"hello": 1}), encoding="utf-8")
    with pytest.raises(baseline.BaselineError):
        baseline.load(p)


# -- module level: compare -----------------------------------------------------

def test_compare_splits_persisted_and_new():
    data = baseline.build([("AndroidManifest.xml", _scan(VULNERABLE))])
    report = _scan(VULNERABLE)
    persisted, fresh = baseline.compare(report.findings, data, "AndroidManifest.xml")
    assert persisted == report.findings
    assert fresh == []


def test_compare_flags_new_findings():
    data = baseline.build([("AndroidManifest.xml", _scan(CLEAN))])
    report = _scan(VULNERABLE)
    persisted, fresh = baseline.compare(report.findings, data, "AndroidManifest.xml")
    assert persisted == []
    assert {f.rule for f in fresh} == {f.rule for f in report.findings}


def test_compare_unknown_target_is_all_new():
    data = baseline.build([("app.apk", _scan(VULNERABLE))])
    report = _scan(VULNERABLE, target="lib.apk")
    persisted, fresh = baseline.compare(report.findings, data, "lib.apk")
    assert persisted == []
    assert len(fresh) == len(report.findings)


def test_baseline_identity_ignores_line_and_offset():
    # The same finding recompiled at a different offset must stay persisted.
    data = baseline.build([("AndroidManifest.xml", _scan(VULNERABLE))])
    report = _scan(VULNERABLE)
    for f in report.findings:
        f.line += 5
        f.offset += 0x100
    persisted, fresh = baseline.compare(report.findings, data, "AndroidManifest.xml")
    assert fresh == []
    assert len(persisted) == len(report.findings)


def test_storage_key_is_portable():
    assert baseline.storage_key("C:\\repo\\app\\AndroidManifest.xml", "C:\\repo") == "app/AndroidManifest.xml"
    assert baseline.storage_key("C:\\elsewhere\\x.apk", "C:\\repo") == "x.apk"


# -- CLI level ------------------------------------------------------------------

def _scan(xml: str, *, target: str = "AndroidManifest.xml"):
    from manifestvet import engine, model

    return engine.run(model.load(xml.encode("utf-8")), target=target)


def test_cli_save_then_scan_is_clean(tmp_path, capsys):
    manifest = _write(tmp_path, "AndroidManifest.xml", VULNERABLE)
    bl = tmp_path / ".manifestvet-baseline.json"

    code = cli.main(["scan", str(manifest), "--save-baseline", str(bl)])
    assert code == 0
    assert bl.is_file()

    code = cli.main(["scan", str(manifest), "--baseline", str(bl)])
    assert code == 0
    out = capsys.readouterr().out
    assert "0 new" in out


def test_cli_baseline_does_not_silence_other_targets(tmp_path, capsys):
    known = _write(tmp_path, "app.xml", VULNERABLE)  # not scanned below
    other = _write(tmp_path, "lib.xml", VULNERABLE)
    bl = tmp_path / "bl.json"
    assert cli.main(["scan", str(known), "--save-baseline", str(bl)]) == 0

    code = cli.main(["scan", str(other), "--baseline", str(bl)])
    assert code == 1  # findings for an unscanned target stay fresh


def test_cli_new_finding_after_baseline_still_fails(tmp_path, capsys):
    bl = tmp_path / "bl.json"
    assert cli.main(["scan", str(_write(tmp_path, "m1", CLEAN)), "--save-baseline", str(bl)]) == 0

    code = cli.main(["scan", str(_write(tmp_path, "m2", VULNERABLE)), "--baseline", str(bl)])
    assert code == 1
    out = capsys.readouterr().out
    assert "0 accepted" in out and "0 new" not in out


def test_cli_missing_baseline_file_exits_two(tmp_path, capsys):
    manifest = _write(tmp_path, "AndroidManifest.xml", VULNERABLE)
    code = cli.main(["scan", str(manifest), "--baseline", str(tmp_path / "nope.json")])
    assert code == 2
    assert "no baseline file" in capsys.readouterr().err


def test_cli_corrupt_baseline_exits_two(tmp_path, capsys):
    manifest = _write(tmp_path, "AndroidManifest.xml", VULNERABLE)
    bl = _write(tmp_path, "bl.json", "]]]")
    code = cli.main(["scan", str(manifest), "--baseline", str(bl)])
    assert code == 2


def test_cli_json_format_with_baseline_reports_only_new(tmp_path, capsys):
    bl = tmp_path / "bl.json"
    dirty = _write(tmp_path, "m1", VULNERABLE)
    assert cli.main(["scan", str(dirty), "--save-baseline", str(bl)]) == 0
    capsys.readouterr()  # drop the generation-mode chatter before reading JSON

    code = cli.main(["scan", str(dirty), "--baseline", str(bl), "-f", "json"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["findings"] == []


def test_cli_quiet_mode_with_baseline(tmp_path, capsys):
    bl = tmp_path / "bl.json"
    dirty = _write(tmp_path, "AndroidManifest.xml", VULNERABLE)
    assert cli.main(["scan", str(dirty), "--save-baseline", str(bl)]) == 0

    code = cli.main(["scan", str(dirty), "--baseline", str(bl), "--quiet"])
    assert code == 0


def test_cli_save_baseline_honours_min_severity(tmp_path, capsys):
    manifest = _write(tmp_path, "AndroidManifest.xml", VULNERABLE)
    bl = tmp_path / "bl.json"
    assert cli.main(["scan", str(manifest), "--save-baseline", str(bl), "--min-severity", "high"]) == 0
    data = baseline.load(bl)
    severities = {e["severity"] for e in data["targets"]["AndroidManifest.xml"]["findings"]}
    assert severities <= {"critical", "high"}


def test_baseline_json_is_diff_friendly(tmp_path):
    # The file must stay diff-friendly: utf-8, indent 2, trailing newline.
    bl = tmp_path / "bl.json"
    baseline.save(bl, baseline.build([("app.apk", _scan(VULNERABLE))]))
    raw = bl.read_text(encoding="utf-8")
    assert raw.endswith("\n")
    assert json.loads(raw)["version"] == 1
