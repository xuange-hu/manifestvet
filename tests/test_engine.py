"""Reporting mechanics: ordering, counts, thresholds, offset narrowing."""

from __future__ import annotations

import pytest
from _helpers import app_xml, manifest, scan_text

from manifestvet import engine


def _report(xml: str) -> engine.Report:
    return scan_text(xml)


NASTY = app_xml(
    '<activity android:name=".Open" android:exported="true"/>'
    '<service android:name=".Svc" android:exported="true"/>',
    application='android:debuggable="true" android:allowBackup="true"',
)


def test_findings_are_sorted_by_severity_then_rule():
    report = _report(NASTY)
    severities = [f.severity for f in report.findings]
    ranks = [engine.SEVERITY_ORDER[s] for s in severities]
    assert ranks == sorted(ranks)


def test_counts_add_up():
    report = _report(NASTY)
    assert sum(report.counts.values()) == len(report.findings)


def test_worst_is_the_highest_severity_present():
    assert _report(NASTY).worst == "critical"


def test_worst_is_none_for_a_clean_report():
    clean = app_xml(
        '<activity android:name=".A" android:exported="false"/>',
        application='android:allowBackup="false" android:usesCleartextTraffic="false"',
    )
    report = _report(clean)
    assert report.findings == []
    assert report.worst == "none"
    assert report.risk == 0


def test_risk_is_capped_at_100():
    from manifestvet import demo

    report = scan_text(demo.VAULT)
    assert report.risk == 100
    assert report.counts["critical"] >= 2


def test_risk_counts_one_critical_as_forty():
    xml = app_xml(
        '<activity android:name=".A" android:exported="false"/>',
        application='android:debuggable="true" android:allowBackup="false" android:usesCleartextTraffic="false"',
    )
    assert _report(xml).risk == 40


@pytest.mark.parametrize(
    "threshold,expected",
    [
        ("none", False),
        ("critical", True),
        ("high", True),
        ("medium", True),
        ("low", True),
        ("note", True),
    ],
)
def test_fail_thresholds(threshold, expected):
    assert _report(NASTY).should_fail(threshold) is expected


def test_fail_threshold_above_the_worst_finding_does_not_fail():
    xml = manifest('<uses-permission android:name="android.permission.QUERY_ALL_PACKAGES"/>')
    report = _report(xml)
    assert report.worst == "low"
    assert report.should_fail("medium") is False
    assert report.should_fail("low") is True


def test_unknown_threshold_never_fails():
    assert _report(NASTY).should_fail("banana") is False


def test_finding_offset_points_at_the_attribute_when_one_is_named():
    xml = app_xml(
        '<activity android:name=".A" android:exported="false"/>',
        application='android:debuggable="true" android:allowBackup="false" android:usesCleartextTraffic="false"',
    )
    finding = next(f for f in _report(xml).findings if f.rule == "MVT001")
    # attribute offsets sit after the element's own start tag offset
    assert finding.offset > 0
    assert finding.line >= 1
    assert 'debuggable="true"' in finding.evidence


def test_report_serialises_with_hex_offsets():
    payload = _report(NASTY).to_dict()
    assert payload["counts"]["critical"] >= 1
    assert all(f["offset_hex"].startswith("0x") for f in payload["findings"])
    assert payload["meta"]["format"] == "text"
    assert payload["meta"]["unresolved_ids"] == []


def test_rules_run_matches_the_registry():
    from manifestvet.rules import REGISTRY

    assert _report(NASTY).rules_run == len(REGISTRY)


def test_triggered_returns_the_rule_ids():
    fired = _report(NASTY).triggered()
    assert "MVT001" in fired
    assert "MVT013" in fired
    assert "MVT014" in fired
