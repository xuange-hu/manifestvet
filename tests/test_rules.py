"""One positive and one negative case per rule, plus the false positives that were
actually hit while building this against real manifests.

The table is the spec: if ``TRIGGERS`` and the registry ever disagree the tests
fail, so adding a rule without a sample is not possible.
"""

from __future__ import annotations

import pytest
from _helpers import app_xml, manifest

from manifestvet.rules import REGISTRY, SEVERITY_ORDER

APP = "<application{attrs}>{body}</application>"

# A modern, correctly configured manifest. Nothing below may fire on it.
CLEAN = app_xml(
    '<activity android:name=".Main" android:exported="false"/>',
    application='android:allowBackup="false" android:usesCleartextTraffic="false"',
)

TRIGGERS: dict[str, str] = {
    "MVT001": app_xml(
        '<activity android:name=".A" android:exported="false"/>',
        application='android:debuggable="true" android:allowBackup="false" android:usesCleartextTraffic="false"',
    ),
    "MVT002": manifest(
        '<application><activity android:name=".A" android:exported="false"/></application>',
        sdk='<uses-sdk android:minSdkVersion="21" android:targetSdkVersion="29"/>',
    ),
    "MVT003": app_xml(
        '<activity android:name=".A" android:exported="false"/>',
        application='android:allowBackup="true" android:usesCleartextTraffic="false"',
    ),
    "MVT004": app_xml(
        '<activity android:name=".A" android:exported="false"/>',
        application='android:allowBackup="false" android:usesCleartextTraffic="true"',
    ),
    "MVT005": app_xml(
        '<activity android:name=".A" android:exported="false"/>',
        application='android:allowBackup="false"',
        sdk='<uses-sdk android:minSdkVersion="21" android:targetSdkVersion="27"/>',
    ),
    "MVT006": app_xml(
        '<activity android:name=".A" android:exported="false"/>',
        application='android:allowBackup="false" android:usesCleartextTraffic="false" '
        'android:requestLegacyExternalStorage="true"',
    ),
    "MVT007": manifest(
        "<application/>",
        attrs='android:sharedUserId="com.example.shared"',
        sdk='<uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34"/>',
    ),
    "MVT008": app_xml(
        '<activity android:name=".A" android:exported="false"/>',
        application='android:allowBackup="false" android:usesCleartextTraffic="false"',
        sdk='<uses-sdk android:minSdkVersion="19" android:targetSdkVersion="34"/>',
    ),
    "MVT009": app_xml(
        '<activity android:name=".A" android:exported="false"/>',
        application='android:allowBackup="false" android:usesCleartextTraffic="false"',
        sdk='<uses-sdk android:minSdkVersion="24" android:targetSdkVersion="30"/>',
    ),
    "MVT010": app_xml(
        '<activity android:name=".A" android:exported="false"/>',
        application='android:allowBackup="false" android:usesCleartextTraffic="false"',
        sdk='<uses-sdk android:minSdkVersion="24"/>',
    ),
    "MVT011": app_xml(
        '<activity android:name=".A" android:exported="false"/>',
        application='android:allowBackup="false" android:usesCleartextTraffic="false"',
        sdk="",
    ),
    "MVT012": app_xml(
        '<activity android:name=".A"><intent-filter>'
        '<action android:name="android.intent.action.SEND"/></intent-filter></activity>',
        application='android:allowBackup="false" android:usesCleartextTraffic="false"',
    ),
    "MVT013": app_xml(
        '<activity android:name=".A" android:exported="true"/>',
        application='android:allowBackup="false" android:usesCleartextTraffic="false"',
    ),
    "MVT014": app_xml(
        '<service android:name=".S" android:exported="true"/>',
        application='android:allowBackup="false" android:usesCleartextTraffic="false"',
    ),
    "MVT015": app_xml(
        '<receiver android:name=".R" android:exported="true"/>',
        application='android:allowBackup="false" android:usesCleartextTraffic="false"',
    ),
    "MVT016": app_xml(
        '<provider android:name=".P" android:authorities="com.example.app.p" android:exported="true"/>',
        application='android:allowBackup="false" android:usesCleartextTraffic="false"',
    ),
    "MVT017": app_xml(
        '<activity android:name=".Hidden" android:exported="true"/>',
        application='android:allowBackup="false" android:usesCleartextTraffic="false"',
    ),
    "MVT018": app_xml(
        '<provider android:name=".P" android:authorities="com.example.app.p" '
        'android:exported="true" android:grantUriPermissions="true"/>',
        application='android:allowBackup="false" android:usesCleartextTraffic="false"',
    ),
    "MVT019": app_xml(
        '<provider android:name=".P" android:authorities="com.example.app.p" android:exported="false">'
        '<grant-uri-permission android:path="/"/></provider>',
        application='android:allowBackup="false" android:usesCleartextTraffic="false"',
    ),
    "MVT020": app_xml(
        '<provider android:name=".P" android:exported="false"/>',
        application='android:allowBackup="false" android:usesCleartextTraffic="false"',
    ),
    "MVT021": app_xml(
        '<activity android:name=".A" android:exported="true" android:launchMode="singleTask"/>',
        application='android:allowBackup="false" android:usesCleartextTraffic="false"',
    ),
    "MVT022": app_xml(
        '<activity android:name=".A" android:exported="false" android:allowTaskReparenting="true"/>',
        application='android:allowBackup="false" android:usesCleartextTraffic="false"',
    ),
    "MVT023": app_xml(
        '<activity android:name=".L" android:exported="true"><intent-filter>'
        '<action android:name="android.intent.action.VIEW"/>'
        '<category android:name="android.intent.category.BROWSABLE"/>'
        '<data android:scheme="https" android:host="example.com"/></intent-filter></activity>',
        application='android:allowBackup="false" android:usesCleartextTraffic="false"',
    ),
    "MVT024": app_xml(
        '<activity android:name=".L" android:exported="true"><intent-filter>'
        '<action android:name="android.intent.action.VIEW"/>'
        '<data android:scheme="https" android:host="*" android:autoVerify="true"/></intent-filter></activity>',
        application='android:allowBackup="false" android:usesCleartextTraffic="false"',
    ),
    "MVT025": app_xml(
        '<activity android:name=".L" android:exported="true"><intent-filter>'
        '<action android:name="android.intent.action.VIEW"/>'
        '<data android:scheme="https" android:host="example.com" android:pathPrefix="/"/></intent-filter></activity>',
        application='android:allowBackup="false" android:usesCleartextTraffic="false"',
    ),
    "MVT026": app_xml(
        '<activity android:name=".L" android:exported="true"><intent-filter>'
        '<action android:name="android.intent.action.VIEW"/>'
        '<data android:scheme="vaultapp" android:host="open"/></intent-filter></activity>',
        application='android:allowBackup="false" android:usesCleartextTraffic="false"',
    ),
    "MVT027": app_xml(
        '<activity android:name=".L" android:exported="false"><intent-filter>'
        '<category android:name="android.intent.category.BROWSABLE"/></intent-filter></activity>',
        application='android:allowBackup="false" android:usesCleartextTraffic="false"',
    ),
    "MVT028": app_xml(
        '<activity android:name=".L" android:exported="false"><intent-filter>'
        '<action android:name="android.intent.action.VIEW"/>'
        '<data android:scheme="vaultapp"/></intent-filter></activity>',
        application='android:allowBackup="false" android:usesCleartextTraffic="false"',
    ),
    "MVT029": app_xml(
        '<receiver android:name=".B" android:exported="true"><intent-filter>'
        '<action android:name="android.intent.action.BOOT_COMPLETED"/></intent-filter></receiver>',
        application='android:allowBackup="false" android:usesCleartextTraffic="false"',
    ),
    "MVT030": app_xml(
        '<receiver android:name=".R" android:exported="false"><intent-filter>'
        '<action android:name="PING"/></intent-filter></receiver>',
        application='android:allowBackup="false" android:usesCleartextTraffic="false"',
    ),
    "MVT031": manifest(
        '<permission android:name="com.example.app.READ" android:protectionLevel="normal"/>'
        "<application/>",
        sdk='<uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34"/>',
    ),
    "MVT032": manifest(
        '<permission android:name="com.example.app.READ"/><application/>',
        sdk='<uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34"/>',
    ),
    "MVT033": manifest(
        '<permission android:name="com.example.app.ADMIN" android:protectionLevel="dangerous"/>'
        "<application/>",
        sdk='<uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34"/>',
    ),
    "MVT034": manifest(
        '<uses-permission android:name="android.permission.INSTALL_PACKAGES"/><application/>',
        sdk='<uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34"/>',
    ),
    "MVT035": manifest(
        '<uses-permission android:name="com.example.app.READ_DATA"/><application/>',
        sdk='<uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34"/>',
    ),
    "MVT036": manifest(
        '<uses-permission android:name="android.permission.QUERY_ALL_PACKAGES"/><application/>',
        sdk='<uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34"/>',
    ),
    "MVT037": app_xml(
        '<activity android:name=".A" android:exported="true" android:permission="android.permission.VIBRATE"/>',
        application='android:allowBackup="false" android:usesCleartextTraffic="false"',
    ),
    "MVT038": app_xml(
        '<provider android:name=".One" android:authorities="com.example.app.shared" android:exported="false"/>'
        '<provider android:name=".Two" android:authorities="com.example.app.shared" android:exported="false"/>',
        application='android:allowBackup="false" android:usesCleartextTraffic="false"',
    ),
    "MVT039": app_xml(
        '<activity android:name=".A" android:exported="true" android:permission="com.example.app.MISSING"/>',
        application='android:allowBackup="false" android:usesCleartextTraffic="false"',
    ),
    "MVT040": app_xml(
        '<activity android:name=".A" android:exported="true" android:process="com.example.shared"/>',
        application='android:allowBackup="false" android:usesCleartextTraffic="false"',
    ),
}

RULE_IDS = sorted(rule.id for rule in REGISTRY)


# -- the table ---------------------------------------------------------------


def test_every_rule_has_a_trigger():
    assert sorted(TRIGGERS) == RULE_IDS, (
        "a rule without a sample cannot be trusted; add it to TRIGGERS"
    )


def test_rule_ids_are_unique_and_well_formed():
    assert len(RULE_IDS) == len(set(RULE_IDS))
    assert all(rule_id.startswith("MVT") and len(rule_id) == 6 for rule_id in RULE_IDS)


def test_rule_metadata_is_complete():
    for rule in REGISTRY:
        assert rule.title and rule.why and rule.fix, rule.id
        assert rule.severity in SEVERITY_ORDER, rule.id
        assert rule.stage in {1, 2, 3}, rule.id


def test_the_rule_table_has_forty_rules():
    # The README, the badge and the demo all quote this number.
    assert len(RULE_IDS) == 40


# -- every rule, both directions --------------------------------------------


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_rule_fires_on_its_sample(rule_id, one_finding):
    finding = one_finding(TRIGGERS[rule_id], rule_id)
    assert finding.severity == next(r.severity for r in REGISTRY if r.id == rule_id)
    assert finding.message
    assert finding.fix


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_rule_is_silent_on_a_clean_manifest(rule_id, rules_fired):
    assert rule_id not in rules_fired(CLEAN)


def test_a_correct_manifest_produces_no_findings(rules_fired):
    assert rules_fired(CLEAN) == set()


# -- false positives that real manifests produced ---------------------------


def test_launcher_activity_is_not_reported_as_an_open_activity(rules_fired):
    xml = app_xml(
        '<activity android:name=".Main" android:exported="true"><intent-filter>'
        '<action android:name="android.intent.action.MAIN"/>'
        '<category android:name="android.intent.category.LAUNCHER"/>'
        "</intent-filter></activity>",
        application='android:allowBackup="false" android:usesCleartextTraffic="false"',
    )
    fired = rules_fired(xml)
    assert "MVT013" not in fired
    assert "MVT017" not in fired


def test_reverse_domain_actions_from_a_library_are_not_flagged(rules_fired):
    # androidx.profileinstaller.action.* is qualified; it is not a global token.
    xml = app_xml(
        '<receiver android:name=".R" android:exported="false"><intent-filter>'
        '<action android:name="androidx.profileinstaller.action.INSTALL_PROFILE"/>'
        "</intent-filter></receiver>",
        application='android:allowBackup="false" android:usesCleartextTraffic="false"',
    )
    assert "MVT030" not in rules_fired(xml)


def test_signature_guard_satisfies_the_weak_guard_rule(rules_fired):
    xml = manifest(
        '<permission android:name="com.example.app.SIG" android:protectionLevel="signature"/>'
        '<application android:allowBackup="false"><activity android:name=".A" '
        'android:exported="true" android:permission="com.example.app.SIG"/></application>',
        sdk='<uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34"/>',
    )
    assert "MVT037" not in rules_fired(xml)


def test_application_level_permission_silences_the_open_export_rules(rules_fired):
    xml = manifest(
        '<permission android:name="com.example.app.SIG" android:protectionLevel="signature"/>'
        '<application android:allowBackup="false" android:permission="com.example.app.SIG">'
        '<activity android:name=".A" android:exported="true"/>'
        '<service android:name=".S" android:exported="true"/></application>',
        sdk='<uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34"/>',
    )
    fired = rules_fired(xml)
    assert not fired & {"MVT013", "MVT014", "MVT015", "MVT016"}


def test_scoped_backup_is_not_flagged(rules_fired):
    xml = app_xml(
        '<activity android:name=".A" android:exported="false"/>',
        application='android:allowBackup="true" android:dataExtractionRules="@xml/backup_rules" '
        'android:usesCleartextTraffic="false"',
    )
    assert "MVT003" not in rules_fired(xml)


def test_two_providers_with_different_authorities_are_fine(rules_fired):
    xml = app_xml(
        '<provider android:name=".One" android:authorities="com.example.app.one" android:exported="false"/>'
        '<provider android:name=".Two" android:authorities="com.example.app.two" android:exported="false"/>',
        application='android:allowBackup="false" android:usesCleartextTraffic="false"',
    )
    assert "MVT038" not in rules_fired(xml)


def test_cleartext_false_is_respected(rules_fired):
    xml = app_xml(
        '<activity android:name=".A" android:exported="false"/>',
        application='android:allowBackup="false" android:usesCleartextTraffic="false"',
        sdk='<uses-sdk android:minSdkVersion="21" android:targetSdkVersion="27"/>',
    )
    assert "MVT005" not in rules_fired(xml)
