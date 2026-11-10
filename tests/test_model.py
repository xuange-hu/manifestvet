"""The model: defaults, bitmasks, inheritance.  Every rule depends on this being right."""

from __future__ import annotations

import pytest
from _helpers import app_xml, manifest

from manifestvet import model
from manifestvet.rules import Context


def _app(xml: str) -> model.App:
    return model.load(xml.encode("utf-8"))


# -- exported default --------------------------------------------------------


def test_exported_declared_wins_over_the_default():
    app = _app(app_xml('<activity android:name=".A" android:exported="false"/>'))
    assert app.effective_exported(app.components[0]) is False


def test_filter_without_exported_is_exported_below_31():
    xml = app_xml(
        '<activity android:name=".A"><intent-filter><action android:name="x.y"/></intent-filter></activity>',
        sdk='<uses-sdk android:minSdkVersion="21" android:targetSdkVersion="30"/>',
    )
    app = _app(xml)
    assert app.target_sdk == 30
    assert app.effective_exported(app.components[0]) is True


def test_no_filter_without_exported_is_not_exported():
    app = _app(app_xml('<activity android:name=".A"/>'))
    assert app.effective_exported(app.components[0]) is False


def test_filter_without_exported_at_31_is_not_treated_as_exported():
    # targetSdk 31+ makes the attribute mandatory; a manifest in this state is
    # broken (MVT012 reports it) and the platform would refuse to install it.
    app = _app(app_xml('<activity android:name=".A"><intent-filter/></activity>'))
    assert app.target_sdk == 34
    assert app.effective_exported(app.components[0]) is False


# -- sdk defaults ------------------------------------------------------------


def test_missing_uses_sdk_falls_back_to_api_1():
    app = _app(manifest("<application/>", sdk=""))
    assert app.min_sdk == 1
    assert app.target_sdk == 1
    assert app.min_sdk_declared is False
    assert app.target_sdk_declared is False


def test_partial_uses_sdk_keeps_the_declared_half():
    app = _app(manifest("<application/>", sdk='<uses-sdk android:minSdkVersion="26"/>'))
    assert app.min_sdk == 26
    assert app.min_sdk_declared is True
    assert app.target_sdk_declared is False


def test_sdk_values_written_as_strings_are_coerced():
    app = _app(manifest("<application/>", sdk='<uses-sdk android:targetSdkVersion="33"/>'))
    assert app.target_sdk == 33


# -- protection levels -------------------------------------------------------


@pytest.mark.parametrize(
    "value,base",
    [
        (0, "normal"),
        (1, "dangerous"),
        (2, "signature"),
        (3, "signatureOrSystem"),
        ("normal", "normal"),
        ("dangerous", "dangerous"),
        ("signature", "signature"),
    ],
)
def test_protection_level_base(value, base):
    assert model.protection_level(value)[0] == base


def test_protection_level_flags_are_decoded_from_the_bitmask():
    base, flags = model.protection_level(0x12)
    assert base == "signature"
    assert "privileged" in flags


def test_protection_level_symbolic_flags():
    base, flags = model.protection_level("signature|privileged")
    assert base == "signature"
    assert flags == ["privileged"]


def test_protection_level_absent_is_normal():
    assert model.protection_level(None)[0] == "normal"


# -- permissions -------------------------------------------------------------


def test_declared_permission_records_level_and_weakness():
    app = _app(
        manifest(
            '<permission android:name="com.example.app.READ" android:protectionLevel="normal"/>'
            '<permission android:name="com.example.app.SECURE" android:protectionLevel="signature"/>'
        )
    )
    read = app.declared_permission("com.example.app.READ")
    secure = app.declared_permission("com.example.app.SECURE")
    assert read is not None and read.weak is True
    assert secure is not None and secure.weak is False


def test_used_permissions_include_max_sdk():
    app = _app(
        manifest(
            '<uses-permission android:name="android.permission.READ_SMS" android:maxSdkVersion="28"/>'
        )
    )
    assert app.used[0].name == "android.permission.READ_SMS"
    assert app.used[0].max_sdk == 28


def test_uses_permission_sdk_23_is_read_too():
    app = _app(manifest('<uses-permission-sdk-23 android:name="android.permission.CAMERA"/>'))
    assert app.uses_permission("android.permission.CAMERA")


# -- components --------------------------------------------------------------


def test_all_component_kinds_are_collected():
    app = _app(
        app_xml(
            '<activity android:name=".A"/>'
            '<activity-alias android:name=".Alias" android:targetActivity=".A"/>'
            '<service android:name=".S"/>'
            '<receiver android:name=".R"/>'
            '<provider android:name=".P" android:authorities="x"/>'
        )
    )
    assert [c.kind for c in app.components] == ["activity", "activity-alias", "service", "receiver", "provider"]


def test_intent_filters_are_parsed_with_data():
    app = _app(
        app_xml(
            '<activity android:name=".A"><intent-filter>'
            '<action android:name="android.intent.action.VIEW"/>'
            '<category android:name="android.intent.category.BROWSABLE"/>'
            '<data android:scheme="https" android:host="e.com" android:pathPattern="/a/.*"/>'
            "</intent-filter></activity>"
        )
    )
    spec = app.components[0].filters[0]
    assert spec.actions == ["android.intent.action.VIEW"]
    assert spec.browsable is True
    assert spec.deep_links[0].is_web is True
    assert spec.deep_links[0].path_pattern == "/a/.*"


def test_launcher_filter_is_recognised():
    app = _app(
        app_xml(
            '<activity android:name=".A"><intent-filter>'
            '<action android:name="android.intent.action.MAIN"/>'
            '<category android:name="android.intent.category.LAUNCHER"/>'
            "</intent-filter></activity>"
        )
    )
    assert app.components[0].filters[0].launcher is True


def test_auto_verify_is_captured_on_the_filter():
    app = _app(
        app_xml(
            '<activity android:name=".A"><intent-filter android:autoVerify="true">'
            '<action android:name="android.intent.action.VIEW"/>'
            '<data android:scheme="https" android:host="e.com"/>'
            "</intent-filter></activity>"
        )
    )
    assert app.components[0].filters[0].auto_verify is True


def test_path_permissions_and_grant_paths_are_separate():
    app = _app(
        app_xml(
            '<provider android:name=".P" android:authorities="a">'
            '<path-permission android:path="/secret" android:readPermission="com.example.app.R"/>'
            '<grant-uri-permission android:pathPrefix="/shared"/>'
            "</provider>"
        )
    )
    provider = app.components[0]
    assert provider.path_permissions[0].read == "com.example.app.R"
    assert provider.grant_paths[0].path == "/shared"


def test_data_spec_describe_is_readable():
    spec = model.DataSpec(scheme="https", host="e.com", path_prefix="/a")
    assert spec.describe() == "https://e.com/a"


# -- guard inheritance -------------------------------------------------------


def test_component_permission_wins_over_application_permission():
    app = _app(
        app_xml(
            '<activity android:name=".A" android:exported="true" android:permission="com.example.app.ONE"/>',
            application='android:permission="com.example.app.TWO"',
        )
    )
    ctx = Context(app)
    assert ctx.guard(app.components[0]) == "com.example.app.ONE"


def test_application_permission_guards_components_that_do_not_override_it():
    app = _app(
        app_xml(
            '<activity android:name=".A" android:exported="true"/>',
            application='android:permission="com.example.app.SIG"',
        )
    )
    ctx = Context(app)
    assert ctx.guard(app.components[0]) == "com.example.app.SIG"


def test_weak_guard_recognises_a_platform_normal_permission():
    app = _app(app_xml('<activity android:name=".A" android:permission="android.permission.INTERNET"/>'))
    assert "platform" in Context(app).weak_guard("android.permission.INTERNET")


def test_weak_guard_is_silent_for_a_signature_permission():
    app = _app(
        manifest(
            '<permission android:name="com.example.app.SIG" android:protectionLevel="signature"/>'
            '<application><activity android:name=".A" android:permission="com.example.app.SIG"/></application>'
        )
    )
    assert Context(app).weak_guard("com.example.app.SIG") == ""


def test_weak_guard_is_silent_for_no_permission():
    app = _app(app_xml('<activity android:name=".A"/>'))
    assert Context(app).weak_guard("") == ""
