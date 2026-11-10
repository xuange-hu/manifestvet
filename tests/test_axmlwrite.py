"""The writer exists so tests and the demo can produce genuinely compiled bytes."""

from __future__ import annotations

import _helpers  # noqa: F401
import pytest

from manifestvet import axml, axmlwrite, engine, model
from manifestvet.attrnames import ANDROID_NS

TEXT = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.rt">
    <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="33"/>
    <application android:allowBackup="false" android:label="Round Trip">
        <activity android:name=".A" android:exported="false">
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <data android:scheme="https" android:host="example.com" android:pathPrefix="/x"/>
            </intent-filter>
        </activity>
        <provider android:name=".P" android:authorities="com.example.rt.p" android:exported="true"/>
    </application>
</manifest>
"""


def test_round_trip_preserves_the_tree():
    doc = axml.parse(axmlwrite.compile_text(TEXT))
    assert doc.root.name == "manifest"
    assert [c.name for c in doc.root.children] == ["uses-sdk", "application"]
    app = doc.root.find("application")
    assert [c.name for c in app.children] == ["activity", "provider"]
    assert app.children[0].children[0].name == "intent-filter"


def test_round_trip_preserves_values_and_types():
    app = axml.parse(axmlwrite.compile_text(TEXT)).root.find("application")
    assert app.get("allowBackup") is False
    assert app.get("label") == "Round Trip"
    activity = app.find("activity")
    assert activity.bget("exported") is False
    filter_element = activity.find("intent-filter")
    data = filter_element.find("data")
    assert data.get("scheme") == "https"
    assert data.get("host") == "example.com"
    assert data.get("pathPrefix") == "/x"


def test_round_trip_in_utf16_mode():
    doc = axml.parse(axmlwrite.compile_text(TEXT, utf16=True))
    assert doc.root.find("application").get("label") == "Round Trip"


def test_compiled_output_declares_the_android_namespace():
    doc = axml.parse(axmlwrite.compile_text(TEXT))
    assert doc.root.find("application").get_attr("label").namespace == ANDROID_NS


def test_compiled_output_resolves_every_android_attribute():
    doc = axml.parse(axmlwrite.compile_text(TEXT))
    assert doc.resource_ids
    assert doc.shift == 0
    # A name that fell back to hex would mean the writer emitted an id the table
    # does not know -- i.e. the round trip only worked by accident.
    assert doc.unresolved == []


def test_text_and_compiled_paths_agree_on_rule_ids():
    """The same manifest must produce the same findings whether it arrives as
    source XML (dev machine) or as AXML (CI artefact). Anything else means one of
    the two readers loses information."""
    from_text = engine.run(model.load(TEXT.encode("utf-8")))
    from_axml = engine.run(model.load(axmlwrite.compile_text(TEXT)))
    assert from_text.triggered() == from_axml.triggered()
    assert [f.rule for f in from_text.findings] == [f.rule for f in from_axml.findings]


def test_compiled_and_text_reports_have_the_same_finding_count():
    from_text = engine.run(model.load(TEXT.encode("utf-8")))
    from_axml = engine.run(model.load(axmlwrite.compile_text(TEXT)))
    assert len(from_text.findings) == len(from_axml.findings)


def test_offsets_differ_between_formats_but_are_all_valid():
    text_doc = model.srctext.parse(TEXT.encode("utf-8"))
    axml_doc = axml.parse(axmlwrite.compile_text(TEXT))
    assert all(0 <= e.offset < text_doc.size for e in text_doc.walk())
    assert all(0 < e.offset < axml_doc.size for e in axml_doc.walk())


@pytest.mark.parametrize("utf16", [False, True])
def test_every_element_gets_an_end_offset(utf16):
    doc = axml.parse(axmlwrite.compile_text(TEXT, utf16=utf16))
    for element in doc.walk():
        assert element.end_offset >= element.offset
