"""Source-tree manifests: expat gives line numbers and byte offsets for free."""

from __future__ import annotations

import _helpers  # noqa: F401
import pytest

from manifestvet import axml, srctext

TEXT = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.src">
    <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34"/>
    <application android:label="Src">
        <activity android:name=".Main" android:exported="true"/>
    </application>
</manifest>
"""


def test_is_text_manifest_detects_xml():
    assert srctext.is_text_manifest(TEXT.encode("utf-8"))
    assert srctext.is_text_manifest(b"\xef\xbb\xbf" + TEXT.encode("utf-8"))
    assert not srctext.is_text_manifest(b"\x03\x00\x08\x00")


def test_lines_come_from_the_source_not_from_an_index():
    doc = srctext.parse(TEXT.encode("utf-8"))
    assert doc.root.line == 2
    assert doc.root.find("uses-sdk").line == 3
    assert doc.root.find("application").line == 4
    assert doc.root.find("application").find("activity").line == 5


def test_byte_offsets_point_at_the_element_start():
    data = TEXT.encode("utf-8")
    doc = srctext.parse(data)
    activity = doc.root.find("application").find("activity")
    assert data[activity.offset : activity.offset + 9] == b"<activity"


def test_namespaced_attributes_keep_their_namespace_uri():
    doc = srctext.parse(TEXT.encode("utf-8"))
    label = doc.root.find("application").get_attr("label")
    assert label.namespace == "http://schemas.android.com/apk/res/android"
    assert label.value == "Src"


def test_unqualified_attributes_have_no_namespace():
    doc = srctext.parse(TEXT.encode("utf-8"))
    package = doc.root.get_attr("package")
    assert package.namespace == ""
    assert package.value == "com.example.src"


def test_values_stay_strings_before_the_model_coerces_them():
    doc = srctext.parse(TEXT.encode("utf-8"))
    assert doc.root.find("application").get("label") == "Src"
    # The text path cannot know that targetSdkVersion is an int; the model calls
    # _as_int, so the raw layer staying a string is correct, not a bug.
    assert doc.root.find("uses-sdk").get("targetSdkVersion") == "34"


def test_malformed_xml_raises_axml_error():
    with pytest.raises(axml.AxmlError) as excinfo:
        srctext.parse(b"<manifest><application></manifest>")
    assert "malformed" in str(excinfo.value)


def test_empty_input_raises():
    with pytest.raises(axml.AxmlError):
        srctext.parse(b"   \n  ")


def test_no_start_tag_raises():
    with pytest.raises(axml.AxmlError):
        srctext.parse(b"just text, not xml")


def test_text_document_has_no_pool_or_resource_map():
    doc = srctext.parse(TEXT.encode("utf-8"))
    assert doc.pool is None
    assert doc.resource_ids == []
    assert doc.unresolved == []
