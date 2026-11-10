"""The reader: chunk walking, string pools, attribute naming, damage tolerance."""

from __future__ import annotations

import os
import struct

import _helpers  # noqa: F401  (puts src/ on sys.path)
import pytest

from manifestvet import axml, axmlwrite
from manifestvet.attrnames import ANDROID_NS, ATTR_IDS, attr_name, detect_resource_map_shift

REAL_APK = os.environ.get(
    "MANIFESTVET_REAL_APK",
    r"C:/Users/juji9/WorkBuddy/2026-10-07-17-33-13/_apks/pickword-ime-from-device.apk",
)

SIMPLE = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">
    <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34"/>
    <application android:allowBackup="false" android:debuggable="true" android:label="App">
        <activity android:name=".Main" android:exported="true"/>
    </application>
</manifest>
"""


def _parsed(text: str = SIMPLE, **kwargs) -> axml.Document:
    return axml.parse(axmlwrite.compile_text(text, **kwargs))


# -- file level --------------------------------------------------------------


def test_header_is_res_xml_type():
    data = axmlwrite.compile_text(SIMPLE)
    assert struct.unpack_from("<H", data, 0)[0] == 0x0003
    assert struct.unpack_from("<I", data, 4)[0] == len(data)


def test_root_and_children():
    doc = _parsed()
    assert doc.root.name == "manifest"
    assert [child.name for child in doc.root.children] == ["uses-sdk", "application"]
    assert [child.name for child in doc.root.find("application").children] == ["activity"]


def test_bad_magic_is_rejected_with_a_useful_message():
    with pytest.raises(axml.AxmlError) as excinfo:
        axml.parse(b"<?xml version='1.0'?><manifest/>")
    assert "RES_XML_TYPE" in str(excinfo.value)


def test_truncated_file_keeps_what_it_can_read():
    data = axmlwrite.compile_text(SIMPLE)
    doc = axml.parse(data[:-40])
    assert doc.root.name == "manifest"
    assert doc.element_count >= 2  # application survives, the tail does not


def test_element_count_matches_tree():
    doc = _parsed()
    assert doc.element_count == 4  # manifest, uses-sdk, application, activity


def test_offsets_are_inside_the_file_and_increasing():
    doc = _parsed()
    offsets = [element.offset for element in doc.walk()]
    assert all(0 < offset < doc.size for offset in offsets)
    assert offsets == sorted(offsets)


# -- values ------------------------------------------------------------------


def test_boolean_attributes_are_bools_not_strings():
    doc = _parsed()
    app = doc.root.find("application")
    assert app.get("debuggable") is True
    assert app.get("allowBackup") is False
    assert app.get("label") == "App"


def test_integer_attribute_is_signed_int():
    doc = _parsed()
    assert doc.root.find("uses-sdk").get("targetSdkVersion") == 34


def test_reference_attribute_is_rendered_as_hex_reference():
    text = SIMPLE.replace('android:label="App"', 'android:label="@0x7f0c0001"')
    doc = _parsed(text)
    assert doc.root.find("application").get("label") == "@0x7f0c0001"


def test_utf8_multibyte_strings_survive():
    text = SIMPLE.replace('android:label="App"', 'android:label="密钥库"')
    doc = _parsed(text)
    # A 3-char CJK string is 9 UTF-8 bytes but 3 UTF-16 units: the pool stores
    # both lengths and a reader that confuses them truncates here.
    assert doc.root.find("application").get("label") == "密钥库"


def test_utf16_pool_is_supported():
    doc = _parsed(utf16=True)
    assert doc.pool.utf8 is False
    assert doc.root.get("package") == "com.example.app"
    assert doc.root.find("application").get("label") == "App"


def test_no_namespaced_attributes_are_resolved_through_the_pool():
    doc = _parsed()
    package = doc.root.get_attr("package")
    assert package is not None
    assert package.namespace == ""
    assert package.res_id == 0
    assert package.resolved  # a name from the pool counts as resolved


def test_android_attributes_resolve_through_the_resource_map():
    doc = _parsed()
    attr = doc.root.find("application").get_attr("allowBackup")
    assert attr.res_id == 0x01010280
    assert attr.namespace == ANDROID_NS
    assert attr.resolved


def test_unresolved_attributes_are_reported_not_dropped():
    doc = _parsed()
    assert doc.unresolved == []


def test_attr_table_covers_the_documented_set():
    for res_id, name in ATTR_IDS.items():
        assert attr_name(res_id) == name
    assert attr_name(0x0101FFFF).startswith("0x0101")


# -- resource map alignment --------------------------------------------------


def test_shift_detection_prefers_zero_when_names_align():
    strings = ["exported", "allowBackup", "unknown"]
    ids = [0x01010010, 0x01010280, 0x01019999]
    assert detect_resource_map_shift(strings, ids) == 0


def test_shift_detection_handles_the_leading_empty_string_layout():
    strings = ["", "exported", "allowBackup"]
    ids = [0x01010010, 0x01010280]
    assert detect_resource_map_shift(strings, ids) == 1


def test_shift_detection_without_a_table_defaults_to_aapt2_layout():
    assert detect_resource_map_shift(["a", "b"], []) == 0
    assert detect_resource_map_shift(["foo", "bar"], [0x01019999, 0x01018888]) == 0


# -- the real thing ----------------------------------------------------------


@pytest.mark.skipif(not os.path.exists(REAL_APK), reason="no real APK on this machine")
def test_real_aapt2_manifest_is_read_correctly():
    """A manifest compiled by aapt2, read without aapt: the semantic assertions
    are what prove the attribute table, not just that parsing did not crash."""
    import zipfile

    data = zipfile.ZipFile(REAL_APK).read("AndroidManifest.xml")
    doc = axml.parse(data)
    assert doc.shift == 0
    assert doc.root.get("package") == "com.pickword.ime"
    assert doc.root.find("uses-sdk").get("targetSdkVersion") == 36

    app = doc.root.find("application")
    assert app.get("debuggable") is True
    assert app.get("allowBackup") is True
    assert isinstance(app.get("debuggable"), bool)

    provider = app.find("provider")
    assert provider.get("authorities") == "com.pickword.ime.androidx-startup"
    assert provider.get("exported") is False

    receiver = app.find("receiver")
    # android.permission.DUMP as a guard: a string, resolved from the pool.
    assert receiver.get("permission") == "android.permission.DUMP"


@pytest.mark.skipif(not os.path.exists(REAL_APK), reason="no real APK on this machine")
def test_real_apk_has_no_unresolved_android_attributes():
    import zipfile

    data = zipfile.ZipFile(REAL_APK).read("AndroidManifest.xml")
    doc = axml.parse(data)
    assert doc.unresolved == []
