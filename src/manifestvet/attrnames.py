"""``android.R.attr`` id -> name, and the resource-map shift heuristic.

Why a table instead of a real ``resources.arsc`` lookup: the attribute *names* in
a compiled manifest are already gone -- aapt replaces them with a resource id
(``android:exported`` is ``0x01010010``).  Resolving them through the app's own
``resources.arsc`` only helps for app-defined attributes; framework attributes
always live in the ``0x0101xxxx`` range and come from the platform table.  Those
ids are part of the public ABI (aapt2 refuses to renumber them), so a table is
the same answer every tool uses, without a 2 MB arsc parse.

Ids that are *not* in the table are surfaced as ``0x0101xxxx`` in the report
rather than dropped -- see :class:`manifestvet.axml.Document.unresolved`.
"""

from __future__ import annotations

ANDROID_NS = "http://schemas.android.com/apk/res/android"

# Only the attributes that appear in AndroidManifest.xml and that a rule can
# act on.  Ordering mirrors android.R.attr's own allocation order.
ATTR_IDS: dict[int, str] = {
    0x01010000: "theme",
    0x01010001: "label",
    0x01010002: "icon",
    0x01010003: "name",
    0x01010004: "manageSpaceActivity",
    0x01010005: "allowClearUserData",
    0x01010006: "permission",
    0x01010007: "readPermission",
    0x01010008: "writePermission",
    0x01010009: "protectionLevel",
    0x0101000A: "permissionGroup",
    0x0101000B: "sharedUserId",
    0x0101000C: "hasCode",
    0x0101000D: "persistent",
    0x0101000E: "enabled",
    0x0101000F: "debuggable",
    0x01010010: "exported",
    0x01010011: "process",
    0x01010012: "taskAffinity",
    0x01010013: "handleProfiling",
    0x01010014: "functionalTest",
    0x01010015: "description",
    0x01010016: "targetPackage",
    0x01010017: "targetClass",
    0x01010018: "authorities",
    0x01010019: "syncable",
    0x0101001A: "initOrder",
    0x0101001B: "grantUriPermissions",
    0x0101001C: "priority",
    0x0101001D: "launchMode",
    0x0101001E: "screenOrientation",
    0x0101001F: "configChanges",
    0x01010020: "descriptionRes",
    0x01010021: "targetSdkVersion",  # legacy spelling, still seen in old APKs
    0x01010022: "minSdkVersion",  # legacy spelling
    0x01010023: "windowSoftInputMode",
    0x01010024: "value",
    0x01010025: "resource",
    0x01010026: "mimeType",
    0x01010027: "scheme",
    0x01010028: "host",
    0x01010029: "port",
    0x0101002A: "path",
    0x0101002B: "pathPrefix",
    0x0101002C: "pathPattern",
    0x0101002D: "pathAdvancedPattern",
    0x01010202: "targetActivity",
    0x01010204: "allowTaskReparenting",
    0x0101020C: "minSdkVersion",
    0x0101021B: "versionCode",
    0x0101021C: "versionName",
    0x01010270: "targetSdkVersion",
    0x01010271: "maxSdkVersion",
    0x01010280: "allowBackup",
    0x010102C7: "required",
    0x010102EC: "largeHeap",
    0x010103A7: "parentActivityName",
    0x010103AF: "supportsRtl",
    0x010104EA: "extractNativeLibs",
    0x010104EB: "fullBackupContent",
    0x010104EC: "usesCleartextTraffic",
    0x010104EE: "autoVerify",
    0x01010505: "directBootAware",
    0x0101050D: "pathAdvancedPattern",
    0x01010527: "networkSecurityConfig",
    0x0101052C: "roundIcon",
    0x01010537: "dataExtractionRules",
    0x01010572: "compileSdkVersion",
    0x01010573: "compileSdkVersionCodename",
    0x01010576: "versionCodeMajor",
    0x0101057A: "appComponentFactory",
    0x01010603: "requestLegacyExternalStorage",
}

# Attributes whose absence matters as much as their presence.  Kept separate so
# rules can name the default behaviour in the finding text.
DEFAULTS_NOTE: dict[str, str] = {
    "exported": "absent = true when the component declares an intent-filter, false otherwise",
    "allowBackup": "absent = true below targetSdk 31, false from 31",
    "usesCleartextTraffic": "absent = true below targetSdk 28, false from 28",
    "debuggable": "absent = false",
    "grantUriPermissions": "absent = false",
}


def attr_name(res_id: int) -> str:
    return ATTR_IDS.get(res_id, f"0x{res_id:08x}")


def is_known(res_id: int) -> bool:
    return res_id in ATTR_IDS


def detect_resource_map_shift(strings: list[str], resource_ids: list[int]) -> int:
    """Return the index shift between the string pool and the resource map.

    Two alignments exist in the wild: aapt2 emits the attribute names starting at
    pool index 0 (shift 0), while older aapt and several repackers keep a leading
    empty string (shift 1).  Counting "ids the table happens to know" cannot tell
    them apart -- both alignments score ~equal, because the ids are dense.  The
    test that does discriminate: the pool *string* at an index and the table name
    for the mapped id must be the **same word**.  Agreement is exact and cheap.
    """
    if not resource_ids:
        return 0

    def agreements(shift: int) -> int:
        hits = 0
        for index, name in enumerate(strings):
            target = index - shift
            if not name or not (0 <= target < len(resource_ids)):
                continue
            if ATTR_IDS.get(resource_ids[target]) == name:
                hits += 1
        return hits

    zero, one = agreements(0), agreements(1)
    if zero == one:
        # No name/table agreement at all (packer stripped the names): fall back
        # to the aapt2 default, which is what modern tooling produces.
        return 0
    return 0 if zero > one else 1
