"""Manifest -> object model.

The rules do not walk XML: they ask questions of an :class:`App` ("which
components are reachable from another app without holding a permission?").
Everything that is easy to get subtly wrong -- the default value of
``android:exported``, the bitmask in ``protectionLevel``, the difference between
``<uses-permission>`` and ``<permission>`` -- is resolved exactly once, here,
with the reason written down next to it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import axml, srctext
from .attrnames import ANDROID_NS
from .axml import AxmlError, Document, Element

COMPONENT_KINDS = ("activity", "activity-alias", "service", "receiver", "provider")
PROVIDER_KINDS = ("provider",)

# Protection levels are a base value (low two bits) plus flags.  A permission
# whose base is normal(0) or dangerous(1) can be held by any app that asks, so
# guarding an exported component with one is the same as guarding with nothing.
_PROTECTION_BASE = {0: "normal", 1: "dangerous", 2: "signature", 3: "signatureOrSystem"}
_PROTECTION_FLAGS = {
    0x10: "privileged",
    0x20: "development",
    0x40: "appop",
    0x80: "pre23",
    0x100: "installer",
    0x200: "verifier",
    0x400: "preinstalled",
    0x800: "setup",
    0x1000: "instant",
    0x2000: "runtime",
    0x4000: "oem",
    0x8000: "vendorPrivileged",
    0x10000: "textClassifier",
    0x20000: "wellbeing",
    0x40000: "documenter",
    0x80000: "configurator",
    0x100000: "incidentReportApprover",
    0x200000: "appPredictor",
    0x400000: "companion",
    0x800000: "retailDemo",
    0x1000000: "recents",
}

# Platform permissions that are *normal* or *dangerous*: any app can obtain them
# by declaring them, so they cannot gate an exported component.
WEAK_PLATFORM_PERMISSIONS = frozenset(
    {
        "android.permission.INTERNET",
        "android.permission.ACCESS_NETWORK_STATE",
        "android.permission.ACCESS_WIFI_STATE",
        "android.permission.CHANGE_WIFI_STATE",
        "android.permission.VIBRATE",
        "android.permission.WAKE_LOCK",
        "android.permission.FOREGROUND_SERVICE",
        "android.permission.RECEIVE_BOOT_COMPLETED",
        "android.permission.SET_WALLPAPER",
        "android.permission.EXPAND_STATUS_BAR",
        "android.permission.KILL_BACKGROUND_PROCESSES",
        "android.permission.NFC",
        "android.permission.BLUETOOTH",
        "android.permission.BLUETOOTH_ADMIN",
        "android.permission.MODIFY_AUDIO_SETTINGS",
        "android.permission.READ_SYNC_SETTINGS",
        "android.permission.WRITE_SYNC_SETTINGS",
        "android.permission.READ_SYNC_STATS",
        "android.permission.AUTHENTICATE_ACCOUNTS",
        "android.permission.MANAGE_ACCOUNTS",
        "android.permission.GET_ACCOUNTS",
        "android.permission.BROADCAST_STICKY",
        "android.permission.READ_PROFILE",
        "android.permission.REORDER_TASKS",
        "android.permission.USE_BIOMETRIC",
        "android.permission.USE_FINGERPRINT",
        "android.permission.POST_NOTIFICATIONS",
        "android.permission.SCHEDULE_EXACT_ALARM",
        "android.permission.QUERY_ALL_PACKAGES",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.READ_CALENDAR",
        "android.permission.WRITE_CALENDAR",
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.READ_MEDIA_IMAGES",
        "android.permission.READ_MEDIA_VIDEO",
        "android.permission.READ_MEDIA_AUDIO",
        "android.permission.READ_PHONE_STATE",
        "android.permission.CALL_PHONE",
        "android.permission.SEND_SMS",
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
    }
)

# Permissions that only the platform or a privileged app can ever hold.  A
# third-party app declaring them gets nothing and, more importantly, gets no
# warning: the request is simply ignored at install time.
SIGNATURE_ONLY_PERMISSIONS = frozenset(
    {
        "android.permission.INSTALL_PACKAGES",
        "android.permission.DELETE_PACKAGES",
        "android.permission.WRITE_SECURE_SETTINGS",
        "android.permission.READ_LOGS",
        "android.permission.DUMP",
        "android.permission.SET_DEBUG_APP",
        "android.permission.MOUNT_UNMOUNT_FILESYSTEMS",
        "android.permission.MANAGE_EXTERNAL_STORAGE",
        "android.permission.MODIFY_PHONE_STATE",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.BIND_DEVICE_ADMIN",
        "android.permission.BIND_INPUT_METHOD",
        "android.permission.BIND_JOB_SERVICE",
        "android.permission.BIND_VPN_SERVICE",
        "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
        "android.permission.CAPTURE_AUDIO_OUTPUT",
        "android.permission.CHANGE_CONFIGURATION",
        "android.permission.REBOOT",
        "android.permission.INJECT_EVENTS",
        "android.permission.STATUS_BAR",
    }
)

# System broadcasts whose senders are protected.  A receiver for one of these
# does not need to be exported: the system delivers even to non-exported
# receivers, so exported=true only widens the surface to third-party senders.
PROTECTED_BROADCASTS = frozenset(
    {
        "android.intent.action.BOOT_COMPLETED",
        "android.intent.action.LOCKED_BOOT_COMPLETED",
        "android.intent.action.PACKAGE_ADDED",
        "android.intent.action.PACKAGE_REMOVED",
        "android.intent.action.PACKAGE_REPLACED",
        "android.intent.action.MY_PACKAGE_REPLACED",
        "android.intent.action.NEW_OUTGOING_CALL",
        "android.intent.action.TIME_SET",
        "android.intent.action.TIMEZONE_CHANGED",
        "android.intent.action.USER_PRESENT",
        "android.intent.action.SIM_STATE_CHANGED",
        "android.intent.action.AIRPLANE_MODE",
        "android.net.conn.CONNECTIVITY_CHANGE",
        "android.net.wifi.STATE_CHANGE",
        "android.intent.action.SCREEN_ON",
        "android.intent.action.SCREEN_OFF",
    }
)


def protection_level(value: object) -> tuple[str, list[str]]:
    """Decode ``android:protectionLevel`` into (base, flags)."""
    if isinstance(value, bool) or value is None:
        return "normal", []
    if isinstance(value, str):
        # Source manifests use the symbolic form, e.g. "signature|privileged".
        parts = [p.strip() for p in value.split("|") if p.strip()]
        base = next((p for p in parts if p in _PROTECTION_BASE.values()), "normal")
        return base, [p for p in parts if p not in _PROTECTION_BASE.values()]
    try:
        number = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return "normal", []
    base = _PROTECTION_BASE.get(number & 0x3, "normal")
    flags = [name for bit, name in _PROTECTION_FLAGS.items() if number & bit]
    return base, flags


def _as_int(value: object) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip(), 0)
    except ValueError:
        return None


@dataclass
class DataSpec:
    """One ``<data>`` element of an intent filter."""

    scheme: str = ""
    host: str = ""
    port: str = ""
    path: str = ""
    path_prefix: str = ""
    path_pattern: str = ""
    mime_type: str = ""
    line: int = 0
    offset: int = 0

    @property
    def is_web(self) -> bool:
        return self.scheme.lower() in {"http", "https"}

    @property
    def has_path(self) -> bool:
        return bool(self.path or self.path_prefix or self.path_pattern)

    def describe(self) -> str:
        parts = [f"{self.scheme}://" if self.scheme else ""]
        parts.append(self.host or "")
        if self.port:
            parts.append(f":{self.port}")
        parts.append(self.path or self.path_prefix or self.path_pattern)
        return "".join(parts) or self.mime_type or "(empty data)"


@dataclass
class IntentFilter:
    actions: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    data: list[DataSpec] = field(default_factory=list)
    auto_verify: bool = False
    line: int = 0
    offset: int = 0

    @property
    def browsable(self) -> bool:
        return "android.intent.category.BROWSABLE" in self.categories

    @property
    def launcher(self) -> bool:
        return "android.intent.action.MAIN" in self.actions and (
            "android.intent.category.LAUNCHER" in self.categories
        )

    @property
    def deep_links(self) -> list[DataSpec]:
        return [d for d in self.data if d.scheme]


@dataclass
class PathPermission:
    path: str
    read: str
    write: str
    line: int
    offset: int


@dataclass
class Component:
    kind: str
    name: str
    element: Element
    filters: list[IntentFilter] = field(default_factory=list)
    path_permissions: list[PathPermission] = field(default_factory=list)
    grant_paths: list[PathPermission] = field(default_factory=list)

    @property
    def line(self) -> int:
        return self.element.line

    @property
    def offset(self) -> int:
        return self.element.offset

    def get(self, name: str, default: object = None) -> object:
        return self.element.get(name, default)

    def bget(self, name: str) -> bool | None:
        return self.element.bget(name)

    def sget(self, name: str) -> str:
        value = self.element.get(name)
        if value is None:
            return ""
        if isinstance(value, bool):
            return "true" if value else "false"
        return str(value)

    @property
    def permission(self) -> str:
        return self.sget("permission")

    @property
    def exported_declared(self) -> bool | None:
        return self.bget("exported")

    def effective_exported(self, target_sdk: int) -> bool:
        """``android:exported`` with the platform default applied.

        Rule: an explicit value wins.  Otherwise a component that declares an
        intent-filter is exported, and one that declares none is not.  (Since
        API 31 the attribute is mandatory when intent-filters are present, so a
        missing value at targetSdk>=31 signals a repacked manifest, not a
        lenient default -- MVT040.)
        """
        declared = self.exported_declared
        if declared is not None:
            return declared
        return bool(self.filters) if target_sdk < 31 else False

    @property
    def label(self) -> str:
        return f"{self.kind} {self.name or '(no android:name)'}"

    def all_actions(self) -> list[str]:
        return [a for f in self.filters for a in f.actions]

    def all_deep_links(self) -> list[DataSpec]:
        return [d for f in self.filters for d in f.deep_links]


@dataclass
class DeclaredPermission:
    name: str
    level_value: object
    element: Element

    @property
    def base(self) -> str:
        return protection_level(self.level_value)[0]

    @property
    def flags(self) -> list[str]:
        return protection_level(self.level_value)[1]

    @property
    def weak(self) -> bool:
        """A guard built on this permission is a guard any app can satisfy."""
        return self.base in {"normal", "dangerous"}


@dataclass
class UsedPermission:
    name: str
    element: Element
    max_sdk: int | None = None


@dataclass
class App:
    package: str
    doc: Document
    manifest: Element
    app_element: Element | None
    components: list[Component]
    declared: list[DeclaredPermission]
    used: list[UsedPermission]
    min_sdk: int
    target_sdk: int
    target_sdk_declared: bool
    min_sdk_declared: bool

    @property
    def app_attrs(self) -> dict[str, object]:
        return self.app_element.android_attrs() if self.app_element else {}

    def components_of(self, *kinds: str) -> list[Component]:
        return [c for c in self.components if c.kind in kinds]

    def declared_permission(self, name: str) -> DeclaredPermission | None:
        for perm in self.declared:
            if perm.name == name:
                return perm
        return None

    def uses_permission(self, name: str) -> bool:
        return any(u.name == name for u in self.used)

    def is_app_namespaced(self, action: str) -> bool:
        return action.startswith(self.package) or action.startswith("android.")

    def effective_exported(self, component: Component) -> bool:
        return component.effective_exported(self.target_sdk)


def _filters(element: Element) -> list[IntentFilter]:
    out: list[IntentFilter] = []
    for node in element.find_all("intent-filter"):
        spec = IntentFilter(line=node.line, offset=node.offset, auto_verify=bool(node.bget("autoVerify")))
        for child in node.children:
            if child.name == "action":
                value = child.sget("name")
                if value:
                    spec.actions.append(value)
            elif child.name == "category":
                value = child.sget("name")
                if value:
                    spec.categories.append(value)
            elif child.name == "data":
                spec.data.append(
                    DataSpec(
                        scheme=child.sget("scheme"),
                        host=child.sget("host"),
                        port=child.sget("port"),
                        path=child.sget("path"),
                        path_prefix=child.sget("pathPrefix"),
                        path_pattern=child.sget("pathPattern"),
                        mime_type=child.sget("mimeType"),
                        line=child.line,
                        offset=child.offset,
                    )
                )
        out.append(spec)
    return out


def _paths(element: Element, tag: str) -> list[PathPermission]:
    out = []
    for node in element.find_all(tag):
        out.append(
            PathPermission(
                path=node.sget("path") or node.sget("pathPrefix") or node.sget("pathPattern"),
                read=node.sget("readPermission"),
                write=node.sget("writePermission"),
                line=node.line,
                offset=node.offset,
            )
        )
    return out


def load(data: bytes) -> App:
    """Parse either a compiled (AXML) or a plain-text manifest into an :class:`App`."""
    if axml.looks_like_axml(data):
        doc = axml.parse(data)
    elif srctext.is_text_manifest(data):
        doc = srctext.parse(data)
    else:
        raise AxmlError("unrecognised manifest format: neither RES_XML_TYPE nor XML text")

    manifest = doc.root
    if manifest.name != "manifest":
        raise AxmlError(f"root element is <{manifest.name}>, expected <manifest>")

    uses_sdk = manifest.find("uses-sdk")
    min_sdk_declared = uses_sdk is not None and uses_sdk.has("minSdkVersion")
    target_sdk_declared = uses_sdk is not None and uses_sdk.has("targetSdkVersion")
    min_sdk = _as_int(uses_sdk.get("minSdkVersion")) if uses_sdk else None
    target_sdk = _as_int(uses_sdk.get("targetSdkVersion")) if uses_sdk else None

    application = manifest.find("application")
    components: list[Component] = []
    if application is not None:
        for node in application.children:
            if node.name not in COMPONENT_KINDS:
                continue
            name = node.sget("name")
            components.append(
                Component(
                    kind=node.name,
                    name=name,
                    element=node,
                    filters=_filters(node),
                    path_permissions=_paths(node, "path-permission"),
                    grant_paths=_paths(node, "grant-uri-permission"),
                )
            )

    declared: list[DeclaredPermission] = []
    for node in manifest.find_all("permission"):
        name = node.sget("name")
        if name:
            declared.append(
                DeclaredPermission(name=name, level_value=node.get("protectionLevel"), element=node)
            )

    used: list[UsedPermission] = []
    for node in manifest.find_all("uses-permission") + manifest.find_all("uses-permission-sdk-23"):
        name = node.sget("name")
        if name:
            used.append(
                UsedPermission(name=name, element=node, max_sdk=_as_int(node.get("maxSdkVersion")))
            )

    # Defaults when <uses-sdk> is missing entirely: minSdk 1, targetSdk 1.  Both
    # are ancient, and every severity that depends on API level keys off this.
    return App(
        package=manifest.sget("package"),
        doc=doc,
        manifest=manifest,
        app_element=application,
        components=components,
        declared=declared,
        used=used,
        min_sdk=min_sdk if min_sdk is not None else 1,
        target_sdk=target_sdk if target_sdk is not None else 1,
        target_sdk_declared=target_sdk_declared,
        min_sdk_declared=min_sdk_declared,
    )


def load_path(path: str) -> App:  # pragma: no cover - thin wrapper
    with open(path, "rb") as handle:
        return load(handle.read())


__all__ = [
    "App",
    "Component",
    "DataSpec",
    "DeclaredPermission",
    "IntentFilter",
    "PathPermission",
    "UsedPermission",
    "COMPONENT_KINDS",
    "WEAK_PLATFORM_PERMISSIONS",
    "SIGNATURE_ONLY_PERMISSIONS",
    "PROTECTED_BROADCASTS",
    "protection_level",
    "load",
    "load_path",
    "Element",
    "Document",
    "ANDROID_NS",
]
