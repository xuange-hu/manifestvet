"""The 40 rules.

Shape of every rule: a pure function of the model that yields :class:`Issue`
objects.  No I/O, no globals, no printing -- the CLI, the MCP server and the
tests all drive the same functions, so a rule that passes in one path is the same
rule in the others.

Severity is about *reachability from another app*, not about how scary the words
sound: an exported provider with ``grantUriPermissions`` is critical because one
``content://`` URI from any installed app reads the file; ``minSdkVersion=19`` is
medium because it removes mitigations the app never asked to lose.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass

from .axml import Element
from .model import (
    PROTECTED_BROADCASTS,
    SIGNATURE_ONLY_PERMISSIONS,
    WEAK_PLATFORM_PERMISSIONS,
    App,
    Component,
)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "note": 4}


@dataclass
class Issue:
    """One rule firing.  ``attr`` narrows the byte offset to a single attribute."""

    message: str
    element: Element | None = None
    evidence: str = ""
    attr: str | None = None
    where: str = ""


@dataclass
class Rule:
    id: str
    title: str
    severity: str
    stage: int
    why: str
    fix: str
    check: Callable[[Context], Iterable[Issue]]


@dataclass
class Context:
    """Everything a rule needs: the app, plus the lookups that must agree on it."""

    app: App

    # -- helpers used by the rule bodies --------------------------------
    def guard(self, component: Component) -> str:
        """The permission that actually gates ``component``, or ``""``.

        A component-level ``android:permission`` wins; the ``<application>``
        level one applies to every component that does not override it.  Missing
        this makes the auditor report guarded components as open.
        """
        if component.permission:
            return component.permission
        app_permission = self.app.app_attrs.get("permission")
        return str(app_permission) if app_permission else ""

    def exported(self, component: Component) -> bool:
        return self.app.effective_exported(component)

    def weak_guard(self, permission: str) -> str:
        """Return a human reason when ``permission`` cannot actually gate anything."""
        if not permission:
            return ""
        declared = self.app.declared_permission(permission)
        if declared is not None and declared.weak:
            return f"declared by the app with protectionLevel={declared.base}"
        if permission in WEAK_PLATFORM_PERMISSIONS:
            return "a normal/dangerous platform permission any app can request"
        return ""


def rule(
    rule_id: str, title: str, severity: str, stage: int, *, why: str, fix: str
) -> Callable[[Callable[[Context], Iterator[Issue]]], Callable[[Context], Iterator[Issue]]]:
    def decorate(func: Callable[[Context], Iterator[Issue]]):
        REGISTRY.append(Rule(rule_id, title, severity, stage, why, fix, func))
        return func

    return decorate


REGISTRY: list[Rule] = []


def _executable() -> list[Rule]:
    return sorted(REGISTRY, key=lambda r: (r.stage, r.id))


# ---------------------------------------------------------------------------
# stage 1 -- facts about a single element
# ---------------------------------------------------------------------------


@rule(
    "MVT001",
    "Application is debuggable",
    "critical",
    1,
    why=(
        "android:debuggable=\"true\" leaves the JDWP agent on. Any process that can reach "
        "the device over adb can attach a debugger, read heap memory (tokens, decrypted "
        "payloads) and use run-as to read the app's private directory. Play rejects it, so "
        "seeing it in a shipped APK means the artifact was built or repacked outside the "
        "release pipeline."
    ),
    fix="Remove android:debuggable, or gate it on a build type (debuggable true only in debug).",
)
def debuggable(ctx: Context) -> Iterator[Issue]:
    app = ctx.app.app_element
    if app is not None and app.bget("debuggable"):
        yield Issue(
            'android:debuggable="true" -- JDWP is reachable, private data is readable via adb',
            app,
            'debuggable="true"',
            attr="debuggable",
            where="application",
        )


@rule(
    "MVT002",
    "Backup enabled by default",
    "medium",
    1,
    why=(
        "Below targetSdk 31, android:allowBackup defaults to true. `adb backup` then writes "
        "the app's private files into an archive the user (or anything holding the backup "
        "transport) can read offline, which is the cheapest way to lift stored sessions."
    ),
    fix='Declare android:allowBackup="false", or scope the backup with dataExtractionRules.',
)
def backup_default_on(ctx: Context) -> Iterator[Issue]:
    app = ctx.app.app_element
    if app is None or app.has("allowBackup") or ctx.app.target_sdk >= 31:
        return
    yield Issue(
        "allowBackup is not declared and targetSdk "
        f"{ctx.app.target_sdk} < 31, so app data goes into `adb backup`",
        app,
        "no allowBackup attribute",
        where="application",
    )


@rule(
    "MVT003",
    "Backup on with nothing excluded",
    "high",
    1,
    why=(
        "allowBackup=\"true\" with neither fullBackupContent nor dataExtractionRules means "
        "every file under the app's data directory is in scope -- including token caches, "
        "databases and anything written to no_backup/ by mistake."
    ),
    fix=(
        "Set allowBackup=\"false\", or point dataExtractionRules at a rules file that excludes "
        "credential caches and no_backup is used for the rest."
    ),
)
def backup_unscoped(ctx: Context) -> Iterator[Issue]:
    app = ctx.app.app_element
    if app is None or app.bget("allowBackup") is not True:
        return
    if app.has("fullBackupContent") or app.has("dataExtractionRules"):
        return
    yield Issue(
        'allowBackup="true" with no fullBackupContent / dataExtractionRules: the whole data dir is backed up',
        app,
        'allowBackup="true"',
        attr="allowBackup",
        where="application",
    )


@rule(
    "MVT004",
    "Cleartext traffic explicitly allowed",
    "medium",
    1,
    why=(
        'android:usesCleartextTraffic="true" re-enables plaintext HTTP for every host the app '
        "talks to, including third-party SDKs. On a hostile network that turns every API call "
        "into a readable, modifiable request."
    ),
    fix="Drop the flag, or scope cleartext to specific dev hosts in a networkSecurityConfig domain-config.",
)
def cleartext_true(ctx: Context) -> Iterator[Issue]:
    app = ctx.app.app_element
    if app is not None and app.bget("usesCleartextTraffic"):
        yield Issue(
            'android:usesCleartextTraffic="true" -- plaintext HTTP is allowed to any host',
            app,
            'usesCleartextTraffic="true"',
            attr="usesCleartextTraffic",
            where="application",
        )


@rule(
    "MVT005",
    "Cleartext allowed by platform default",
    "medium",
    1,
    why=(
        "Before targetSdk 28 cleartext is permitted unless blocked. The manifest does not say "
        "so, which is why this is easy to miss in review: nothing in the file looks wrong."
    ),
    fix="Raise targetSdk to 28+, or set usesCleartextTraffic=\"false\" explicitly.",
)
def cleartext_default(ctx: Context) -> Iterator[Issue]:
    app = ctx.app.app_element
    if app is None or app.has("usesCleartextTraffic") or ctx.app.target_sdk >= 28:
        return
    yield Issue(
        f"targetSdk {ctx.app.target_sdk} < 28 and usesCleartextTraffic is unset: cleartext is allowed",
        app,
        "no usesCleartextTraffic attribute",
        where="application",
    )


@rule(
    "MVT006",
    "Legacy external storage requested",
    "low",
    1,
    why=(
        "requestLegacyExternalStorage keeps the pre-scoped-storage view of /sdcard alive. Any "
        "other app holding READ_EXTERNAL_STORAGE can read whatever this app writes there -- the "
        "classic way a downloaded file leaks to every file manager on the device."
    ),
    fix="Move to scoped storage (MediaStore / app-specific dirs) and drop the flag.",
)
def legacy_storage(ctx: Context) -> Iterator[Issue]:
    app = ctx.app.app_element
    if app is not None and app.bget("requestLegacyExternalStorage"):
        yield Issue(
            'requestLegacyExternalStorage="true" -- files land where every storage-permitted app can read them',
            app,
            'requestLegacyExternalStorage="true"',
            attr="requestLegacyExternalStorage",
            where="application",
        )


@rule(
    "MVT007",
    "sharedUserId declared",
    "high",
    1,
    why=(
        "A shared UID puts this app and every other app with the same userId into one sandbox: "
        "same data dir, same process namespace, same permissions. It is deprecated since API 29 "
        "and can never be removed later without breaking the install."
    ),
    fix="Remove sharedUserId and pass data between the apps over a content provider or a bound service.",
)
def shared_uid(ctx: Context) -> Iterator[Issue]:
    value = ctx.app.manifest.sget("sharedUserId")
    if value:
        yield Issue(
            f'sharedUserId="{value}" merges this app into another app\'s sandbox',
            ctx.app.manifest,
            f'sharedUserId="{value}"',
            attr="sharedUserId",
            where="manifest",
        )


@rule(
    "MVT008",
    "minSdkVersion below 21",
    "medium",
    1,
    why=(
        "Below API 21 the platform has no ART, no per-app SELinux domain per UID and no "
        "modern TLS stack. Every library the app ships then has to carry its own fallbacks, "
        "and the old code paths are the ones nobody tests."
    ),
    fix="Raise minSdkVersion to at least 21 (24+ if the dependency graph allows it).",
)
def min_sdk_low(ctx: Context) -> Iterator[Issue]:
    if ctx.app.min_sdk >= 21:
        return
    yield Issue(
        f"minSdkVersion={ctx.app.min_sdk} -- pre-ART platform without modern sandboxing",
        ctx.app.manifest.find("uses-sdk") or ctx.app.manifest,
        f"minSdkVersion={ctx.app.min_sdk}",
        attr="minSdkVersion",
        where="uses-sdk",
    )


@rule(
    "MVT009",
    "targetSdkVersion below 31",
    "medium",
    1,
    why=(
        "targetSdk gates which mitigations the platform applies. Below 31 the app keeps "
        "the permissive defaults for android:exported, mutable PendingIntents and "
        "unscoped backups -- the three things this tool reports on most often."
    ),
    fix="Raise targetSdkVersion to the current Play requirement (34+ as of 2026).",
)
def target_sdk_low(ctx: Context) -> Iterator[Issue]:
    if not ctx.app.target_sdk_declared or ctx.app.target_sdk >= 31:
        return
    yield Issue(
        f"targetSdkVersion={ctx.app.target_sdk} -- pre-31 defaults are applied (exported, PendingIntent, backup)",
        ctx.app.manifest.find("uses-sdk") or ctx.app.manifest,
        f"targetSdkVersion={ctx.app.target_sdk}",
        attr="targetSdkVersion",
        where="uses-sdk",
    )


@rule(
    "MVT010",
    "targetSdkVersion not declared",
    "medium",
    1,
    why=(
        "Without targetSdkVersion the platform assumes the oldest behaviour it still supports, "
        "so every compatibility shim stays on. It is also the one field Play refuses to publish "
        "without, which makes its absence a sign of a hand-built APK."
    ),
    fix="Declare targetSdkVersion in <uses-sdk> (or via the Gradle targetSdk).",
)
def target_sdk_missing(ctx: Context) -> Iterator[Issue]:
    if ctx.app.target_sdk_declared:
        return
    yield Issue(
        "no targetSdkVersion in <uses-sdk>: the platform falls back to legacy behaviour",
        ctx.app.manifest.find("uses-sdk") or ctx.app.manifest,
        "no targetSdkVersion",
        where="uses-sdk",
    )


@rule(
    "MVT011",
    "<uses-sdk> missing entirely",
    "medium",
    1,
    why=(
        "No <uses-sdk> at all means minSdk 1 and targetSdk 1: the app claims to run on API 1 "
        "and opts out of every behavioural change since. Nothing else in the manifest can be "
        "judged against an API level, so the rest of this report is guesswork."
    ),
    fix="Add <uses-sdk android:minSdkVersion=... android:targetSdkVersion=...> (normally Gradle does this).",
)
def uses_sdk_missing(ctx: Context) -> Iterator[Issue]:
    if ctx.app.manifest.find("uses-sdk") is not None:
        return
    yield Issue(
        "no <uses-sdk> element: minSdk and targetSdk both default to 1",
        ctx.app.manifest,
        "missing <uses-sdk>",
        where="manifest",
    )


@rule(
    "MVT012",
    "android:exported missing where the platform requires it",
    "note",
    1,
    why=(
        "Since API 31 a component that declares an intent-filter must declare android:exported; "
        "the build fails otherwise. A manifest in that state has been repacked by something that "
        "does not run the real checks, which is worth knowing before trusting the rest of it."
    ),
    fix="Add the explicit android:exported value that matches the intent.",
)
def exported_missing(ctx: Context) -> Iterator[Issue]:
    if ctx.app.target_sdk < 31:
        return
    for component in ctx.app.components:
        if component.filters and component.exported_declared is None:
            yield Issue(
                f"{component.label} declares an intent-filter but no android:exported "
                "(build-time error at targetSdk 31+, i.e. a repacked manifest)",
                component.element,
                f"<{component.kind}> with intent-filter, no exported",
                where=component.label,
            )


# -- exported surface --------------------------------------------------------


def _exported_without_guard(ctx: Context, kind: str, what: str) -> Iterator[Issue]:
    for component in ctx.app.components_of(kind):
        if not ctx.exported(component):
            continue
        # The launcher entry point is exported by definition -- every app has one
        # and it carries no data. Flagging it would put a "high" on every APK in
        # existence and drown the findings that matter.
        if any(spec.launcher for spec in component.filters):
            continue
        guard = ctx.guard(component)
        if guard:
            continue
        yield Issue(
            f"{component.label} is exported with no permission -- {what}",
            component.element,
            'android:exported="true" with no android:permission',
            attr="exported",
            where=component.label,
        )


@rule(
    "MVT013",
    "Exported activity with no permission",
    "high",
    1,
    why=(
        "Any installed app can start an exported activity with an explicit Intent and hand it "
        "arbitrary extras. If it is a settings screen, a WebView wrapper or a file picker, that "
        "is a confused-deputy path into the app's own privileges."
    ),
    fix="Set android:exported=\"false\", or require a signature-level permission.",
)
def exported_activity(ctx: Context) -> Iterator[Issue]:
    return _exported_without_guard(ctx, "activity", "any app can start it with arbitrary extras")


@rule(
    "MVT014",
    "Exported service with no permission",
    "high",
    1,
    why=(
        "A third-party app can bind or start the service and then call every public method "
        "on its Binder interface, in this app's UID, with this app's permissions."
    ),
    fix="Set android:exported=\"false\", or bind behind a signature-level permission.",
)
def exported_service(ctx: Context) -> Iterator[Issue]:
    return _exported_without_guard(ctx, "service", "any app can bind and call its Binder methods")


@rule(
    "MVT015",
    "Exported receiver with no permission",
    "high",
    1,
    why=(
        "An exported receiver takes broadcasts from any app. The payload is attacker-controlled "
        "and lands in onReceive before any validation, which is how state machines get driven "
        "into states the developer never wrote."
    ),
    fix="Set android:exported=\"false\" unless another app must reach it, and guard with a signature permission if so.",
)
def exported_receiver(ctx: Context) -> Iterator[Issue]:
    return _exported_without_guard(ctx, "receiver", "any app can send it a crafted broadcast")


@rule(
    "MVT016",
    "Exported provider with no read/write permission",
    "high",
    1,
    why=(
        "The provider answers content:// queries from any app. Without readPermission / "
        "writePermission the only thing between another app and the data is the provider's own "
        "URI matching -- and `content://authority/` plus a guessed path is a very short guess."
    ),
    fix="Set android:exported=\"false\", or declare readPermission and writePermission at signature level.",
)
def exported_provider(ctx: Context) -> Iterator[Issue]:
    for component in ctx.app.components_of("provider"):
        if not ctx.exported(component):
            continue
        if component.permission or component.sget("readPermission") or component.sget("writePermission"):
            continue
        if ctx.guard(component):
            continue
        yield Issue(
            f"{component.label} is exported with no readPermission / writePermission "
            f"(authorities={component.sget('authorities') or 'none'})",
            component.element,
            "exported provider, no permission",
            attr="exported",
            where=component.label,
        )


@rule(
    "MVT017",
    "Exported activity with no intent-filter",
    "low",
    1,
    why=(
        "Exported with no filter means the activity is reachable only by an explicit Intent "
        "naming its class -- still reachable, since class names are in the APK, but the "
        "attacker has to know the name. Usually this is an android:exported left at true by "
        "copy-paste rather than a deliberate decision."
    ),
    fix="Set android:exported=\"false\" if nothing outside the app is meant to start it.",
)
def exported_activity_no_filter(ctx: Context) -> Iterator[Issue]:
    for component in ctx.app.components_of("activity", "activity-alias"):
        if not ctx.exported(component) or component.filters or ctx.guard(component):
            continue
        yield Issue(
            f"{component.label} is exported without any intent-filter: reachable by explicit Intent only",
            component.element,
            "exported, no intent-filter",
            attr="exported",
            where=component.label,
        )


@rule(
    "MVT018",
    "Provider grants URI permissions",
    "high",
    1,
    why=(
        "grantUriPermissions=\"true\" lets a caller pass a content:// URI to a third app and "
        "have that app receive access too. Without a permission on the provider, that is a "
        "transferable capability: one leaked URI reads the file from anywhere."
    ),
    fix="Drop grantUriPermissions, or pair it with path-permission entries that scope the grantable paths.",
)
def provider_grant_uri(ctx: Context) -> Iterator[Issue]:
    for component in ctx.app.components_of("provider"):
        if component.bget("grantUriPermissions") is not True:
            continue
        if component.permission or component.sget("readPermission"):
            continue
        yield Issue(
            f"{component.label} sets grantUriPermissions without a readPermission: URI access is transferable",
            component.element,
            "grantUriPermissions=true",
            attr="grantUriPermissions",
            where=component.label,
        )


@rule(
    "MVT019",
    "Provider path rule covers the whole tree",
    "high",
    1,
    why=(
        "A <path-permission path=\"/\"> or <grant-uri-permission pathPrefix=\"/\"> entry applies "
        "to every path under the authority. Paired with an export, it is the classic "
        "../ traversal: the provider asks the filesystem for the joined path and hands back "
        "whatever it resolves to."
    ),
    fix="Narrow the path to the subtree that is shared, and validate the resolved path against a canonical prefix.",
)
def provider_root_path(ctx: Context) -> Iterator[Issue]:
    for component in ctx.app.components_of("provider"):
        for entry in component.path_permissions + component.grant_paths:
            if entry.path not in {"/", "/*"}:
                continue
            if entry.read or entry.write:
                continue
            tag = "path-permission" if entry in component.path_permissions else "grant-uri-permission"
            yield Issue(
                f"{component.label} has <{tag} path=\"{entry.path}\"> with no read/write permission",
                component.element,
                f'<{tag} path="{entry.path}">',
                where=component.label,
            )


@rule(
    "MVT020",
    "Provider without authorities",
    "medium",
    1,
    why=(
        "A <provider> with no android:authorities cannot be addressed at all: the install "
        "fails, or the element is dead weight. Either way it is a manifest that no build "
        "actually validated."
    ),
    fix="Declare android:authorities=\"${applicationId}.provider\" or delete the element.",
)
def provider_no_authority(ctx: Context) -> Iterator[Issue]:
    for component in ctx.app.components_of("provider"):
        if not component.sget("authorities"):
            yield Issue(
                f"{component.label} has no android:authorities",
                component.element,
                "provider without authorities",
                where=component.label,
            )


# -- task / UI ---------------------------------------------------------------


@rule(
    "MVT021",
    "Exported activity uses a hijackable launch mode",
    "medium",
    1,
    why=(
        "singleTask / singleInstance activities are matched by taskAffinity as well as by "
        "class name. A malicious app that declares the same affinity can have its activity "
        "placed at the root of this app's task (StrandHogg 2.0), so the user sees the real "
        "app's UI on top of the attacker's screen."
    ),
    fix="Keep exported activities at standard launchMode, or set an empty taskAffinity and check `dumpsys activity`.",
)
def task_hijack(ctx: Context) -> Iterator[Issue]:
    for component in ctx.app.components_of("activity"):
        mode = component.sget("launchMode")
        if mode not in {"singleTask", "singleInstance"}:
            continue
        if not ctx.exported(component):
            continue
        yield Issue(
            f'{component.label} is exported with launchMode="{mode}": taskAffinity can be hijacked',
            component.element,
            f'launchMode="{mode}"',
            attr="launchMode",
            where=component.label,
        )


@rule(
    "MVT022",
    "allowTaskReparenting enabled",
    "low",
    1,
    why=(
        "allowTaskReparenting lets the system move the activity into another task whose "
        "affinity matches. On its own it is a UX feature; combined with a shared affinity it "
        "is the other half of a task-hijack chain."
    ),
    fix="Remove android:allowTaskReparenting unless the reparenting is intentional.",
)
def allow_reparenting(ctx: Context) -> Iterator[Issue]:
    for component in ctx.app.components_of("activity"):
        if component.bget("allowTaskReparenting") is True:
            yield Issue(
                f"{component.label} sets allowTaskReparenting=true",
                component.element,
                "allowTaskReparenting=true",
                attr="allowTaskReparenting",
                where=component.label,
            )


# -- deep links --------------------------------------------------------------


@rule(
    "MVT023",
    "Web deep link without autoVerify",
    "medium",
    1,
    why=(
        "An http/https filter without android:autoVerify leaves the link unverified, so any "
        "installed app can register the same host and win the intent. The user taps a link to "
        "your domain and lands in someone else's UI, prefilled with your URL."
    ),
    fix="Add android:autoVerify=\"true\" and publish /.well-known/assetlinks.json for the host.",
)
def deeplink_no_verify(ctx: Context) -> Iterator[Issue]:
    for component in ctx.app.components:
        for spec in component.all_deep_links():
            if not spec.is_web:
                continue
            if any(f.auto_verify for f in component.filters if spec in f.data):
                continue
            yield Issue(
                f"{component.label} matches {spec.describe()} without autoVerify: another app can claim the host",
                component.element,
                f"{spec.scheme}://{spec.host or '*'} without autoVerify",
                where=component.label,
            )


@rule(
    "MVT024",
    "Deep link matches every host",
    "medium",
    1,
    why=(
        'android:host="*" matches any host, so the filter is not a link into your app -- it is '
        "a claim on every URL of that scheme. Depending on the intent, the system may route "
        "unrelated links here, and a hostile app can use the same wildcard to intercept yours."
    ),
    fix="Name the specific host (and subdomains) the app serves.",
)
def deeplink_wildcard_host(ctx: Context) -> Iterator[Issue]:
    for component in ctx.app.components:
        for spec in component.all_deep_links():
            if spec.host != "*":
                continue
            yield Issue(
                f'{component.label} declares <data android:host="*"> -- every host matches',
                component.element,
                'host="*"',
                where=component.label,
            )


@rule(
    "MVT025",
    "Deep link matches the whole path",
    "medium",
    1,
    why=(
        "pathPrefix=\"/\" or pathPattern=\".*\" accepts any path under the host, so the app "
        "becomes the handler for pages it has no business rendering. Whatever the handler does "
        "with the trailing path (WebView.loadUrl is the usual) is now attacker-chosen input."
    ),
    fix="Match the concrete paths the app serves, and validate the path again inside the handler.",
)
def deeplink_wildcard_path(ctx: Context) -> Iterator[Issue]:
    for component in ctx.app.components:
        for spec in component.all_deep_links():
            if not spec.has_path:
                continue
            wildcard = spec.path_prefix == "/" or spec.path_pattern in {".*", "/.*", ".*/.*"}
            if not wildcard:
                continue
            shown = spec.path_prefix or spec.path_pattern
            yield Issue(
                f'{component.label} matches path "{shown}" -- the entire path space of the host',
                component.element,
                f'path="{shown}"',
                where=component.label,
            )


@rule(
    "MVT026",
    "Custom-scheme deep link into an exported activity",
    "medium",
    1,
    why=(
        "A custom scheme (myapp://) is first-come-first-served: any app can register the same "
        "string. When the target activity is exported and unguarded, the link is a way for "
        "another app to drive this one's UI with chosen parameters."
    ),
    fix="Treat custom-scheme parameters as untrusted input, and keep the handler activity unexported where possible.",
)
def deeplink_custom_scheme(ctx: Context) -> Iterator[Issue]:
    for component in ctx.app.components_of("activity"):
        if not ctx.exported(component) or ctx.guard(component):
            continue
        for spec in component.all_deep_links():
            if spec.is_web or spec.scheme in {"content", "file", "android-app"}:
                continue
            yield Issue(
                f"{component.label} is exported and handles {spec.describe()} -- any app can invoke this scheme",
                component.element,
                f'scheme="{spec.scheme}"',
                where=component.label,
            )


@rule(
    "MVT027",
    "BROWSABLE filter with no data",
    "note",
    1,
    why=(
        "BROWSABLE without any <data> element cannot match a URL: the category promises link "
        "handling the filter cannot deliver. Harmless at runtime, but it hides the real filter "
        "in review."
    ),
    fix="Add the <data> elements the filter is meant to match, or drop the BROWSABLE category.",
)
def browsable_no_data(ctx: Context) -> Iterator[Issue]:
    for component in ctx.app.components:
        for spec_filter in component.filters:
            if spec_filter.browsable and not spec_filter.data:
                yield Issue(
                    f"{component.label} has a BROWSABLE intent-filter with no <data>",
                    component.element,
                    "BROWSABLE without <data>",
                    where=component.label,
                )


@rule(
    "MVT028",
    "<data> scheme without host",
    "low",
    1,
    why=(
        "A scheme on its own (no host, no path) matches every URI with that scheme. For http "
        "that means the app claims to handle the entire web; for a custom scheme it means any "
        "shape of input reaches the handler."
    ),
    fix="Add android:host and a path constraint to every <data> that carries a scheme.",
)
def data_scheme_only(ctx: Context) -> Iterator[Issue]:
    for component in ctx.app.components:
        for spec in component.all_deep_links():
            if spec.host or spec.has_path or spec.mime_type:
                continue
            yield Issue(
                f'{component.label} has <data android:scheme="{spec.scheme}"> with no host or path',
                component.element,
                f'scheme="{spec.scheme}" only',
                where=component.label,
            )


@rule(
    "MVT029",
    "Exported receiver for a protected system broadcast",
    "medium",
    1,
    why=(
        "The platform delivers protected broadcasts (BOOT_COMPLETED, PACKAGE_ADDED, ...) to "
        "non-exported receivers too -- the protection is on the sender. Setting exported=\"true\" "
        "adds nothing for these actions except a way for other apps to send them anyway."
    ),
    fix='Set android:exported="false" on receivers that only listen to system broadcasts.',
)
def receiver_protected_broadcast(ctx: Context) -> Iterator[Issue]:
    for component in ctx.app.components_of("receiver"):
        if not ctx.exported(component):
            continue
        for action in component.all_actions():
            if action in PROTECTED_BROADCASTS:
                yield Issue(
                    f"{component.label} is exported and listens for {action} "
                    "(system-protected: exporting it adds only surface)",
                    component.element,
                    f"{action} on an exported receiver",
                    where=component.label,
                )
                break


@rule(
    "MVT030",
    "Intent filter action is not qualified",
    "medium",
    1,
    why=(
        "Action strings share one global namespace. A reverse-domain action "
        "(com.example.app.SYNC) is implicitly owned; a bare word (SYNC, UPDATE, PING) is owned "
        "by whoever registers it first, and any app can declare the same string with a higher "
        "priority to intercept the implicit intent."
    ),
    fix="Qualify every custom action with the application id (or the fully qualified class name).",
)
def action_not_namespaced(ctx: Context) -> Iterator[Issue]:
    for component in ctx.app.components:
        for spec_filter in component.filters:
            for action in spec_filter.actions:
                if action.startswith("android.") or "." in action:
                    continue
                yield Issue(
                    f'{component.label} declares the unqualified action "{action}" -- any app can register it too',
                    component.element,
                    f'action "{action}"',
                    where=component.label,
                )


# -- permissions -------------------------------------------------------------


@rule(
    "MVT031",
    "App-defined permission is normal-level",
    "medium",
    1,
    why=(
        "A permission declared with protectionLevel normal (the default) is granted to any app "
        "that asks for it at install time, silently. If it is meant to protect a component, the "
        "protection is decorative."
    ),
    fix="Use protectionLevel=\"signature\" for permissions that gate components.",
)
def permission_normal(ctx: Context) -> Iterator[Issue]:
    for perm in ctx.app.declared:
        if perm.base != "normal":
            continue
        yield Issue(
            f'<permission android:name="{perm.name}"> is {perm.base}-level: any app can hold it',
            perm.element,
            "protectionLevel=normal",
            attr="protectionLevel",
            where=f"permission {perm.name}",
        )


@rule(
    "MVT032",
    "App-defined permission has no protectionLevel",
    "low",
    1,
    why=(
        "protectionLevel is not inherited from anywhere; omitting it means normal. The omission "
        "reads as \"I forgot\" and is a reliable sign the permission was never threat-modelled."
    ),
    fix="Always write protectionLevel explicitly, even when it is normal.",
)
def permission_no_level(ctx: Context) -> Iterator[Issue]:
    for perm in ctx.app.declared:
        if perm.element.has("protectionLevel"):
            continue
        yield Issue(
            f'<permission android:name="{perm.name}"> declares no protectionLevel (defaults to normal)',
            perm.element,
            "no protectionLevel attribute",
            where=f"permission {perm.name}",
        )


@rule(
    "MVT033",
    "App-defined permission is dangerous-level",
    "note",
    1,
    why=(
        "A dangerous permission shows the user a runtime prompt. For an app-defined permission "
        "that prompt explains nothing, so users grant it to make the dialog go away -- and any "
        "app that asks gets the same grant."
    ),
    fix="Reserve dangerous level for permissions that map to real user-visible capability, otherwise use signature.",
)
def permission_dangerous(ctx: Context) -> Iterator[Issue]:
    for perm in ctx.app.declared:
        if perm.base != "dangerous":
            continue
        yield Issue(
            f'<permission android:name="{perm.name}"> is dangerous-level: '
            "users grant it without understanding what it gates",
            perm.element,
            "protectionLevel=dangerous",
            attr="protectionLevel",
            where=f"permission {perm.name}",
        )


@rule(
    "MVT034",
    "Requests a permission it can never hold",
    "medium",
    1,
    why=(
        "Signature and privileged permissions are only granted to apps signed with the platform "
        "key or preinstalled in the system image. A third-party app that declares them gets no "
        "error and no grant -- the feature silently degrades, and the manifest reads as if the "
        "capability were there."
    ),
    fix="Remove the request, and reach the capability through a bound service, an accessibility "
        "service or a user-granted role instead.",
)
def permission_never_granted(ctx: Context) -> Iterator[Issue]:
    for used in ctx.app.used:
        if used.name not in SIGNATURE_ONLY_PERMISSIONS:
            continue
        yield Issue(
            f'requests {used.name}, which is signature|privileged: never granted to a third-party app',
            used.element,
            f"uses-permission {used.name}",
            where=f"uses-permission {used.name}",
        )


@rule(
    "MVT035",
    "Requests an undefined permission",
    "low",
    1,
    why=(
        "A permission name that is neither a platform permission nor declared by this app is "
        "ignored at install. It is almost always a typo (READ_SMS vs READ_SMSS), and the code "
        "that depends on it fails a permission check at runtime instead of at review time."
    ),
    fix="Fix the name, or declare the permission in this manifest if it is app-defined.",
)
def permission_typo(ctx: Context) -> Iterator[Issue]:
    declared = {perm.name for perm in ctx.app.declared}
    for used in ctx.app.used:
        if used.name.startswith("android.permission.") or used.name in declared:
            continue
        yield Issue(
            f'requests "{used.name}", which is neither a platform permission nor declared here',
            used.element,
            f"uses-permission {used.name}",
            where=f"uses-permission {used.name}",
        )


@rule(
    "MVT036",
    "Requests QUERY_ALL_PACKAGES",
    "low",
    1,
    why=(
        "QUERY_ALL_PACKAGES turns the app into an inventory of everything installed -- a "
        "fingerprinting primitive, and a Play policy violation unless the app's core purpose "
        "needs it."
    ),
    fix="Replace it with a <queries> block naming the specific packages or intent shapes the app talks to.",
)
def query_all_packages(ctx: Context) -> Iterator[Issue]:
    for used in ctx.app.used:
        if used.name != "android.permission.QUERY_ALL_PACKAGES":
            continue
        yield Issue(
            "requests QUERY_ALL_PACKAGES: the app can enumerate every installed package",
            used.element,
            "uses-permission QUERY_ALL_PACKAGES",
            where="uses-permission QUERY_ALL_PACKAGES",
        )


@rule(
    "MVT037",
    "Exported component is gated by a permission any app can hold",
    "critical",
    3,
    why=(
        "The component declares a guard, so it reads as protected -- but the guard is a normal "
        "or dangerous permission, either a platform one (INTERNET, VIBRATE) or one this app "
        "declares at that level. Any app can request it and be granted at install. This is the "
        "most common false sense of security in Android manifests."
    ),
    fix="Guard with a signature-level permission, or set exported=\"false\" and pass data over a "
        "Binder interface with a caller check (getCallingUid).",
)
def weak_guard_component(ctx: Context) -> Iterator[Issue]:
    for component in ctx.app.components:
        if not ctx.exported(component):
            continue
        guard = ctx.guard(component)
        reason = ctx.weak_guard(guard)
        if not reason:
            continue
        yield Issue(
            f"{component.label} is exported and guarded by {guard} -- {reason}",
            component.element,
            f'android:permission="{guard}"',
            attr="permission",
            where=component.label,
        )


@rule(
    "MVT038",
    "Two providers share an authority",
    "high",
    3,
    why=(
        "Authorities are unique per device. Two providers claiming the same one means the second "
        "never installs, or -- worse -- one of them silently answers queries meant for the other. "
        "In a plugin/feature-module setup this is how a staging authority ships to production."
    ),
    fix="Give each provider a distinct authority derived from the application id and the module.",
)
def duplicate_authority(ctx: Context) -> Iterator[Issue]:
    seen: dict[str, Component] = {}
    for component in ctx.app.components_of("provider"):
        for authority in component.sget("authorities").split(";"):
            authority = authority.strip()
            if not authority:
                continue
            if authority in seen:
                yield Issue(
                    f'{component.label} reuses the authority "{authority}" already declared by {seen[authority].label}',
                    component.element,
                    f'authorities="{authority}"',
                    attr="authorities",
                    where=component.label,
                )
            else:
                seen[authority] = component


@rule(
    "MVT039",
    "Component guard names a permission that does not exist",
    "low",
    3,
    why=(
        "android:permission pointing at a name neither the platform nor this app defines is "
        "silently ignored: the component ends up effectively unguarded while reading as guarded. "
        "Typos here survive review precisely because the line looks right."
    ),
    fix="Correct the permission name, or declare the permission in this manifest.",
)
def guard_typo(ctx: Context) -> Iterator[Issue]:
    declared = {perm.name for perm in ctx.app.declared}
    known_platform_prefix = "android.permission."
    for component in ctx.app.components:
        guard = component.permission
        if not guard:
            continue
        if guard.startswith(known_platform_prefix) or guard in declared:
            continue
        yield Issue(
            f'{component.label} is guarded by "{guard}", which no manifest declares: the guard does not exist',
            component.element,
            f'android:permission="{guard}"',
            attr="permission",
            where=component.label,
        )


@rule(
    "MVT040",
    "Exported component runs in a global process",
    "low",
    3,
    why=(
        'A process name without a leading colon (android:process="com.example.shared") is global: '
        "any other app with the same sharedUserId and process name joins it. Memory in that "
        "process is then shared with code this app does not control."
    ),
    fix="Use a per-app private process (android:process=\":remote\") when isolation is the point.",
)
def global_process(ctx: Context) -> Iterator[Issue]:
    for component in ctx.app.components:
        process = component.sget("process")
        if not process or process.startswith(":"):
            continue
        if not ctx.exported(component):
            continue
        yield Issue(
            f'{component.label} is exported and runs in the global process "{process}"',
            component.element,
            f'android:process="{process}"',
            attr="process",
            where=component.label,
        )


def validate_registry() -> None:
    """Fail loudly at import time if the rule table drifted."""
    ids = [r.id for r in REGISTRY]
    if len(ids) != len(set(ids)):
        duplicates = {i for i in ids if ids.count(i) > 1}
        raise RuntimeError(f"duplicate rule ids: {sorted(duplicates)}")
    for r in REGISTRY:
        if r.severity not in SEVERITY_ORDER:
            raise RuntimeError(f"{r.id}: unknown severity {r.severity}")
        if not r.why or not r.fix:
            raise RuntimeError(f"{r.id}: every rule needs a why and a fix")


validate_registry()
