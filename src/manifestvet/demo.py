"""``manifestvet demo`` -- a self-contained corpus, no network, no APK on disk.

Three manifests, and the reason there are three rather than one: some rules are
mutually exclusive by construction.  ``allowBackup`` cannot be both absent and
explicitly true, ``targetSdk`` cannot be both declared and missing, and
``android:exported`` cannot be both required (targetSdk 31+) and optional.  A
single "bad manifest" would silently stop covering half the rule table the moment
someone tightened a rule -- so coverage is asserted against the union, in
``tests/test_demo.py``.

The text is compiled to AXML at runtime by :mod:`manifestvet.axmlwrite`; the demo
therefore runs the same reader a real APK goes through.
"""

from __future__ import annotations

from . import axmlwrite, engine, model, render

VAULT = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.vault"
    android:versionCode="42"
    android:versionName="1.0"
    android:sharedUserId="com.example.shared">

    <uses-sdk android:minSdkVersion="19" android:targetSdkVersion="29"/>

    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.INSTALL_PACKAGES"/>
    <uses-permission android:name="android.permission.QUERY_ALL_PACKAGES"/>
    <uses-permission android:name="com.example.vault.READ_DATA"/>

    <permission android:name="com.example.vault.READ" android:protectionLevel="normal"/>
    <permission android:name="com.example.vault.WRITE"/>
    <permission android:name="com.example.vault.ADMIN" android:protectionLevel="dangerous"/>

    <application
        android:label="Vault"
        android:debuggable="true"
        android:usesCleartextTraffic="true"
        android:requestLegacyExternalStorage="true">

        <activity android:name=".LauncherActivity" android:exported="true" android:launchMode="singleTask">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>

        <activity android:name=".ExportActivity"
            android:exported="true"
            android:allowTaskReparenting="true"/>

        <activity android:name=".LinkActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.DEFAULT"/>
                <category android:name="android.intent.category.BROWSABLE"/>
                <data android:scheme="https" android:host="vault.example.com" android:pathPrefix="/"/>
            </intent-filter>
        </activity>

        <activity android:name=".WildcardActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.BROWSABLE"/>
                <data android:scheme="http" android:host="*"/>
            </intent-filter>
        </activity>

        <activity android:name=".CustomSchemeActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.BROWSABLE"/>
                <data android:scheme="vaultapp"/>
            </intent-filter>
        </activity>

        <activity android:name=".GuardedActivity"
            android:exported="true"
            android:permission="android.permission.INTERNET"/>

        <activity android:name=".TypoGuardActivity"
            android:exported="true"
            android:permission="com.example.vault.NOT_DECLARED"/>

        <activity android:name=".GlobalProcessActivity"
            android:exported="true"
            android:process="com.example.shared"/>

        <service android:name=".SyncService" android:exported="true"/>

        <receiver android:name=".PingReceiver" android:exported="true">
            <intent-filter>
                <action android:name="PING"/>
            </intent-filter>
        </receiver>

        <receiver android:name=".BootReceiver" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED"/>
            </intent-filter>
        </receiver>

        <receiver android:name=".EmptyFilterReceiver" android:exported="true">
            <intent-filter>
                <category android:name="android.intent.category.BROWSABLE"/>
            </intent-filter>
        </receiver>

        <provider android:name=".VaultProvider"
            android:exported="true"
            android:authorities="com.example.vault.provider"/>

        <provider android:name=".CacheProvider"
            android:exported="true"
            android:authorities="com.example.vault.cache"
            android:grantUriPermissions="true">
            <grant-uri-permission android:path="/"/>
        </provider>

        <provider android:name=".GhostProvider" android:exported="false"/>

        <provider android:name=".DupProvider"
            android:exported="false"
            android:authorities="com.example.vault.provider"/>
    </application>
</manifest>
"""

LEGACY = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.legacy">
    <application android:label="Legacy" android:allowBackup="true">
        <activity android:name=".MainActivity"/>
    </application>
</manifest>
"""

MODERN = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.modern">
    <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34"/>
    <application android:label="Modern">
        <activity android:name=".ShareTarget">
            <intent-filter>
                <action android:name="android.intent.action.SEND"/>
                <category android:name="android.intent.category.DEFAULT"/>
            </intent-filter>
        </activity>
    </application>
</manifest>
"""

CORPUS: dict[str, str] = {
    "vault": VAULT,
    "legacy": LEGACY,
    "modern": MODERN,
}


def compiled(name: str) -> bytes:
    return axmlwrite.compile_text(CORPUS[name])


def reports() -> list[engine.Report]:
    out = []
    for name in CORPUS:
        app = model.load(compiled(name))
        out.append(engine.run(app, target=f"demo/{name}/AndroidManifest.xml"))
    return out


def run(*, color: bool = True, explain: bool = False, out=print) -> int:
    """Print the demo corpus report.  Returns a process exit code."""
    all_reports = reports()
    triggered: set[str] = set()
    total = 0
    for report in all_reports:
        triggered |= report.triggered()
        total += len(report.findings)
        out(render.text(report, color=color, explain=explain))

    rules = {r.id for r in engine.rules.REGISTRY}
    missing = sorted(rules - triggered)
    out("=" * 72)
    out(f"corpus: {len(all_reports)} manifests, {total} findings, {len(triggered)}/{len(rules)} rules fired")
    if missing:
        out(f"rules with no sample in the corpus: {', '.join(missing)}")
    else:
        out("every rule in the table has a sample manifest that triggers it")
    return 0 if not missing else 1
