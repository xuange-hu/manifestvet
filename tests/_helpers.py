"""Helpers shared by the test modules (kept out of conftest so they can be imported)."""

from __future__ import annotations

import os
import sys

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from manifestvet import engine, model  # noqa: E402


def manifest(body: str, *, package: str = "com.example.app", attrs: str = "", sdk: str | None = None) -> str:
    """Wrap ``body`` in a <manifest> with a modern targetSdk unless overridden."""
    uses_sdk = sdk if sdk is not None else '<uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34"/>'
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android"\n'
        f'    package="{package}"{(" " + attrs) if attrs else ""}>\n'
        f"    {uses_sdk}\n"
        f"    {body}\n"
        "</manifest>\n"
    )


def app_xml(body: str, *, application: str = "", package: str = "com.example.app", sdk: str | None = None) -> str:
    """<manifest> + <application> wrapper for component tests."""
    inner = f"<application{(' ' + application) if application else ''}>\n{body}\n</application>"
    return manifest(inner, package=package, sdk=sdk)


def scan_text(xml: str, *, target: str = "AndroidManifest.xml") -> engine.Report:
    return engine.run(model.load(xml.encode("utf-8")), target=target)
