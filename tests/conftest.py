"""Fixtures.  Helpers live in ``_helpers`` so tests can import them directly."""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _helpers import scan_text  # noqa: E402

from manifestvet import axmlwrite, model  # noqa: E402


@pytest.fixture
def rules_fired():
    """Factory: manifest text -> set of rule ids that fired."""

    def _fired(xml: str) -> set[str]:
        return scan_text(xml).triggered()

    return _fired


@pytest.fixture
def one_finding():
    """Factory: manifest text + rule id -> the single finding for that rule."""

    def _one(xml: str, rule_id: str):
        report = scan_text(xml)
        matches = [f for f in report.findings if f.rule == rule_id]
        assert matches, f"{rule_id} did not fire; fired: {sorted(report.triggered())}"
        return matches[0]

    return _one


@pytest.fixture
def app_of():
    """Factory: manifest text -> parsed model."""

    def _app(xml: str) -> model.App:
        return model.load(xml.encode("utf-8"))

    return _app


@pytest.fixture
def compiled_apk(tmp_path):
    """Factory: manifest text -> a real .apk zip holding a compiled manifest."""

    import zipfile

    def _make(xml: str, name: str = "app.apk") -> str:
        path = tmp_path / name
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("AndroidManifest.xml", axmlwrite.compile_text(xml))
            archive.writestr("classes.dex", b"dex\n035\x00")
        return str(path)

    return _make
