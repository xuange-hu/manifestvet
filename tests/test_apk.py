"""Input discovery: apk/aab/zip, bare files, directory walks."""

from __future__ import annotations

import os
import zipfile

import pytest
from _helpers import app_xml

from manifestvet import apk

XML = app_xml('<activity android:name=".A" android:exported="false"/>')


def _zip(path, entries: dict[str, bytes]) -> str:
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return str(path)


def test_apk_manifest_is_read(tmp_path):
    path = _zip(tmp_path / "a.apk", {"AndroidManifest.xml": b"manifest-bytes"})
    assert apk.from_apk(__import__("pathlib").Path(path)) == b"manifest-bytes"


def test_aab_layout_is_read(tmp_path):
    path = _zip(tmp_path / "a.aab", {"base/manifest/AndroidManifest.xml": b"aab-manifest"})
    assert apk.from_apk(__import__("pathlib").Path(path)) == b"aab-manifest"


def test_archive_without_manifest_raises(tmp_path):
    path = _zip(tmp_path / "a.apk", {"classes.dex": b"dex"})
    with pytest.raises(FileNotFoundError):
        apk.from_apk(__import__("pathlib").Path(path))


def test_is_archive_recognises_extensions(tmp_path):
    path = _zip(tmp_path / "a.apk", {"AndroidManifest.xml": b"x"})
    assert apk.is_archive(__import__("pathlib").Path(path)) is True
    text = tmp_path / "plain.xml"
    text.write_text("<manifest/>", encoding="utf-8")
    assert apk.is_archive(text) is False


def test_iter_targets_on_a_file(tmp_path):
    path = tmp_path / "AndroidManifest.xml"
    path.write_text(XML, encoding="utf-8")
    targets = apk.iter_targets(path)
    assert len(targets) == 1
    assert targets[0][0].endswith("AndroidManifest.xml")


def test_iter_targets_on_a_directory_sorted_by_path(tmp_path):
    for name in ("b/AndroidManifest.xml", "a/AndroidManifest.xml"):
        target = tmp_path / name
        target.parent.mkdir(parents=True)
        target.write_text(XML, encoding="utf-8")
    names = [name for name, _ in apk.iter_targets(tmp_path)]
    assert names == sorted(names)


def test_iter_targets_skips_build_output(tmp_path):
    for name in ("app/src/main/AndroidManifest.xml", "app/build/intermediates/AndroidManifest.xml"):
        target = tmp_path / name
        target.parent.mkdir(parents=True)
        target.write_text(XML, encoding="utf-8")
    names = [name for name, _ in apk.iter_targets(tmp_path)]
    assert len(names) == 1
    assert "intermediates" not in names[0]


def test_iter_targets_skips_git_and_node_modules(tmp_path):
    for name in (".git/AndroidManifest.xml", "node_modules/x/AndroidManifest.xml", "AndroidManifest.xml"):
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(XML, encoding="utf-8")
    assert len(apk.iter_targets(tmp_path)) == 1


def test_iter_targets_missing_path_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        apk.iter_targets(tmp_path / "nope")


def test_iter_targets_empty_directory_returns_empty(tmp_path):
    assert apk.iter_targets(tmp_path) == []


def test_manifest_name_match_is_case_insensitive(tmp_path):
    path = tmp_path / "androidmanifest.XML"
    path.write_text(XML, encoding="utf-8")
    assert len(apk.iter_targets(tmp_path)) == 1


def test_walk_does_not_follow_symlink_loops(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (real / "AndroidManifest.xml").write_text(XML, encoding="utf-8")
    link = tmp_path / "link"
    try:
        os.symlink(real, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    assert len(apk.iter_targets(tmp_path)) >= 1
