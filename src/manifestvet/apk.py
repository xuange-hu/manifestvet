"""Find manifests: inside an APK, as a bare file, or by walking a source tree.

An APK is a zip; the manifest is stored uncompressed-named ``AndroidManifest.xml``
and is always the compiled form.  A source checkout has the plain-text one and
often several (overlays per build type, per module), so a directory scan reports
each with its path -- which manifest a finding came from is part of the finding.
"""

from __future__ import annotations

import os
import zipfile
from pathlib import Path

# Directories that contain copies of the same manifest, never new information.
SKIP_DIRS = {
    ".git",
    ".gradle",
    ".idea",
    "build",
    "out",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    "intermediates",
    "merged_manifests",
}

MANIFEST_NAMES = {"androidmanifest.xml"}


def is_archive(path: Path) -> bool:
    return path.suffix.lower() in {".apk", ".aab", ".zip", ".apks"} or zipfile.is_zipfile(path)


def from_apk(path: Path) -> bytes:
    with zipfile.ZipFile(path) as archive:
        for name in ("AndroidManifest.xml", "base/manifest/AndroidManifest.xml"):
            try:
                return archive.read(name)
            except KeyError:
                continue
        # AABs keep the manifest under base/manifest/; anything else is not an app.
        candidates = [n for n in archive.namelist() if n.lower().endswith("androidmanifest.xml")]
        if not candidates:
            raise FileNotFoundError(f"{path}: no AndroidManifest.xml inside the archive")
        return archive.read(candidates[0])


def iter_targets(path: Path) -> list[tuple[str, bytes]]:
    """Return ``(display_name, manifest_bytes)`` for everything under ``path``."""
    if path.is_dir():
        found: list[tuple[str, bytes]] = []
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for name in files:
                if name.lower() not in MANIFEST_NAMES:
                    continue
                full = Path(root) / name
                try:
                    data = full.read_bytes()
                except OSError:
                    continue
                found.append((str(full), data))
        found.sort(key=lambda item: item[0])
        return found

    if not path.exists():
        raise FileNotFoundError(f"{path}: no such file or directory")

    if is_archive(path):
        return [(str(path), from_apk(path))]
    return [(str(path), path.read_bytes())]
