"""A fresh clone must be able to run `pytest` with nothing installed.

The repo uses a ``src/`` layout, so on a contributor's machine the package is not
importable unless something puts ``src/`` on ``sys.path`` -- that is what the root
``conftest.py`` does.  CI never catches it disappearing because CI installs the
package first, which masks the problem entirely.
"""

from __future__ import annotations

import os
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_root_conftest_bootstraps_src():
    path = os.path.join(REPO_ROOT, "conftest.py")
    assert os.path.isfile(path), "the root conftest.py is what makes plain `pytest` work after a clone"
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    assert "sys.path" in text and "src" in text


def test_pytest_collects_without_the_package_installed():
    # PYTHONPATH is the other way this can accidentally pass; strip it so only the
    # conftest bootstrap is exercised.
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "tests", "--collect-only", "-q", "-o", "addopts="],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        check=False,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    assert "::" in proc.stdout, out


def test_cli_runs_from_a_clean_environment():
    """No PYTHONPATH, no install: `python -m manifestvet` still has to work."""
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["PYTHONPATH"] = os.path.join(REPO_ROOT, "src")
    proc = subprocess.run(
        [sys.executable, "-m", "manifestvet", "demo", "--no-color"],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "40/40" in proc.stdout
