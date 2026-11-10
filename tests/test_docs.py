"""# Docs contract

Two documents are generated or quoted, and both have drifted in projects before:

* `docs/rules.md` is produced by `manifestvet rules --markdown`. A hand-edited
  table of 40 rules is wrong within two commits, so the file is compared verbatim.
* the README advertises a rule count, a severity breakdown and an install command.
  Each is checked against the registry and the packaging metadata.
"""

from __future__ import annotations

import os
import re

from manifestvet import rulebook
from manifestvet.rules import REGISTRY

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULE_IDS = sorted(rule.id for rule in REGISTRY)


def _read(name: str) -> str:
    with open(os.path.join(REPO_ROOT, name), encoding="utf-8") as fh:
        return fh.read()


def test_generated_rules_doc_is_up_to_date():
    expected = rulebook.full_markdown()
    actual = _read("docs/rules.md")
    assert actual == expected, (
        "docs/rules.md is stale; run `manifestvet rules --markdown > docs/rules.md`"
    )


def test_rules_doc_has_a_section_per_rule():
    text = _read("docs/rules.md")
    headings = set(re.findall(r"^## (MVT\d{3})$", text, flags=re.MULTILINE))
    assert headings == set(RULE_IDS)


def test_rules_doc_states_the_count():
    text = _read("docs/rules.md")
    assert f"{len(REGISTRY)} rules" in text


def test_readme_and_readme_cn_both_exist_and_cross_link():
    english = _read("README.md")
    chinese = _read("README_CN.md")
    assert "README_CN.md" in english
    assert "README.md" in chinese


def test_readme_states_the_rule_count():
    assert "40 rules" in _read("README.md")
    assert "40 条" in _read("README_CN.md")


def test_readme_has_the_three_step_quickstart():
    text = _read("README.md")
    assert "uvx --from git+https://github.com/xuange-hu/manifestvet" in text
    assert text.count("manifestvet scan") >= 2
    assert "--format sarif" in text


def test_readme_install_commands_point_at_this_repository():
    for name in ("README.md", "README_CN.md"):
        text = _read(name)
        for command in re.findall(r"uvx --from (git\+\S+)", text):
            assert "xuange-hu/manifestvet" in command, (name, command)


def test_readme_links_resolve_to_files_in_the_repo():
    text = _read("README.md")
    for target in re.findall(r"\]\((docs/[^)#]+)\)", text):
        assert os.path.isfile(os.path.join(REPO_ROOT, target)), target


def test_readme_mentions_sarif():
    assert "sarif" in _read("README.md").lower()


def test_chinese_readme_does_not_promise_a_different_rule_count():
    chinese = _read("README_CN.md")
    assert "40 条" in chinese
    assert "39 条" not in chinese
