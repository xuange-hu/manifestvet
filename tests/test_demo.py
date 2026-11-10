"""The demo corpus is a claim: every rule has a sample that triggers it."""

from __future__ import annotations

import pytest

from manifestvet import axml, demo, engine, model
from manifestvet.rules import REGISTRY

RULE_IDS = {rule.id for rule in REGISTRY}


def test_corpus_has_three_manifests():
    assert sorted(demo.CORPUS) == ["legacy", "modern", "vault"]


@pytest.mark.parametrize("name", sorted(demo.CORPUS))
def test_every_corpus_entry_compiles_to_axml(name):
    data = demo.compiled(name)
    assert data[:2] == b"\x03\x00"
    doc = axml.parse(data)
    assert doc.root.name == "manifest"
    assert doc.unresolved == []


@pytest.mark.parametrize("name", sorted(demo.CORPUS))
def test_every_corpus_entry_parses_into_a_model(name):
    app = model.load(demo.compiled(name))
    assert app.package.startswith("com.example.")


def test_the_corpus_covers_the_whole_rule_table():
    fired: set[str] = set()
    for report in demo.reports():
        fired |= report.triggered()
    assert fired == RULE_IDS
    assert len(RULE_IDS) == 40


def test_the_corpus_is_deterministic():
    first = [(r.target, sorted(r.triggered())) for r in demo.reports()]
    second = [(r.target, sorted(r.triggered())) for r in demo.reports()]
    assert first == second


def test_vault_is_the_hostile_one():
    vault = next(r for r in demo.reports() if "vault" in r.target)
    assert vault.counts["critical"] >= 2
    assert vault.risk == 100


def test_legacy_documents_the_pre_sdk_world():
    legacy = next(r for r in demo.reports() if "legacy" in r.target)
    assert legacy.app.target_sdk == 1
    assert {"MVT010", "MVT011", "MVT003"} <= legacy.triggered()


def test_modern_shows_the_repacked_manifest_smell():
    modern = next(r for r in demo.reports() if "modern" in r.target)
    assert modern.triggered() == {"MVT012"}


def test_demo_run_reports_success(capsys):
    code = demo.run(color=False)
    out = capsys.readouterr().out
    assert code == 0
    assert "40/40" in out


def test_text_and_compiled_paths_agree_for_the_corpus():
    for name, text in demo.CORPUS.items():
        text_rules = engine.run(model.load(text.encode("utf-8"))).triggered()
        axml_rules = engine.run(model.load(demo.compiled(name))).triggered()
        assert text_rules == axml_rules, name
