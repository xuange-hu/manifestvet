# Contributing

The most useful contribution here is a **manifest that the tool gets wrong**, not a patch.
A rule that misses a real pattern, or fires on a benign one, is worth more than a style fix.

## Adding a rule

1. Pick an id. Ids are stable — CI suppressions and the docs reference them — so the next
   free number is `MVT041`, never a renumber.
2. Write the rule in `src/manifestvet/rules.py` with `why` and `fix` filled in. `why` is
   the threat, not a restatement of the check.
3. Add a **sample manifest that triggers it** to `tests/test_rules.py::TRIGGERS`. The test
   `test_every_rule_has_a_trigger` fails until you do, and `manifestvet demo` will report
   the rule as uncovered.
4. Regenerate the docs: `manifestvet rules --markdown > docs/rules.md`.
5. If the rule depends on a new `android.R.attr` id, add it to `attrnames.py`. Unknown ids
   fall back to `0x0101xxxx` in the report rather than being dropped, so a missing entry is
   visible but silent in the rules — which is why `tests/test_axml.py` asserts that a real
   aapt2 manifest resolves every attribute.

## Adding a parser capability

The reader is the part with the sharp edges. Two rules, both learned the hard way:

- **Never drop what you cannot decode.** An attribute whose id is not in the table is
  reported as hex and shows up in `Document.unresolved`. Silently skipping it turns a
  parsing gap into a false "clean" report.
- **Test against real bytes.** `axmlwrite.compile_text()` can build a compiled manifest
  from text, including the UTF-16 pool and the alternate resource-map alignment. A test
  that only round-trips the writer proves the writer agrees with itself, not with aapt2.

## Running things

```bash
python -m pip install -e ".[mcp]" pytest ruff
python -m pytest -q
ruff check .
manifestvet demo            # 40/40 rules must fire
manifestvet rules --markdown > docs/rules.md
```

## Style

- Zero runtime dependencies. Stdlib only, and `tests/test_packaging.py` enforces it by
  parsing every module's top-level imports.
- Findings are written for a developer who has to fix them: what happened, where (line +
  byte offset), what it costs, what to do.
- Comments explain *why*, especially where the platform's behaviour is surprising
  (`android:exported` defaults, `protectionLevel` bitmasks, the resource-map shift).
