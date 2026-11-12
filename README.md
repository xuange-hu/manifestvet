# manifestvet

[![CI](https://github.com/xuange-hu/manifestvet/actions/workflows/ci.yml/badge.svg)](https://github.com/xuange-hu/manifestvet/actions/workflows/ci.yml)
![tests-315%20passing](https://img.shields.io/badge/tests-315%20passing-brightgreen)
![dependencies-0](https://img.shields.io/badge/dependencies-0-blue)
![rules-40](https://img.shields.io/badge/rules-40-informational)
![mcp-7%20tools](https://img.shields.io/badge/mcp-7%20tools-blueviolet)
![license-MIT](https://img.shields.io/badge/license-MIT-lightgrey)

**Read an Android manifest the way an attacker does — with the bytes that prove each answer, and no `aapt`, no Java, no dependency to install.**

[中文说明](README_CN.md) · [Rule reference](docs/rules.md) · [Why AXML needs its own reader](docs/axml.md)

```console
$ manifestvet scan app-release.apk
app-release.apk
  package=com.example.vault  minSdk=19  targetSdk=29  components=16  format=axml  shift=0
  45 findings  critical=2  high=15  medium=16  low=10  note=2  risk=100/100

[critical] MVT001  Application is debuggable
           android:debuggable="true" -- JDWP is reachable, private data is readable via adb
           at line 19, offset 0xcc0
           bytes: debuggable="true"
           fix:   Remove android:debuggable, or gate it on a build type (debuggable true only in debug).

[critical] MVT037  Exported component is gated by a permission any app can hold
           activity .GuardedActivity is exported and guarded by android.permission.INTERNET
           -- a normal/dangerous platform permission any app can request
           at line 61, offset 0x1450
           bytes: android:permission="android.permission.INTERNET"
           fix:   Guard with a signature-level permission, or set exported="false" and pass
                  data over a Binder interface with a caller check (getCallingUid).
```

## Contents

- [Three steps](#three-steps)
- [Why this exists](#why-this-exists)
- [The rules](#the-rules)
- [MCP](#mcp)
- [How it compares](#how-it-compares)
- [Verified, not asserted](#verified-not-asserted)
- [Limitations](#limitations)
- [License](#license)

## Three steps

```bash
# 1. run it without installing anything
uvx --from git+https://github.com/xuange-hu/manifestvet manifestvet demo

# 2. audit an APK, a manifest file, or a whole source tree
uvx --from git+https://github.com/xuange-hu/manifestvet manifestvet scan path/to/app.apk
uvx --from git+https://github.com/xuange-hu/manifestvet manifestvet scan app/src/main/AndroidManifest.xml

# 3. put it in CI
uvx --from git+https://github.com/xuange-hu/manifestvet manifestvet scan app-release.apk \
    --format sarif --fail-on high > manifestvet.sarif
```

`scan` accepts `.apk`, `.aab`, `.zip`, a bare `AndroidManifest.xml` (compiled **or** source),
or a directory it walks, skipping `build/`, `.gradle/` and `intermediates/`.

### Baselines: accept known findings, fail only on new ones

```bash
# snapshot today's reality (exits 0 even with findings)
manifestvet scan app-release.apk --save-baseline .manifestvet-baseline.json

# later runs: findings recorded in the baseline are accepted; a NEW finding exits 1
manifestvet scan app-release.apk --baseline .manifestvet-baseline.json
```

The baseline file is diff-friendly JSON keyed by `(rule, where, message)` — deliberately
not line or offset, which move on every recompile. Targets are keyed relative to the
scan root, so the file survives a different checkout path. Commit it next to your CI
workflow.

Python 3.10+. Zero runtime dependencies. The `mcp` extra is the only optional one.

## Why this exists

Every existing manifest checker either wraps `aapt`/`apktool` (so it needs a JDK and an
SDK, and can only tell you *that* the manifest says something) or reimplements the format
in a heavyweight framework. Three things follow from that, and they are the whole design:

**1. Byte-level provenance.** Findings carry the byte offset of the `ResXMLTree_node` — or
of the exact attribute — plus the line aapt recorded. `--format sarif` turns them into code
scanning annotations; `manifestvet attrs` dumps the whole tree with offsets so you can check
the tool's work instead of trusting it.

**2. AXML is parsed, not shelled out.** Attribute names do not exist in a compiled manifest:
`android:exported` is the integer `0x01010010`, and the local name has to be recovered from
the resource map. That recovery is where manifests get misread, so it is implemented here,
tested against a real aapt2-produced APK, and documented in [docs/axml.md](docs/axml.md).

**3. The model, not the XML, is what gets audited.** Rules ask an `App` object
*"which components can another app reach without holding a permission?"* — which means
`android:exported` defaults, `<application android:permission>` inheritance and
`protectionLevel` bitmasks are resolved once, correctly, in `model.py`.

## The rules

40 rules in three stages. Full text with reasoning and fixes: [docs/rules.md](docs/rules.md).

| stage | what it looks at | examples |
|---|---|---|
| 1 — element | one node at a time | `debuggable`, `allowBackup` default, cleartext, `sharedUserId`, `minSdk`/`targetSdk` |
| 2 — component | component + its intent-filters | exported service with no guard, provider with `grantUriPermissions`, `host="*"`, task hijacking |
| 3 — app | relationships across components | a guard any app can hold (`INTERNET`), duplicate authorities, a guard that names a permission nobody declares |

The ones that catch real bugs rather than style:

- **MVT037** — an exported component "protected" by a normal/dangerous permission. Any app can
  request `android.permission.INTERNET` and be granted at install; the guard is decorative.
  This is the most common false sense of security in Android manifests.
- **MVT039** — `android:permission="com.example.app.SIG"` where no `<permission>` of that name
  exists. Silently ignored, so the component is open while reading as guarded.
- **MVT038** — two providers on one authority. One of them never installs, or one answers
  queries meant for the other.
- **MVT018/MVT019** — `grantUriPermissions` plus a `path="/"` rule: a `content://` URI becomes
  a transferable capability that reads the file from any app.

## MCP

Seven tools, for Claude Code / Cursor / Cline:

```json
{
  "mcpServers": {
    "manifestvet": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/xuange-hu/manifestvet[mcp]", "manifestvet-mcp"]
    }
  }
}
```

| tool | use |
|---|---|
| `manifestvet_scan` | audit an APK / manifest / directory |
| `manifestvet_manifest` | audit manifest **text** pasted inline — no file needed |
| `manifestvet_components` | the attack surface as a table: component, exported, guard, weak guard |
| `manifestvet_explain` | one rule: what, why, fix, doc anchor |
| `manifestvet_rules` | the table, filtered by stage or severity |
| `manifestvet_sarif` | SARIF 2.1.0 |
| `manifestvet_demo` | audit a generated corpus; one call proves all 40 rules work |

`manifestvet mcp --check` prints the same list from the CLI.

## How it compares

| | manifestvet | MobSF | apkleaks | `aapt2 dump xmltree` |
|---|---|---|---|---|
| runtime | Python stdlib | Django app + JADX + JDK | Python + jadx | Android SDK |
| output | rules + byte offsets | web report | strings/URLs | raw attribute dump |
| source manifests | yes (same rules) | no | no | no |
| CI (SARIF, exit codes) | yes | no | no | no |
| model of `exported` defaults | yes | partial | n/a | no judgement |

## Verified, not asserted

- `manifestvet demo` builds three manifests **at runtime**, compiles them to AXML, and
  asserts that all 40 rules fire across the corpus (`tests/test_demo.py`). Nothing is a
  checked-in binary fixture, so a rule cannot quietly stop being covered.
- The reader is tested against a real aapt2-compiled APK: package, `targetSdkVersion`,
  `debuggable`, provider `exported=false` and a `android.permission.DUMP` guard are asserted
  semantically, not just "it parsed".
- Source-XML and AXML inputs are asserted to produce **identical findings** — the same
  manifest audited on a dev machine and in CI cannot disagree.
- `ruff` clean, tests on 3.10 / 3.11 / 3.12 / 3.13.

## Limitations

- Java/Kotlin code is not analysed: an exported activity that validates its extras is still
  reported, because the finding is about reachability, not about whether the code is careful.
- `android:protectionLevel` is decoded from the bitmask; app-defined permission *groups* are
  not modelled.
- Resources referenced as `@0x7f...` are reported by id — resolving them needs
  `resources.arsc`, which is out of scope for a manifest auditor.
- AAB input reads `base/manifest/AndroidManifest.xml`; feature-module manifests are audited
  when you point the tool at the source tree instead.

## License

MIT.
