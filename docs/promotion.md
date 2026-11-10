# Launch copy

Written to be posted as-is. Every claim here is asserted by a test in this repo; if a
number changes, the README badge check and `tests/test_docs.py` fail first.

---

## Show HN

**Show HN: manifestvet – read an Android manifest without aapt, with byte offsets**

Every Android manifest checker I found wraps `aapt`/`apktool` or reimplements the format
inside a framework. Both mean a JDK and an SDK on the box, and both mean the output is
"the manifest contains X" rather than "here are the bytes that prove X".

The part that made me write a reader: in a compiled manifest the attribute *names are
gone*. `android:exported` is stored as the integer `0x01010010`, and the local name has to
be recovered from a resource map that is indexed relative to the string pool. Two
alignments of that map exist in the wild, and choosing wrong renames every attribute to its
neighbour without raising anything — a rule simply stops firing. My first reader did
exactly that and reported zero attributes on a real APK. The fix is to require that the
pool string and the table name for the same index are the same word; aapt2 gives ~24
agreements one way and ~0 the other.

What it does now: 40 rules over the surface another app can actually reach — exported
components with no guard, components "guarded" by a permission any app can request
(`INTERNET`, `VIBRATE`), providers with `grantUriPermissions` and `path="/"`, `singleTask`
exported activities, duplicate authorities, and a guard that names a permission nobody
declares (silently ignored, so the component is open while reading as guarded).

Same rules over `.apk`, `.aab`, source-tree XML, or a directory. A test asserts the text
and compiled paths produce identical findings, so a dev machine and CI cannot disagree.

Python 3.10+, zero dependencies, SARIF output, 7 MCP tools.

`uvx --from git+https://github.com/xuange-hu/manifestvet manifestvet demo` — builds three
manifests at runtime, compiles them, and asserts all 40 rules fire.

Feedback I am most interested in: manifests where a rule fires wrongly. That is worth more
than a feature request.

---

## r/androiddev

**A manifest auditor that reads the compiled format itself (no aapt, no JDK)**

Short version: point it at an APK or at `app/src/main/AndroidManifest.xml`, get a list of
components another app can reach without holding a permission, with the byte offset of the
attribute that proves it.

Things it catches that lint will not:

- `android:permission="android.permission.INTERNET"` as a guard on an exported component.
  Any app can request INTERNET and is granted at install — the guard is decorative.
- `android:permission="com.yourapp.SIG"` where no `<permission>` of that name exists. The
  platform ignores it and the component is open, while the manifest reads as protected.
- Two `<provider>` on one authority (module/plugin setups): one never installs, or one
  answers the other's queries.
- `grantUriPermissions="true"` plus `<path-permission path="/">`: a `content://` URI
  becomes a capability you can hand to another app.

Also: exported receivers with only system broadcasts (exporting them adds surface and
nothing else), `targetSdk < 31` keeping the permissive `exported` default, `allowBackup`
left on with no `dataExtractionRules`.

`manifestvet scan app/build/outputs/apk/release/app-release.apk --format sarif --fail-on high`
is the CI one-liner. Exit 0 clean, 1 findings at threshold, 2 unreadable input — the
distinction matters in a pre-commit hook.

---

## r/netsec

**manifestvet: an AXML reader and 40-rule manifest audit, written to be verifiable**

The interesting part for this subreddit is not the rule list, it is the format work:

- `ResXMLTree_attrExt.attributeStart` is relative to the attribute block, not the chunk.
  Read it from the chunk header and every element parses with zero attributes — a failure
  that looks like "the manifest is clean".
- the resource map alignment problem described above;
- `TYPE_INT_BOOLEAN` arrives as `0xFFFFFFFF`, not `"true"`. A reader that stringifies
  everything reports `debuggable="4294967295"` and every boolean rule dies quietly.

`docs/axml.md` has the struct layouts, the two alignment conventions, and the modified-UTF-8
string pool (u16 UTF-16 length then u8 byte length — confusing them truncates labels).

Validation: the reader is asserted against a real aapt2-compiled APK semantically (package,
`targetSdkVersion`, `debuggable`, provider `exported=false`, a `android.permission.DUMP`
guard), not just "it parsed".

---

## X / Twitter thread

1/ Android manifest checkers all wrap aapt. I wrote the reader instead — because in a
compiled manifest the attribute names don't exist: `android:exported` is `0x01010010`.

2/ The name comes from a resource map indexed against the string pool. Two alignments exist
in the wild. Pick wrong and every attribute is renamed to its neighbour — silently. Your
rules just stop firing.

3/ The test that discriminates: the pool string and the table name for the same index must
be the same word. aapt2: ~24 agreements one way, ~0 the other.

4/ So findings carry the byte offset of the node (or the exact attribute) and the line aapt
recorded. `manifestvet attrs` dumps the whole tree with offsets so you can check my work.

5/ 40 rules over what another app can reach. The ones that catch real bugs: a guard of
`android.permission.INTERNET`, a guard naming a permission nobody declares, duplicate
provider authorities, `grantUriPermissions` + `path="/"`.

6/ Zero dependencies, Python 3.10+, SARIF, 7 MCP tools. Same rules for APK and source XML —
a test asserts both paths give identical findings.

`uvx --from git+https://github.com/xuange-hu/manifestvet manifestvet demo`

---

## Where to post, and what to expect

| channel | audience | expected |
|---|---|---|
| Show HN | tool-hungry engineers | 1 good day of traffic if the title lands; comments are about the format work, not the rules |
| r/androiddev | app developers | most likely to convert to stars; lead with the `INTERNET` guard, not with AXML |
| r/netsec | security people | will ask for Java-level analysis; the honest answer is in the README's limitations |
| X | low conversion, but the thread is quotable | useful as a link target from the README |

Give each channel the angle it cares about. The AXML story is for HN and netsec; the
"your exported activity is guarded by INTERNET" story is for androiddev.
