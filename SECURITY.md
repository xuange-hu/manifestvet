# Security policy

## Scope

`manifestvet` reads untrusted files (`AndroidManifest.xml`, `.apk` archives). That makes
the parser itself part of the attack surface: a crafted manifest must not be able to crash
a CI job into an unbounded loop, allocate GBs, or execute anything.

What is in scope:

- a manifest or archive that crashes the tool, hangs it, or makes it allocate without bound;
- a manifest that makes the tool report *fewer* findings than it should (a parsing bug that
  silently drops components is a security bug, not a quality issue);
- a finding that is wrong in a way that could make a reader ship a vulnerable app.

What is not in scope:

- rules that fire on a pattern you consider acceptable — that is a discussion, open an issue;
- the absence of a rule you would like (a PR with a sample manifest is welcome);
- anything that requires running the analysed app.

## Reporting

Open a private security advisory on GitHub (`Security` → `Advisories` → `New draft
advisory`). Please include the manifest bytes or a minimal reproducer; the repo's own
writer (`manifestvet.axmlwrite`) can produce a compiled sample from text, which is the
fastest way to hand over a case.

Expect an initial response within a week. This is a single-maintainer project, not a
product with an SLA.

## Supported versions

The latest release. The format is a decade-stable ABI; old releases will be told to
upgrade rather than patched.
