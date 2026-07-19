# ADR-0001 — Governed integration admission

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-07-19 |
| Scope | PMORG-Platform source governance only |

## Context

Slice 0 correctly rejected every upstream-owned change. Later slices need a
way to add narrow Onyx wiring without weakening the thin-fork boundary or
turning a ledger declaration into authorization.

## Decision

The ownership policy reserves `backend/pmorg/**` and `web/src/pmorg/**` for
future PMORG-owned product code. Everything else continues to default to
upstream-owned, and the seam policy continues to default to deny.

An upstream-owned path may be admitted only when it matches exactly one
explicit, non-wildcard seam and exactly one patch-ledger v2 record. The seam
must reference a safe, existing, accepted machine-readable authorization and
safe, existing protector tests. The record must bind the exact upstream and
patched bytes, Git regular-file modes, canonical upstream tree digest,
official source reference, requirements or capabilities, ownership, license,
Onyx surface, protector tests, revalidation and removal semantics. Paths with
a PMORG-prefixed component remain forbidden below upstream-owned roots.

A concrete seam uses two protected changes:

1. An authorization change adds an accepted
   `pmorg.platform.seam-authorization/v1` JSON decision and its Python
   protector tests, then lands on `main`.
2. A later patch change, based on that protected commit, adds the immutable
   seam entry, exact patch record, exact ledger owner and upstream bytes/mode
   in one atomic seam commit whose parent is that base. CI supplies the exact
   trusted PR base as `PMORG_PROTECTED_BASE_SHA`.

When separately installed, the PMORG governance workflow derives that value
from the GitHub PR or merge-queue event. It runs only the verifier's own unit
suite globally; the verifier executes exact active protector selectors so a
prospective red-before-patch protector can first land dormant on protected
`main`. A developer-provided local value can aid diagnosis but is not trusted
merge evidence. This mechanism-only change reserves the workflow path but does
not install or claim execution of that future gate.

The seam binds the authorization commit, protected base, authorization bytes,
allowed classifications and protector-test bytes. A new seam must use and be
introduced atomically on the exact protected base; an existing unchanged seam
remains valid when that base becomes an ancestor of later protected bases.
Changing an admitted seam or its bound authorization/tests requires a new
authorization and a new seam ID.
Slice 0.1 accepts only byte-bound `unittest.TestCase` protector methods under
`pmorg/tests/test_*.py`. The gate runs every bound selector explicitly and
requires exactly one execution with no failure, error, skip, expected failure
or unexpected success.

The current allowlist and upstream patch-record set remain empty. This ADR
authorizes the admission mechanism, not a concrete seam.

## Consequences

- A later seam requires its own accepted ADR, policy entry, exact record and
  tests in the protected two-change sequence before the upstream modification
  can pass verification.
- Missing, duplicate, broad, dangling, mismatched or mislicensed declarations
  fail closed.
- The automated PMORG-domain check is deliberately lexical. It prevents a
  PMORG-named package from crossing the ownership boundary; exact-diff review
  and later canonical patch evidence must still establish that upstream code
  contains only minimal integration wiring.
- This transition emits no release evidence, changes no runtime behavior and
  makes no qualification, admission, `A-PATCH-*` or `G3-A` claim.
