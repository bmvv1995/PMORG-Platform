# PMORG Platform

PMORG Platform is the V3 implementation repository defined by PMORG
requirements baseline `RB-1/C2`. It is a governed fork of Onyx with Odoo as
the operational domain anchor and PMORG Semantic Core as a first-class bounded
context. Every build declares two independent axes:
`onyx_surface: ce|ee` and `usage_mode: development_test|production`.

This checkout is at bootstrap stage. It does not yet implement or claim
conformance with PMORG V3.

## Pinned inputs

| Input | Version | Commit |
|---|---|---|
| Onyx release | `v4.3.9` | `1da679cefc96165c6b9b64c3bc769584b88f88c2` |
| PMORG specification candidate | `RB-1/C2` | `a90e56408cc4a884fc246c19d82c69f13d549e8d` |

The PMORG pin is the current accepted candidate from PR #5 and must be replaced
with that PR's final merge commit before PR #17 leaves draft. The complete
machine-readable record is
[`pmorg/baseline-manifest.json`](pmorg/baseline-manifest.json).

## Repository roles

- `upstream` points to the official `onyx-dot-app/onyx` repository;
- `origin` points to the private `bmvv1995/PMORG-Platform` repository;
- the separate PMORG repository owns requirements, contracts, evaluation and
  the SB3 executable reference baseline;
- this repository owns the Onyx-PMORG product implementation.

## Bootstrap invariants

- no PMORG domain behavior is added before upstream/spec inputs are recorded;
- the build manifest fixes both Onyx axes; they are not free runtime flags;
- `ce` excludes EE; every `ee` build has complete inventory;
  `ee + development_test` refuses production/distribution and
  `ee + production` requires signed authorization bound to build and target;
- PMORG maps every required capability to
  `reuse|patch|pmorg_independent`, reuses adequate Onyx capabilities by
  default, and never copies EE source into PMORG-owned modules;
- every upstream-core modification is recorded in the patch ledger;
- PMORG domain code is kept separate from upstream code wherever a stable
  boundary exists;
- a release claim requires the applicable `G3` gates from `RB-1/C2`, not
  merely a successful Onyx startup.

See [the CE artifact qualification when `onyx_surface=ce`](pmorg/CE-BOUNDARY.md)
and [the patch ledger](pmorg/PATCH-LEDGER.md).
