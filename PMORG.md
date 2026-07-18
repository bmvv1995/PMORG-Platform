# PMORG Platform

PMORG Platform is the V3 implementation repository defined by PMORG
requirements baseline `RB-1`. It is a governed fork of Onyx Community
Edition with Odoo as the operational domain anchor and PMORG Semantic Core as
a first-class bounded context.

This checkout is at bootstrap stage. It does not yet implement or claim
conformance with PMORG V3.

## Pinned inputs

| Input | Version | Commit |
|---|---|---|
| Onyx release | `v4.3.9` | `1da679cefc96165c6b9b64c3bc769584b88f88c2` |
| PMORG specification | `RB-1` | `618a5cf4fc604b687c18b41f6d085ec8a03bf4a8` |

The complete machine-readable record is
[`pmorg/baseline-manifest.json`](pmorg/baseline-manifest.json).

## Repository roles

- `upstream` points to the official `onyx-dot-app/onyx` repository.
- `origin` points to the private `bmvv1995/PMORG-Platform` repository;
- the separate PMORG repository owns requirements, contracts, evaluation and
  the SB3 executable reference baseline;
- this repository owns the Onyx-PMORG product implementation.

## Bootstrap invariants

- no PMORG domain behavior is added before the upstream baseline is recorded;
- product code from Onyx `ee` directories is excluded from PMORG CE build
  artifacts;
- every upstream-core modification is recorded in the patch ledger;
- PMORG domain code is kept separate from upstream code wherever a stable
  boundary exists;
- a release claim requires the applicable Gates from `RB-1`, not merely a
  successful Onyx startup.

See [the CE boundary](pmorg/CE-BOUNDARY.md) and
[the patch ledger](pmorg/PATCH-LEDGER.md).
