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
| PMORG specification | `RB-1/C2` | `05bc4df345d2d65e05b510135a4d99c9edbf886e` |

The PMORG pin is the final squash-merge commit of PR #5 on `PMORG/master`.
[`pmorg/baseline-manifest.json`](pmorg/baseline-manifest.json) is the
machine-readable bootstrap snapshot used by this repository; it is not a
second normative requirements source. If the snapshot and the pinned PMORG
commit disagree, the PMORG commit governs and the platform snapshot must be
regenerated and reviewed.

## Repository roles

- `upstream` points to the official `onyx-dot-app/onyx` repository;
- `origin` points to the private `bmvv1995/PMORG-Platform` repository;
- the separate PMORG repository owns requirements, contracts, evaluation and
  the SB3 executable reference baseline;
- this repository owns the Onyx-PMORG product implementation.

## Bootstrap invariants

- no PMORG domain behavior is added before upstream/spec inputs are recorded;
- a release-authority-signed `ReleaseBuildDefinitionPayload` fixes the
  specification/platform/Onyx pins, build recipe and inputs, expected artifact
  catalog, qualification policy map and runtime scope policy map before build;
- the detached `BuildQualificationManifest` binds the exact canonical artifact
  set, image lock, surface/mode axes, report payloads and byte-closed evidence
  indexes; a separate DSSE `BuildQualificationAttestation` binds that manifest
  to trusted time, revocation and bounded revalidation;
- `onyx_surface` and `usage_mode` are immutable build axes, not caller-selected
  runtime flags. The exhaustive matrix admits only `ce|ee + development_test`
  on an attested synthetic sandbox, `ce + production` on a client target with
  CE release authorization, and `ee + production` on a client target with
  Enterprise authorization. Opposite target/destination classes fail closed;
- deploy, startup and watchdog independently reconstruct the effective
  payload and target descriptors and verify measurement plus admission. A
  watchdog inherits the admitted parent operation and quiesces the workload
  and all organizational effects before a missed deadline;
- registry publish and artifact export use a separate distribution payload,
  destination measurement and admission. Active transfers inherit their
  parent operation, revalidate through commit and abort without visible
  partial bytes before expiry, redirect or destination drift;
- PMORG maps the complete applicable requirement set to exactly one
  `reuse|patch|pmorg_independent` disposition per capability. Candidate search
  and provenance use independently derived source-scope denominators pinned to
  the same BQM commits; adequate Onyx capability is reused by default and any
  deviation requires a temporally valid, signed ADR/waiver;
- `ce` contains zero EE files, imports, dependencies or layers; every `ee`
  build has a complete inventory. EE code is never copied into PMORG-owned
  modules;
- PMORG domain modules, rules and types exist only under PMORG-owned roots.
  Upstream files contain only minimal wiring in pre-authorized seams; every
  upstream modification is exact-once in the patch ledger and passes the seam
  allowlist plus ownership-boundary scan;
- every evidence, trust, authorization, receipt and report reference resolves
  to content-addressed bytes offline. Hashes do not self-authorize and evidence
  graphs are acyclic;
- a release claim requires the applicable `G3` gates from `RB-1/C2`, not
  merely a successful Onyx startup.

PR #17 is only Slice 0 governance. The contracts above are requirements for
later build and runtime slices; this branch has not emitted their canonical
artefacts and makes no `A-LIC-*`, `A-PATCH-*` or `G3-A` PASS claim.

See [the CE artifact qualification when `onyx_surface=ce`](pmorg/CE-BOUNDARY.md)
and [the patch ledger](pmorg/PATCH-LEDGER.md).
