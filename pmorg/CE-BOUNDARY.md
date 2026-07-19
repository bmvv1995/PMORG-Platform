# PMORG CE artifact qualification

## Current status

PR #17 is Slice 0 governance only. It records the matrix and the evidence
contract but does not build a CE artifact, emit a canonical qualification
bundle, authorize deployment/distribution or claim `G3-A` PASS.

## Scope

`ce` is one allowed value of `onyx_surface`, not a universal product
boundary and not a prerequisite for Semantic Core, contracts or Onyx-PMORG
integration. Every build declares both `onyx_surface: ce|ee` and
`usage_mode: development_test|production`.

The reproducible source baseline is the mixed-source Onyx release `v4.3.9` at
commit `1da679cefc96165c6b9b64c3bc769584b88f88c2`. Source provenance is
separate from artifact contents.

## CE artifact rule

An artifact with `onyx_surface=ce` contains zero product files, imports,
dependencies or saved image layers from:

```text
backend/ee/**
web/src/app/ee/**
web/src/ee/**
```

EE-specific test trees and dependency groups are excluded from CE
qualification. Their presence in the upstream checkout does not make the CE
artifact non-compliant; their presence in the saved artifact does.

## EE surface disposition

Every `onyx_surface=ee` build inventories the exact capabilities, source
paths, dependencies, patches and image layers it uses. EE source remains in
upstream paths and is never copied into PMORG-owned modules.

- `ee + development_test` requires signed synthetic-environment admission and
  permits distribution only to a controlled synthetic registry/export target;
- `ee + production` requires signed commercial authorization bound to the
  artifact, client target/destination, legal entity, seats/scope, agreement and
  validity;
- missing, expired, mismatched or untrusted admission fails closed at deploy
  and startup, watchdog, publish/export and transfer revalidation.

## Exhaustive surface/mode matrix

| Surface | Mode | Admitted runtime target | Admitted distribution target | Required basis |
|---|---|---|---|---|
| `ce` | `development_test` | attested synthetic sandbox | controlled synthetic registry/export | synthetic-environment measurement |
| `ee` | `development_test` | attested synthetic sandbox | controlled synthetic registry/export | synthetic measurement plus complete EE inventory |
| `ce` | `production` | client | client destination | CE release authorization |
| `ee` | `production` | client | client destination | Enterprise authorization bound to entity, seats/scope and agreement |

Both `development_test + client` combinations and both
`production + synthetic` combinations are explicit denials. Contract tests may
simulate every cell only with synthetic fixtures and credentials; no production
endpoint, data, identity, channel or authorization is used as test evidence.

## Known upstream behavior

At the pinned release:

- `backend/Dockerfile` copies `backend/ee` into the backend image;
- `pyproject.toml` includes the `ee` dependency group among default groups;
- frontend EE directories are present in the source tree;
- the official `onyx-foss` mirror is rebuilt with rewritten history and is
  force-pushed without release tags.

The default upstream build is therefore not accepted as evidence for
`onyx_surface=ce`. PMORG uses dedicated definitions and explicit dependency
selection for that surface.

## Qualification and evidence chain

A CE boundary scan is one specialized qualification report, not a build
attestation by itself. `A-LIC-001` remains pending until the release candidate
materializes the complete `RB-1/C2` chain:

1. an externally authorized, DSSE-signed `ReleaseBuildDefinitionPayload` fixes
   the baseline/spec/platform/Onyx commits, `onyx_surface=ce`, allowed usage
   modes, build recipe/input set, expected artifact catalog, qualification
   policy map and runtime scope policy map before build;
2. the `RuntimeScopePolicyMap` has exactly one unique entry for
   `deployment_runtime`, `registry_publish` and `artifact_export`, with the
   same baseline and surface as the release definition and BQM;
3. `BuildQualificationManifest` contains the exact expected/observed artifact
   set, image lock and required report hashes with zero
   missing/unexpected/duplicate artefacts. Its qualification bundle contains
   every required role, including CE boundary, SBOM, license, patch ledger,
   capability disposition, provenance, vulnerability and upstream-test bytes;
4. every evidence reference carries logical name, media type, digest, size and
   bundle-relative path. Indexes are canonical, exact, offline-resolvable and
   acyclic; an URI, tag, boolean or report digest without bytes is not evidence;
5. the detached DSSE `BuildQualificationAttestation` binds the BQM and artifact
   set to accepted verification material, revocation evidence, trusted-time
   receipt, validity window and revalidation deadline;
6. two clean builds from identical input snapshots reproduce ordered artifact
   descriptors, artifact-set/image-lock, qualification-bundle and report
   payload hashes. Only attestation/execution envelopes, receipts and temporal
   windows may differ.

The CE boundary report therefore extends the common `QualificationReport`
envelope and is bound to the BQM artifact set, Onyx commit, surface, mode,
policy/tool/input snapshots and its own byte-closed evidence bundle.

## Runtime and distribution admission

Qualification does not authorize use. Deploy, startup and watchdog each
reconstruct the actual runtime payload and target descriptor/fingerprint from
trusted OCI/runtime APIs and bytes, validate target measurement plus
`DeploymentAdmissionRecord`, trusted time and revocation, and quiesce before a
missed deadline. Watchdog revalidation inherits `deploy|startup`; it cannot
select another scope or authorization operation.

Registry publish and artifact export reconstruct the exact distributed subset
and destination descriptor/fingerprint, validate separate measurement plus
`DistributionAdmissionRecord` before the first byte and again after
authentication/redirect changes. Transfer revalidation inherits
`registry_publish|artifact_export`; drift, expiry or a deadline crossing aborts
the transfer without making partial bytes visible.

## Capability and provenance closure

The capability catalog covers exactly the requirements applicable to the
release. Candidate search uses independently derived CE/EE source scopes at the
BQM Onyx commit; every capability has exactly one disposition record and an
adequate Onyx candidate is reused by default. `patch` or
`pmorg_independent` in its presence requires a DSSE ADR/waiver bound to the
same build, candidates and implementation, with trusted time and expiry.

Provenance scans complete PMORG-owned and EE denominators at the BQM
PMORG-Platform/Onyx commits. Raw and classified matches are bijective;
`licensed_patch` is valid only for a direct EE patch with Enterprise ownership
and exact ledger owner, never for an EE copy under a PMORG-owned path.

Full `G3-A` additionally requires exact patch coverage, migrations and
independent restores, supply-chain evidence and vulnerability triage. A local
CE scan or successful Onyx startup cannot produce that verdict.

The official FOSS mirror is informative only, not the pinned baseline for
`RB-1/C2`.
