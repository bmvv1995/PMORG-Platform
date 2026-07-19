# PMORG CE artifact qualification

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
  technically refuses production or distribution;
- `ee + production` requires signed commercial authorization bound to the
  artifact, client target, legal entity, seats/scope, agreement and validity;
- missing, expired, mismatched or untrusted admission fails closed at deploy
  and startup.

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

## CE qualification subset

The `A-LIC-001` and `A-UPSTREAM-001` subset remains pending until:

1. source tag, source commit, PMORG spec commit, `onyx_surface` and
   `usage_mode` are fixed in the signed build manifest;
2. backend and frontend CE artifacts build from clean state;
3. source, import, dependency, filesystem and layer scans report zero EE
   product content;
4. selected upstream tests pass on baseline and fork;
5. digests, SBOM and the CE boundary report are recorded.

This does not by itself claim full `G3-A` PASS. Full `G3-A` also requires
capability disposition, patch coverage, clean migrations, independent restore,
supply-chain evidence and vulnerability triage.

The official FOSS mirror is informative only, not the pinned baseline for
`RB-1/C2`.
