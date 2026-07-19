# PMORG CE delivery profile

## Scope

The CE artifact is one supported delivery profile of PMORG, not the universal
product boundary and not a prerequisite for Semantic Core, contracts or the
Onyx-PMORG integration. A build declares exactly one profile: `ce` or
`licensed-ee`.

The reproducible source baseline is the mixed-source Onyx release `v4.3.9` at
commit `1da679cefc96165c6b9b64c3bc769584b88f88c2`. Source provenance is
separate from artifact contents.

## CE artifact rule

A `ce` image or package contains zero product files, imports or layers from:

```text
backend/ee/**
web/src/app/ee/**
web/src/ee/**
```

EE-specific test trees and dependency groups are excluded from CE
qualification. Their presence in the upstream checkout does not make the CE
artifact non-compliant; their presence in the saved artifact does.

## Licensed-EE sibling profile

A `licensed-ee` build may reuse required Onyx EE capability without
reimplementing it. It must inventory the exact capability, source paths,
dependencies and image provenance. EE source is never copied into PMORG-owned
modules. Commercial authorization is mandatory before any client deployment,
but is not a blocker for design or synthetic evaluation.

## Known upstream behavior

At the pinned release:

- `backend/Dockerfile` copies `backend/ee` into the backend image;
- `pyproject.toml` includes the `ee` dependency group among default groups;
- frontend EE directories are present in the source tree;
- the official `onyx-foss` mirror is rebuilt with rewritten history and is
  force-pushed without release tags.

The default upstream build is therefore not accepted as evidence for the
`ce` profile. PMORG uses dedicated definitions and explicit dependency
selection for that profile.

## CE qualification subset

The `A-LIC-001` and `A-UPSTREAM-001` subset remains pending until:

1. source tag, source commit, PMORG spec commit and profile are in the manifest;
2. backend and frontend CE artifacts build from clean state;
3. source, import, filesystem and layer scans report zero EE product files;
4. dependency export excludes the upstream EE group;
5. selected upstream tests pass on baseline and fork;
6. digests, SBOM and the CE boundary report are recorded.

This does not by itself claim full `G3-A` PASS. Full G3-A also requires patch
coverage, clean migrations, independent restore, supply-chain evidence and
vulnerability triage.

The official FOSS mirror is informative only, not the pinned baseline for
`RB-1/C2`.
