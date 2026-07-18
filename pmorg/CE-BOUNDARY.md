# PMORG CE boundary

## Decision

The reproducible source baseline is the official Onyx release `v4.3.9` at
commit `1da679cefc96165c6b9b64c3bc769584b88f88c2`.

That repository is mixed-source. Its root license identifies Onyx Enterprise
License content under `ee` directories and MIT-licensed content outside those
restrictions. PMORG therefore distinguishes source provenance from the
contents of a distributable CE artifact.

## Artifact rule

A PMORG MVP CE image or package must contain zero product files, imports or
layers sourced from these path families:

```text
backend/ee/**
web/src/app/ee/**
web/src/ee/**
```

EE-specific test trees and dependency groups are also excluded from the CE
qualification run. Their presence in the upstream source checkout is not
evidence that a PMORG artifact is CE-clean.

## Known upstream behavior

At the pinned release:

- `backend/Dockerfile` copies `backend/ee` into the backend image;
- `pyproject.toml` includes the `ee` dependency group among default groups;
- frontend EE directories are present in the source tree;
- the official `onyx-foss` mirror is rebuilt with rewritten history and is
  force-pushed without release tags.

The default upstream build is therefore not accepted as the PMORG CE build.
PMORG will use dedicated build definitions and explicit dependency groups.

## Qualification conditions

Gate A remains pending until all of the following are reproducible:

1. source tag, source commit and PMORG spec commit are present in the build
   manifest;
2. backend and frontend CE artifacts build from clean state;
3. an artifact and layer scan reports zero `ee` product files;
4. dependency export does not include the upstream `ee` group;
5. required upstream tests pass on the clean baseline and on the PMORG fork;
6. image digests, SBOM and the CE boundary report are recorded.

The official FOSS mirror is an informative comparison source, not the pinned
baseline for `RB-1`.
