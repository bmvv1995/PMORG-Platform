# PMORG patch ledger

All differences from the pinned Onyx baseline are classified here. A patch is
not accepted merely because it is located under a PMORG-named directory.
The machine-readable source is
[`patch-ledger.json`](patch-ledger.json); this document explains its policy.

| ID | Area | Classification | Upstream files modified | Reason | Verification |
|---|---|---|---|---|---|
| `PL-000` | bootstrap governance | PMORG-owned | none | pin upstream/spec inputs and define the Onyx surface/usage-mode matrix | manifest and diff checks |
| `PL-001` | Codex project agents | PMORG-owned | none | define least-privilege roles for mapping, architecture review, tests and bounded implementation | TOML parse and fork consistency check |
| `PL-002` | V3 delivery plan | PMORG-owned | none | record the migration sequence and verification strategy before product implementation | fork consistency check |

## Classifications

- `PMORG-owned`: new PMORG files that do not alter upstream behavior;
- `integration`: narrow upstream change required to expose a stable PMORG
  boundary;
- `upstream-candidate`: generic fix intended to be proposed upstream;
- `temporary`: time-bounded patch with an owner and removal condition.

Every entry after `PL-000` must identify affected fork paths, the contract or
requirement it implements, and the tests that prevent drift. When upstream
files are modified, the entry must list them explicitly.
Every changed path must match exactly one ledger entry. Brackets in declared
paths are literal characters, including dynamic route segments.

## Thin-fork ownership boundary

PMORG modules, domain rules and domain types live exclusively under roots
declared PMORG-owned by the versioned boundary policy. Upstream-owned files may
contain only minimal integration wiring in a seam authorized before build.
Adding a seam requires an ADR, policy update and protector tests; a ledger note
written after the change cannot authorize it retroactively.

For every directly modified upstream path the release ledger records at least:

```text
path · base/patched blob hashes · upstream source ref
reason · owner · upstream issue/PR · requirement/capability
ownership_class · license_class · Onyx surface
seam ID · protector tests · last revalidation
conflict notes · removal condition when temporary
```

The boundary scan and ledger are evaluated over the exact diff from the pinned
Onyx commit. PASS requires each upstream path exactly once, every path inside
the seam allowlist, matching base/patched bytes and zero PMORG domain
semantics under upstream-owned roots. A direct CE patch remains
`upstream_ce_direct_patch + mit-expat`; a direct EE patch remains
`upstream_ee_direct_patch + onyx-enterprise` and cannot appear in a CE build.

The source ledger is an input, not release evidence by declaration. A release
emits a specialized `patch-ledger-report` extending `QualificationReport`,
bound to the BQM artifact set, Onyx commit, surface/mode, policy/tool/input
snapshots and a byte-closed evidence index. Its direct patch refs include exact
source refs, blob hashes, ownership/license and protector-test results.

Capability disposition and provenance consume the same records. Every
implementation path matches the final provenance inventory; `reuse` has no
patch refs, `patch` has an exact ledger owner, and `pmorg_independent` contains
only PMORG-owned paths. Any candidate, record, report or source scope from a
different spec/platform/Onyx commit, artifact set, surface or mode is invalid.

PR #17 currently contains only Slice 0 PMORG-owned governance paths and no
upstream modification. Its seam allowlist is empty, and the Slice 0 verifier
rejects every upstream-owned change even if a proposed seam or ledger record
is structurally complete. A later G3-A slice may admit a seam only after it
adds the canonical boundary/evidence validator and the associated negative
tests. Slice 0 defines these controls but has not emitted a
`patch-ledger-report`, capability/provenance bundle or `A-PATCH-*`/`G3-A` PASS
verdict.

Run the consistency check with:

```bash
python3 pmorg/scripts/verify_fork.py
```
