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
| `PL-003` | governed integration admission decision | PMORG-owned | none | record the decision to replace the Slice 0 hard freeze with versioned, default-deny admission prerequisites without authorizing a seam; `PL-000` owns the policy, verifier and tests | fork policy and negative tests |

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
contain only reviewed minimal integration wiring in a seam authorized before
the patch. The automated domain guard is lexical: it rejects PMORG-prefixed
path components under upstream-owned roots, while exact-diff review and later
canonical patch evidence establish the content boundary. It does not claim to
infer domain semantics from arbitrary source text.

Adding a concrete seam is a two-change protected workflow. First, an accepted
`pmorg.platform.seam-authorization/v1` JSON decision and its Python protector
tests land on `main`. Protectors are byte-bound `unittest.TestCase` methods
under `pmorg/tests/test_*.py`; the gate runs each exact selector and requires
one execution with no failure, error, skip, expected failure or unexpected
success. A later PR based on that protected commit may add the immutable seam
entry, exact record, exact ledger owner and upstream bytes/mode as one atomic
seam commit whose parent is the protected base. CI passes that exact base
commit through `PMORG_PROTECTED_BASE_SHA`; the seam binds the
authorization/base commits plus the byte hashes of the decision and protector
tests. A ledger note written in the patch PR cannot authorize it retroactively.
Changing a landed seam or its bound evidence requires a new authorization and
new seam ID.

For every directly modified upstream path the release ledger records at least:

```text
path · base/patched blob hashes and Git modes · upstream source ref/tree digest
reason · owner · upstream issue/PR · requirement/capability
ownership_class · license_class · Onyx surface
seam ID · protector tests · last revalidation
conflict notes · removal condition when temporary
```

The boundary scan and ledger are evaluated over the exact diff from the pinned
Onyx commit. PASS requires each upstream path exactly once, every path inside
the seam allowlist, matching base/patched bytes and regular-file modes, a
canonical pinned-tree digest and no PMORG-prefixed path components under
upstream-owned roots. A direct CE patch remains
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

Slice 0 was merged with zero upstream modifications. The first successor
governance slice keeps the concrete seam allowlist and upstream patch-record
set empty while activating a versioned, default-deny admission validator. A
future upstream path must have exactly one explicit seam, one exact v2 record,
a safe existing accepted ADR, safe existing protector-test references, matching
base/patched bytes and modes and valid ownership/license/surface disposition.
The authorization must already exist on the exact protected PR base; the
concrete seam and patch cannot be introduced together. PMORG-prefixed
directories remain forbidden below upstream-owned roots.

This mechanism does not itself authorize a seam and has not emitted a
`patch-ledger-report`, capability/provenance bundle or `A-PATCH-*`/`G3-A` PASS
verdict. The baseline remains `not_yet_qualified`.

Run the consistency check with:

```bash
python3 pmorg/scripts/verify_fork.py
```

On a PR that contains or preserves concrete seams, CI must bind validation to
the trusted protected base:

```bash
PMORG_PROTECTED_BASE_SHA=<exact-protected-base-commit> \
  python3 pmorg/scripts/verify_fork.py
```

The exact PMORG-owned path `.github/workflows/pmorg-governance.yml` is reserved
for the gate that will supply this value from the GitHub pull-request or
merge-queue event, check full Git history, run the verifier and then run only
`pmorg.tests.test_verify_fork`. Active byte-bound protectors are executed by
the verifier itself; prospective red-before-patch protectors must not be swept
into global discovery before their seam is active. The workflow is deliberately
not installed by this mechanism-only change. Its later CI-bootstrap change must
be separately reviewed and admitted without claiming a check that never ran.
A locally supplied value is diagnostic only and is not merge evidence. The
future gate rejects a new seam when unrelated feature commits sit between its
stored protected base and its introduction; this keeps the post-merge Git proof
valid for squash, rebase or merge-commit strategies.

On `origin/main`, the verifier instead proves each immutable seam's first
introduction parent from Git history. The concrete allowlist and upstream
patch-record set are empty in this slice, so no authorization is implied.
