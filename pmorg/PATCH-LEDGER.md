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
| `PL-004` | CI seam authorizations | PMORG-owned | none | pre-authorize exact Zizmor, Helm-generation and actionlint seams with byte-bound golden targets and distinguish active protectors from retired evidence | fork consistency, fixture binding, protector lifecycle and active-suite discovery proof |
| `PL-005` | Zizmor private-repository seam | integration | `.github/workflows/zizmor.yml` | preserve fail-closed scanning while making SARIF publication an explicit private-repository opt-in | exact protector selector and fork consistency check |
| `PL-007` | Helm static ephemeral lane successor | integration | `.github/workflows/pr-helm-chart-testing.yml` | preserve fail-closed Helm validation while replacing per-run dynamic dispatch with a static, manually started ephemeral lane | exact protector selector and fork consistency check |
| `PL-008` | actionlint Helm lane catalog seam | integration | `.github/actionlint.yml` | declare the byte-exact `helm-lane` runner label required by the static Helm lane | exact protector selector and fork consistency check |

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

Protector tests for a future upstream seam are authorization locks, not global
pre-patch regression tests. They land on protected `main` before the seam and
must fail against the unmodified upstream bytes. The global governance suite
runs only `pmorg.tests.test_verify_fork`; once a concrete seam is admitted, the
verifier loads each byte-bound protector selector only from the trusted base
and executes it exactly once against candidate data. Candidate test modules
are parsed and hash-checked but never imported. This red-before-patch lifecycle
prevents a prospective test from silently authorizing bytes it cannot
distinguish or from becoming executable input to a privileged PR inspection.

Package-aware test discovery is documented in
[`ACTIVE-TEST-SUITE.md`](ACTIVE-TEST-SUITE.md). Its data-derived hook runs every
ordinary PMORG test and every active seam protector while retaining, but not
executing, immutable protector evidence for superseded seams. The hook's exact
active and retired sets and its failure propagation are themselves tested.

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

A same-path revision is a successor generation, never a mutation or generic
waiver. Its dormant
`pmorg.platform.seam-successor-authorization/v1` decision must land before the
activation and bind the exact predecessor seam, patch record, ledger owner,
authorization bytes, patched bytes and Git mode, plus distinct successor
seam/record/owner IDs and the byte-exact target. The later activation commit
must be the direct child of that protected base and atomically replace the
active seam, record, owner and path bytes. The canonical `base_blob_hash`,
upstream source, ownership, license and Onyx surfaces remain anchored to the
pinned Onyx tree; predecessor PMORG bytes cannot be laundered into a new
upstream base. Full Git history must reconstruct one immutable, non-forking
generation chain with exactly one active endpoint per path. Retired ADRs and
protector bytes remain byte- and mode-identical in every committed descendant,
while only the active generation's trusted protector executes against a
candidate.

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
governance slice activated the versioned, default-deny admission validator
while keeping its concrete seam and record sets empty. A later protected base
then landed ADR-0002/ADR-0003, immutable protector bytes and byte-exact golden
targets before this atomic bootstrap admitted exactly two CI seams and their
v2 records. Any additional upstream path still requires its own explicit seam,
exact record, safe pre-existing accepted ADR and protector references, matching
base/patched bytes and modes and valid ownership/license/surface disposition.
PMORG-prefixed directories remain forbidden below upstream-owned roots.

These CI admissions do not emit a `patch-ledger-report`,
capability/provenance bundle or `A-PATCH-*`/`G3-A` PASS verdict. The product
baseline remains `not_yet_qualified`.

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

The exact PMORG-owned path `.github/workflows/pmorg-governance.yml` obtains this
value from a `pull_request_target` event. It runs from the exact base checkout,
binds a separate candidate checkout to the event base/head/test-merge SHAs and
invokes the trusted verifier against that candidate without executing
candidate Python. Trusted unit tests run only from the base checkout. Active
byte-bound protectors are loaded from that same trusted base; prospective
red-before-patch protectors are not swept into global discovery before their
seam is active. A locally supplied value remains diagnostic only and is not
merge evidence. The inspection rejects a new seam when unrelated feature
commits sit between its stored base and its introduction; this keeps the
post-merge Git proof valid for squash, rebase or merge-commit strategies.

The current private-repository GitHub plan provides neither branch protection
nor rulesets, so this workflow cannot itself prevent a direct push or an owner
override and its `push` event is only a best-effort self-audit using the
just-pushed bytes. Until enforced PR-only writes and an independently required
check are available, exact-tree review
and the controlled owner merge remain the operational trust anchor. The
repository must not present the check as an enforced release gate. Likewise,
`merge_group` admission is deliberately deferred until a ruleset, organization
required workflow or external GitHub App can protect the evaluator source and
bind its result to the actual merge-group tree. This platform prerequisite is
tracked in [issue #24](https://github.com/bmvv1995/PMORG-Platform/issues/24).

On `origin/main`, the verifier instead proves each immutable seam's first
introduction parent from Git history. The concrete allowlist and upstream
patch-record set contain only the three active CI seams documented above:
Zizmor, the second Helm generation and the actionlint runner-label catalog.
They imply no authorization for product or additional upstream paths. Dormant
successor and new-path decisions under `pmorg/adr/**` authorize no executable
change by themselves; they become effective only through a later protected
atomic activation satisfying the policy above.
