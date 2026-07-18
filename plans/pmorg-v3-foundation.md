# PMORG V3 foundation and migration plan

## Issues to Address

PMORG Platform is currently a governed Onyx Community Edition bootstrap. It
does not yet implement the `RB-1` product contract. The implementation must add
PMORG as a first-class product subsystem without turning Onyx, Odoo, the
Semantic Ledger, or the orchestrator into competing sources of truth.

The foundation must address these problems before product-level features are
added:

- materialize `pmorg-contracts/1.0` as strict, versioned, content-addressed
  contracts;
- establish a PMORG package boundary that does not depend on Onyx, Odoo, or
  Hermes in its domain layer;
- keep Odoo as the formal operational source of truth and `project.task` as
  the canonical work registry;
- create the Semantic Core as an authoritative bounded context with its own
  database, migrations, role, backup, and lifecycle;
- ensure every PMORG turn enters through one authenticated Turn Coordinator;
- prevent the generic Onyx chat/tool loop from executing Odoo mutations;
- port SB3 behavior and tests selectively without treating SB3 schemas or
  deployment topology as V3;
- maintain a thin, auditable Onyx fork and a reproducible CE artifact;
- preserve the zero-production-testing boundary throughout evaluation.

## Important Notes

### Normative inputs

- PMORG requirements: `RB-1`, commit
  `618a5cf4fc604b687c18b41f6d085ec8a03bf4a8`.
- Onyx baseline: `v4.3.9`, commit
  `1da679cefc96165c6b9b64c3bc769584b88f88c2`.
- The requirements repository owns specifications, evaluation assets, and
  V1/V2/SB3 references.
- This repository owns the V3 implementation and preserves Onyx history.

### Architecture boundaries

- `backend/pmorg/domain` must not import `onyx`, Odoo clients, Hermes clients,
  FastAPI, persistence models, or transport implementations.
- `backend/pmorg/application` owns use cases and ports.
- `backend/pmorg/interaction` owns the Turn Coordinator.
- `backend/pmorg/integrations` owns Onyx, Odoo, Hermes, and gateway adapters.
- `services/semantic-core` is independently deployable and owns the Semantic
  Ledger schema and migrations.
- Onyx knowledge, vector search, and KG are reconstructible projections. They
  are never the organizational ledger.
- Onyx personal memory is disabled for PMORG agents until a separate scope
  policy exists.
- The Onyx tenant identifier is not a substitute for `OrganizationContext`.
- MCP exposes Semantic Core externally but is not used as an internal HTTP
  loopback between modules in the same process.

### SB3 migration posture

SB3 is an executable reference, not a production foundation. Its source files
match PMORG commit `618a5cf` byte-for-byte for the shared AIPM, memory, Odoo,
runner, profiles, and worldgen assets. Port behavior through contract tests.

Reuse or adapt:

- initiative and task lifecycle concepts;
- `project.task` extensions;
- identity, criteria, trusted clock, lease, and outbox concepts;
- deterministic runner and simulated channel;
- three organization profiles, worldgen, and longitudinal scenarios;
- negative tests for identity, anti-poisoning, replay, and forbidden writes.

Reimplement:

- `OrganizationContext`, live capability registry, and full anchor identity;
- authenticated Odoo command envelopes;
- request-hash idempotency and complete optimistic concurrency;
- multi-company and cross-organization authorization;
- Evidence/Claim/Assessment/Contradiction/Supersession persistence;
- standard MCP and the V3 evaluation kernel.

Do not port:

- the AIPM UI, generic RAG/embedding wrappers, or in-memory sessions;
- static registry fallbacks;
- the custom JSON-RPC service described as MCP;
- the SB3 compose topology or mutable image tags;
- Hermes Kanban as another work registry.

### CE experiment disposition

The earlier local CE experiment remains outside this branch. Re-evaluate and
port only:

- dedicated CE Docker build definitions;
- explicit dependency-group selection;
- artifact/layer boundary scanning and its negative tests;
- reproducible image and manifest checks.

Do not port the broad removals from Onyx backend/frontend. The CE requirement
is an artifact boundary, not permission to rewrite unrelated Onyx behavior.
Only imports that actually prevent an EE-free artifact may receive narrow,
tested seams.

## Implementation Strategy

### Slice 0 — governed baseline

Status: complete on branch `v3-foundation`.

- isolate a clean worktree from the abandoned CE experiment;
- record project-scoped agent roles;
- keep every fork change covered by the patch ledger;
- require `verify_fork.py` to pass before and after every slice.

### Slice 1 — Gate A CE artifact qualification

- build dedicated backend and frontend CE artifacts from the pinned upstream
  source without copying the Onyx `ee` path families;
- select dependency groups explicitly instead of changing general development
  defaults or deleting Enterprise source from the checkout;
- port the source/import/layer scanner and its negative fixtures from the
  isolated CE experiment;
- replace only the minimum frontend imports that make an EE-free build
  impossible; every upstream edit requires a patch-ledger entry and a
  protector test;
- run the selected unmodified upstream suites on the clean baseline and on the
  fork;
- record image digests, SBOM, dependency export, license report, source
  manifest, CE boundary report, and any versioned test waiver;
- prove that no Enterprise product file, import, dependency group, or historical
  image layer exists in the qualified artifacts.

This slice establishes the distributable substrate. It does not disable or
rewrite unrelated Onyx behavior in the source checkout.

### Slice 2 — complete contract spine

- add top-level `backend/pmorg` package boundaries;
- implement all contracts frozen by `pmorg-contracts/1.0`, including their
  nested types and command payload schemas required by later slices;
- generate committed JSON Schema with write contracts using
  `additionalProperties: false`;
- generate a deterministic contract manifest containing every schema digest
  and the pinned PMORG specification commit;
- add drift checks between Pydantic models, JSON Schema, examples, and the
  manifest;
- enforce that the domain package has no forbidden infrastructure imports.

Implementation may use several small commits, but no partial group is
published or described as `pmorg-contracts/1.0`. No API, database, Odoo call,
LLM call, or UI is part of this slice.

### Slice 3 — public evaluation inputs and oracle boundary

- port the three public organization manifests before Odoo profile tests use
  them;
- materialize versioned module/anchor-pack expectations, logical IDs, policy
  references, public fixtures, and `world.lock` inputs;
- create the private-oracle interface and network/credential boundary without
  exposing its data to SUT;
- define canonical example payloads shared by contract, Odoo, Semantic Core,
  runner, and independent-client tests;
- generate the initial run-bundle manifest with pinned spec/build/profile
  inputs, without claiming a product gate verdict.

### Slice 4 — Semantic Core evidence kernel

- create an independently deployable Semantic Core service and database;
- add its own SQLAlchemy metadata, Alembic tree, database role, credentials,
  backup path, and configuration;
- implement service-to-service authentication and scopes; bind the presented
  `OrganizationContext` to the authenticated caller and Odoo-owned identity
  mapping instead of trusting payload fields;
- implement registry negotiation and immutable evidence capture;
- persist evidence payload bytes in a scoped object store or content-addressed
  resolver, verify their hash before ledger insertion, and apply explicit ACL,
  retention, redaction, and secret-rejection rules;
- persist request hash and return the original receipt on a valid replay;
- reject an idempotency key reused with a different request hash;
- enforce organization/company scope before reads or writes;
- expose the same application services through an internal API and a
  standards-compliant MCP server;
- prove that deleting a search projection cannot delete evidence or payloads.

### Slice 5 — complete Semantic Core lifecycle

- implement claim proposal, assessments, authority validation, and independent
  validator rules;
- implement valid time versus recorded time, contradiction, dispute,
  supersession, and immutable history;
- implement commitments and outcomes as semantic objects linked to formal Odoo
  bindings without copying formal state;
- implement deterministic recall, `as_of`, and timeline queries filtered by
  organization, company, ACL, registry, time, and status before ranking;
- create reconstructible Onyx search/KG projections and prove ledger survival
  and equivalent projection hashes after rebuild;
- complete internal API and MCP operations for the frozen semantic contract.

### Slice 6 — Odoo control-plane foundation

- port and adapt the minimal `pmorg_core` addon under `odoo/addons`;
- install with Project only, without HR or Inventory;
- use the public profile manifests from Slice 3 to qualify all three clean
  module combinations and exact registry snapshots;
- implement Odoo-owned organization and identity bindings, initiative,
  criteria, task orchestration fields, state version, trusted clock, command
  inbox, and transactional outbox;
- publish a live, versioned capability registry from active modules, approved
  anchor packs, company, ACL, and policy;
- implement full `AnchorReference` resolution with instance, company, ACL,
  registry fingerprint, and observed record version;
- forbid generic model/method/values and SQL/ORM endpoints.

### Slice 7 — Odoo longitudinal domain and controllers

- implement immutable plan versions, commitments, approvals, outcomes, and
  outcome verification;
- implement wait conditions, `next_check_at`, intervention/escalation records,
  monitoring/autonomy policies, health flags, and controller checkpoints;
- implement the frozen initiative, task, run/lease, plan, commitment, approval,
  and outcome state transitions with optimistic concurrency on every mutation;
- ensure each deterministic controller performs at most one idempotent step,
  persists its next check, and can resume under a new runtime;
- qualify manual Odoo changes, expired leases, late results, and transactional
  inbox/outbox reconciliation.

### Slice 8 — authenticated read-only PMORG turn

- add one `/pmorg/v1` router seam to Onyx;
- resolve an authenticated Onyx user through an Odoo-owned binding to
  `pmorg.identity`;
- mark PMORG agents/personas explicitly and refuse their execution through the
  generic `/send-chat-message` route; UI and future gateway paths must invoke
  the same Turn API;
- validate `OrganizationContext` and the live Odoo registry before retrieval;
- capture inbound content as evidence before cognitive execution;
- call Onyx cognitive runtime through a bounded adapter with personal memory
  disabled and only read/proposal tools exposed;
- restrict MVP knowledge retrieval to a synthetic, uniform-access corpus until
  permission-aware retrieval is independently qualified;
- return a `CognitiveStepResult`; treat all model output as proposals or
  evidence, never as truth or an executed effect;
- persist any returned proposal through the complete Semantic Core lifecycle;
- add a minimal authenticated `/pmorg` workspace showing context, evidence
  receipt, bounded result, and provenance.

### Slice 9 — first controlled Odoo effect

- implement only `pmorg.task.propose` first;
- perform deterministic tool preflight outside the model loop;
- require the appropriate autonomy/approval result;
- validate expected version, lease where applicable, payload schema, actor,
  company, registry, and command-bound approval;
- write business state, receipt, and outbox event atomically;
- prove duplicate delivery and retry do not duplicate the task.

### Slice 10 — M0 structural path

- port the deterministic runner and simulated channel to V3 contracts;
- create the public XNX fixture from clean Odoo volumes;
- complete initiative → clarification → evidence → validated claim → controlled
  task → evidence → verified outcome;
- reconstruct the full timeline from Odoo and Semantic Core records;
- run three identical clean executions for `ORG-DIST`.

### Slice 11 — profile and longitudinal qualification

- execute the already-materialized profiles using the same qualified build;
- qualify absent-module closed-world behavior;
- add virtual-time silence, follow-up, escalation, restart, lease expiry,
  delayed response, replay, contradiction, supersession, optimistic conflict,
  service outage, recovery, and final closure;
- replace the V2 kernel with sealed V3 run bundles and Gates A–F verdicts.

Hermes, a stochastic operator, and a real communication channel remain Gates
G–I. They do not change the contracts or ownership established above.

## Tests

### Every slice

- `python3 pmorg/scripts/verify_fork.py`;
- `git diff --check`;
- targeted Ruff and type checks for changed Python packages;
- patch-ledger coverage for every path changed from upstream.

### CE artifact qualification

- clean backend and frontend builds with explicit non-EE dependency groups;
- source, import graph, filesystem, and every saved-image-layer scan;
- negative fixtures that inject forbidden files, imports, dependencies, and
  historical layers;
- selected upstream unit/type/build suites before and after the minimum seams;
- SBOM, digest, license, vulnerability, and patch-ledger reports.

### Contract spine

- valid canonical examples for every schema;
- refusal of unknown write fields and unknown major versions;
- invalid UUID, int64, semver, hash, timestamp, and URI cases;
- required nullable keys distinguished from absent keys;
- schema generation and digest determinism;
- no forbidden imports from the domain package.

### Semantic Core

- evidence replay and idempotency conflict;
- evidence without valid context or hash refusal;
- cross-organization and cross-company negative tests;
- service impersonation, invalid credential/scope, and context-binding tests;
- payload hash verification, retention, redaction, and secret-rejection tests;
- temporal and immutable-field behavior;
- claim authority, independent validation, contradiction, supersession,
  commitment, outcome, recall, and timeline tests;
- independent migration, restore, and index rebuild tests;
- MCP interoperability using a client independent of the server internals.

### Odoo control plane

- clean install for all three module profiles;
- exact registry snapshots and absent-module negative cases;
- anchor resolution, stale record, ACL, company, and fingerprint cases;
- one-winner lease races, stale-version conflicts, and 1,000 replayed commands;
- atomic business effect, receipt, and outbox under injected failures.

### Turn and controlled effect

- anonymous and unbound identities refused;
- PMORG agents refused through generic Onyx chat and accepted only through the
  Turn API;
- evidence committed before cognitive execution;
- personal Onyx memory not injected;
- no mutating Odoo tool exposed to the model loop;
- prompt injection cannot expand tools, anchor types, autonomy, or scope;
- unauthorized retrieval is refused before any LLM call;
- cross-organization and cross-company knowledge retrieval returns no content
  or citations;
- secrets are absent from prompts, logs, traces, evidence, and receipts;
- Onyx, Odoo, and Semantic Ledger credentials and database roles are isolated;
- degraded behavior for Odoo or Semantic Core unavailability;
- exactly one task and receipt after repeated command delivery;
- targeted frontend lint, type, component, and production-build checks.

### MVP qualification

- Gates A–F from `RB-1` on clean synthetic volumes only;
- identical build across `ORG-MIN`, `ORG-SERV`, and `ORG-DIST`;
- three deterministic runs per required scenario and fault case;
- sealed traces, canonical projections, checksums, and explicit
  `PASS`/`FAIL`/`INVALID` verdicts;
- network and credential probes proving that SUT cannot reach production or
  the private oracle.
