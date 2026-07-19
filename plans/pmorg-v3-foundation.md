# PMORG V3 foundation and migration plan

## Issues to Address

PMORG Platform is currently a governed Onyx bootstrap. It does not yet
implement the `RB-1/C2` product contract. The implementation must add PMORG as
a first-class product subsystem without turning Onyx, Odoo, the Semantic
Ledger, or the orchestrator into competing sources of truth.

The foundation must address these problems before product-level features are
added:

- materialize `pmorg-contracts/1.0` as strict, versioned, content-addressed
  contracts and make the incompatible V2 wire contracts explicitly
  superseded for V3;
- establish a PMORG package boundary whose domain layer does not depend on
  Onyx, Odoo, or a concrete orchestrator;
- keep Odoo as the formal operational source of truth and `project.task` as
  the canonical work registry;
- establish Odoo-owned organization, identity, registry, and anchor resolution
  before Semantic Core consumes them;
- create Semantic Core as an authoritative bounded context with its own
  database, migrations, role, backup, and lifecycle;
- ensure every PMORG turn enters through authenticated Turn Admission, with
  identity binding and the privacy/secrets verdict completed before any
  durable content storage;
- prevent the generic Onyx chat/tool loop from executing PMORG turns or Odoo
  mutations;
- make claim validation a system-policy transition, with human intervention
  limited to vocabulary and consequential anchor reconciliation;
- implement the Odoo-owned D1-D5 provenance-gap lifecycle and its read-only
  PMORG workspace projection;
- port SB3 behavior and tests selectively without treating SB3 schemas or
  deployment topology as V3;
- maintain a thin, auditable Onyx fork and reproducible artifacts for the
  declared Onyx surface and usage mode;
- disable upstream telemetry and update checks and enforce deny-by-default SUT
  egress;
- preserve the zero-production-testing boundary throughout evaluation.

## Important Notes

### Normative inputs

- PMORG requirements: `RB-1/C2` candidate, PMORG PR #5 head
  `a90e56408cc4a884fc246c19d82c69f13d549e8d`. Replace this pin with the
  accepted final commit before PR #17 leaves draft.
- Onyx baseline: `v4.3.9`, commit
  `1da679cefc96165c6b9b64c3bc769584b88f88c2`.
- The requirements repository owns specifications, contracts, evaluation
  assets, and V1/V2/SB3 references.
- This repository owns the V3 implementation and preserves Onyx history.
- Every build and run bundle declares `onyx_surface: ce|ee` and
  `usage_mode: development_test|production`.
- Odoo image/revision, PostgreSQL/search/object-store revisions, and all
  authoritative store migrations are pinned before any release-candidate
  qualification.

### Architecture boundaries

- `backend/pmorg/domain` must not import `onyx`, Odoo clients, orchestrator
  clients, FastAPI, persistence models, or transport implementations.
- `backend/pmorg/application` owns use cases and ports.
- `backend/pmorg/interaction` owns Turn Admission and the Turn Coordinator.
- `backend/pmorg/integrations` owns Onyx, Odoo, orchestrator, and gateway
  adapters. Hermes is optional, not a domain dependency.
- `services/semantic-core` is independently deployable and owns the Semantic
  Ledger schema and migrations.
- Odoo owns formal state, the canonical task registry, organization/identity
  bindings, capability registry, and anchor resolution.
- Semantic Core owns evidence, claims, assessments, semantic history, and
  validation receipts; it validates against the live Odoo registry.
- Onyx knowledge, vector search, and KG are reconstructible projections, never
  the organizational ledger.
- The orchestrator owns scheduling, retries, checkpoints, and execution of
  longitudinal control loops, but not formal state, canonical tasks, or
  semantic truth.
- Onyx personal memory is disabled for PMORG agents until a separate scope
  policy exists.
- The Onyx tenant identifier is not a substitute for `OrganizationContext`.
- MCP exposes Semantic Core externally but is not an internal HTTP loopback
  between modules in the same process.
- An existing Onyx capability is reused by default only when it passes PMORG
  contracts, isolation, security, and commercial constraints; deviation
  requires a versioned ADR or waiver.
- Onyx EE code is never copied into PMORG-owned modules. Direct EE patches are
  classified `license_class=onyx-enterprise` and remain under the Onyx
  Enterprise terms.
- Upstream telemetry and update checks are disabled. SUT runtime egress is
  deny-by-default; exceptions are gate-scoped, allow-listed, time-bounded, and
  recorded in the run bundle.

### SB3 and V2 migration posture

SB3 is an executable reference, not a production foundation. Its shared AIPM,
memory, Odoo, runner, profile, and worldgen assets remain behavior/test sources.

For V3, orchestrator/Odoo V2 `1.0/1.1` and `pmorg-memory/1.0` are
superseded by `pmorg-contracts/1.0`. V3 publishes no V2 aliases and performs
no dual-write. Legacy fixtures and any later import use an isolated,
versioned, removable compatibility adapter implementing
`14-V2-CONTRACT-SUPERSESSION.md`; unverifiable legacy state remains
`reference-only`.

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
- the SB3 Compose topology or mutable image tags;
- any orchestrator Kanban, including Hermes Kanban, as another work registry.

### Onyx surface and usage-mode disposition

The earlier CE experiment remains outside this branch and is relevant only to
`onyx_surface=ce`. Re-evaluate and port dedicated CE Docker definitions,
explicit non-EE dependency selection, artifact/layer scans, negative fixtures,
and reproducible image evidence. Do not port broad removals from Onyx; use only
narrow, tested seams needed for a CE artifact.

For `onyx_surface=ee`, keep EE code in its original upstream paths and
inventory every capability, dependency, patch, and image layer. With
`usage_mode=development_test`, permit only synthetic development/evaluation
and enforce a technical guard that refuses production use or distribution.
With `usage_mode=production`, require a verified authorization record binding
the licensed entity, seats/scope, agreement reference, validity window, and
verifier receipt. Missing, expired, or mismatched evidence fails closed.

CE qualification is not a prerequisite for contracts, Odoo, Semantic Core, or
Turn work. Every release candidate must nevertheless close `G3-A` for its
declared surface/mode before receiving an MVP verdict.

## Implementation Strategy

Slice numbers express architectural dependencies, not a universal serial
queue. After Slice 0, exploratory builds and the contract spine may proceed in
parallel. Slice 1 must not emit signed qualification/admission/disposition
records or close G3-A until Slice 2 publishes the canonical schema manifest and
digest. No CE-only task blocks Odoo or Semantic Core work.

### Slice 0 — governed baseline

Status: in cross-review on `sol/v3-foundation`.

- record project-scoped agent roles with canonical ownership language;
- pin upstream and candidate specification inputs;
- narrow the patch ledger so every changed path has exactly one owner;
- reject uncovered and multiply owned paths;
- cross-record and validate the specification pin;
- require fork verification before and after every later slice.

### Slice 1 — Onyx substrate and G3-A qualification

- add immutable `onyx_surface` and `usage_mode` inputs to build, release,
  SBOM, and run-bundle manifests;
- build backend/frontend artifacts from pinned source without relocating or
  copying EE code into PMORG-owned paths;
- for `ce`, prove that no EE product file, import, dependency group, or saved
  image layer exists;
- for every `ee` build, inventory all capability/file/dependency/patch/layer
  provenance;
- emit a signed, content-addressed `BuildQualificationManifest` that binds
  artifact digest, both axes, inventory/boundary reports, SBOM and verifier;
- require a signed `DeploymentAdmissionRecord` at deploy and startup:
  `ee + development_test` admits only an attested synthetic target and rejects
  production/distribution; `ee + production` binds authorization entity,
  seats/scope, agreement, validity, artifact and client target;
- materialize a versioned required-capability catalog and a complete
  `reuse|patch|pmorg_independent` disposition report; deviations from an
  adequate Onyx capability require ADR/waiver, expiry and tests;
- record `license_class=onyx-enterprise` for every direct EE patch;
- run selected unmodified upstream suites on baseline and fork;
- disable telemetry/update checks and enforce audited deny-by-default egress;
- record image digests, SBOM, dependency export, license report, source
  manifest, surface/mode report, authorization state, vulnerability triage,
  and versioned waivers.

This slice establishes a distributable substrate for the selected matrix cell.
It does not rewrite unrelated Onyx behavior.

### Slice 2 — complete contract spine and V2 supersession

- add top-level `backend/pmorg` package boundaries;
- implement every contract frozen by `pmorg-contracts/1.0`, including
  `BuildQualificationManifest`, `DeploymentAdmissionRecord`,
  `CapabilityDispositionRecord`, nested types and command payloads needed by
  later slices;
- generate committed JSON Schema with
  `additionalProperties: false` for writes;
- generate a deterministic manifest containing every schema digest and pinned
  specification commit;
- enforce drift checks among models, schemas, examples, and manifest;
- enforce no forbidden infrastructure imports from the domain package;
- expose only `pmorg-contracts/1.0` as the V3 wire surface;
- implement a pure isolated V2 mapper with `LegacySourceIdentity`,
  `LegacyProvenance`, request-hash conflict semantics, error/state mapping,
  and the 8-to-11 Semantic Core operation mapping;
- forbid V2 aliases, dual-write, and promotion of unverifiable legacy records
  into authoritative V3 state.

No API, database, Odoo call, LLM call, or UI is part of this slice.

### Slice 3 — public evaluation inputs and oracle boundary

- port the three public organization manifests before Odoo profile tests;
- materialize module/anchor-pack expectations, logical IDs, policy references,
  fixtures, and `world.lock`;
- materialize V2 supersession fixtures for identity, memory, idempotency,
  task/run state, and longitudinal command mapping;
- create the private-oracle interface and network/credential boundary without
  exposing oracle data to SUT;
- define canonical examples shared by contracts, Odoo, Semantic Core, runner,
  and independent-client tests;
- generate the initial run-bundle manifest without claiming a gate verdict.

### Slice 4 — Odoo control-plane foundation

- port and adapt the minimal `pmorg_core` addon under `odoo/addons`;
- install with Project only, without HR or Inventory;
- qualify all three clean module profiles and exact registry snapshots;
- implement Odoo-owned organization/identity bindings, initiative, criteria,
  task orchestration fields, state version, trusted clock, command inbox, and
  transactional outbox;
- publish a live versioned capability registry from active modules, approved
  anchor packs, company, ACL, and policy;
- implement full `AnchorReference` resolution with instance, company, ACL,
  registry fingerprint, and observed record version;
- expose narrow authenticated reads for Semantic Core context binding,
  registry negotiation, and anchor validation;
- forbid generic model/method/values and SQL/ORM endpoints.

### Slice 5 — Semantic Core evidence kernel

- create an independently deployable service/database with SQLAlchemy metadata,
  Alembic, database role, credentials, backup path, and configuration;
- authenticate service calls and bind presented `OrganizationContext` to the
  caller plus Odoo-owned organization/identity mapping from Slice 4;
- negotiate only the live Odoo registry and validate anchors through the
  narrow capability layer;
- implement immutable evidence capture after Turn Admission;
- persist accepted payload bytes in scoped object storage/content-addressed
  resolution and verify hashes before ledger insertion;
- apply ACL, retention, redaction, and secret-rejection rules;
- return original receipts on valid idempotent replay and reject key/hash
  conflicts;
- enforce organization/company scope before reads/writes;
- expose equivalent internal API and standards-compliant MCP services;
- prove deleting a search projection cannot delete evidence or payloads.

### Slice 6 — complete Semantic Core lifecycle

- implement claim proposals, assessments, authority, and validator
  independence;
- make every claim transition system-only: only the authenticated policy
  engine/validator service may emit the verdict and transition actor;
- expose no human/cognitive API, action, or UI for claim verdict/approval,
  whole-claim accept/reject, or editing claim kind, owner, term, predicate, or
  normalized value;
- limit positive semantic HIL to vocabulary governance and consequential
  ambiguous-anchor reconciliation, then rerun extraction/assessment/policy
  automatically;
- keep business action approvals and human outcome verification separate; they
  cannot create or modify semantic verdicts;
- implement valid versus recorded time, contradiction, dispute, supersession,
  and immutable history;
- implement commitments/outcomes linked to formal Odoo bindings without
  copying formal state;
- implement deterministic recall, `as_of`, and timeline queries filtered by
  organization, company, ACL, registry, time, and status before ranking;
- create reconstructible Onyx search/KG projections and prove equivalent
  hashes after rebuild;
- complete internal API and MCP operations for the frozen contract.

### Slice 7 — Odoo longitudinal domain and controllers

- implement immutable plan versions, commitments, approvals, outcomes, and
  outcome verification;
- implement waits, `next_check_at`, interventions/escalations,
  monitoring/autonomy policy, health flags, and controller checkpoints;
- enforce frozen transitions and optimistic concurrency on every mutation;
- implement system-only `pmorg.task.activate_due`: idempotently move
  `waiting_response|waiting_approval|scheduled` to `ready` only on a
  correlated event or due trusted tick, always before a new claim;
- implement Odoo-owned `pmorg.provenance.gap` with deterministic D1-D5
  detection, materiality, stable deduplication, and
  `open -> explained|dismissed`;
- compare Odoo effects/events with Semantic Core evidence/bindings/receipts
  through a narrow authenticated API;
- permit gap resolution only from verified receipts/policy, never model text
  or human semantic annotation;
- publish only a read-only Onyx-PMORG digest, materiality/age ordering, and
  aggregate coverage rate; clarification re-enters through Turn Admission;
- ensure each controller performs one idempotent step, persists its next
  check, and resumes under another runtime;
- qualify manual changes, expired leases, late results, due activation, gap
  reconciliation, and inbox/outbox recovery.

A gap is a missing-provenance signal, never a personnel verdict or dossier.

### Slice 8 — authenticated read-only PMORG turn

- add one `/pmorg/v1` router seam and one `admit_message` entry shared by UI
  and future Communication Gateway;
- keep inbound envelope/raw content transient before admission;
- resolve the sender through Odoo-owned `pmorg.identity`; absent/ambiguous
  binding creates no organizational effect and persists no content;
- run privacy/secrets policy after identity binding and before any transcript,
  content ref/hash, evidence, chunk, embedding, prompt, trace, log, or
  orchestrator checkpoint;
- on refusal, destroy the buffer and persist exactly one metadata-only
  `PrivacyRejectionReceipt` with no content/ref/hash;
- after acceptance, validate `OrganizationContext` and live registry, capture
  evidence, and emit payload-free `AdmittedMessage`;
- expose only the admitted receipt to runner/orchestrator and continue through
  the same Turn API;
- refuse PMORG agents through generic `/send-chat-message`;
- use a bounded Onyx adapter with personal memory disabled and only
  read/proposal tools;
- for `ce`, use synthetic uniform-access knowledge until permission-aware
  retrieval is qualified; for `ee`, independently qualify applicable Onyx
  access controls; Odoo/PMORG isolation remains mandatory;
- return `CognitiveStepResult`; treat model output only as proposal/evidence;
- persist proposals through the full Semantic Core lifecycle;
- add a minimal `/pmorg` workspace showing context, receipts, bounded result,
  provenance digest, and vocabulary/anchor reconciliation only.

### Slice 9 — first controlled Odoo effect

- implement only `pmorg.task.propose` first;
- perform deterministic preflight outside the model loop;
- require the autonomy/approval result;
- validate expected version, lease, schema, actor, company, registry, and
  command-bound approval;
- write business state, receipt, and outbox atomically;
- prove duplicate delivery/retry creates exactly one task and receipt.

### Slice 10 — G3-D vertical slice M0

- port the runner and simulated channel to implementation-agnostic contracts;
- create the public XNX fixture from clean Odoo volumes;
- complete initiative -> clarification -> evidence -> validated claim ->
  controlled task -> evidence -> verified outcome;
- reconstruct the full Odoo/Semantic timeline;
- run three identical clean executions for `ORG-DIST`.

### Slice 11 — G3-E/G3-F profile and longitudinal qualification

- execute all public organization profiles using the same qualified build;
- qualify absent-module closed-world behavior;
- add virtual-time silence, follow-up, escalation, restart, due activation,
  lease expiry, delayed response, replay, contradiction, supersession,
  optimistic conflict, outage, recovery, and closure;
- replace the V2 kernel with sealed V3 run bundles and aggregate
  `G3-A`-`G3-F` verdicts.

A stochastic operator, external persistent orchestrator, and real channel
remain `G3-G`, `G3-H`, and `G3-I`. Hermes is one candidate for G3-H;
these gates do not change ownership or contracts.

## Tests

### Every slice

- `python3 pmorg/scripts/verify_fork.py`;
- `git diff --check`;
- targeted Ruff/type checks;
- patch-ledger coverage with exactly one owner per changed path;
- pin/manifests parse and agree;
- relevant unit, contract, integration, and negative tests;
- zero production endpoints, data, identities, channels, or credentials.

### Onyx surface/mode and G3-A

- clean builds for each declared matrix cell;
- `ce`: source/import/dependency/filesystem/every-layer scans with zero EE;
- every `ee`: complete capability/file/dependency/patch/layer inventory;
- signed build manifest with immutable axes, artifact digest and verifier;
- `ee + development_test`: signed synthetic-target admission and rejection of
  every production/distribution attempt;
- `ee + production`: signed authorization bound to entity, seats/scope,
  agreement, validity, artifact and client target; missing/expired/mismatch/
  untrusted refusal at deploy and startup;
- 100% required-capability catalog coverage by a disposition report;
- direct EE patch license classification and zero EE copied into PMORG modules;
- negative fixtures for undeclared paths, imports, dependencies, layers,
  surface/mode mismatches, and authorization drift;
- upstream unit/type/build suites before/after seams;
- telemetry/update checks disabled and arbitrary egress denied;
- SBOM, digest, license, vulnerability, authorization-state, and patch reports;
- clean migrations, independent restore, and supply-chain triage required for
  full G3-A, not only CE boundary evidence.

### Contract spine and V2 supersession

- canonical valid examples for every schema;
- unknown writes/major versions refused;
- invalid UUID/int64/semver/hash/timestamp/URI cases;
- required-nullable keys distinct from absent keys;
- deterministic schema generation/digests and no forbidden domain imports;
- V2-to-V3 operation/error/identity/state/idempotency fixtures;
- `B-IDEM-MIG-001`, `B-MIG-PROV-001`, `C-IDEM-MIG-001`,
  `F-MIG-STATE-001`, and `F-MIG-LONG-001`;
- no V2 alias/dual-write and unverifiable legacy state remains
  `reference-only`.

### Semantic Core

- replay/conflict, missing context/hash, cross-org/company refusal;
- impersonation, invalid credentials/scope, context binding;
- payload hash, retention, redaction, and secret rejection;
- temporal/immutable behavior, authority, validator independence,
  contradiction, supersession, commitment, outcome, recall, timeline;
- zero human/cognitive claim verdicts, approvals, transitions, or semantic
  editing surfaces; every transition actor is the policy service;
- HIL only for vocabulary/anchor reconciliation, followed by automatic
  re-extraction/policy validation;
- migration/restore/index rebuild and independent MCP interoperability.

### Odoo control plane and longitudinal controllers

- clean install for all three module profiles;
- exact registry snapshots and absent-module negatives;
- anchor stale/ACL/company/fingerprint cases;
- one-winner leases, optimistic conflicts, and 1,000 replayed commands;
- atomic effect/receipt/outbox under injected failures;
- `activate_due`: correlated response, approval, due tick, premature refusal,
  replay, and activation-before-claim;
- D1-D5 gap detection, stable deduplication, verified closure, no personnel
  verdict, and equivalent coverage digest after restart.

### Turn and controlled effect

- anonymous/unbound identity refused without durable content;
- generic Onyx chat refuses PMORG agents;
- privacy refusal precedes every content/ref/hash/transcript/evidence/index/
  prompt/log/checkpoint surface and emits one metadata-only receipt;
- accepted evidence exists before cognitive execution and only payload-free
  `AdmittedMessage` reaches runner/orchestrator;
- personal memory absent; no mutating Odoo tool in the model loop;
- prompt injection cannot expand tools, anchors, autonomy, or scope;
- unauthorized retrieval refused before LLM;
- cross-org/company retrieval returns no content/citations;
- secrets absent from all prompts/logs/traces/evidence/receipts;
- credentials/roles isolated and degraded modes tested;
- repeated command delivery yields one task and receipt;
- frontend lint/type/component/production build checks.

### MVP qualification

- `G3-A`-`G3-F` from `RB-1/C2` on clean synthetic volumes only;
- identical build across `ORG-MIN`, `ORG-SERV`, and `ORG-DIST`;
- three deterministic runs per required scenario/fault;
- sealed traces, projections, checksums, and explicit verdicts;
- network/credential probes prove SUT cannot reach production, private oracle,
  telemetry/update endpoints, or arbitrary non-allow-listed destinations.
