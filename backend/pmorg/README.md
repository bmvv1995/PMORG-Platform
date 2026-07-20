# PMORG backend boundary

This package is the PMORG V3 product boundary inside the governed Onyx fork.
Its layers point inward:

- `domain` contains infrastructure-independent domain code;
- `application` owns use cases and ports;
- `interaction` owns Turn Admission and coordination;
- `integrations` owns concrete Onyx, Odoo, gateway, and orchestrator adapters;
- `contracts` exposes the single V3 wire surface, `pmorg-contracts/1.0`.

The domain layer must not import outer PMORG layers, Onyx, Odoo clients,
orchestration clients, persistence libraries, transports, or framework code.
`pmorg.boundaries` enforces this rule by inspecting the domain source tree.

Slice 2a establishes only these boundaries and their guardrails. It does not
implement contract payloads, APIs, databases, Odoo behavior, runtime wiring,
release qualification, or a G3-A verdict.

The first signed-record use case lives in `application.rbdp`. It emits and
verifies canonical Ed25519 DSSE envelopes for CE development-test release build
definitions. Private and public test key bytes are accepted only through an
environment mapping; key files, production keys, EE/production admissions,
build execution, and release qualification remain outside this boundary.
