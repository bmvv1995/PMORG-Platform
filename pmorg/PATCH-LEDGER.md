# PMORG patch ledger

All differences from the pinned Onyx baseline are classified here. A patch is
not accepted merely because it is located under a PMORG-named directory.
The machine-readable source is
[`patch-ledger.json`](patch-ledger.json); this document explains its policy.

| ID | Area | Classification | Upstream files modified | Reason | Verification |
|---|---|---|---|---|---|
| `PL-000` | bootstrap governance | PMORG-owned | none | pin upstream/spec inputs and define the CE boundary | manifest and diff checks |
| `PL-001` | Codex project agents | PMORG-owned | none | define least-privilege roles for mapping, architecture review, tests and bounded implementation | TOML parse and fork consistency check |

## Classifications

- `PMORG-owned`: new PMORG files that do not alter upstream behavior;
- `integration`: narrow upstream change required to expose a stable PMORG
  boundary;
- `upstream-candidate`: generic fix intended to be proposed upstream;
- `temporary`: time-bounded patch with an owner and removal condition.

Every entry after `PL-000` must identify the affected upstream files, the
contract or requirement it implements, and the tests that prevent drift.

Run the consistency check with:

```bash
python3 pmorg/scripts/verify_fork.py
```
