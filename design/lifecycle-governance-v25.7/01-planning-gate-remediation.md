# V25.7 Planning-Gate Remediation Specification

Status: `DRAFT / REVIEW_REQUIRED`

## 1. Authority And Intent

Repair the four reported runtime planning defects without changing frozen V25.6.
The model may submit candidates only. A separately operated external authority
records review receipts. It is never inferred from a `*_REVIEW_REQUIRED` enum.

## 2. Objective, Scope, And Facts

The guarded flow is `BASELINE -> external ACCEPT -> SPEC -> external ACCEPT ->
PLAN -> existing PLAN approval`. The current flow accepts SPEC/PLAN after a
state-only check, accepts a caller digest, does not close inherited authority,
and drops rejected submissions from the event chain. Runtime, SQLite migration,
integrity replay, authority CLI, and focused tests are in scope; protected
target source, V25.6 artifacts, remotes, credentials, deployment, and CI
configuration are out of scope.

## 3. Requirements And Acceptance Binding

| Requirement | Acceptance | Production rule |
| --- | --- | --- |
| R450 | A473 | Exact immediate-predecessor external review receipt is required and atomically consumed. |
| R451 | A474 | Guard derives the canonical PLAN packet digest. |
| R452 | A475 | Exact inherited authority closure includes canonical `ra_mappings`. |
| R453 | A476 | Every rejected resolved-Run submission appends bounded evidence. |

## 4. Materiality And Applicability

All four rules are material. No section is `N_A`: review authorization,
canonical packet identity, acceptance authority, and evidence replay are each
production inputs to planning state transitions.

## 5. Alternatives And Selection

| Alternative | Result | Reason |
| --- | --- | --- |
| State-only predecessor gate | Rejected | It permits the reported review bypass. |
| Model-submitted digest | Rejected | Restricted models cannot reliably construct it. |
| ID-set-only inheritance | Rejected | It permits R/A redirection. |
| One generic external review receipt and exact closure | Selected | It binds authority and allows deterministic replay. |

## 6. Normative Machine Artifacts

`contracts.py` normalizes candidate/receipt input. `facade.py` separates model
submission from authority recording. `execution.py` executes gates and ordered
writes. `database.py` owns schema/migration/event chaining. `integrity.py`
replays all receipt/closure/event invariants. `test_v24_planning_persistence.py`
is the primary production-path oracle.

Receipt schema, normalized before persistence:

```text
review_id, kind=PLANNING_REVIEW_RECEIPT, run_id, artifact_id,
artifact_kind in {BASELINE,SPEC}, artifact_digest, artifact_revision,
base_sha, workspace_digest, issued_revision, source in {ci,independent-review,user},
nonce, issued_at, decision in {ACCEPT,REQUEST_CHANGES}, authority_ref
```

## 7. Components And Dependency Direction

Model-facing paths are exact and may only submit candidates:

```text
plugin guard_submit_{baseline,spec,plan}
  -> RPC submit_{baseline,spec,plan}
  -> MCP guard_submit_{baseline,spec,plan}
  -> Guardian.submit_{baseline,spec,plan}
  -> StateStore.store_planning_artifact
  -> ExecutionRepository.store_planning_artifact
```

The external-only path is `opencode-guard authority record-planning-review ->
Guardian.record_planning_review_receipt -> StateStore -> ExecutionRepository`.
It has no RPC, MCP, or plugin tool registration. Adapters do not calculate
digests, closure, review eligibility, or persistence state.

## 8. Operations And Surface Resolution

`submit_baseline`, `submit_spec`, and `submit_plan` take `body`, expected
revision, bound session/context/skill digests. PLAN `implementation` accepts
only `packet` and `phases`; `packet_digest` is an unknown field and fails.
The response returns the server-derived digest. `record-planning-review` is an
authority CLI operation and accepts the receipt above. Its caller is outside
the model-facing tool allowlist.

## 9. Data And Integrity

Migration adds:

```sql
CREATE TABLE planning_review_receipts (
  review_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind = 'PLANNING_REVIEW_RECEIPT'),
  run_id TEXT NOT NULL, artifact_id TEXT NOT NULL,
  artifact_kind TEXT NOT NULL CHECK (artifact_kind IN ('BASELINE','SPEC')),
  artifact_digest TEXT NOT NULL, artifact_revision INTEGER NOT NULL,
  base_sha TEXT NOT NULL, workspace_digest TEXT NOT NULL,
  issued_revision INTEGER NOT NULL, source TEXT NOT NULL,
  nonce TEXT NOT NULL, issued_at TEXT NOT NULL, decision TEXT NOT NULL,
  authority_ref TEXT NOT NULL, consumed_at TEXT DEFAULT NULL,
  UNIQUE (run_id, nonce),
  FOREIGN KEY (run_id, artifact_id, artifact_digest)
    REFERENCES planning_artifacts(run_id, artifact_id, digest) ON DELETE RESTRICT
);
```

`consumed_at IS NULL` is the sole unconsumed representation; a non-NULL value
is the immutable consumption observation time. The actual migration pins this
nullable table SQL, triggers, expected-table sets, and schema version in
`database.py`; `integrity.py` verifies receipt fields, foreign keys, event
ordering, and consumed state with the same `IS NULL`/`IS NOT NULL` model. Older databases remain
`COMPATIBILITY_READ_ONLY` rather than gaining a writable path.

## 10. Lifecycle And Concurrency

BASELINE stores into `BASELINE_REVIEW_REQUIRED`. SPEC requires a matching,
unconsumed BASELINE `ACCEPT`; PLAN requires an equivalent SPEC `ACCEPT`.
`REQUEST_CHANGES`, wrong source binding, stale issued revision, duplicate
nonce, or consumed receipt never advances state. SQLite `BEGIN IMMEDIATE`
serializes writers; a compare-and-swap consumption condition prevents replay.

## 11. Ordered Transactions And Replay

For SPEC/PLAN, one write transaction does, in order:

1. load Run, artifact, receipt, and immediate predecessor;
2. validate anchors, exact closure, state, and receipt decision;
3. `UPDATE planning_review_receipts SET consumed_at = ? WHERE review_id = ?
   AND consumed_at IS NULL` and require exactly one changed row;
4. insert successor artifact/candidate, planning state, and success event;
5. commit.

Any failure before commit rolls back the receipt consumption and all successor
writes. A concurrent/replayed consumer observes zero changed rows and fails
`PLANNING_REVIEW_REQUIRED`. Integrity replay requires each successor event to
name the consumed receipt and confirms exactly-once consumption.

## 12. Failure And Recovery

Candidate validation first runs in its own write transaction. On `GuardError`
after a Run resolves, that transaction rolls back. A new write transaction
appends `PLANNING_SUBMISSION_REJECTED` with `{kind,input_digest,error_code,
observed_at}`; `input_digest` is empty only when canonicalization failed. Raw
body text is never persisted. The event advances revision but leaves planning
artifacts, candidates, and planning state unchanged. The re-raised stable error
includes `current_revision` for retry. If the Run cannot be resolved, no event
is possible and the original error is returned.

## 13. Security, Trust, And Review Independence

The authority CLI is intentionally absent from plugin, RPC, and MCP model
surfaces. Receipts require distinct external source metadata, immutable ID,
nonce, artifact and Run anchors. The model can observe a review-required state
but cannot write the receipt through its planning submission operation. No raw
candidate body, credential, or arbitrary error detail enters failure events.

## 14. Automatic Controller

There is no automatic controller for planning review. Guard never manufactures
an `ACCEPT`, consumes a receipt without a successor, or performs product
acceptance. Manual external review and later independent acceptance remain
separate.

## 15. Executable Rule Registry

| Rule | Production projection | Reject code | Tests |
| --- | --- | --- | --- |
| PR-REVIEW | predecessor state/artifact/receipt rows | `PLANNING_REVIEW_REQUIRED` | missing, rejected, forged, stale, replay, concurrent consume |
| PR-DIGEST | normalized PLAN packet and registered Run checks | `INVALID_PLANNING_ARTIFACT` | absent digest accepted, supplied digest rejected |
| PR-CLOSURE | normalized predecessor/successor canonical fields | `PLANNING_INHERITANCE_MISMATCH` | delete/add/substitute/redirect all fields |
| PR-FAILURE | failed request, Run, event chain | original stable code plus event | malformed/sequence/closure/review failures |

## 16. External Mutation Registry

| Mutation ID | Procedure | Expected rule |
| --- | --- | --- |
| M450-1 | Submit SPEC/PLAN with no predecessor receipt | PR-REVIEW |
| M450-2 | Use `REQUEST_CHANGES`, stale, wrong-artifact, forged, replayed, or concurrent receipt | PR-REVIEW; exactly one `IS NULL -> timestamp` transition |
| M451-1 | Add any `implementation.packet_digest` value | PR-DIGEST |
| M452-1 | Delete/add/substitute/redirect each closure field, including `ra_mappings` pair reassignment | PR-CLOSURE |
| M453-1 | Force every candidate rejection family | PR-FAILURE, exactly one event/no successor write |

The validator-owned expected mutation IDs are fixed in the V25.7 test fixture;
removing a family or its meta-check fails the test suite.

## 17. Verification And Benchmark

Run the commands in Section 20's packet. Unit tests use real SQLite and
parallel writers. RPC/MCP/plugin tests prove only candidate routes are exposed
to models and PLAN input has no digest. Database-open tests cover fresh schema,
migration, trigger tampering, foreign-key check, and integrity replay.

## 18. Minimal Vertical Slice

1. Store BASELINE.
2. Record an external BASELINE `ACCEPT` for its exact row.
3. Store exact-closure SPEC and atomically consume BASELINE receipt.
4. Record external SPEC `ACCEPT`.
5. Submit PLAN without digest; Guard returns derived digest and atomically
   consumes SPEC receipt.
6. Assert each negative mutation preserves successor state and appends exactly
   one bounded rejection event.

## 19. Implementation Plan Binding

P9 implements schema, contracts, persistence, integrity, facade, and authority
CLI. P10 removes PLAN digest input from model adapters. P11 adds unit,
integration, plugin, mutation, migration, and concurrency tests. P12 obtains
same-SHA CI and independent review. Every changed file maps to R450-R453 and
A473-A476 in current traceability.

## 20. Independent Review Packet

Required packet: frozen V25.7 specification digest; migration/schema fingerprint;
receipt atomic-consume traces; closure and R/A-redirection mutations; failure
event replay; focused unit/integration/plugin results; root lint/format/mypy/
build results; CI run/job/SHA evidence; and independent review with no Critical
or Required finding. Self-test is evidence, not acceptance.
