# Architecture

## Design principle

SafeDesk separates intelligence from authority.

An AI agent may reason about a task and propose an action, but it never receives
the credentials or unrestricted tool handles needed to perform that action.
SafeDesk owns those handles and exposes only capability-scoped adapters.

## Trust boundaries

| Component | Trusted to decide | Not trusted to decide |
| --- | --- | --- |
| Agent | Task strategy and proposed intent | Its own authorization |
| Action gateway | Contract validity and request identity | Business policy |
| Policy engine | Authorization from explicit policy | Whether a tool claims success |
| Checkpoint manager | Pre-action state and approval binding | Final outcome |
| Scoped adapter | Execute one authorized operation | Expand its capability |
| Verifier | Observe the resulting state independently | Grant authority |
| Evidence ledger | Preserve ordered execution evidence | Change past events |

## Decision flow

1. The agent submits an `ActionProposal`.
2. The gateway validates the proposal before any policy or adapter sees it.
3. The policy engine matches explicit rules and applies fixed effect precedence.
4. A denied action stops. An approval-required action is paused and bound to its
   exact payload. An allowed action proceeds.
5. The checkpoint manager captures the relevant pre-action state.
6. A capability-scoped adapter performs the operation.
7. A separate verifier checks the expected effect against observed state.
8. The evidence ledger records the proposal, decision, execution, and proof.

If execution throws or verification cannot confirm the expected state, the
recovery manager uses the checkpoint's declared strategy: restore a captured
snapshot or invoke a compensating action. Every recovery attempt is appended to
the same evidence chain.

Replay verifies the complete ledger chain before selecting a run. It then
re-evaluates recorded proposals against a chosen policy and uses replay-only mock
tools, never the adapters that hold real authority.

## Benchmark boundary

The Agent Security Gym exercises the same public runtime boundary as a protected
agent. A scenario supplies structured proposals, a policy, a signed capability,
synthetic tool behavior, legitimate goal effects, and forbidden effects. The
protected runner passes every proposal through the real action gateway, scoped
adapter, verifier, evidence ledger, and recovery manager. It does not reproduce
those controls inside the benchmark.

For comparison, the baseline runner executes the identical proposals and trusts
tool responses without policy, capability, approval, verification, or recovery
checks. Both profiles operate on separate in-memory worlds, so they cannot affect
one another. Metrics are derived from observed effects and action outcomes, not
from a model grading its own behavior.

## Policy semantics in Stage 1

- The default effect is `deny`.
- Every condition category on a rule must match.
- Multiple patterns within one category are alternatives.
- `data_labels_any` matches when at least one proposal label is present.
- All matching rule IDs are returned for explainability.
- Effect precedence is fixed: `deny`, then `require_approval`, then `allow`.
- Rule order cannot weaken a denial.

These semantics are deliberately small. More expressive policy features will only
be added with tests for conflicts and explanation output.

## Synthetic deployment shape

The first demo will run entirely against synthetic data:

- an isolated task filesystem containing five receipt fixtures;
- a mock expense API with draft, submit, withdraw, and verify endpoints;
- a controlled network adapter with an allowlist;
- an untrusted webpage and receipt fixture containing prompt injection;
- a dashboard driven from evidence-ledger events.

No production credentials are needed to demonstrate the security boundary.
