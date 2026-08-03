# Stage 3 evidence, replay, and recovery

Stage 3 makes SafeDesk executions explainable after they happen and recoverable
when the underlying action supports it.

## Evidence ledger

Every lifecycle event records:

- a global sequence number and event ID;
- run and action identifiers;
- event type and timestamp;
- structured evidence payload;
- the previous entry's SHA-256 hash;
- the current entry's SHA-256 hash.

The hash covers the canonicalized entry content, including `previous_hash`.
Changing an old payload, deleting an entry inside the chain, or reordering entries
breaks verification at a deterministic sequence number. Read APIs return deep
copies so callers cannot mutate the in-memory ledger accidentally.

The chain is tamper-evident, not tamper-proof. A storage administrator who can
replace the entire ledger could recompute an unsigned chain, and an unanchored
tail could be truncated without local detection. Production hardening would
persist entries in append-only storage and periodically anchor or sign the chain
head outside that trust domain.

## Recorded lifecycle

The Stage 3 gateway records:

```text
ACTION_PROPOSED
  → POLICY_DECISION
  → APPROVAL_REQUESTED / APPROVAL_CONSUMED
  → CHECKPOINT_CAPTURED
  → EXECUTION_SUCCEEDED / EXECUTION_FAILED
  → VERIFICATION_SUCCEEDED / VERIFICATION_FAILED
  → RECOVERY_STARTED
  → RECOVERY_SUCCEEDED / RECOVERY_FAILED
```

Capability tokens and signing secrets are never written to the ledger. The event
records only the capability identifier used for the attempt.

## Independent verification

Adapters report what they believe happened. A separate `OutcomeVerifier` observes
the synthetic system state and compares it with the proposal and adapter result.

For the expense demo:

- draft creation is verified by looking up the returned draft ID and amount;
- submission is verified by resolving the confirmation ID to an observed claim;
- a fake success response with no matching state becomes
  `verification_failed`;
- uncertain reversible state is automatically recovered.

The verifier is a separate code path but currently shares the same process and
synthetic state store. A production verifier should use an independent read path,
credential, or downstream event source.

## Recovery strategies

SafeDesk binds every recovery checkpoint to the exact canonical action payload.
Checkpoints are single-use and expose only a snapshot digest, not the stored
snapshot.

Two strategies are implemented:

1. `snapshot_restore` restores captured pre-action state for reversible changes.
2. `compensating_action` performs an explicit follow-up operation when literal
   rollback is unavailable. The expense demo withdraws the synthetic claim
   created by a successful submission.

The gateway can trigger recovery automatically after an execution or verification
failure, or manually using the checkpoint returned with a successful action.

## Safe replay

Replay first verifies the complete global evidence chain. It then selects the
requested run, parses its recorded proposals, and evaluates them against:

- the original policy;
- a stricter or modified policy;
- replay-only mocked tools supplied by the caller.

Replay tools do not receive capability tokens and cannot invoke the real adapters.
The result states whether the replayed decision and mocked result are equivalent
to the recorded execution.

## Failure injection

The test harness can deliberately:

- throw before adapter execution;
- throw after a mutation;
- return a false success without changing state;
- crash a verifier;
- force an explicit verification failure.

This makes recovery and diagnosis paths reproducible instead of depending on
rare external failures.

## Test boundary

Run the Stage 3 scenarios with:

```bash
npm run test:stage3
```

The suite proves:

- modified evidence fails chain verification;
- an original run replays equivalently with a deterministic mock;
- a stricter policy changes the replay decision without invoking the mock;
- post-execution failures restore prior state;
- false success and verifier crashes are detected and recovered;
- manual recovery is single-use;
- externally reversible submissions use a compensating withdrawal.

## Current limitations

- The ledger and recovery checkpoints are in memory.
- Snapshot contents are not yet encrypted at rest.
- Capability expiration can prevent delayed manual recovery.
- Real APIs need idempotency keys and service-specific compensation semantics.
- Filesystem recovery still needs descriptor-level hardening against host-level
  time-of-check/time-of-use races.
- Cross-service workflow compensation and durable retry orchestration remain
  future work.
