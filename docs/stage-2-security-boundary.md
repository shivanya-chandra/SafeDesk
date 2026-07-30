# Stage 2 security boundary

Stage 2 moves SafeDesk from policy simulation to capability-controlled execution.

## Capability tokens

The runtime signs capability manifests with HMAC-SHA-256. Each manifest is bound
to one agent and task and declares:

- an expiration time;
- allowed operations;
- resource patterns;
- optional destination patterns.

The action gateway verifies a capability before evaluating policy. Every adapter
then verifies it again at the execution boundary. Possessing an adapter object
without a valid token does not grant authority.

The Stage 2 implementation uses an in-process signing authority for the synthetic
demo. A production deployment would isolate signing keys in a separate service or
hardware-backed key store and rotate them.

## File isolation

The file adapter maps `/task/**` resources into a temporary task root. It checks
both the lexical path and the resolved real path, which blocks:

- `../` path traversal;
- absolute paths outside the task root;
- symbolic links that resolve outside the task root.

Tests create only synthetic files inside an operating-system temporary directory.

## Network isolation

The network adapter requires an explicit HTTPS destination and rejects embedded
credentials. Destination authorization is checked against the signed capability
before the injected transport is called.

The demo transport is an in-memory test double. Stage 2 performs no real network
requests, so tests cannot leak data or mutate an external service.

## Approval integrity

Approval checkpoints hash the canonical action proposal together with the active
policy ID and version. The checkpoint is:

- short-lived;
- approved by an identified user;
- valid for the exact reviewed payload;
- single-use.

Changing the amount, destination, resource, policy version, or any other proposal
field after approval produces `ACTION_CHANGED` and stops execution.

## Remaining limitations

- Checkpoints and synthetic expense records are in-memory only.
- HMAC keys are process-local.
- Executions are not yet recorded in a tamper-evident ledger.
- Adapter results are not independently verified.
- Retry and compensation behavior begins in Stage 3.

