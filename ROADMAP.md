# SafeDesk delivery roadmap

Each stage ends with a runnable test boundary. A stage is complete only when its
acceptance checks pass.

## Stage 1 — Contracts and deterministic policy ✅

Build the security vocabulary and the first enforceable decision boundary.

Deliverables:

- typed, runtime-validated action proposals and policy documents;
- deny-by-default policy evaluation;
- operation, resource, destination, risk, and data-label matching;
- the initial architecture and threat model;
- unit tests for allowed, denied, and approval-required actions.

Acceptance:

- malformed proposals are rejected before evaluation;
- identical inputs always produce identical decisions;
- an explicit deny cannot be overridden by an allow;
- the flagship attack's file and network requests are denied;
- `npm run check` passes.

## Stage 2 — Action gateway and scoped execution ✅

Put real authority behind SafeDesk-controlled adapters.

Deliverables:

- an action-gateway service;
- expiring capability manifests;
- sandboxed file and network adapters;
- approval checkpoints bound to exact action payloads;
- synthetic expense-report tools.

Acceptance:

- agents cannot invoke adapters without a signed capability;
- path traversal and unapproved destinations fail at the adapter boundary;
- approved actions cannot be changed after approval;
- integration tests run without real personal data or external side effects.

## Stage 3 — Evidence, replay, and recovery ✅

Make every side effect explainable, verifiable, and recoverable where possible.

Deliverables:

- append-only, hash-chained evidence ledger;
- before/after checkpoints and independent outcome verification;
- replay against original or modified policies;
- reversible and compensating transaction handlers;
- failure injection for adapters and verifiers.

Acceptance:

- ledger tampering is detected;
- recorded runs can be replayed deterministically with mocked tools;
- reversible mutations restore prior state;
- false tool-success responses are caught by verification.

## Stage 4 — Agent Security Gym ✅

Turn the threat model into a measurable adversarial benchmark.

Deliverables:

- malicious receipt and prompt-injection fixtures;
- redirect, confused-recipient, stale-price, retry-loop, and false-success cases;
- baseline-agent versus SafeDesk-protected runs;
- containment, completion, false-block, verification, and recovery metrics.

Acceptance:

- benchmark runs are reproducible from one command;
- every scenario declares legitimate goals and forbidden effects;
- reports distinguish security containment from task usability;
- the flagship expense-report attack is blocked end to end.

## Stage 5 — Recruiter-facing product and hardening

Expose the engineering clearly without weakening the runtime boundary.

Deliverables:

- execution timeline and policy-explanation dashboard;
- approval and recovery views;
- architecture diagrams and a concise demo script;
- CI quality gates, security checks, and deployable sample environment;
- documented limitations and future work.

Acceptance:

- a reviewer can reproduce the demo from the README;
- the UI reads structured ledger data rather than inventing agent state;
- CI runs type, unit, integration, and security-gym checks;
- no real credentials or personal data are required.
