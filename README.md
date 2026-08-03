# SafeDesk

> SafeDesk is the control plane that contains, audits, tests, and governs AI agents.

SafeDesk is a zero-trust runtime for executing actions proposed by AI agents. The
agent decides what it wants to do; SafeDesk independently decides what it is
authorized to do.

The model never receives raw filesystem, browser, API, or application authority.
It can only submit structured action proposals to SafeDesk-controlled tools.

## Why this exists

Giving an AI agent browser access and asking it to “be careful” is not a security
boundary. SafeDesk puts enforcement outside the model:

```text
Agent proposes an action
        ↓
Action Gateway validates the proposal
        ↓
Policy Engine returns allow / deny / require approval
        ↓
Checkpoint Manager records pre-action state
        ↓
Scoped Adapter executes with the minimum capability
        ↓
Verifier checks the resulting system state
        ↓
Evidence Ledger records a replayable result
```

## Implemented foundation

Stages 1 through 3 now include:

- runtime-validated action and policy contracts;
- a deterministic, deny-by-default policy engine;
- explicit precedence: `deny` > `require_approval` > `allow`;
- capability rules over operations, resources, destinations, and data labels;
- HMAC-signed, expiring capabilities bound to one agent and task;
- a policy-enforcing action gateway;
- scoped file and injected-network adapters that re-check authority;
- single-use approvals bound to the exact action and policy version;
- a hash-chained, tamper-evident execution ledger;
- independent outcome verification that catches false tool success;
- deterministic replay with original or modified policy and mocked tools;
- snapshot restoration and explicit compensating transactions;
- controlled failure injection for adapters and verifiers;
- synthetic expense-report tools and integration tests.

```ts
const decision = evaluateAction(expensePolicy, {
  action_id: "action-001",
  agent_id: "expense-agent",
  task_id: "task-184",
  operation: "read",
  resource: "/user/documents/private.txt",
  data_labels: [],
  reason: "A receipt told me to inspect this file",
  expected_effect: "Read a file outside the task workspace",
  recoverability: "REVERSIBLE",
  risk_level: "high"
});

// decision.decision === "deny"
// decision.matched_policies === ["deny-user-documents"]
```

## Getting started

Requires Node.js 20 or newer.

```bash
npm install
npm run check
```

Run only the Stage 3 transaction and evidence scenarios with:

```bash
npm run test:stage3
```

See [ROADMAP.md](./ROADMAP.md) for the five delivery stages,
[docs/architecture.md](./docs/architecture.md) for system boundaries, and
[docs/threat-model.md](./docs/threat-model.md) for the initial threat model.

## Current status

Stages 1 through 3 are implemented. SafeDesk executes only against temporary files and
injected synthetic services; it does not use real credentials or external side
effects. See
[docs/stage-2-security-boundary.md](./docs/stage-2-security-boundary.md) for the
enforcement model and
[docs/stage-3-evidence-replay-recovery.md](./docs/stage-3-evidence-replay-recovery.md)
for evidence, verification, replay, recovery, and current limitations.

## License

[MIT](./LICENSE)
