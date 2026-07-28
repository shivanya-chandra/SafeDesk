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

## Stage 1: policy foundation

The first working slice includes:

- runtime-validated action and policy contracts;
- a deterministic, deny-by-default policy engine;
- explicit precedence: `deny` > `require_approval` > `allow`;
- capability rules over operations, resources, destinations, and data labels;
- tests for the flagship malicious-receipt scenario.

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

See [ROADMAP.md](./ROADMAP.md) for the five delivery stages,
[docs/architecture.md](./docs/architecture.md) for system boundaries, and
[docs/threat-model.md](./docs/threat-model.md) for the initial threat model.

## Current status

Stage 1 is implemented. SafeDesk does not execute real external side effects yet;
that boundary is intentionally reserved for Stage 2.

## License

[MIT](./LICENSE)

