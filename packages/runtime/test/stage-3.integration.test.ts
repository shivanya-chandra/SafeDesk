import {
  describe,
  expect,
  it
} from "vitest";
import {
  policySetSchema,
  type ActionProposal
} from "@safedesk/contracts";
import {
  ActionGateway,
  ApprovalCheckpointManager,
  CapabilityAuthority,
  EvidenceLedger,
  FaultInjectingAdapter,
  FaultInjectingVerifier,
  InjectedFailureError,
  RecoveryManager,
  ReplayEngine,
  type AdapterResult,
  type FaultDefinition,
  type OutcomeVerifier,
  type ReplayTool,
  type ToolAdapter,
  type VerifierFaultDefinition
} from "../src/index.js";
import {
  SyntheticExpenseService,
  SyntheticExpenseVerifier
} from "../../../examples/expense-report/src/synthetic-expense-service.js";
import expensePolicyDocument from "../../../examples/expense-report/policy.json" with {
  type: "json"
};

const policy = policySetSchema.parse(expensePolicyDocument);
const signingSecret = "stage-3-test-signing-secret-32-bytes";

function makeCreateProposal(actionId: string): ActionProposal {
  return {
    action_id: actionId,
    agent_id: "expense-agent",
    task_id: "task-stage-3",
    operation: "create",
    resource: "expense_report_draft",
    parameters: {
      amount: 428.17,
      receipt_count: 5
    },
    data_labels: ["PERSONAL", "FINANCIAL"],
    reason: "Prepare a synthetic expense draft",
    expected_effect: "Create one local draft for $428.17",
    recoverability: "REVERSIBLE",
    risk_level: "medium"
  };
}

function createRuntime(
  faults: ReadonlyMap<string, FaultDefinition> = new Map(),
  verifierFaults: ReadonlyMap<string, VerifierFaultDefinition> = new Map()
): {
  gateway: ActionGateway;
  ledger: EvidenceLedger;
  service: SyntheticExpenseService;
  token: string;
  approvals: ApprovalCheckpointManager;
} {
  const authority = new CapabilityAuthority(signingSecret);
  const token = authority.issue({
    agent_id: "expense-agent",
    task_id: "task-stage-3",
    expires_at: new Date(Date.now() + 60_000).toISOString(),
    operations: ["create", "submit"],
    resources: ["expense_report_draft", "expense-report-*"],
    destinations: ["expenses.company.test/**"]
  });
  const service = new SyntheticExpenseService(authority);
  const adapter: ToolAdapter = faults.size
    ? new FaultInjectingAdapter(service, faults)
    : service;
  const baseVerifier: OutcomeVerifier = new SyntheticExpenseVerifier(service);
  const verifier: OutcomeVerifier = verifierFaults.size
    ? new FaultInjectingVerifier(baseVerifier, verifierFaults)
    : baseVerifier;
  const ledger = new EvidenceLedger();
  const recovery = new RecoveryManager();
  const approvals = new ApprovalCheckpointManager();
  const gateway = new ActionGateway(
    policy,
    authority,
    approvals,
    new Map([
      ["create", adapter],
      ["submit", adapter]
    ]),
    {
      ledger,
      recovery,
      verifiers: new Map([
        ["create", verifier],
        ["submit", verifier]
      ])
    }
  );

  return {
    gateway,
    ledger,
    service,
    token,
    approvals
  };
}

describe("Stage 3 evidence, replay, verification, and recovery", () => {
  it("detects modified evidence without exposing mutable internal entries", () => {
    let eventNumber = 0;
    const ledger = new EvidenceLedger(
      () => new Date("2026-08-03T00:00:00.000Z"),
      () => `event-${++eventNumber}`
    );
    ledger.append({
      run_id: "run-integrity",
      action_id: "action-1",
      event_type: "action_proposed",
      payload: {
        value: 1
      }
    });
    ledger.append({
      run_id: "run-integrity",
      action_id: "action-1",
      event_type: "policy_decision",
      payload: {
        decision: "allow"
      }
    });

    const exportedEntries = ledger.read();
    const firstEntry = exportedEntries[0];

    if (!firstEntry) {
      throw new Error("Expected a first evidence entry.");
    }

    firstEntry.payload.value = 999;

    expect(ledger.verify()).toEqual({
      valid: true,
      checked_entries: 2
    });
    expect(EvidenceLedger.verifyEntries(exportedEntries)).toMatchObject({
      valid: false,
      broken_at_sequence: 1,
      reason: "Entry content does not match its recorded hash."
    });
  });

  it("replays a verified run deterministically with a mocked tool", async () => {
    const {
      gateway,
      ledger,
      token
    } = createRuntime();
    ledger.append({
      run_id: "unrelated-run",
      event_type: "action_proposed",
      payload: {
        intentionally_unrelated: true
      }
    });
    const proposal = makeCreateProposal("action-replay");
    const execution = await gateway.execute({
      proposal,
      capability_token: token,
      run_id: "run-replay"
    });

    expect(execution.status).toBe("executed");

    if (execution.status !== "executed") {
      throw new Error("Expected the recorded action to execute.");
    }

    expect(execution.verification?.status).toBe("verified");
    expect(ledger.verify()).toMatchObject({ valid: true });

    let replayCalls = 0;
    const replayTool: ReplayTool = {
      execute: async (): Promise<AdapterResult> => {
        replayCalls += 1;
        return structuredClone(execution.result);
      }
    };
    const engine = new ReplayEngine();
    const outcomes = await engine.replay(
      ledger.read(),
      policy,
      new Map([["create", replayTool]]),
      "run-replay"
    );

    expect(replayCalls).toBe(1);
    expect(outcomes).toHaveLength(1);
    expect(outcomes[0]).toMatchObject({
      action_id: proposal.action_id,
      equivalent: true,
      replay_decision: {
        decision: "allow"
      },
      replay_result: execution.result
    });

    replayCalls = 0;
    const stricterPolicy = policySetSchema.parse({
      id: "strict-replay-policy",
      version: "2.0.0",
      default_effect: "deny",
      rules: []
    });
    const stricterOutcomes = await engine.replay(
      ledger.read(),
      stricterPolicy,
      new Map([["create", replayTool]]),
      "run-replay"
    );

    expect(replayCalls).toBe(0);
    expect(stricterOutcomes[0]).toMatchObject({
      equivalent: false,
      replay_decision: {
        decision: "deny"
      }
    });
  });

  it("restores a reversible mutation after an injected post-execution failure", async () => {
    const proposal = makeCreateProposal("action-fail-after");
    const runtime = createRuntime(
      new Map([
        [
          proposal.action_id,
          {
            mode: "throw_after_execution"
          }
        ]
      ])
    );

    await expect(
      runtime.gateway.execute({
        proposal,
        capability_token: runtime.token,
        run_id: "run-recovery"
      })
    ).rejects.toBeInstanceOf(InjectedFailureError);

    expect(runtime.service.draftCount).toBe(0);
    expect(
      runtime.ledger.read("run-recovery").map((entry) => entry.event_type)
    ).toEqual([
      "action_proposed",
      "policy_decision",
      "checkpoint_captured",
      "execution_failed",
      "recovery_started",
      "recovery_succeeded"
    ]);
    expect(runtime.ledger.verify()).toMatchObject({ valid: true });
  });

  it("catches false tool success through independent state verification", async () => {
    const proposal = makeCreateProposal("action-false-success");
    const runtime = createRuntime(
      new Map([
        [
          proposal.action_id,
          {
            mode: "false_success",
            false_result: {
              status: "draft_created",
              draft_id: "draft-fake",
              amount: 428.17,
              receipt_count: 5
            }
          }
        ]
      ])
    );
    const result = await runtime.gateway.execute({
      proposal,
      capability_token: runtime.token,
      run_id: "run-false-success"
    });

    expect(result.status).toBe("verification_failed");

    if (result.status === "verification_failed") {
      expect(result.verification).toMatchObject({
        status: "failed",
        evidence: {
          draft_id: "draft-fake",
          observed_draft: null
        }
      });
      expect(result.recovery?.status).toBe("recovered");
    }

    expect(runtime.service.draftCount).toBe(0);
    expect(
      runtime.ledger
        .read("run-false-success")
        .map((entry) => entry.event_type)
    ).toContain("verification_failed");
  });

  it("records verifier crashes and recovers the resulting uncertain mutation", async () => {
    const proposal = makeCreateProposal("action-verifier-crash");
    const runtime = createRuntime(
      new Map(),
      new Map([
        [
          proposal.action_id,
          {
            mode: "throw"
          }
        ]
      ])
    );
    const result = await runtime.gateway.execute({
      proposal,
      capability_token: runtime.token,
      run_id: "run-verifier-crash"
    });

    expect(result.status).toBe("verification_failed");

    if (result.status === "verification_failed") {
      expect(result.verification).toMatchObject({
        status: "failed",
        evidence: {
          verifier_error: {
            name: "InjectedVerifierFailureError"
          }
        }
      });
      expect(result.recovery?.status).toBe("recovered");
    }

    expect(runtime.service.draftCount).toBe(0);
    expect(
      runtime.ledger
        .read("run-verifier-crash")
        .map((entry) => entry.event_type)
    ).toContain("recovery_succeeded");
  });

  it("supports a single-use manual recovery transaction", async () => {
    const runtime = createRuntime();
    const proposal = makeCreateProposal("action-manual-recovery");
    const execution = await runtime.gateway.execute({
      proposal,
      capability_token: runtime.token,
      run_id: "run-manual-recovery"
    });

    expect(execution.status).toBe("executed");

    if (
      execution.status !== "executed" ||
      !execution.recovery_checkpoint
    ) {
      throw new Error("Expected a recoverable execution checkpoint.");
    }

    expect(runtime.service.draftCount).toBe(1);
    const recovered = await runtime.gateway.recover({
      proposal,
      capability_token: runtime.token,
      recovery_checkpoint_id:
        execution.recovery_checkpoint.checkpoint_id,
      run_id: "run-manual-recovery"
    });

    expect(recovered).toMatchObject({
      status: "recovered",
      checkpoint: {
        status: "restored"
      },
      result: {
        status: "state_restored",
        draft_count: 0
      }
    });
    expect(runtime.service.draftCount).toBe(0);

    await expect(
      runtime.gateway.recover({
        proposal,
        capability_token: runtime.token,
        recovery_checkpoint_id:
          execution.recovery_checkpoint.checkpoint_id,
        run_id: "run-manual-recovery"
      })
    ).rejects.toMatchObject({
      code: "RECOVERY_CHECKPOINT_CONSUMED"
    });
  });

  it("uses a compensating transaction for an externally reversible action", async () => {
    const runtime = createRuntime();
    const draftProposal = makeCreateProposal("action-compensation-draft");
    const draftExecution = await runtime.gateway.execute({
      proposal: draftProposal,
      capability_token: runtime.token,
      run_id: "run-compensation"
    });

    if (draftExecution.status !== "executed") {
      throw new Error("Expected the draft to be created.");
    }

    const draftId = draftExecution.result.draft_id;

    if (typeof draftId !== "string") {
      throw new Error("Expected a synthetic draft ID.");
    }

    const submitProposal: ActionProposal = {
      action_id: "action-compensating-submit",
      agent_id: "expense-agent",
      task_id: "task-stage-3",
      operation: "submit",
      resource: "expense-report-0728",
      destination: "expenses.company.test/reports",
      parameters: {
        draft_id: draftId,
        amount: 428.17
      },
      data_labels: ["PERSONAL", "FINANCIAL"],
      reason: "Submit the synthetic expense report",
      expected_effect: "Create one external claim for $428.17",
      recoverability: "EXTERNALLY_REVERSIBLE",
      risk_level: "high"
    };
    const pending = await runtime.gateway.execute({
      proposal: submitProposal,
      capability_token: runtime.token,
      run_id: "run-compensation"
    });

    if (pending.status !== "approval_required") {
      throw new Error("Expected approval before submission.");
    }

    runtime.approvals.approve(
      pending.checkpoint.checkpoint_id,
      "demo-user"
    );
    const submission = await runtime.gateway.execute({
      proposal: submitProposal,
      capability_token: runtime.token,
      checkpoint_id: pending.checkpoint.checkpoint_id,
      run_id: "run-compensation"
    });

    expect(submission.status).toBe("executed");

    if (
      submission.status !== "executed" ||
      !submission.recovery_checkpoint
    ) {
      throw new Error("Expected a compensating recovery checkpoint.");
    }

    expect(submission.recovery_checkpoint.strategy).toBe(
      "compensating_action"
    );
    expect(runtime.service.claimCount).toBe(1);

    const compensation = await runtime.gateway.recover({
      proposal: submitProposal,
      capability_token: runtime.token,
      recovery_checkpoint_id:
        submission.recovery_checkpoint.checkpoint_id,
      run_id: "run-compensation"
    });

    expect(compensation.result).toMatchObject({
      status: "claim_withdrawn"
    });
    expect(runtime.service.claimCount).toBe(0);
  });
});
