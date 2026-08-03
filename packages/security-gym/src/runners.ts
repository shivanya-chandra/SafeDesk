import type { ActionProposal } from "@safedesk/contracts";
import {
  ActionGateway,
  ApprovalCheckpointManager,
  CapabilityAuthority,
  EvidenceLedger,
  RecoveryManager,
  type GatewayResult,
  type ToolAdapter
} from "@safedesk/runtime";
import {
  SecurityGymAdapter,
  SecurityGymVerifier
} from "./gym-adapter.js";
import { calculateMetrics } from "./metrics.js";
import { securityScenarios, validateScenarios } from "./scenarios.js";
import type {
  ActionOutcome,
  ProfileReport,
  ScenarioAction,
  ScenarioRunResult,
  SecurityGymReport,
  SecurityScenario
} from "./types.js";
import { GymWorld } from "./world.js";

function errorReason(error: unknown): string {
  if (error && typeof error === "object" && "code" in error) {
    return String(error.code);
  }

  return error instanceof Error ? error.message : String(error);
}

function completedGoal(
  scenario: SecurityScenario,
  world: GymWorld
): boolean {
  return scenario.goal_effects.every((effectId) => world.hasEffect(effectId));
}

function scenarioResult(
  scenario: SecurityScenario,
  profile: ScenarioRunResult["profile"],
  world: GymWorld,
  outcomes: ActionOutcome[],
  evidence: {
    valid: boolean | null;
    count: number;
    recoveryAttempts: number;
    recoverySuccesses: number;
  }
): ScenarioRunResult {
  const utilizedOperations = [
    ...new Set(
      outcomes
        .filter((outcome) => outcome.status !== "blocked")
        .map((outcome) => outcome.operation)
    )
  ];
  const forbiddenObserved = world.observed(scenario.forbidden_effects);

  return {
    scenario_id: scenario.id,
    title: scenario.title,
    category: scenario.category,
    profile,
    task_completed: completedGoal(scenario, world),
    attack_contained: forbiddenObserved.length === 0,
    goal_effects_observed: world.observed(scenario.goal_effects),
    forbidden_effects_observed: forbiddenObserved,
    outcomes,
    evidence_chain_valid: evidence.valid,
    evidence_event_count: evidence.count,
    recovery_attempts: evidence.recoveryAttempts,
    recovery_successes: evidence.recoverySuccesses,
    utilized_operations: utilizedOperations,
    granted_operations:
      profile === "safedesk" ? [...new Set(scenario.capability.operations)] : []
  };
}

export class BaselineRunner {
  async run(scenario: SecurityScenario): Promise<ScenarioRunResult> {
    const world = new GymWorld();
    const outcomes: ActionOutcome[] = [];

    for (const action of scenario.actions) {
      world.executeUnchecked(action);
      outcomes.push({
        action_id: action.proposal.action_id,
        operation: action.proposal.operation,
        expectation: action.expectation,
        status: "executed",
        reason: "Baseline trusted the proposed action and tool response.",
        verification_performed: false,
        verified: false,
        approval_required: false,
        deduplicated: false
      });
    }

    return scenarioResult(scenario, "baseline", world, outcomes, {
      valid: null,
      count: 0,
      recoveryAttempts: 0,
      recoverySuccesses: 0
    });
  }
}

function outcomeFromResult(
  action: ScenarioAction,
  result: GatewayResult,
  approvalRequired: boolean
): ActionOutcome {
  if (result.status === "denied") {
    return {
      action_id: action.proposal.action_id,
      operation: action.proposal.operation,
      expectation: action.expectation,
      status: "blocked",
      reason: result.decision.explanation,
      verification_performed: false,
      verified: false,
      approval_required: approvalRequired,
      deduplicated: false
    };
  }

  if (result.status === "approval_required") {
    return {
      action_id: action.proposal.action_id,
      operation: action.proposal.operation,
      expectation: action.expectation,
      status: "blocked",
      reason: "Required approval was not granted.",
      verification_performed: false,
      verified: false,
      approval_required: true,
      deduplicated: false
    };
  }

  if (result.status === "verification_failed") {
    return {
      action_id: action.proposal.action_id,
      operation: action.proposal.operation,
      expectation: action.expectation,
      status: "verification_failed",
      reason: result.verification.explanation,
      verification_performed: true,
      verified: false,
      approval_required: approvalRequired,
      deduplicated: Boolean(result.result.deduplicated)
    };
  }

  return {
    action_id: action.proposal.action_id,
    operation: action.proposal.operation,
    expectation: action.expectation,
    status: "executed",
    reason:
      result.verification?.explanation ?? "Action executed without a verifier.",
    verification_performed: Boolean(result.verification),
    verified: result.verification?.status === "verified",
    approval_required: approvalRequired,
    deduplicated: Boolean(result.result.deduplicated)
  };
}

async function executeProtectedAction(
  gateway: ActionGateway,
  approvals: ApprovalCheckpointManager,
  action: ScenarioAction,
  capabilityToken: string,
  runId: string
): Promise<ActionOutcome> {
  let approvalRequired = false;

  try {
    let result = await gateway.execute({
      proposal: action.proposal,
      capability_token: capabilityToken,
      run_id: runId
    });

    if (result.status === "approval_required") {
      approvalRequired = true;

      if (!action.auto_approve) {
        return outcomeFromResult(action, result, true);
      }

      approvals.approve(result.checkpoint.checkpoint_id, "gym-user");
      result = await gateway.execute({
        proposal: action.proposal,
        capability_token: capabilityToken,
        checkpoint_id: result.checkpoint.checkpoint_id,
        run_id: runId
      });
    }

    return outcomeFromResult(action, result, approvalRequired);
  } catch (error) {
    return {
      action_id: action.proposal.action_id,
      operation: action.proposal.operation,
      expectation: action.expectation,
      status: "blocked",
      reason: errorReason(error),
      verification_performed: false,
      verified: false,
      approval_required: approvalRequired,
      deduplicated: false
    };
  }
}

export class SafeDeskRunner {
  async run(scenario: SecurityScenario): Promise<ScenarioRunResult> {
    const world = new GymWorld();
    const authority = new CapabilityAuthority(
      `security-gym-${scenario.id}`.padEnd(64, "-")
    );
    const capabilityToken = authority.issue({
      agent_id: "security-gym-agent",
      task_id: scenario.id,
      expires_at: new Date(Date.now() + 60_000).toISOString(),
      operations: scenario.capability.operations,
      resources: scenario.capability.resources,
      ...(scenario.capability.destinations
        ? { destinations: scenario.capability.destinations }
        : {})
    });
    const adapter = new SecurityGymAdapter(scenario, world, authority);
    const verifier = new SecurityGymVerifier(scenario, world);
    const approvals = new ApprovalCheckpointManager();
    const ledger = new EvidenceLedger();
    const recovery = new RecoveryManager();
    const adapterEntries = scenario.capability.operations.map(
      (operation): [string, ToolAdapter] => [operation, adapter]
    );
    const verifierEntries = scenario.capability.operations.map(
      (operation) => [operation, verifier] as const
    );
    const gateway = new ActionGateway(
      scenario.policy,
      authority,
      approvals,
      new Map(adapterEntries),
      {
        ledger,
        recovery,
        verifiers: new Map(verifierEntries)
      }
    );
    const outcomes: ActionOutcome[] = [];

    for (const action of scenario.actions) {
      outcomes.push(
        await executeProtectedAction(
          gateway,
          approvals,
          action,
          capabilityToken,
          scenario.id
        )
      );
    }

    const entries = ledger.read();
    const recoveryAttempts = entries.filter(
      (entry) => entry.event_type === "recovery_started"
    ).length;
    const recoverySuccesses = entries.filter(
      (entry) => entry.event_type === "recovery_succeeded"
    ).length;

    return scenarioResult(scenario, "safedesk", world, outcomes, {
      valid: ledger.verify().valid,
      count: entries.length,
      recoveryAttempts,
      recoverySuccesses
    });
  }
}

async function runProfile(
  profile: ProfileReport["profile"],
  scenarios: readonly SecurityScenario[]
): Promise<ProfileReport> {
  const runner =
    profile === "baseline" ? new BaselineRunner() : new SafeDeskRunner();
  const scenarioResults: ScenarioRunResult[] = [];

  for (const scenario of scenarios) {
    scenarioResults.push(await runner.run(scenario));
  }

  return {
    profile,
    scenario_results: scenarioResults,
    metrics: calculateMetrics(scenarioResults)
  };
}

export async function runSecurityGym(
  scenarios: readonly SecurityScenario[] = securityScenarios
): Promise<SecurityGymReport> {
  validateScenarios(scenarios);
  const baseline = await runProfile("baseline", scenarios);
  const safedesk = await runProfile("safedesk", scenarios);

  return {
    benchmark: "SafeDesk Agent Security Gym",
    version: "1.0.0",
    scenario_count: scenarios.length,
    baseline,
    safedesk
  };
}

export function proposalKey(proposal: ActionProposal): string {
  return `${proposal.task_id}:${proposal.action_id}`;
}
