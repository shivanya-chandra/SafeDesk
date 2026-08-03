import type { ActionProposal } from "@safedesk/contracts";
import {
  AdapterBoundaryError,
  type AdapterResult,
  type CapabilityAuthority,
  type OutcomeVerifier,
  type ToolAdapter,
  type VerificationContext,
  type VerificationResult
} from "@safedesk/runtime";
import type {
  ScenarioAction,
  SecurityScenario
} from "./types.js";
import {
  GymWorld,
  type GymWorldSnapshot
} from "./world.js";

interface GymAdapterSnapshot {
  world: GymWorldSnapshot;
  completed_actions: Array<[string, AdapterResult]>;
}
function isAdapterSnapshot(value: unknown): value is GymAdapterSnapshot {
  if (!value || typeof value !== "object") {
    return false;
  }

  const snapshot = value as Record<string, unknown>;

  return (
    Boolean(snapshot.world) &&
    Array.isArray(snapshot.completed_actions)
  );
}

export class SecurityGymAdapter implements ToolAdapter {
  private readonly actions = new Map<string, ScenarioAction>();
  private completedActions = new Map<string, AdapterResult>();

  constructor(
    scenario: SecurityScenario,
    private readonly world: GymWorld,
    private readonly authority: CapabilityAuthority
  ) {
    for (const scenarioAction of scenario.actions) {
      this.actions.set(scenarioAction.proposal.action_id, scenarioAction);
    }
  }

  async execute(
    proposal: ActionProposal,
    capabilityToken: string
  ): Promise<AdapterResult> {
    this.authority.authorize(capabilityToken, proposal);
    const action = this.getAction(proposal.action_id);
    const completed = this.completedActions.get(proposal.action_id);

    if (completed) {
      return {
        ...structuredClone(completed),
        deduplicated: true
      };
    }

    const behavior = action.behavior;
    let result: AdapterResult;

    if (behavior.kind === "redirect") {
      this.authority.authorize(capabilityToken, {
        ...proposal,
        destination: behavior.final_destination
      });
      this.world.recordAction(proposal.action_id);
      this.world.applyEffect(action.effect_id);
      result = {
        status: "navigated",
        effect_id: action.effect_id,
        final_destination: behavior.final_destination
      };
    } else if (behavior.kind === "stale_state") {
      const approvedAmount = proposal.parameters?.approved_amount;

      if (approvedAmount !== behavior.current_amount) {
        throw new AdapterBoundaryError(
          "INVALID_TOOL_INPUT",
          `State changed before execution: approved ${String(approvedAmount)}, current ${behavior.current_amount}.`
        );
      }

      this.world.recordAction(proposal.action_id);
      this.world.applyEffect(action.effect_id);
      result = {
        status: "charged",
        effect_id: action.effect_id,
        charged_amount: behavior.current_amount
      };
    } else if (behavior.kind === "false_success") {
      this.world.recordAction(proposal.action_id);
      result = {
        status: "success",
        effect_id: action.effect_id
      };
    } else {
      this.world.recordAction(proposal.action_id);
      this.world.applyEffect(action.effect_id);
      result = {
        status: "success",
        effect_id: action.effect_id
      };
    }

    this.completedActions.set(
      proposal.action_id,
      structuredClone(result)
    );
    return result;
  }

  async captureState(
    proposal: ActionProposal,
    capabilityToken: string
  ): Promise<unknown> {
    this.authority.authorize(capabilityToken, proposal);

    return {
      world: this.world.snapshot(),
      completed_actions: [...this.completedActions.entries()].map(
        ([actionId, result]) => [actionId, structuredClone(result)]
      )
    } satisfies GymAdapterSnapshot;
  }

  async restoreState(
    proposal: ActionProposal,
    snapshot: unknown,
    capabilityToken: string
  ): Promise<AdapterResult> {
    this.authority.authorize(capabilityToken, proposal);

    if (!isAdapterSnapshot(snapshot)) {
      throw new AdapterBoundaryError(
        "INVALID_TOOL_INPUT",
        "Security Gym recovery snapshot is malformed."
      );
    }

    this.world.restore(snapshot.world);
    this.completedActions = new Map(
      snapshot.completed_actions.map(([actionId, result]) => [
        actionId,
        structuredClone(result)
      ])
    );

    return {
      status: "gym_state_restored"
    };
  }

  private getAction(actionId: string): ScenarioAction {
    const action = this.actions.get(actionId);

    if (!action) {
      throw new AdapterBoundaryError(
        "RESOURCE_NOT_FOUND",
        `No Security Gym action fixture exists for: ${actionId}.`
      );
    }

    return action;
  }
}

export class SecurityGymVerifier implements OutcomeVerifier {
  private readonly actions = new Map<string, ScenarioAction>();

  constructor(
    scenario: SecurityScenario,
    private readonly world: GymWorld
  ) {
    for (const action of scenario.actions) {
      this.actions.set(action.proposal.action_id, action);
    }
  }

  async verify(context: VerificationContext): Promise<VerificationResult> {
    const action = this.actions.get(context.proposal.action_id);

    if (!action) {
      return {
        status: "failed",
        explanation: "No scenario expectation exists for the action.",
        evidence: {}
      };
    }

    const observedCount = this.world.effectCount(action.effect_id);
    const resultEffect = context.adapter_result.effect_id;
    const redirectChangedDestination =
      action.behavior.kind === "redirect" &&
      context.adapter_result.final_destination !== context.proposal.destination;
    const verified =
      observedCount > 0 &&
      resultEffect === action.effect_id &&
      !redirectChangedDestination;

    return {
      status: verified ? "verified" : "failed",
      explanation: verified
        ? "The claimed effect exists in independently observed gym state."
        : "The adapter result does not match independently observed gym state.",
      evidence: {
        expected_effect_id: action.effect_id,
        result_effect_id:
          typeof resultEffect === "string" ? resultEffect : null,
        observed_count: observedCount,
        redirect_changed_destination: redirectChangedDestination
      }
    };
  }
}
