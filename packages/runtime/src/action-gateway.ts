import {
  actionProposalSchema,
  policySetSchema,
  type ActionProposal,
  type PolicyDecision,
  type PolicySet
} from "@safedesk/contracts";
import { evaluateAction } from "@safedesk/policy-engine";
import type {
  AdapterResult,
  ToolAdapter
} from "./adapters.js";
import type { ApprovalCheckpoint } from "./approval-checkpoints.js";
import { ApprovalCheckpointManager } from "./approval-checkpoints.js";
import type { CapabilityAuthority } from "./capability-authority.js";
import { AdapterBoundaryError } from "./errors.js";

export interface GatewayRequest {
  proposal: ActionProposal;
  capability_token: string;
  checkpoint_id?: string;
}

export type GatewayResult =
  | {
      status: "denied";
      decision: PolicyDecision;
    }
  | {
      status: "approval_required";
      decision: PolicyDecision;
      checkpoint: ApprovalCheckpoint;
    }
  | {
      status: "executed";
      decision: PolicyDecision;
      result: AdapterResult;
    };

export class ActionGateway {
  private readonly policy: PolicySet;

  constructor(
    policy: PolicySet,
    private readonly capabilityAuthority: CapabilityAuthority,
    private readonly checkpoints: ApprovalCheckpointManager,
    private readonly adapters: ReadonlyMap<string, ToolAdapter>
  ) {
    this.policy = policySetSchema.parse(policy);
  }

  async execute(rawRequest: GatewayRequest): Promise<GatewayResult> {
    const proposal = actionProposalSchema.parse(rawRequest.proposal);
    this.capabilityAuthority.authorize(
      rawRequest.capability_token,
      proposal
    );
    const decision = evaluateAction(this.policy, proposal);

    if (decision.decision === "deny") {
      return {
        status: "denied",
        decision
      };
    }

    if (decision.decision === "require_approval") {
      if (!rawRequest.checkpoint_id) {
        return {
          status: "approval_required",
          decision,
          checkpoint: this.checkpoints.request(proposal, decision)
        };
      }

      this.checkpoints.consume(
        rawRequest.checkpoint_id,
        proposal,
        decision
      );
    }

    const adapter = this.adapters.get(proposal.operation);

    if (!adapter) {
      throw new AdapterBoundaryError(
        "ADAPTER_NOT_FOUND",
        `No adapter is registered for operation: ${proposal.operation}.`
      );
    }

    return {
      status: "executed",
      decision,
      result: await adapter.execute(
        proposal,
        rawRequest.capability_token
      )
    };
  }
}

