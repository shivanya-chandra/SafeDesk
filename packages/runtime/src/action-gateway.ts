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
import type { EvidenceEventType } from "./evidence-ledger.js";
import { EvidenceLedger } from "./evidence-ledger.js";
import {
  AdapterBoundaryError
} from "./errors.js";
import type {
  RecoveryCheckpointView
} from "./recovery.js";
import { RecoveryManager } from "./recovery.js";
import type {
  OutcomeVerifier,
  VerificationResult
} from "./verification.js";

export interface GatewayRequest {
  proposal: ActionProposal;
  capability_token: string;
  checkpoint_id?: string;
  run_id?: string;
}

export interface GatewayRecoveryRequest {
  proposal: ActionProposal;
  capability_token: string;
  recovery_checkpoint_id: string;
  run_id?: string;
}

export interface GatewayRecoveryResult {
  status: "recovered";
  checkpoint: RecoveryCheckpointView;
  result: AdapterResult;
}

export interface RecoveryAttempt {
  status: "recovered" | "failed";
  checkpoint: RecoveryCheckpointView;
  result?: AdapterResult;
  error?: {
    name: string;
    message: string;
  };
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
      verification?: VerificationResult;
      recovery_checkpoint?: RecoveryCheckpointView;
    }
  | {
      status: "verification_failed";
      decision: PolicyDecision;
      result: AdapterResult;
      verification: VerificationResult;
      recovery?: RecoveryAttempt;
    };

export interface ActionGatewayOptions {
  ledger?: EvidenceLedger;
  verifiers?: ReadonlyMap<string, OutcomeVerifier>;
  recovery?: RecoveryManager;
}

function errorEvidence(error: unknown): {
  name: string;
  message: string;
} {
  if (error instanceof Error) {
    return {
      name: error.name,
      message: error.message
    };
  }

  return {
    name: "UnknownError",
    message: String(error)
  };
}

export class ActionGateway {
  private readonly policy: PolicySet;
  private readonly ledger: EvidenceLedger | undefined;
  private readonly verifiers: ReadonlyMap<string, OutcomeVerifier>;
  private readonly recovery: RecoveryManager | undefined;

  constructor(
    policy: PolicySet,
    private readonly capabilityAuthority: CapabilityAuthority,
    private readonly approvals: ApprovalCheckpointManager,
    private readonly adapters: ReadonlyMap<string, ToolAdapter>,
    options: ActionGatewayOptions = {}
  ) {
    this.policy = policySetSchema.parse(policy);
    this.ledger = options.ledger;
    this.verifiers = options.verifiers ?? new Map();
    this.recovery = options.recovery;
  }

  async execute(rawRequest: GatewayRequest): Promise<GatewayResult> {
    const proposal = actionProposalSchema.parse(rawRequest.proposal);
    const runId = rawRequest.run_id ?? proposal.task_id;
    const capability = this.capabilityAuthority.authorize(
      rawRequest.capability_token,
      proposal
    );

    this.appendEvent(runId, proposal.action_id, "action_proposed", {
      proposal,
      capability_id: capability.capability_id
    });

    const decision = evaluateAction(this.policy, proposal);
    this.appendEvent(runId, proposal.action_id, "policy_decision", {
      decision
    });

    if (decision.decision === "deny") {
      return {
        status: "denied",
        decision
      };
    }

    if (decision.decision === "require_approval") {
      if (!rawRequest.checkpoint_id) {
        const checkpoint = this.approvals.request(proposal, decision);
        this.appendEvent(runId, proposal.action_id, "approval_requested", {
          checkpoint
        });

        return {
          status: "approval_required",
          decision,
          checkpoint
        };
      }

      const checkpoint = this.approvals.consume(
        rawRequest.checkpoint_id,
        proposal,
        decision
      );
      this.appendEvent(runId, proposal.action_id, "approval_consumed", {
        checkpoint_id: checkpoint.checkpoint_id,
        approver_id: checkpoint.approver_id ?? "unknown"
      });
    }

    const adapter = this.getAdapter(proposal.operation);
    const recoveryCheckpoint = await this.recovery?.capture(
      adapter,
      proposal,
      rawRequest.capability_token
    );

    if (recoveryCheckpoint) {
      this.appendEvent(runId, proposal.action_id, "checkpoint_captured", {
        checkpoint: recoveryCheckpoint
      });
    }

    let result: AdapterResult;

    try {
      result = await adapter.execute(
        proposal,
        rawRequest.capability_token
      );

      if (recoveryCheckpoint && this.recovery) {
        this.recovery.recordExecution(
          recoveryCheckpoint.checkpoint_id,
          result
        );
      }

      this.appendEvent(runId, proposal.action_id, "execution_succeeded", {
        result
      });
    } catch (error) {
      this.appendEvent(runId, proposal.action_id, "execution_failed", {
        error: errorEvidence(error)
      });
      await this.tryRecover(
        runId,
        proposal,
        rawRequest.capability_token,
        adapter,
        recoveryCheckpoint
      );
      throw error;
    }

    const verifier = this.verifiers.get(proposal.operation);

    if (!verifier) {
      return {
        status: "executed",
        decision,
        result,
        ...(recoveryCheckpoint
          ? { recovery_checkpoint: recoveryCheckpoint }
          : {})
      };
    }

    let verification: VerificationResult;

    try {
      verification = await verifier.verify({
        proposal,
        adapter_result: result
      });
    } catch (error) {
      verification = {
        status: "failed",
        explanation: "Verifier failed before it could confirm external state.",
        evidence: {
          verifier_error: errorEvidence(error)
        }
      };
    }

    const verificationEvent: EvidenceEventType =
      verification.status === "verified"
        ? "verification_succeeded"
        : "verification_failed";
    this.appendEvent(runId, proposal.action_id, verificationEvent, {
      verification
    });

    if (verification.status === "failed") {
      const recovery = await this.tryRecover(
        runId,
        proposal,
        rawRequest.capability_token,
        adapter,
        recoveryCheckpoint
      );

      return {
        status: "verification_failed",
        decision,
        result,
        verification,
        ...(recovery ? { recovery } : {})
      };
    }

    return {
      status: "executed",
      decision,
      result,
      verification,
      ...(recoveryCheckpoint
        ? { recovery_checkpoint: recoveryCheckpoint }
        : {})
    };
  }

  async recover(
    rawRequest: GatewayRecoveryRequest
  ): Promise<GatewayRecoveryResult> {
    const proposal = actionProposalSchema.parse(rawRequest.proposal);
    const runId = rawRequest.run_id ?? proposal.task_id;
    this.capabilityAuthority.authorize(
      rawRequest.capability_token,
      proposal
    );
    const adapter = this.getAdapter(proposal.operation);

    if (!this.recovery) {
      throw new AdapterBoundaryError(
        "RECOVERY_NOT_SUPPORTED",
        "The action gateway has no recovery manager."
      );
    }

    this.appendEvent(runId, proposal.action_id, "recovery_started", {
      checkpoint_id: rawRequest.recovery_checkpoint_id,
      trigger: "manual"
    });

    try {
      const recovered = await this.recovery.recover(
        rawRequest.recovery_checkpoint_id,
        adapter,
        proposal,
        rawRequest.capability_token
      );
      this.appendEvent(runId, proposal.action_id, "recovery_succeeded", {
        checkpoint: recovered.checkpoint,
        result: recovered.result,
        trigger: "manual"
      });

      return {
        status: "recovered",
        ...recovered
      };
    } catch (error) {
      this.appendEvent(runId, proposal.action_id, "recovery_failed", {
        checkpoint_id: rawRequest.recovery_checkpoint_id,
        error: errorEvidence(error),
        trigger: "manual"
      });
      throw error;
    }
  }

  private getAdapter(operation: string): ToolAdapter {
    const adapter = this.adapters.get(operation);

    if (!adapter) {
      throw new AdapterBoundaryError(
        "ADAPTER_NOT_FOUND",
        `No adapter is registered for operation: ${operation}.`
      );
    }

    return adapter;
  }

  private appendEvent(
    runId: string,
    actionId: string,
    eventType: EvidenceEventType,
    payload: Record<string, unknown>
  ): void {
    this.ledger?.append({
      run_id: runId,
      action_id: actionId,
      event_type: eventType,
      payload
    });
  }

  private async tryRecover(
    runId: string,
    proposal: ActionProposal,
    capabilityToken: string,
    adapter: ToolAdapter,
    checkpoint: RecoveryCheckpointView | undefined
  ): Promise<RecoveryAttempt | undefined> {
    if (!this.recovery || !checkpoint) {
      return undefined;
    }

    this.appendEvent(runId, proposal.action_id, "recovery_started", {
      checkpoint_id: checkpoint.checkpoint_id,
      trigger: "automatic"
    });

    try {
      const recovered = await this.recovery.recover(
        checkpoint.checkpoint_id,
        adapter,
        proposal,
        capabilityToken
      );
      this.appendEvent(runId, proposal.action_id, "recovery_succeeded", {
        checkpoint: recovered.checkpoint,
        result: recovered.result,
        trigger: "automatic"
      });

      return {
        status: "recovered",
        checkpoint: recovered.checkpoint,
        result: recovered.result
      };
    } catch (error) {
      const normalizedError = errorEvidence(error);
      this.appendEvent(runId, proposal.action_id, "recovery_failed", {
        checkpoint_id: checkpoint.checkpoint_id,
        error: normalizedError,
        trigger: "automatic"
      });

      return {
        status: "failed",
        checkpoint,
        error: normalizedError
      };
    }
  }
}
