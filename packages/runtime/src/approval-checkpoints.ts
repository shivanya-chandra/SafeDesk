import { createHash, randomUUID } from "node:crypto";
import type {
  ActionProposal,
  PolicyDecision
} from "@safedesk/contracts";
import { canonicalJson } from "./canonical-json.js";
import { ApprovalError } from "./errors.js";
import type { RuntimeClock } from "./capability-authority.js";

export type CheckpointStatus = "pending" | "approved" | "consumed";

export interface ApprovalCheckpoint {
  checkpoint_id: string;
  action_digest: string;
  action_id: string;
  policy_id: string;
  policy_version: string;
  status: CheckpointStatus;
  created_at: string;
  expires_at: string;
  approved_at?: string;
  approver_id?: string;
}

function digestAction(
  proposal: ActionProposal,
  decision: PolicyDecision
): string {
  return createHash("sha256")
    .update(
      canonicalJson({
        proposal,
        policy_id: decision.policy_id,
        policy_version: decision.policy_version
      })
    )
    .digest("hex");
}

export class ApprovalCheckpointManager {
  private readonly checkpoints = new Map<string, ApprovalCheckpoint>();
  private readonly clock: RuntimeClock;
  private readonly ttlMs: number;

  constructor(
    options: {
      clock?: RuntimeClock;
      ttlMs?: number;
    } = {}
  ) {
    this.clock = options.clock ?? (() => new Date());
    this.ttlMs = options.ttlMs ?? 5 * 60 * 1000;
  }

  request(
    proposal: ActionProposal,
    decision: PolicyDecision
  ): ApprovalCheckpoint {
    const now = this.clock();
    const checkpoint: ApprovalCheckpoint = {
      checkpoint_id: randomUUID(),
      action_digest: digestAction(proposal, decision),
      action_id: proposal.action_id,
      policy_id: decision.policy_id,
      policy_version: decision.policy_version,
      status: "pending",
      created_at: now.toISOString(),
      expires_at: new Date(now.getTime() + this.ttlMs).toISOString()
    };

    this.checkpoints.set(checkpoint.checkpoint_id, checkpoint);
    return { ...checkpoint };
  }

  approve(checkpointId: string, approverId: string): ApprovalCheckpoint {
    const checkpoint = this.getMutable(checkpointId);
    this.assertNotExpired(checkpoint);

    if (checkpoint.status !== "pending") {
      throw new ApprovalError(
        "CHECKPOINT_NOT_PENDING",
        "Only a pending checkpoint can be approved."
      );
    }

    checkpoint.status = "approved";
    checkpoint.approved_at = this.clock().toISOString();
    checkpoint.approver_id = approverId;
    return { ...checkpoint };
  }

  consume(
    checkpointId: string,
    proposal: ActionProposal,
    decision: PolicyDecision
  ): ApprovalCheckpoint {
    const checkpoint = this.getMutable(checkpointId);
    this.assertNotExpired(checkpoint);

    if (checkpoint.status === "consumed") {
      throw new ApprovalError(
        "CHECKPOINT_CONSUMED",
        "Approval checkpoint has already been consumed."
      );
    }

    if (checkpoint.status !== "approved") {
      throw new ApprovalError(
        "CHECKPOINT_NOT_APPROVED",
        "Action cannot execute before the checkpoint is approved."
      );
    }

    if (checkpoint.action_digest !== digestAction(proposal, decision)) {
      throw new ApprovalError(
        "ACTION_CHANGED",
        "The proposed action or active policy changed after approval."
      );
    }

    checkpoint.status = "consumed";
    return { ...checkpoint };
  }

  get(checkpointId: string): ApprovalCheckpoint {
    return { ...this.getMutable(checkpointId) };
  }

  private getMutable(checkpointId: string): ApprovalCheckpoint {
    const checkpoint = this.checkpoints.get(checkpointId);

    if (!checkpoint) {
      throw new ApprovalError(
        "CHECKPOINT_NOT_FOUND",
        "Approval checkpoint does not exist."
      );
    }

    return checkpoint;
  }

  private assertNotExpired(checkpoint: ApprovalCheckpoint): void {
    if (new Date(checkpoint.expires_at).getTime() <= this.clock().getTime()) {
      throw new ApprovalError(
        "CHECKPOINT_EXPIRED",
        "Approval checkpoint has expired."
      );
    }
  }
}

