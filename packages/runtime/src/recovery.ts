import {
  createHash,
  randomUUID
} from "node:crypto";
import type {
  ActionProposal,
  RecoveryClass
} from "@safedesk/contracts";
import type {
  AdapterResult,
  ToolAdapter
} from "./adapters.js";
import { canonicalJson } from "./canonical-json.js";
import type { RuntimeClock } from "./capability-authority.js";
import {
  AdapterBoundaryError,
  RecoveryError
} from "./errors.js";

export type RecoveryCheckpointStatus = "available" | "restored";
export type RecoveryStrategy = "snapshot_restore" | "compensating_action";

export interface RecoveryCheckpointView {
  checkpoint_id: string;
  action_id: string;
  action_digest: string;
  snapshot_digest: string;
  recoverability: RecoveryClass;
  strategy: RecoveryStrategy;
  captured_at: string;
  status: RecoveryCheckpointStatus;
}

interface StoredRecoveryCheckpoint extends RecoveryCheckpointView {
  snapshot: unknown;
  execution_result?: AdapterResult;
}

function digest(value: unknown): string {
  return createHash("sha256")
    .update(canonicalJson(value))
    .digest("hex");
}

function toView(checkpoint: StoredRecoveryCheckpoint): RecoveryCheckpointView {
  const {
    snapshot: _snapshot,
    execution_result: _executionResult,
    ...view
  } = checkpoint;

  return { ...view };
}

function supportsSnapshotRecovery(
  adapter: ToolAdapter
): adapter is ToolAdapter & Required<Pick<ToolAdapter, "captureState" | "restoreState">> {
  return Boolean(adapter.captureState && adapter.restoreState);
}

function supportsCompensation(
  adapter: ToolAdapter
): adapter is ToolAdapter & Required<Pick<ToolAdapter, "compensate">> {
  return Boolean(adapter.compensate);
}

export class RecoveryManager {
  private readonly checkpoints = new Map<string, StoredRecoveryCheckpoint>();

  constructor(private readonly clock: RuntimeClock = () => new Date()) {}

  async capture(
    adapter: ToolAdapter,
    proposal: ActionProposal,
    capabilityToken: string
  ): Promise<RecoveryCheckpointView | undefined> {
    if (proposal.recoverability === "IRREVERSIBLE") {
      return undefined;
    }

    const prefersCompensation =
      proposal.recoverability === "COMPENSATING_ACTION_AVAILABLE" ||
      proposal.recoverability === "EXTERNALLY_REVERSIBLE";
    const strategy: RecoveryStrategy | undefined =
      prefersCompensation && supportsCompensation(adapter)
        ? "compensating_action"
        : supportsSnapshotRecovery(adapter)
          ? "snapshot_restore"
          : supportsCompensation(adapter)
            ? "compensating_action"
            : undefined;

    if (!strategy) {
      return undefined;
    }

    let snapshot: unknown = null;

    if (strategy === "snapshot_restore") {
      if (!supportsSnapshotRecovery(adapter)) {
        throw new AdapterBoundaryError(
          "RECOVERY_NOT_SUPPORTED",
          "Adapter does not implement state capture."
        );
      }

      snapshot = await adapter.captureState(proposal, capabilityToken);
    }
    const checkpoint: StoredRecoveryCheckpoint = {
      checkpoint_id: randomUUID(),
      action_id: proposal.action_id,
      action_digest: digest(proposal),
      snapshot_digest: digest(snapshot),
      recoverability: proposal.recoverability,
      strategy,
      captured_at: this.clock().toISOString(),
      status: "available",
      snapshot: structuredClone(snapshot)
    };

    this.checkpoints.set(checkpoint.checkpoint_id, checkpoint);
    return toView(checkpoint);
  }

  recordExecution(
    checkpointId: string,
    result: AdapterResult
  ): RecoveryCheckpointView {
    const checkpoint = this.getStored(checkpointId);
    checkpoint.execution_result = structuredClone(result);
    return toView(checkpoint);
  }

  get(checkpointId: string): RecoveryCheckpointView {
    return toView(this.getStored(checkpointId));
  }

  async recover(
    checkpointId: string,
    adapter: ToolAdapter,
    proposal: ActionProposal,
    capabilityToken: string
  ): Promise<{
    checkpoint: RecoveryCheckpointView;
    result: AdapterResult;
  }> {
    const checkpoint = this.getStored(checkpointId);

    if (checkpoint.status === "restored") {
      throw new RecoveryError(
        "RECOVERY_CHECKPOINT_CONSUMED",
        "Recovery checkpoint has already been restored."
      );
    }

    if (
      checkpoint.action_id !== proposal.action_id ||
      checkpoint.action_digest !== digest(proposal)
    ) {
      throw new RecoveryError(
        "RECOVERY_ACTION_CHANGED",
        "Recovery request does not match the checkpointed action."
      );
    }

    let result: AdapterResult;

    if (checkpoint.strategy === "compensating_action") {
      if (!supportsCompensation(adapter)) {
        throw new AdapterBoundaryError(
          "RECOVERY_NOT_SUPPORTED",
          "Adapter does not implement a compensating action."
        );
      }

      if (!checkpoint.execution_result) {
        throw new RecoveryError(
          "RECOVERY_RESULT_MISSING",
          "Compensation requires the recorded execution result."
        );
      }

      result = await adapter.compensate(
        proposal,
        structuredClone(checkpoint.execution_result),
        capabilityToken
      );
    } else {
      if (!supportsSnapshotRecovery(adapter)) {
        throw new AdapterBoundaryError(
          "RECOVERY_NOT_SUPPORTED",
          "Adapter does not implement state restoration."
        );
      }

      result = await adapter.restoreState(
        proposal,
        structuredClone(checkpoint.snapshot),
        capabilityToken
      );
    }

    checkpoint.status = "restored";

    return {
      checkpoint: toView(checkpoint),
      result
    };
  }

  private getStored(checkpointId: string): StoredRecoveryCheckpoint {
    const checkpoint = this.checkpoints.get(checkpointId);

    if (!checkpoint) {
      throw new RecoveryError(
        "RECOVERY_CHECKPOINT_NOT_FOUND",
        "Recovery checkpoint does not exist."
      );
    }

    return checkpoint;
  }
}
