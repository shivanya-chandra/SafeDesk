import type { AdapterResult } from "@safedesk/runtime";
import type { ScenarioAction } from "./types.js";

export interface GymWorldSnapshot {
  effect_counts: Array<[string, number]>;
  action_counts: Array<[string, number]>;
}
function increment(map: Map<string, number>, key: string): number {
  const next = (map.get(key) ?? 0) + 1;
  map.set(key, next);
  return next;
}

function isSnapshot(value: unknown): value is GymWorldSnapshot {
  if (!value || typeof value !== "object") {
    return false;
  }

  const snapshot = value as Record<string, unknown>;

  return (
    Array.isArray(snapshot.effect_counts) &&
    Array.isArray(snapshot.action_counts)
  );
}

export class GymWorld {
  private effectCounts = new Map<string, number>();
  private actionCounts = new Map<string, number>();

  applyEffect(effectId: string): void {
    increment(this.effectCounts, effectId);
  }

  recordAction(actionId: string): number {
    return increment(this.actionCounts, actionId);
  }

  effectCount(effectId: string): number {
    return this.effectCounts.get(effectId) ?? 0;
  }

  hasEffect(effectId: string): boolean {
    return this.effectCount(effectId) > 0;
  }

  observed(effectIds: readonly string[]): string[] {
    return effectIds.filter((effectId) => this.hasEffect(effectId));
  }

  snapshot(): GymWorldSnapshot {
    return {
      effect_counts: [...this.effectCounts.entries()],
      action_counts: [...this.actionCounts.entries()]
    };
  }

  restore(rawSnapshot: unknown): void {
    if (!isSnapshot(rawSnapshot)) {
      throw new Error("Security Gym world snapshot is malformed.");
    }

    this.effectCounts = new Map(rawSnapshot.effect_counts);
    this.actionCounts = new Map(rawSnapshot.action_counts);
  }

  executeUnchecked(action: ScenarioAction): AdapterResult {
    const invocationCount = this.recordAction(action.proposal.action_id);
    const behavior = action.behavior;

    if (behavior.kind === "redirect") {
      this.applyEffect(behavior.forbidden_effect_id);

      return {
        status: "navigated",
        claimed_effect_id: action.effect_id,
        final_destination: behavior.final_destination
      };
    }

    if (behavior.kind === "stale_state") {
      this.applyEffect(action.effect_id);
      this.applyEffect(behavior.forbidden_effect_id);

      return {
        status: "charged",
        claimed_effect_id: action.effect_id,
        charged_amount: behavior.current_amount
      };
    }

    if (behavior.kind === "false_success") {
      this.applyEffect(behavior.forbidden_effect_id);

      return {
        status: "success",
        claimed_effect_id: action.effect_id
      };
    }

    this.applyEffect(action.effect_id);

    if (invocationCount > 1 && behavior.duplicate_effect_id) {
      this.applyEffect(behavior.duplicate_effect_id);
    }

    return {
      status: "success",
      effect_id: action.effect_id,
      invocation_count: invocationCount
    };
  }
}
