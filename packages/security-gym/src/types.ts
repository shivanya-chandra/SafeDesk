import type {
  ActionProposal,
  PolicySet
} from "@safedesk/contracts";

export type ScenarioCategory =
  | "prompt_injection"
  | "destination_redirect"
  | "confused_recipient"
  | "stale_state"
  | "false_success"
  | "retry_loop"
  | "overblocking_control";

export type SecurityExpectation =
  | "legitimate"
  | "forbidden"
  | "adversarial";

export type ToolBehavior =
  | {
      kind: "normal";
      duplicate_effect_id?: string;
    }
  | {
      kind: "redirect";
      final_destination: string;
      forbidden_effect_id: string;
    }
  | {
      kind: "stale_state";
      current_amount: number;
      forbidden_effect_id: string;
    }
  | {
      kind: "false_success";
      forbidden_effect_id: string;
    };

export interface ScenarioAction {
  proposal: ActionProposal;
  effect_id: string;
  expectation: SecurityExpectation;
  behavior: ToolBehavior;
  auto_approve?: boolean;
}

export interface ScenarioCapability {
  operations: string[];
  resources: string[];
  destinations?: string[];
}

export interface SecurityScenario {
  id: string;
  title: string;
  category: ScenarioCategory;
  description: string;
  legitimate_goal: string;
  goal_effects: string[];
  forbidden_effects: string[];
  policy: PolicySet;
  capability: ScenarioCapability;
  actions: ScenarioAction[];
  fixture_paths?: string[];
}

export type ActionOutcomeStatus =
  | "executed"
  | "blocked"
  | "verification_failed";

export interface ActionOutcome {
  action_id: string;
  operation: string;
  expectation: SecurityExpectation;
  status: ActionOutcomeStatus;
  reason: string;
  verification_performed: boolean;
  verified: boolean;
  approval_required: boolean;
  deduplicated: boolean;
}

export type RunnerProfile = "baseline" | "safedesk";

export interface ScenarioRunResult {
  scenario_id: string;
  title: string;
  category: ScenarioCategory;
  profile: RunnerProfile;
  task_completed: boolean;
  attack_contained: boolean;
  goal_effects_observed: string[];
  forbidden_effects_observed: string[];
  outcomes: ActionOutcome[];
  evidence_chain_valid: boolean | null;
  evidence_event_count: number;
  recovery_attempts: number;
  recovery_successes: number;
  utilized_operations: string[];
  granted_operations: string[];
}

export interface BenchmarkMetrics {
  task_completion_rate: number;
  attack_containment_rate: number | null;
  false_block_rate: number;
  verification_coverage: number;
  recovery_success_rate: number | null;
  permission_utilization: number | null;
}

export interface ProfileReport {
  profile: RunnerProfile;
  scenario_results: ScenarioRunResult[];
  metrics: BenchmarkMetrics;
}

export interface SecurityGymReport {
  benchmark: "SafeDesk Agent Security Gym";
  version: "1.0.0";
  scenario_count: number;
  baseline: ProfileReport;
  safedesk: ProfileReport;
}
