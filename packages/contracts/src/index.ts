import { z } from "zod";

export const dataLabelSchema = z.enum([
  "PUBLIC",
  "PERSONAL",
  "FINANCIAL",
  "CONFIDENTIAL",
  "SECRET",
  "UNTRUSTED"
]);

export const recoveryClassSchema = z.enum([
  "REVERSIBLE",
  "REVERSE_WITHIN_WINDOW",
  "COMPENSATING_ACTION_AVAILABLE",
  "EXTERNALLY_REVERSIBLE",
  "IRREVERSIBLE"
]);

export const riskLevelSchema = z.enum(["low", "medium", "high", "critical"]);

export const actionProposalSchema = z.object({
  action_id: z.string().min(1),
  agent_id: z.string().min(1),
  task_id: z.string().min(1),
  operation: z.string().min(1),
  resource: z.string().min(1),
  destination: z.string().min(1).optional(),
  data_labels: z.array(dataLabelSchema),
  reason: z.string().min(1),
  expected_effect: z.string().min(1),
  recoverability: recoveryClassSchema,
  risk_level: riskLevelSchema
}).strict();

export const policyEffectSchema = z.enum([
  "allow",
  "deny",
  "require_approval"
]);

export const policyConditionsSchema = z.object({
  agent_ids: z.array(z.string().min(1)).min(1).optional(),
  operations: z.array(z.string().min(1)).min(1).optional(),
  resources: z.array(z.string().min(1)).min(1).optional(),
  destinations: z.array(z.string().min(1)).min(1).optional(),
  data_labels_any: z.array(dataLabelSchema).min(1).optional(),
  risk_levels: z.array(riskLevelSchema).min(1).optional()
}).strict();

export const policyRuleSchema = z.object({
  id: z.string().min(1),
  description: z.string().min(1),
  effect: policyEffectSchema,
  conditions: policyConditionsSchema,
  explanation: z.string().min(1)
}).strict();

export const policySetSchema = z.object({
  id: z.string().min(1),
  version: z.string().min(1),
  default_effect: z.literal("deny").default("deny"),
  rules: z.array(policyRuleSchema)
}).strict();

export type DataLabel = z.infer<typeof dataLabelSchema>;
export type RecoveryClass = z.infer<typeof recoveryClassSchema>;
export type RiskLevel = z.infer<typeof riskLevelSchema>;
export type ActionProposal = z.infer<typeof actionProposalSchema>;
export type PolicyEffect = z.infer<typeof policyEffectSchema>;
export type PolicyConditions = z.infer<typeof policyConditionsSchema>;
export type PolicyRule = z.infer<typeof policyRuleSchema>;
export type PolicySet = z.infer<typeof policySetSchema>;

export interface PolicyDecision {
  action_id: string;
  decision: PolicyEffect;
  matched_policies: string[];
  policy_id: string;
  policy_version: string;
  risk_level: RiskLevel;
  explanation: string;
}
