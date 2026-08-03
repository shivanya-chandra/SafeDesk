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

const actionParametersSchema: z.ZodType<Record<string, unknown>> = z.record(
  z.string(),
  z.unknown()
);

export const actionProposalSchema = z.object({
  action_id: z.string().min(1),
  agent_id: z.string().min(1),
  task_id: z.string().min(1),
  operation: z.string().min(1),
  resource: z.string().min(1),
  destination: z.string().min(1).optional(),
  parameters: actionParametersSchema.optional(),
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

export const policyDecisionSchema = z.object({
  action_id: z.string().min(1),
  decision: policyEffectSchema,
  matched_policies: z.array(z.string()),
  policy_id: z.string().min(1),
  policy_version: z.string().min(1),
  risk_level: riskLevelSchema,
  explanation: z.string()
}).strict();

export interface CapabilityGrant {
  agent_id: string;
  task_id: string;
  expires_at: string;
  operations: string[];
  resources: string[];
  destinations?: string[] | undefined;
}

export interface CapabilityManifest extends CapabilityGrant {
  capability_id: string;
  issued_at: string;
}

export const capabilityGrantSchema: z.ZodType<CapabilityGrant> = z.object({
  agent_id: z.string().min(1),
  task_id: z.string().min(1),
  expires_at: z.string().datetime(),
  operations: z.array(z.string().min(1)).min(1),
  resources: z.array(z.string().min(1)).min(1),
  destinations: z.array(z.string().min(1)).min(1).optional()
}).strict();

export const capabilityManifestSchema: z.ZodType<CapabilityManifest> = z.object({
  capability_id: z.string().min(1),
  agent_id: z.string().min(1),
  task_id: z.string().min(1),
  issued_at: z.string().datetime(),
  expires_at: z.string().datetime(),
  operations: z.array(z.string().min(1)).min(1),
  resources: z.array(z.string().min(1)).min(1),
  destinations: z.array(z.string().min(1)).min(1).optional()
}).strict();

export type DataLabel = z.infer<typeof dataLabelSchema>;
export type RecoveryClass = z.infer<typeof recoveryClassSchema>;
export type RiskLevel = z.infer<typeof riskLevelSchema>;
export type ActionProposal = z.infer<typeof actionProposalSchema>;
export type PolicyEffect = z.infer<typeof policyEffectSchema>;
export type PolicyConditions = z.infer<typeof policyConditionsSchema>;
export type PolicyRule = z.infer<typeof policyRuleSchema>;
export type PolicySet = z.infer<typeof policySetSchema>;
export type PolicyDecision = z.infer<typeof policyDecisionSchema>;
