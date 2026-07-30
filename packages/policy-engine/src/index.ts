import {
  actionProposalSchema,
  policySetSchema,
  type ActionProposal,
  type PolicyConditions,
  type PolicyDecision,
  type PolicyEffect,
  type PolicyRule,
  type PolicySet
} from "@safedesk/contracts";

const effectPrecedence: Record<PolicyEffect, number> = {
  allow: 1,
  require_approval: 2,
  deny: 3
};

export function matchesPattern(value: string, pattern: string): boolean {
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&");
  const expression = escaped.replaceAll("**", "\u0000").replaceAll("*", "[^/]*").replaceAll("\u0000", ".*");
  return new RegExp(`^${expression}$`).test(value);
}

function anyPatternMatches(value: string, patterns: string[]): boolean {
  return patterns.some((pattern) => matchesPattern(value, pattern));
}

function conditionsMatch(
  proposal: ActionProposal,
  conditions: PolicyConditions
): boolean {
  if (
    conditions.agent_ids &&
    !conditions.agent_ids.includes(proposal.agent_id)
  ) {
    return false;
  }

  if (
    conditions.operations &&
    !anyPatternMatches(proposal.operation, conditions.operations)
  ) {
    return false;
  }

  if (
    conditions.resources &&
    !anyPatternMatches(proposal.resource, conditions.resources)
  ) {
    return false;
  }

  if (
    conditions.destinations &&
    (!proposal.destination ||
      !anyPatternMatches(proposal.destination, conditions.destinations))
  ) {
    return false;
  }

  if (
    conditions.data_labels_any &&
    !conditions.data_labels_any.some((label) =>
      proposal.data_labels.includes(label)
    )
  ) {
    return false;
  }

  if (
    conditions.risk_levels &&
    !conditions.risk_levels.includes(proposal.risk_level)
  ) {
    return false;
  }

  return true;
}

function strongestEffect(rules: PolicyRule[]): PolicyEffect {
  return rules.reduce<PolicyEffect>(
    (strongest, rule) =>
      effectPrecedence[rule.effect] > effectPrecedence[strongest]
        ? rule.effect
        : strongest,
    "allow"
  );
}

export function evaluateAction(
  rawPolicy: PolicySet,
  rawProposal: ActionProposal
): PolicyDecision {
  const policy = policySetSchema.parse(rawPolicy);
  const proposal = actionProposalSchema.parse(rawProposal);
  const matchedRules = policy.rules.filter((rule) =>
    conditionsMatch(proposal, rule.conditions)
  );

  if (matchedRules.length === 0) {
    return {
      action_id: proposal.action_id,
      decision: policy.default_effect,
      matched_policies: [],
      policy_id: policy.id,
      policy_version: policy.version,
      risk_level: proposal.risk_level,
      explanation: `No policy rule matched; applied default effect: ${policy.default_effect}.`
    };
  }

  const decision = strongestEffect(matchedRules);
  const decisiveRules = matchedRules.filter((rule) => rule.effect === decision);

  return {
    action_id: proposal.action_id,
    decision,
    matched_policies: matchedRules.map((rule) => rule.id),
    policy_id: policy.id,
    policy_version: policy.version,
    risk_level: proposal.risk_level,
    explanation: decisiveRules.map((rule) => rule.explanation).join(" ")
  };
}
