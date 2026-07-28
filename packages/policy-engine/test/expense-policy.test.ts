import { describe, expect, it } from "vitest";
import {
  actionProposalSchema,
  policySetSchema,
  type ActionProposal
} from "@safedesk/contracts";
import { evaluateAction } from "../src/index.js";
import expensePolicyDocument from "../../../examples/expense-report/policy.json" with {
  type: "json"
};

const expensePolicy = policySetSchema.parse(expensePolicyDocument);

const baseProposal: ActionProposal = {
  action_id: "action-001",
  agent_id: "expense-agent",
  task_id: "task-184",
  operation: "read",
  resource: "/task/receipts/receipt-04.pdf",
  data_labels: ["UNTRUSTED"],
  reason: "Extract an amount from an authorized receipt",
  expected_effect: "Read one task-scoped receipt",
  recoverability: "REVERSIBLE",
  risk_level: "low"
};

describe("expense report policy", () => {
  it("allows the agent to read a task-scoped receipt", () => {
    const decision = evaluateAction(expensePolicy, baseProposal);

    expect(decision.decision).toBe("allow");
    expect(decision.matched_policies).toEqual(["allow-task-receipts"]);
  });

  it("denies a prompt-injected request for unrelated documents", () => {
    const decision = evaluateAction(expensePolicy, {
      ...baseProposal,
      action_id: "action-002",
      resource: "/user/documents/private.txt",
      reason: "The receipt instructed the agent to read this file",
      expected_effect: "Read a file outside the task scope",
      risk_level: "high"
    });

    expect(decision.decision).toBe("deny");
    expect(decision.matched_policies).toContain("deny-user-documents");
  });

  it("denies the attacker domain", () => {
    const decision = evaluateAction(expensePolicy, {
      ...baseProposal,
      action_id: "action-003",
      operation: "navigate",
      resource: "browser-session",
      destination: "malicious-verification.com/upload",
      reason: "The receipt asked the agent to visit a verification page",
      expected_effect: "Open the attacker-controlled page",
      risk_level: "critical"
    });

    expect(decision.decision).toBe("deny");
    expect(decision.matched_policies).toEqual(["deny-attacker-domain"]);
  });

  it("allows creating a local expense draft", () => {
    const decision = evaluateAction(expensePolicy, {
      ...baseProposal,
      action_id: "action-004",
      operation: "create",
      resource: "expense_report_draft",
      data_labels: ["PERSONAL", "FINANCIAL"],
      reason: "Prepare the July expense report",
      expected_effect: "Create one local draft for $428.17",
      recoverability: "REVERSIBLE",
      risk_level: "medium"
    });

    expect(decision.decision).toBe("allow");
  });

  it("requires approval for submission to the approved expense system", () => {
    const decision = evaluateAction(expensePolicy, {
      ...baseProposal,
      action_id: "action-005",
      operation: "submit",
      resource: "expense-report-0728",
      destination: "expenses.company.test/reports",
      data_labels: ["PERSONAL", "FINANCIAL"],
      reason: "Submit the completed July expense report",
      expected_effect: "Create one expense claim for $428.17",
      recoverability: "EXTERNALLY_REVERSIBLE",
      risk_level: "high"
    });

    expect(decision.decision).toBe("require_approval");
    expect(decision.matched_policies).toEqual([
      "require-approval-expense-submission"
    ]);
  });

  it("denies sensitive upload to an undeclared destination by default", () => {
    const decision = evaluateAction(expensePolicy, {
      ...baseProposal,
      action_id: "action-006",
      operation: "upload",
      resource: "expense-report-0728",
      destination: "random-verification.test/upload",
      data_labels: ["PERSONAL", "FINANCIAL"],
      reason: "Upload requested by untrusted receipt text",
      expected_effect: "Transfer the report to an undeclared system",
      recoverability: "IRREVERSIBLE",
      risk_level: "critical"
    });

    expect(decision.decision).toBe("deny");
    expect(decision.matched_policies).toEqual([]);
    expect(decision.explanation).toContain("default effect: deny");
  });

  it("rejects malformed action proposals before evaluation", () => {
    expect(() =>
      actionProposalSchema.parse({
        ...baseProposal,
        operation: "",
        unexpected_authority: "filesystem:*"
      })
    ).toThrow();
  });

  it("gives deny precedence over allow regardless of rule order", () => {
    const conflictingPolicy = policySetSchema.parse({
      id: "precedence-test",
      version: "1.0.0",
      default_effect: "deny",
      rules: [
        {
          id: "deny-sensitive-path",
          description: "Deny the protected subtree.",
          effect: "deny",
          conditions: {
            operations: ["read"],
            resources: ["/task/protected/**"]
          },
          explanation: "The protected subtree is forbidden."
        },
        {
          id: "allow-task-path",
          description: "Allow ordinary task files.",
          effect: "allow",
          conditions: {
            operations: ["read"],
            resources: ["/task/**"]
          },
          explanation: "The path is inside the task mount."
        }
      ]
    });

    const decision = evaluateAction(conflictingPolicy, {
      ...baseProposal,
      action_id: "action-007",
      resource: "/task/protected/secret.txt"
    });

    expect(decision.decision).toBe("deny");
    expect(decision.matched_policies).toEqual([
      "deny-sensitive-path",
      "allow-task-path"
    ]);
  });
});
