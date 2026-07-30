import { describe, expect, it } from "vitest";
import type { ActionProposal } from "@safedesk/contracts";
import {
  AuthorizationError,
  CapabilityAuthority
} from "../src/index.js";

const proposal: ActionProposal = {
  action_id: "action-001",
  agent_id: "expense-agent",
  task_id: "task-184",
  operation: "read",
  resource: "/task/receipts/receipt-04.txt",
  data_labels: ["UNTRUSTED"],
  reason: "Read an authorized task receipt",
  expected_effect: "Return the receipt text",
  recoverability: "REVERSIBLE",
  risk_level: "low"
};

describe("CapabilityAuthority", () => {
  it("rejects a forged token", () => {
    const authority = new CapabilityAuthority("a".repeat(32));

    expect(() => authority.authorize("forged-token", proposal)).toThrow(
      AuthorizationError
    );
  });

  it("rejects a capability after its expiration time", () => {
    let now = new Date("2026-07-30T00:00:00.000Z");
    const authority = new CapabilityAuthority(
      "b".repeat(32),
      () => now
    );
    const token = authority.issue({
      agent_id: proposal.agent_id,
      task_id: proposal.task_id,
      expires_at: "2026-07-30T00:01:00.000Z",
      operations: ["read"],
      resources: ["/task/receipts/**"]
    });

    now = new Date("2026-07-30T00:01:01.000Z");

    expect(() => authority.authorize(token, proposal)).toThrowError(
      expect.objectContaining({
        code: "CAPABILITY_EXPIRED"
      })
    );
  });

  it("binds a capability to one agent and task", () => {
    const authority = new CapabilityAuthority("c".repeat(32));
    const token = authority.issue({
      agent_id: proposal.agent_id,
      task_id: proposal.task_id,
      expires_at: new Date(Date.now() + 60_000).toISOString(),
      operations: ["read"],
      resources: ["/task/receipts/**"]
    });

    expect(() =>
      authority.authorize(token, {
        ...proposal,
        task_id: "task-attacker"
      })
    ).toThrowError(
      expect.objectContaining({
        code: "CAPABILITY_BINDING_MISMATCH"
      })
    );
  });
});
