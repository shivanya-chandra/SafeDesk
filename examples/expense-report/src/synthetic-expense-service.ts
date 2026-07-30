import type { ActionProposal } from "@safedesk/contracts";
import {
  AdapterBoundaryError,
  type AdapterResult,
  type CapabilityAuthority,
  type ToolAdapter
} from "@safedesk/runtime";

interface ExpenseDraft {
  draft_id: string;
  amount: number;
  receipt_count: number;
}

interface ExpenseClaim extends ExpenseDraft {
  confirmation_id: string;
}

function requirePositiveNumber(
  parameters: Record<string, unknown> | undefined,
  key: string
): number {
  const value = parameters?.[key];

  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    throw new AdapterBoundaryError(
      "INVALID_TOOL_INPUT",
      `${key} must be a positive number.`
    );
  }

  return value;
}

function requireString(
  parameters: Record<string, unknown> | undefined,
  key: string
): string {
  const value = parameters?.[key];

  if (typeof value !== "string" || value.length === 0) {
    throw new AdapterBoundaryError(
      "INVALID_TOOL_INPUT",
      `${key} must be a non-empty string.`
    );
  }

  return value;
}

export class SyntheticExpenseService implements ToolAdapter {
  private readonly drafts = new Map<string, ExpenseDraft>();
  private readonly claims = new Map<string, ExpenseClaim>();

  constructor(private readonly capabilityAuthority: CapabilityAuthority) {}

  async execute(
    proposal: ActionProposal,
    capabilityToken: string
  ): Promise<AdapterResult> {
    this.capabilityAuthority.authorize(capabilityToken, proposal);

    if (proposal.operation === "create") {
      return this.createDraft(proposal);
    }

    if (proposal.operation === "submit") {
      return this.submitDraft(proposal);
    }

    if (proposal.operation === "verify") {
      return this.verifyClaim(proposal);
    }

    throw new AdapterBoundaryError(
      "UNSUPPORTED_OPERATION",
      `Synthetic expense service does not support: ${proposal.operation}.`
    );
  }

  private createDraft(proposal: ActionProposal): AdapterResult {
    const amount = requirePositiveNumber(proposal.parameters, "amount");
    const receiptCount = requirePositiveNumber(
      proposal.parameters,
      "receipt_count"
    );
    const draftId = `draft-${String(this.drafts.size + 1).padStart(4, "0")}`;
    const draft: ExpenseDraft = {
      draft_id: draftId,
      amount,
      receipt_count: receiptCount
    };

    this.drafts.set(draftId, draft);

    return {
      status: "draft_created",
      ...draft
    };
  }

  private submitDraft(proposal: ActionProposal): AdapterResult {
    const draftId = requireString(proposal.parameters, "draft_id");
    const expectedAmount = requirePositiveNumber(
      proposal.parameters,
      "amount"
    );
    const draft = this.drafts.get(draftId);

    if (!draft) {
      throw new AdapterBoundaryError(
        "RESOURCE_NOT_FOUND",
        "Expense draft does not exist."
      );
    }

    if (draft.amount !== expectedAmount) {
      throw new AdapterBoundaryError(
        "INVALID_TOOL_INPUT",
        "Submitted amount does not match the stored draft."
      );
    }

    const confirmationId = `EXP-${String(this.claims.size + 1).padStart(5, "0")}`;
    const claim: ExpenseClaim = {
      ...draft,
      confirmation_id: confirmationId
    };

    this.claims.set(confirmationId, claim);

    return {
      status: "submitted",
      ...claim
    };
  }

  private verifyClaim(proposal: ActionProposal): AdapterResult {
    const confirmationId = requireString(
      proposal.parameters,
      "confirmation_id"
    );
    const claim = this.claims.get(confirmationId);

    return {
      status: claim ? "verified" : "not_found",
      confirmation_id: confirmationId,
      exists: Boolean(claim)
    };
  }
}

