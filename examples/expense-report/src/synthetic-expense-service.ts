import type { ActionProposal } from "@safedesk/contracts";
import {
  AdapterBoundaryError,
  type AdapterResult,
  type CapabilityAuthority,
  type OutcomeVerifier,
  type ToolAdapter,
  type VerificationContext,
  type VerificationResult
} from "@safedesk/runtime";

export interface ExpenseDraft {
  draft_id: string;
  amount: number;
  receipt_count: number;
}

export interface ExpenseClaim extends ExpenseDraft {
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

  async captureState(
    proposal: ActionProposal,
    capabilityToken: string
  ): Promise<unknown> {
    this.capabilityAuthority.authorize(capabilityToken, proposal);

    return {
      drafts: [...this.drafts.values()].map((draft) => ({ ...draft })),
      claims: [...this.claims.values()].map((claim) => ({ ...claim }))
    };
  }

  async restoreState(
    proposal: ActionProposal,
    snapshot: unknown,
    capabilityToken: string
  ): Promise<AdapterResult> {
    this.capabilityAuthority.authorize(capabilityToken, proposal);

    if (!isExpenseSnapshot(snapshot)) {
      throw new AdapterBoundaryError(
        "INVALID_TOOL_INPUT",
        "Expense recovery snapshot is malformed."
      );
    }

    this.drafts.clear();
    this.claims.clear();

    for (const draft of snapshot.drafts) {
      this.drafts.set(draft.draft_id, { ...draft });
    }

    for (const claim of snapshot.claims) {
      this.claims.set(claim.confirmation_id, { ...claim });
    }

    return {
      status: "state_restored",
      draft_count: this.drafts.size,
      claim_count: this.claims.size
    };
  }

  async compensate(
    proposal: ActionProposal,
    executionResult: AdapterResult,
    capabilityToken: string
  ): Promise<AdapterResult> {
    this.capabilityAuthority.authorize(capabilityToken, proposal);

    if (proposal.operation === "create") {
      const draftId = requireString(executionResult, "draft_id");
      const removed = this.drafts.delete(draftId);

      if (!removed) {
        throw new AdapterBoundaryError(
          "RESOURCE_NOT_FOUND",
          "Compensation could not find the created draft."
        );
      }

      return {
        status: "draft_deleted",
        draft_id: draftId
      };
    }

    if (proposal.operation === "submit") {
      const confirmationId = requireString(
        executionResult,
        "confirmation_id"
      );
      const removed = this.claims.delete(confirmationId);

      if (!removed) {
        throw new AdapterBoundaryError(
          "RESOURCE_NOT_FOUND",
          "Compensation could not find the submitted claim."
        );
      }

      return {
        status: "claim_withdrawn",
        confirmation_id: confirmationId
      };
    }

    throw new AdapterBoundaryError(
      "RECOVERY_NOT_SUPPORTED",
      `No compensating action exists for: ${proposal.operation}.`
    );
  }

  getDraft(draftId: string): ExpenseDraft | undefined {
    const draft = this.drafts.get(draftId);
    return draft ? { ...draft } : undefined;
  }

  getClaim(confirmationId: string): ExpenseClaim | undefined {
    const claim = this.claims.get(confirmationId);
    return claim ? { ...claim } : undefined;
  }

  get draftCount(): number {
    return this.drafts.size;
  }

  get claimCount(): number {
    return this.claims.size;
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

interface ExpenseSnapshot {
  drafts: ExpenseDraft[];
  claims: ExpenseClaim[];
}

function isExpenseDraft(value: unknown): value is ExpenseDraft {
  if (!value || typeof value !== "object") {
    return false;
  }

  const draft = value as Record<string, unknown>;

  return (
    typeof draft.draft_id === "string" &&
    typeof draft.amount === "number" &&
    typeof draft.receipt_count === "number"
  );
}

function isExpenseClaim(value: unknown): value is ExpenseClaim {
  if (!isExpenseDraft(value)) {
    return false;
  }

  return (
    "confirmation_id" in value &&
    typeof value.confirmation_id === "string"
  );
}

function isExpenseSnapshot(value: unknown): value is ExpenseSnapshot {
  if (!value || typeof value !== "object") {
    return false;
  }

  const snapshot = value as Record<string, unknown>;

  return (
    Array.isArray(snapshot.drafts) &&
    snapshot.drafts.every(isExpenseDraft) &&
    Array.isArray(snapshot.claims) &&
    snapshot.claims.every(isExpenseClaim)
  );
}

export class SyntheticExpenseVerifier implements OutcomeVerifier {
  constructor(private readonly state: SyntheticExpenseService) {}

  async verify({
    proposal,
    adapter_result: result
  }: VerificationContext): Promise<VerificationResult> {
    if (proposal.operation === "create") {
      const draftId = result.draft_id;
      const observedDraft =
        typeof draftId === "string"
          ? this.state.getDraft(draftId)
          : undefined;
      const expectedAmount = proposal.parameters?.amount;
      const verified = Boolean(
        observedDraft &&
        observedDraft.amount === expectedAmount &&
        result.status === "draft_created"
      );

      return {
        status: verified ? "verified" : "failed",
        explanation: verified
          ? "The draft exists in independent expense-system state with the expected amount."
          : "The adapter claimed success, but the expected draft was not observed.",
        evidence: {
          draft_id: typeof draftId === "string" ? draftId : null,
          observed_draft: observedDraft ?? null
        }
      };
    }

    if (proposal.operation === "submit") {
      const confirmationId = result.confirmation_id;
      const observedClaim =
        typeof confirmationId === "string"
          ? this.state.getClaim(confirmationId)
          : undefined;
      const expectedAmount = proposal.parameters?.amount;
      const verified = Boolean(
        observedClaim &&
        observedClaim.amount === expectedAmount &&
        result.status === "submitted"
      );

      return {
        status: verified ? "verified" : "failed",
        explanation: verified
          ? "The confirmation ID resolves to an independently observed expense claim."
          : "The adapter claimed submission, but no matching claim was observed.",
        evidence: {
          confirmation_id:
            typeof confirmationId === "string" ? confirmationId : null,
          observed_claim: observedClaim ?? null
        }
      };
    }

    return {
      status: "failed",
      explanation: `No synthetic verifier is defined for operation: ${proposal.operation}.`,
      evidence: {}
    };
  }
}
