import type { ActionProposal } from "@safedesk/contracts";
import type { AdapterResult } from "./adapters.js";

export interface VerificationContext {
  proposal: ActionProposal;
  adapter_result: AdapterResult;
}

export interface VerificationResult {
  status: "verified" | "failed";
  explanation: string;
  evidence: Record<string, unknown>;
}

export interface OutcomeVerifier {
  verify(context: VerificationContext): Promise<VerificationResult>;
}

