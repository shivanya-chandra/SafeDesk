import type { ActionProposal } from "@safedesk/contracts";
import type {
  AdapterResult,
  ToolAdapter
} from "./adapters.js";
import {
  AdapterBoundaryError,
  InjectedFailureError,
  InjectedVerifierFailureError
} from "./errors.js";
import type {
  OutcomeVerifier,
  VerificationContext,
  VerificationResult
} from "./verification.js";

export type FaultMode =
  | "throw_before_execution"
  | "throw_after_execution"
  | "false_success";

export interface FaultDefinition {
  mode: FaultMode;
  false_result?: AdapterResult;
}

export class FaultInjectingAdapter implements ToolAdapter {
  constructor(
    private readonly delegate: ToolAdapter,
    private readonly faults: ReadonlyMap<string, FaultDefinition>
  ) {}

  async execute(
    proposal: ActionProposal,
    capabilityToken: string
  ): Promise<AdapterResult> {
    const fault = this.faults.get(proposal.action_id);

    if (fault?.mode === "throw_before_execution") {
      throw new InjectedFailureError("before_execution");
    }

    if (fault?.mode === "false_success") {
      return fault.false_result ?? {
        status: "synthetic_false_success"
      };
    }

    const result = await this.delegate.execute(proposal, capabilityToken);

    if (fault?.mode === "throw_after_execution") {
      throw new InjectedFailureError("after_execution");
    }

    return result;
  }

  async captureState(
    proposal: ActionProposal,
    capabilityToken: string
  ): Promise<unknown> {
    if (!this.delegate.captureState) {
      throw new AdapterBoundaryError(
        "RECOVERY_NOT_SUPPORTED",
        "Wrapped adapter does not support state capture."
      );
    }

    return this.delegate.captureState(proposal, capabilityToken);
  }

  async restoreState(
    proposal: ActionProposal,
    snapshot: unknown,
    capabilityToken: string
  ): Promise<AdapterResult> {
    if (!this.delegate.restoreState) {
      throw new AdapterBoundaryError(
        "RECOVERY_NOT_SUPPORTED",
        "Wrapped adapter does not support state restoration."
      );
    }

    return this.delegate.restoreState(
      proposal,
      snapshot,
      capabilityToken
    );
  }

  async compensate(
    proposal: ActionProposal,
    executionResult: AdapterResult,
    capabilityToken: string
  ): Promise<AdapterResult> {
    if (!this.delegate.compensate) {
      throw new AdapterBoundaryError(
        "RECOVERY_NOT_SUPPORTED",
        "Wrapped adapter does not support compensation."
      );
    }

    return this.delegate.compensate(
      proposal,
      executionResult,
      capabilityToken
    );
  }
}

export type VerifierFaultMode = "throw" | "force_failure";

export interface VerifierFaultDefinition {
  mode: VerifierFaultMode;
  explanation?: string;
}

export class FaultInjectingVerifier implements OutcomeVerifier {
  constructor(
    private readonly delegate: OutcomeVerifier,
    private readonly faults: ReadonlyMap<string, VerifierFaultDefinition>
  ) {}

  async verify(context: VerificationContext): Promise<VerificationResult> {
    const fault = this.faults.get(context.proposal.action_id);

    if (fault?.mode === "throw") {
      throw new InjectedVerifierFailureError();
    }

    if (fault?.mode === "force_failure") {
      return {
        status: "failed",
        explanation:
          fault.explanation ?? "Synthetic verification failure injected.",
        evidence: {
          injected_failure: true
        }
      };
    }

    return this.delegate.verify(context);
  }
}
