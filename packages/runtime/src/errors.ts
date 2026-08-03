export type AuthorizationErrorCode =
  | "MALFORMED_TOKEN"
  | "INVALID_SIGNATURE"
  | "CAPABILITY_EXPIRED"
  | "CAPABILITY_BINDING_MISMATCH"
  | "CAPABILITY_OPERATION_DENIED"
  | "CAPABILITY_RESOURCE_DENIED"
  | "CAPABILITY_DESTINATION_DENIED";

export class AuthorizationError extends Error {
  readonly code: AuthorizationErrorCode;

  constructor(code: AuthorizationErrorCode, message: string) {
    super(message);
    this.name = "AuthorizationError";
    this.code = code;
  }
}

export type ApprovalErrorCode =
  | "CHECKPOINT_NOT_FOUND"
  | "CHECKPOINT_EXPIRED"
  | "CHECKPOINT_NOT_PENDING"
  | "CHECKPOINT_NOT_APPROVED"
  | "CHECKPOINT_CONSUMED"
  | "ACTION_CHANGED";

export class ApprovalError extends Error {
  readonly code: ApprovalErrorCode;

  constructor(code: ApprovalErrorCode, message: string) {
    super(message);
    this.name = "ApprovalError";
    this.code = code;
  }
}

export type AdapterBoundaryErrorCode =
  | "UNSUPPORTED_OPERATION"
  | "PATH_OUTSIDE_ROOT"
  | "INVALID_DESTINATION"
  | "MISSING_DESTINATION"
  | "ADAPTER_NOT_FOUND"
  | "INVALID_TOOL_INPUT"
  | "RESOURCE_NOT_FOUND"
  | "RECOVERY_NOT_SUPPORTED";

export class AdapterBoundaryError extends Error {
  readonly code: AdapterBoundaryErrorCode;

  constructor(code: AdapterBoundaryErrorCode, message: string) {
    super(message);
    this.name = "AdapterBoundaryError";
    this.code = code;
  }
}

export class EvidenceIntegrityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EvidenceIntegrityError";
  }
}

export class InjectedFailureError extends Error {
  readonly phase: "before_execution" | "after_execution";

  constructor(phase: "before_execution" | "after_execution") {
    super(`Synthetic failure injected ${phase.replace("_", " ")}.`);
    this.name = "InjectedFailureError";
    this.phase = phase;
  }
}

export class InjectedVerifierFailureError extends Error {
  constructor() {
    super("Synthetic verifier failure injected.");
    this.name = "InjectedVerifierFailureError";
  }
}

export type RecoveryErrorCode =
  | "RECOVERY_CHECKPOINT_NOT_FOUND"
  | "RECOVERY_CHECKPOINT_CONSUMED"
  | "RECOVERY_ACTION_CHANGED"
  | "RECOVERY_RESULT_MISSING";

export class RecoveryError extends Error {
  readonly code: RecoveryErrorCode;

  constructor(code: RecoveryErrorCode, message: string) {
    super(message);
    this.name = "RecoveryError";
    this.code = code;
  }
}
