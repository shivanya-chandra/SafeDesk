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
  | "RESOURCE_NOT_FOUND";

export class AdapterBoundaryError extends Error {
  readonly code: AdapterBoundaryErrorCode;

  constructor(code: AdapterBoundaryErrorCode, message: string) {
    super(message);
    this.name = "AdapterBoundaryError";
    this.code = code;
  }
}

