import {
  createHmac,
  randomUUID,
  timingSafeEqual
} from "node:crypto";
import {
  actionProposalSchema,
  capabilityGrantSchema,
  capabilityManifestSchema,
  type ActionProposal,
  type CapabilityGrant,
  type CapabilityManifest
} from "@safedesk/contracts";
import { matchesPattern } from "@safedesk/policy-engine";
import { canonicalJson } from "./canonical-json.js";
import { AuthorizationError } from "./errors.js";

export type RuntimeClock = () => Date;

function anyPatternMatches(value: string, patterns: string[]): boolean {
  return patterns.some((pattern) => matchesPattern(value, pattern));
}

export class CapabilityAuthority {
  private readonly secret: Buffer;
  private readonly clock: RuntimeClock;

  constructor(secret: string | Uint8Array, clock: RuntimeClock = () => new Date()) {
    this.secret = Buffer.from(secret);
    this.clock = clock;

    if (this.secret.byteLength < 32) {
      throw new Error("Capability signing secret must contain at least 32 bytes.");
    }
  }

  issue(rawGrant: CapabilityGrant): string {
    const grant = capabilityGrantSchema.parse(rawGrant);
    const issuedAt = this.clock();
    const expiresAt = new Date(grant.expires_at);

    if (expiresAt.getTime() <= issuedAt.getTime()) {
      throw new AuthorizationError(
        "CAPABILITY_EXPIRED",
        "Cannot issue a capability that is already expired."
      );
    }

    const manifest = capabilityManifestSchema.parse({
      ...grant,
      capability_id: randomUUID(),
      issued_at: issuedAt.toISOString()
    });
    const encodedManifest = Buffer.from(canonicalJson(manifest)).toString(
      "base64url"
    );

    return `${encodedManifest}.${this.sign(encodedManifest)}`;
  }

  verify(token: string): CapabilityManifest {
    const parts = token.split(".");

    if (parts.length !== 2 || !parts[0] || !parts[1]) {
      throw new AuthorizationError(
        "MALFORMED_TOKEN",
        "Capability token is malformed."
      );
    }

    const [encodedManifest, providedSignature] = parts;
    const expectedSignature = this.sign(encodedManifest);
    const providedBytes = Buffer.from(providedSignature, "base64url");
    const expectedBytes = Buffer.from(expectedSignature, "base64url");

    if (
      providedBytes.byteLength !== expectedBytes.byteLength ||
      !timingSafeEqual(providedBytes, expectedBytes)
    ) {
      throw new AuthorizationError(
        "INVALID_SIGNATURE",
        "Capability signature is invalid."
      );
    }

    let decoded: unknown;

    try {
      decoded = JSON.parse(
        Buffer.from(encodedManifest, "base64url").toString("utf8")
      );
    } catch {
      throw new AuthorizationError(
        "MALFORMED_TOKEN",
        "Capability payload is not valid JSON."
      );
    }

    const parsed = capabilityManifestSchema.safeParse(decoded);

    if (!parsed.success) {
      throw new AuthorizationError(
        "MALFORMED_TOKEN",
        "Capability payload does not match the manifest contract."
      );
    }

    if (new Date(parsed.data.expires_at).getTime() <= this.clock().getTime()) {
      throw new AuthorizationError(
        "CAPABILITY_EXPIRED",
        "Capability has expired."
      );
    }

    return parsed.data;
  }

  authorize(
    token: string,
    rawProposal: ActionProposal
  ): CapabilityManifest {
    const capability = this.verify(token);
    const proposal = actionProposalSchema.parse(rawProposal);

    if (
      capability.agent_id !== proposal.agent_id ||
      capability.task_id !== proposal.task_id
    ) {
      throw new AuthorizationError(
        "CAPABILITY_BINDING_MISMATCH",
        "Capability is bound to a different agent or task."
      );
    }

    if (!anyPatternMatches(proposal.operation, capability.operations)) {
      throw new AuthorizationError(
        "CAPABILITY_OPERATION_DENIED",
        `Capability does not grant operation: ${proposal.operation}.`
      );
    }

    if (!anyPatternMatches(proposal.resource, capability.resources)) {
      throw new AuthorizationError(
        "CAPABILITY_RESOURCE_DENIED",
        `Capability does not grant resource: ${proposal.resource}.`
      );
    }

    if (
      proposal.destination &&
      (!capability.destinations ||
        !anyPatternMatches(proposal.destination, capability.destinations))
    ) {
      throw new AuthorizationError(
        "CAPABILITY_DESTINATION_DENIED",
        `Capability does not grant destination: ${proposal.destination}.`
      );
    }

    return capability;
  }

  private sign(encodedManifest: string): string {
    return createHmac("sha256", this.secret)
      .update(encodedManifest)
      .digest("base64url");
  }
}

