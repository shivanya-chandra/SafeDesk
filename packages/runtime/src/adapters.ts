import {
  readFile,
  realpath
} from "node:fs/promises";
import {
  isAbsolute,
  relative,
  resolve,
  sep
} from "node:path";
import type { ActionProposal } from "@safedesk/contracts";
import type { CapabilityAuthority } from "./capability-authority.js";
import { AdapterBoundaryError } from "./errors.js";

export type AdapterResult = Record<string, unknown>;

export interface ToolAdapter {
  execute(
    proposal: ActionProposal,
    capabilityToken: string
  ): Promise<AdapterResult>;
  captureState?(
    proposal: ActionProposal,
    capabilityToken: string
  ): Promise<unknown>;
  restoreState?(
    proposal: ActionProposal,
    snapshot: unknown,
    capabilityToken: string
  ): Promise<AdapterResult>;
  compensate?(
    proposal: ActionProposal,
    executionResult: AdapterResult,
    capabilityToken: string
  ): Promise<AdapterResult>;
}

function isInside(root: string, candidate: string): boolean {
  const relativePath = relative(root, candidate);

  return (
    relativePath !== "" &&
    relativePath !== ".." &&
    !relativePath.startsWith(`..${sep}`) &&
    !isAbsolute(relativePath)
  );
}

export class ScopedFileAdapter implements ToolAdapter {
  constructor(
    private readonly taskRoot: string,
    private readonly capabilityAuthority: CapabilityAuthority,
    private readonly virtualRoot = "/task"
  ) {}

  async execute(
    proposal: ActionProposal,
    capabilityToken: string
  ): Promise<AdapterResult> {
    this.capabilityAuthority.authorize(capabilityToken, proposal);

    if (proposal.operation !== "read") {
      throw new AdapterBoundaryError(
        "UNSUPPORTED_OPERATION",
        `File adapter does not support operation: ${proposal.operation}.`
      );
    }

    const prefix = `${this.virtualRoot}/`;

    if (!proposal.resource.startsWith(prefix)) {
      throw new AdapterBoundaryError(
        "PATH_OUTSIDE_ROOT",
        "Resource is outside the adapter's virtual task root."
      );
    }

    const root = await realpath(this.taskRoot);
    const relativeResource = proposal.resource.slice(prefix.length);
    const candidate = resolve(root, relativeResource);

    if (!isInside(root, candidate)) {
      throw new AdapterBoundaryError(
        "PATH_OUTSIDE_ROOT",
        "Resolved path escapes the task filesystem root."
      );
    }

    let resolvedResource: string;

    try {
      resolvedResource = await realpath(candidate);
    } catch {
      throw new AdapterBoundaryError(
        "RESOURCE_NOT_FOUND",
        "Requested task resource does not exist."
      );
    }

    if (!isInside(root, resolvedResource)) {
      throw new AdapterBoundaryError(
        "PATH_OUTSIDE_ROOT",
        "Resolved file target escapes the task filesystem root."
      );
    }

    const content = await readFile(resolvedResource, "utf8");

    return {
      resource: proposal.resource,
      content,
      bytes: Buffer.byteLength(content),
      data_labels: proposal.data_labels
    };
  }
}

export interface NetworkRequest {
  operation: string;
  url: string;
  parameters?: Record<string, unknown>;
}

export interface NetworkTransport {
  request(request: NetworkRequest): Promise<AdapterResult>;
}

export class ScopedNetworkAdapter implements ToolAdapter {
  constructor(
    private readonly capabilityAuthority: CapabilityAuthority,
    private readonly transport: NetworkTransport
  ) {}

  async execute(
    proposal: ActionProposal,
    capabilityToken: string
  ): Promise<AdapterResult> {
    this.capabilityAuthority.authorize(capabilityToken, proposal);

    if (!proposal.destination) {
      throw new AdapterBoundaryError(
        "MISSING_DESTINATION",
        "Network actions require an explicit destination."
      );
    }

    let url: URL;

    try {
      url = new URL(
        proposal.destination.includes("://")
          ? proposal.destination
          : `https://${proposal.destination}`
      );
    } catch {
      throw new AdapterBoundaryError(
        "INVALID_DESTINATION",
        "Network destination is not a valid URL."
      );
    }

    if (
      url.protocol !== "https:" ||
      url.username !== "" ||
      url.password !== ""
    ) {
      throw new AdapterBoundaryError(
        "INVALID_DESTINATION",
        "Only credential-free HTTPS destinations are supported."
      );
    }

    return this.transport.request({
      operation: proposal.operation,
      url: url.toString(),
      ...(proposal.parameters ? { parameters: proposal.parameters } : {})
    });
  }
}
