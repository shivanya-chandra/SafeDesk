import {
  createHash,
  randomUUID
} from "node:crypto";
import { canonicalJson } from "./canonical-json.js";
import type { RuntimeClock } from "./capability-authority.js";

const genesisHash = "0".repeat(64);

export type EvidenceEventType =
  | "action_proposed"
  | "policy_decision"
  | "approval_requested"
  | "approval_consumed"
  | "checkpoint_captured"
  | "execution_succeeded"
  | "execution_failed"
  | "verification_succeeded"
  | "verification_failed"
  | "recovery_started"
  | "recovery_succeeded"
  | "recovery_failed";

export interface EvidenceEventInput {
  run_id: string;
  action_id?: string;
  event_type: EvidenceEventType;
  payload: Record<string, unknown>;
}

export interface EvidenceEntry extends EvidenceEventInput {
  sequence: number;
  event_id: string;
  occurred_at: string;
  previous_hash: string;
  entry_hash: string;
}

export interface LedgerVerification {
  valid: boolean;
  checked_entries: number;
  broken_at_sequence?: number;
  reason?: string;
}

type EventIdFactory = () => string;

function cloneEntry(entry: EvidenceEntry): EvidenceEntry {
  return structuredClone(entry);
}

function calculateEntryHash(entry: Omit<EvidenceEntry, "entry_hash">): string {
  return createHash("sha256")
    .update(canonicalJson(entry))
    .digest("hex");
}

export class EvidenceLedger {
  private readonly entries: EvidenceEntry[] = [];

  constructor(
    private readonly clock: RuntimeClock = () => new Date(),
    private readonly eventIdFactory: EventIdFactory = randomUUID
  ) {}

  append(input: EvidenceEventInput): EvidenceEntry {
    const previousEntry = this.entries.at(-1);
    const material: Omit<EvidenceEntry, "entry_hash"> = {
      sequence: this.entries.length + 1,
      event_id: this.eventIdFactory(),
      run_id: input.run_id,
      ...(input.action_id ? { action_id: input.action_id } : {}),
      event_type: input.event_type,
      occurred_at: this.clock().toISOString(),
      payload: structuredClone(input.payload),
      previous_hash: previousEntry?.entry_hash ?? genesisHash
    };
    const entry: EvidenceEntry = {
      ...material,
      entry_hash: calculateEntryHash(material)
    };

    this.entries.push(entry);
    return cloneEntry(entry);
  }

  read(runId?: string): EvidenceEntry[] {
    return this.entries
      .filter((entry) => !runId || entry.run_id === runId)
      .map(cloneEntry);
  }

  verify(): LedgerVerification {
    return EvidenceLedger.verifyEntries(this.entries);
  }

  static verifyEntries(entries: readonly EvidenceEntry[]): LedgerVerification {
    let previousHash = genesisHash;

    for (const [index, entry] of entries.entries()) {
      const expectedSequence = index + 1;

      if (entry.sequence !== expectedSequence) {
        return {
          valid: false,
          checked_entries: index,
          broken_at_sequence: entry.sequence,
          reason: `Expected sequence ${expectedSequence}, received ${entry.sequence}.`
        };
      }

      if (entry.previous_hash !== previousHash) {
        return {
          valid: false,
          checked_entries: index,
          broken_at_sequence: entry.sequence,
          reason: "Previous hash does not match the preceding entry."
        };
      }

      const {
        entry_hash: recordedHash,
        ...material
      } = entry;
      const calculatedHash = calculateEntryHash(material);

      if (recordedHash !== calculatedHash) {
        return {
          valid: false,
          checked_entries: index,
          broken_at_sequence: entry.sequence,
          reason: "Entry content does not match its recorded hash."
        };
      }

      previousHash = recordedHash;
    }

    return {
      valid: true,
      checked_entries: entries.length
    };
  }
}

