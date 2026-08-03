import {
  actionProposalSchema,
  policyDecisionSchema,
  policySetSchema,
  type ActionProposal,
  type PolicyDecision,
  type PolicySet
} from "@safedesk/contracts";
import { evaluateAction } from "@safedesk/policy-engine";
import type { AdapterResult } from "./adapters.js";
import { canonicalJson } from "./canonical-json.js";
import {
  EvidenceLedger,
  type EvidenceEntry
} from "./evidence-ledger.js";
import { EvidenceIntegrityError } from "./errors.js";

export interface ReplayTool {
  execute(proposal: ActionProposal): Promise<AdapterResult>;
}

export interface ReplayOutcome {
  action_id: string;
  recorded_decision?: PolicyDecision;
  replay_decision: PolicyDecision;
  recorded_result?: AdapterResult;
  replay_result?: AdapterResult;
  equivalent: boolean;
}

function readPayloadValue(
  entry: EvidenceEntry | undefined,
  key: string
): unknown {
  return entry?.payload[key];
}

export class ReplayEngine {
  async replay(
    entries: readonly EvidenceEntry[],
    rawPolicy: PolicySet,
    tools: ReadonlyMap<string, ReplayTool>,
    runId?: string
  ): Promise<ReplayOutcome[]> {
    const integrity = EvidenceLedger.verifyEntries(entries);

    if (!integrity.valid) {
      throw new EvidenceIntegrityError(
        `Cannot replay an invalid evidence chain: ${integrity.reason ?? "unknown integrity failure"}`
      );
    }

    const policy = policySetSchema.parse(rawPolicy);
    const replayEntries = runId
      ? entries.filter((entry) => entry.run_id === runId)
      : entries;
    const proposedEntries = replayEntries.filter(
      (entry) => entry.event_type === "action_proposed"
    );
    const seenActions = new Set<string>();
    const outcomes: ReplayOutcome[] = [];

    for (const proposedEntry of proposedEntries) {
      const proposal = actionProposalSchema.parse(
        readPayloadValue(proposedEntry, "proposal")
      );

      if (seenActions.has(proposal.action_id)) {
        continue;
      }

      seenActions.add(proposal.action_id);
      const actionEntries = replayEntries.filter(
        (entry) => entry.action_id === proposal.action_id
      );
      const recordedDecisionValue = readPayloadValue(
        actionEntries.find((entry) => entry.event_type === "policy_decision"),
        "decision"
      );
      const recordedDecision = recordedDecisionValue
        ? policyDecisionSchema.parse(recordedDecisionValue)
        : undefined;
      const recordedResultValue = readPayloadValue(
        actionEntries.find((entry) => entry.event_type === "execution_succeeded"),
        "result"
      );
      const recordedResult =
        recordedResultValue &&
        typeof recordedResultValue === "object" &&
        !Array.isArray(recordedResultValue)
          ? (recordedResultValue as AdapterResult)
          : undefined;
      const replayDecision = evaluateAction(policy, proposal);
      let replayResult: AdapterResult | undefined;

      if (replayDecision.decision !== "deny") {
        const tool = tools.get(proposal.operation);

        if (tool) {
          replayResult = await tool.execute(proposal);
        }
      }

      const decisionsEquivalent = recordedDecision
        ? canonicalJson(recordedDecision) === canonicalJson(replayDecision)
        : false;
      const resultsEquivalent = recordedResult
        ? canonicalJson(recordedResult) === canonicalJson(replayResult)
        : replayResult === undefined;

      outcomes.push({
        action_id: proposal.action_id,
        ...(recordedDecision ? { recorded_decision: recordedDecision } : {}),
        replay_decision: replayDecision,
        ...(recordedResult ? { recorded_result: recordedResult } : {}),
        ...(replayResult ? { replay_result: replayResult } : {}),
        equivalent: decisionsEquivalent && resultsEquivalent
      });
    }

    return outcomes;
  }
}
