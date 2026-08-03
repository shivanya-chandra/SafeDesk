import type {
  BenchmarkMetrics,
  SecurityGymReport
} from "./types.js";

function formatMetric(value: number | null): string {
  return value === null ? "n/a" : `${value.toFixed(1)}%`;
}
function metricRows(
  baseline: BenchmarkMetrics,
  safedesk: BenchmarkMetrics
): Array<[string, string, string]> {
  return [
    [
      "Task completion",
      formatMetric(baseline.task_completion_rate),
      formatMetric(safedesk.task_completion_rate)
    ],
    [
      "Attack containment",
      formatMetric(baseline.attack_containment_rate),
      formatMetric(safedesk.attack_containment_rate)
    ],
    [
      "False-block rate",
      formatMetric(baseline.false_block_rate),
      formatMetric(safedesk.false_block_rate)
    ],
    [
      "Verification coverage",
      formatMetric(baseline.verification_coverage),
      formatMetric(safedesk.verification_coverage)
    ],
    [
      "Recovery success",
      formatMetric(baseline.recovery_success_rate),
      formatMetric(safedesk.recovery_success_rate)
    ],
    [
      "Permission utilization",
      formatMetric(baseline.permission_utilization),
      formatMetric(safedesk.permission_utilization)
    ]
  ];
}

function pad(value: string, width: number): string {
  return value.padEnd(width, " ");
}

export function formatSecurityGymReport(report: SecurityGymReport): string {
  const rows = metricRows(report.baseline.metrics, report.safedesk.metrics);
  const lines = [
    `${report.benchmark} v${report.version}`,
    `${report.scenario_count} deterministic scenarios`,
    "",
    `${pad("Metric", 26)} ${pad("Baseline", 12)} SafeDesk`,
    `${"-".repeat(26)} ${"-".repeat(12)} ${"-".repeat(12)}`,
    ...rows.map(
      ([metric, baseline, safedesk]) =>
        `${pad(metric, 26)} ${pad(baseline, 12)} ${safedesk}`
    ),
    "",
    "Scenario comparison"
  ];

  for (const scenario of report.safedesk.scenario_results) {
    const baseline = report.baseline.scenario_results.find(
      (candidate) => candidate.scenario_id === scenario.scenario_id
    );
    const baselineStatus = baseline?.attack_contained ? "contained" : "exposed";
    const safeDeskStatus = scenario.attack_contained ? "contained" : "exposed";
    const completion = scenario.task_completed ? "complete" : "blocked";

    lines.push(
      `- ${scenario.title}: baseline=${baselineStatus}, safedesk=${safeDeskStatus}, task=${completion}`
    );
  }

  lines.push(
    "",
    "Synthetic benchmark only; results do not claim security for arbitrary models or production integrations."
  );

  return lines.join("\n");
}
