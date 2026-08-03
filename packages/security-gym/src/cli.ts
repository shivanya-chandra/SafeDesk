import {
  formatSecurityGymReport,
  runSecurityGym
} from "./index.js";

const report = await runSecurityGym();
const wantsJson = process.argv.includes("--json");

process.stdout.write(
  wantsJson
    ? `${JSON.stringify(report, null, 2)}\n`
    : `${formatSecurityGymReport(report)}\n`
);
