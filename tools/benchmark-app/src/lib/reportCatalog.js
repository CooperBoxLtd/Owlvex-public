const path = require('path');

const REPORT_ROOT = path.resolve(__dirname, '..', '..', 'reports');
const REPORTS = new Map([
  ['daily-refunds', 'daily-refunds.csv'],
  ['tenant-summary', 'tenant-summary.csv'],
]);

function resolveReportPath(reportId) {
  const fileName = REPORTS.get(reportId);
  if (!fileName) {
    throw new Error('unknown_report');
  }
  return path.join(REPORT_ROOT, fileName);
}

module.exports = { REPORT_ROOT, resolveReportPath };
