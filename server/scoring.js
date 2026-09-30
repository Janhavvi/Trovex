const deductions = {
  CRITICAL: 15,
  HIGH: 8,
  MEDIUM: 4,
  LOW: 1,
  INFO: 0,
};

export function calculatePostureScore(findings, { sensitiveSector = false } = {}) {
  const sectorMultipliers = sensitiveSector
    ? { CRITICAL: 1.5, HIGH: 1.5, MEDIUM: 1.2, LOW: 1, INFO: 1 }
    : { CRITICAL: 1, HIGH: 1, MEDIUM: 1, LOW: 1, INFO: 1 };
  const totalDeduction = findings
    .filter((finding) => finding.status === 'CONFIRMED')
    .reduce((total, finding) => {
      const severity = String(finding.severity || '').toUpperCase();
      return total + (deductions[severity] || 0) * (sectorMultipliers[severity] || 1);
    }, 0);
  return Math.max(0, Math.round((100 - totalDeduction) * 100) / 100);
}

export function gradePostureScore(score) {
  return score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
}
