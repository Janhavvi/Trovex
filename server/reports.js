import PDFDocument from 'pdfkit';
import { createHash } from 'node:crypto';

const colors = {
  ink: '#102130',
  muted: '#52677a',
  cyan: '#007d98',
  line: '#d8e1e8',
  pale: '#f2f6f8',
  red: '#b42318',
  orange: '#b54708',
  yellow: '#8a6500',
  green: '#067647',
};

function plainText(value) {
  return String(value ?? '')
    .replace(/<[^>]*>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/\s+/g, ' ')
    .trim();
}

function severityColor(severity) {
  return ({ CRITICAL: colors.red, HIGH: colors.orange, MEDIUM: colors.yellow, LOW: colors.cyan, INFO: colors.muted })[severity] || colors.muted;
}

function ensureSpace(document, height) {
  if (document.y + height > document.page.height - document.page.margins.bottom) document.addPage();
}

function sectionHeading(document, title) {
  ensureSpace(document, 34);
  document.moveDown(0.7);
  document.fillColor(colors.ink).font('Helvetica-Bold').fontSize(12).text(title);
  document.moveDown(0.35);
  document.strokeColor(colors.line).lineWidth(0.7).moveTo(document.page.margins.left, document.y).lineTo(document.page.width - document.page.margins.right, document.y).stroke();
  document.moveDown(0.55);
}

export function buildSarifReport(findings, target) {
  const levelFor = (severity) => ({
    CRITICAL: 'error',
    HIGH: 'error',
    MEDIUM: 'warning',
    LOW: 'note',
    INFO: 'none',
  })[severity] || 'note';
  const normalized = findings.map((finding) => {
    let uri = finding.endpoint || target;
    try {
      uri = new URL(uri, target).href;
    } catch {
      uri = target;
    }
    return { finding, uri, ruleId: String(finding.id || finding.cwe || 'TROVEX-UNKNOWN') };
  });
  const rules = normalized.map(({ finding, ruleId }) => {
    const tags = ['security'];
    if (finding.cwe && /^CWE-\d+$/.test(finding.cwe)) tags.push(`external/cwe/${finding.cwe.toLowerCase()}`);
    if (finding.owasp && finding.owasp !== 'OWASP ZAP Baseline') tags.push(`external/owasp/${String(finding.owasp).toLowerCase().replace(/[^a-z0-9]+/g, '-')}`);
    return {
      id: ruleId,
      shortDescription: { text: plainText(finding.title || ruleId) },
      fullDescription: { text: plainText(finding.business_impact || finding.title || ruleId) },
      help: finding.remediation ? { text: plainText(finding.remediation) } : undefined,
      defaultConfiguration: { level: levelFor(finding.severity) },
      properties: {
        tags,
        ...(Number(finding.cvss_score) > 0 ? { 'security-severity': String(finding.cvss_score) } : {}),
        precision: finding.status === 'CONFIRMED' ? 'high' : 'low',
      },
    };
  });
  const results = normalized.map(({ finding, uri, ruleId }, index) => ({
    ruleId,
    ruleIndex: index,
    level: levelFor(finding.severity),
    message: { text: plainText(`${finding.title || 'Security finding'}${finding.business_impact ? `: ${finding.business_impact}` : ''}`) },
    locations: [{ physicalLocation: { artifactLocation: { uri } } }],
    partialFingerprints: {
      primaryLocationLineHash: createHash('sha256').update(`${ruleId}\n${uri}`).digest('hex'),
    },
    properties: {
      trovexId: finding.id,
      severity: finding.severity,
      status: finding.status,
      lifecycle: finding.lifecycle,
      cvssScore: finding.cvss_score,
      cvssVector: finding.cvss_vector,
      cwe: finding.cwe,
      owasp: finding.owasp,
      certIn: finding.cert_in,
      dpdpRelevant: finding.dpdp_relevant,
    },
  }));

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'Trovex Platform',
          version: '1.0.0',
          informationUri: 'https://trovex.local/',
          rules,
        },
      },
      invocations: [{ executionSuccessful: true, properties: { target, scanMode: 'LAB_ONLY' } }],
      results,
    }],
  };
}

export function generateExecutivePdf({ overview, findings, evidenceIntegrity }) {
  return new Promise((resolve, reject) => {
    const document = new PDFDocument({ size: 'A4', margin: 48, info: { Title: 'Trovex Executive Security Assessment', Author: 'Trovex Platform', Subject: 'Evidence-first security assessment report' } });
    const chunks = [];
    document.on('data', (chunk) => chunks.push(chunk));
    document.on('end', () => resolve(Buffer.concat(chunks)));
    document.on('error', reject);

    const width = document.page.width;
    const margin = document.page.margins.left;
    document.rect(0, 0, width, 116).fill(colors.ink);
    document.fillColor('#ffffff').font('Helvetica-Bold').fontSize(19).text('TROVEX', margin, 32, { characterSpacing: 2 });
    document.fillColor('#a8c3d4').font('Helvetica').fontSize(9).text('SAFE. PROVEN. FIXED.  |  SECURITY ASSESSMENT', margin, 61);
    document.fillColor('#d8e1e8').fontSize(8).text(`Generated ${new Date().toISOString()}`, margin, 91);

    document.y = 139;
    document.fillColor(colors.ink).font('Helvetica-Bold').fontSize(22).text('Executive Assessment Report');
    document.moveDown(0.35);
    document.fillColor(colors.muted).font('Helvetica').fontSize(10).text(`Target: ${plainText(overview.target || 'Not configured')}`);

    const cardY = document.y + 18;
    const gap = 10;
    const cardWidth = (width - margin * 2 - gap * 3) / 4;
    const metrics = [
      ['POSTURE', overview.hasScan ? `${overview.postureScore} / 100` : 'N/A'],
      ['GRADE', overview.hasScan ? overview.grade : 'N/A'],
      ['CONFIRMED', String(overview.confirmedFindings ?? 0)],
      ['UNVERIFIED', String(overview.unverifiedFindings ?? 0)],
    ];
    metrics.forEach(([label, value], index) => {
      const x = margin + index * (cardWidth + gap);
      document.roundedRect(x, cardY, cardWidth, 58, 4).fill(colors.pale);
      document.fillColor(colors.muted).font('Helvetica-Bold').fontSize(7).text(label, x + 9, cardY + 10, { width: cardWidth - 18 });
      document.fillColor(colors.ink).font('Helvetica-Bold').fontSize(15).text(value, x + 9, cardY + 29, { width: cardWidth - 18 });
    });
    document.y = cardY + 75;

    sectionHeading(document, 'Severity Summary');
    const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
    const severityText = severities.map((severity) => `${severity}: ${overview.severityCounts?.[severity] ?? 0}`).join('     ');
    document.fillColor(colors.ink).font('Helvetica').fontSize(9).text(severityText, { lineGap: 4 });

    sectionHeading(document, 'Assessment Summary');
    const summary = overview.hasScan
      ? `${overview.confirmedFindings ?? 0} confirmed and ${overview.unverifiedFindings ?? 0} unverified findings are in the latest completed assessment. Only confirmed findings affect the posture score.`
      : 'No completed assessment is available. Start an authorized lab assessment to generate findings and evidence.';
    document.fillColor(colors.ink).font('Helvetica').fontSize(9).text(summary, { lineGap: 3 });
    if (evidenceIntegrity) {
      document.moveDown(0.55);
      document.fillColor(evidenceIntegrity.valid ? colors.green : colors.red).font('Helvetica-Bold').fontSize(9)
        .text(`Evidence integrity: ${evidenceIntegrity.valid ? 'VALID' : 'VIOLATION'} · ${evidenceIntegrity.verifiedCount}/${evidenceIntegrity.recordCount} records verified`);
    }

    sectionHeading(document, `Findings (${findings.length})`);
    if (!findings.length) {
      document.fillColor(colors.muted).font('Helvetica').fontSize(9).text('No findings are available for this report.');
    }
    for (const finding of findings) {
      ensureSpace(document, 96);
      const startY = document.y;
      document.fillColor(severityColor(finding.severity)).font('Helvetica-Bold').fontSize(8)
        .text(`${plainText(finding.severity)}  ·  ${plainText(finding.status)}  ·  ${plainText(finding.id)}`);
      document.moveDown(0.22);
      document.fillColor(colors.ink).font('Helvetica-Bold').fontSize(11).text(plainText(finding.title), { width: width - margin * 2 });
      document.moveDown(0.25);
      document.fillColor(colors.muted).font('Helvetica').fontSize(8).text(`Endpoint: ${plainText(finding.endpoint || overview.target)}`, { width: width - margin * 2 });
      const details = [
        finding.cwe && finding.cwe !== 'N/A' ? `CWE: ${plainText(finding.cwe)}` : null,
        finding.owasp ? `OWASP: ${plainText(finding.owasp)}` : null,
        finding.cvss_score ? `CVSS: ${plainText(finding.cvss_score)}` : null,
      ].filter(Boolean).join('   ·   ');
      if (details) {
        document.moveDown(0.2);
        document.fillColor(colors.muted).font('Helvetica').fontSize(8).text(details, { width: width - margin * 2 });
      }
      const impact = plainText(finding.business_impact);
      if (impact) {
        document.moveDown(0.35);
        document.fillColor(colors.ink).font('Helvetica').fontSize(8).text(impact, { width: width - margin * 2, lineGap: 2 });
      }
      const remediation = plainText(finding.remediation);
      if (remediation) {
        document.moveDown(0.3);
        document.fillColor(colors.cyan).font('Helvetica').fontSize(8).text(`Remediation: ${remediation}`, { width: width - margin * 2, lineGap: 2 });
      }
      document.y = Math.max(document.y, startY + 48) + 10;
      document.strokeColor(colors.line).lineWidth(0.5).moveTo(margin, document.y).lineTo(width - margin, document.y).stroke();
      document.moveDown(0.5);
    }

    document.moveDown(0.5);
    document.fillColor(colors.muted).font('Helvetica').fontSize(7)
      .text('Assessment scope is enforced by the Trovex backend. Scanner alerts remain unverified until independently validated.', { align: 'left' });
    document.end();
  });
}
