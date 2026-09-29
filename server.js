import express from 'express';
import { randomUUID, timingSafeEqual } from 'node:crypto';
import {
  createScan,
  getCompletedScans,
  finishScan,
  getLatestCompletedFindings,
  getKillSwitch,
  getScan,
  setKillSwitch,
  updateScanStatus,
} from './server/database.js';

const app = express();
const DEFAULT_PORT = Number(process.env.PORT || 3001);
const N8N_BASE_URL = process.env.N8N_BASE_URL || 'http://localhost:5678';
const N8N_WEBHOOK_URL = process.env.N8N_WEBHOOK_URL || `${N8N_BASE_URL}/webhook/trovex-assessment`;
const AUTHORIZED_LAB_URL = (process.env.AUTHORIZED_LAB_URL || '').replace(/\/$/, '');
const LAB_AUTHORIZATION_REF = process.env.LAB_AUTHORIZATION_REF || '';
const LAB_AUTHORIZATION_VALID_UNTIL = process.env.LAB_AUTHORIZATION_VALID_UNTIL || '';
const INTERNAL_SCAN_TOKEN = process.env.INTERNAL_SCAN_TOKEN || '';
const MONITOR_TOKEN = process.env.MONITOR_TOKEN || '';
const DASHBOARD_USER = process.env.DASHBOARD_USER || '';
const DASHBOARD_PASSWORD = process.env.DASHBOARD_PASSWORD || '';
let lastScanAt = 0;
let serverInstance = null;

app.use(express.json());
app.set('trust proxy', 1);

function hasValidInternalToken(req) {
  const providedToken = Buffer.from(req.get('authorization')?.replace(/^Bearer\s+/i, '') || '');
  const expectedToken = Buffer.from(INTERNAL_SCAN_TOKEN);
  return Boolean(INTERNAL_SCAN_TOKEN
    && providedToken.length === expectedToken.length
    && timingSafeEqual(providedToken, expectedToken));
}

function hasValidMonitorToken(req) {
  const providedToken = Buffer.from(req.get('authorization')?.replace(/^Bearer\s+/i, '') || '');
  const expectedToken = Buffer.from(MONITOR_TOKEN);
  return Boolean(MONITOR_TOKEN
    && providedToken.length === expectedToken.length
    && timingSafeEqual(providedToken, expectedToken));
}

function requireDashboardAuth(req, res, next) {
  if (req.path === '/api/health') return next();
  if (req.path.startsWith('/api/internal/scans/')) return next();
  if (req.path === '/api/automation/run' && hasValidMonitorToken(req)) return next();
  if (!DASHBOARD_USER || !DASHBOARD_PASSWORD) {
    if (process.env.NODE_ENV !== 'production') return next();
    return res.status(503).json({ error: 'dashboard authentication is not configured' });
  }

  const [scheme, encoded] = (req.get('authorization') || '').split(' ');
  if (scheme?.toLowerCase() === 'basic' && encoded) {
    let user = '';
    let password = '';
    try {
      [user, password] = Buffer.from(encoded, 'base64').toString().split(/:(.*)/s, 2);
    } catch {
      // Invalid credentials receive the same response as missing credentials.
    }
    const userBytes = Buffer.from(user || '');
    const expectedUser = Buffer.from(DASHBOARD_USER);
    const passwordBytes = Buffer.from(password || '');
    const expectedPassword = Buffer.from(DASHBOARD_PASSWORD);
    if (userBytes.length === expectedUser.length
      && passwordBytes.length === expectedPassword.length
      && timingSafeEqual(userBytes, expectedUser)
      && timingSafeEqual(passwordBytes, expectedPassword)) return next();
  }

  res.set('WWW-Authenticate', 'Basic realm="Trovex Security Dashboard"');
  return res.status(401).json({ error: 'dashboard authentication required' });
}

const overview = {
  name: 'trovex-platform',
  status: 'ok',
  target: 'lab.local:8000',
  postureScore: 82,
  grade: 'B',
  confirmedFindings: 9,
  unverifiedFindings: 2,
  criticalFindings: 4,
  attackChains: 2,
};

const findings = [
  {
    id: 'F-001',
    title: 'Reflected XSS in Search Parameter',
    severity: 'HIGH',
    status: 'CONFIRMED',
    endpoint: '/dashboard?search=',
    module: 'Injection',
  },
  {
    id: 'F-002',
    title: 'IDOR on Telemetry Records',
    severity: 'HIGH',
    status: 'CONFIRMED',
    endpoint: '/api/telemetry/{id}',
    module: 'Role Matrix',
  },
  {
    id: 'F-003',
    title: 'Admin Routes Accessible by Analyst Token',
    severity: 'CRITICAL',
    status: 'CONFIRMED',
    endpoint: '/api/admin/*',
    module: 'Role Matrix',
  },
];

const attackChains = [
  {
    id: 'AC-001',
    title: 'Analyst token → admin route takeover',
    severity: 'CRITICAL',
    narrative: 'A weak role check allows an analyst token to reach admin endpoints and modify configuration.',
  },
  {
    id: 'AC-002',
    title: 'Prompt injection → false alert generation',
    severity: 'HIGH',
    narrative: 'A malicious feed item manipulates AI summary generation and creates misleading operational intelligence.',
  },
];

const evidence = [
  {
    id: 'EV-1042',
    type: 'API trace',
    owner: 'Auth module',
    confidence: 'High',
  },
  {
    id: 'EV-1047',
    type: 'Role matrix evidence',
    owner: 'Role matrix',
    confidence: 'High',
  },
];

app.get('/api/health', (_req, res) => {
  res.json({
    status: 'ok',
    name: 'trovex-platform',
    uptime: process.uptime(),
    database: process.env.DATABASE_URL ? 'postgres-configured' : 'local-memory',
  });
});

app.use(requireDashboardAuth);

app.get('/api/automation/status', async (_req, res) => {
  try {
    const response = await fetch(`${N8N_BASE_URL}/healthz`, {
      signal: AbortSignal.timeout(3000),
    });

    res.json({
      configured: true,
      connected: response.ok,
      workflowWebhook: '/webhook/trovex-assessment',
    });
  } catch {
    res.json({
      configured: true,
      connected: false,
      workflowWebhook: '/webhook/trovex-assessment',
    });
  }
});

app.post('/api/automation/run', async (req, res) => {
  const { event, payload = {} } = req.body ?? {};
  if (typeof event !== 'string' || !event.trim()) {
    return res.status(400).json({ error: 'event must be a non-empty string' });
  }
  if (event !== 'assessment.started') {
    return res.status(400).json({ error: 'unsupported automation event' });
  }
  try {
    if (await getKillSwitch()) {
      return res.status(423).json({ error: 'assessment scanning is disabled by the kill switch' });
    }
  } catch {
    return res.status(503).json({ error: 'unable to verify the scan kill switch' });
  }
  if (!AUTHORIZED_LAB_URL || !LAB_AUTHORIZATION_REF || !INTERNAL_SCAN_TOKEN) {
    return res.status(503).json({ error: 'authorized lab scanning is not configured' });
  }
  if ((payload.target && payload.target !== AUTHORIZED_LAB_URL)
    || (payload.authorizationRef && payload.authorizationRef !== LAB_AUTHORIZATION_REF)) {
    return res.status(403).json({ error: 'requested target is outside the authorized lab scope' });
  }
  const validUntil = Date.parse(LAB_AUTHORIZATION_VALID_UNTIL);
  if (!Number.isFinite(validUntil) || validUntil <= Date.now()) {
    return res.status(403).json({ error: 'lab authorization is missing or expired' });
  }
  if (Date.now() - lastScanAt < 60_000) {
    return res.status(429).json({ error: 'only one assessment may be started per minute' });
  }

  const scanId = randomUUID();
  try {
    await createScan({ id: scanId, target: AUTHORIZED_LAB_URL, status: 'queued' });
    lastScanAt = Date.now();
  } catch {
    return res.status(503).json({ error: 'unable to persist the assessment job' });
  }

  try {
    const response = await fetch(N8N_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        event,
        payload: {
          scanId,
          target: AUTHORIZED_LAB_URL,
          authorizationRef: LAB_AUTHORIZATION_REF,
        },
        source: 'trovex-platform',
      }),
      signal: AbortSignal.timeout(30000),
    });
    const responseBody = await response.json().catch(() => ({}));

    if (!response.ok) {
      await updateScanStatus(scanId, 'failed', responseBody.reason || 'n8n rejected the assessment');
      const status = response.status >= 500 ? 502 : response.status;
      return res.status(status).json(Object.keys(responseBody).length
        ? responseBody
        : { error: 'n8n webhook rejected the request', upstreamStatus: response.status });
    }

    await updateScanStatus(scanId, 'running');
    return res.status(202).json({ scanId, status: 'running', n8n: responseBody });
  } catch {
    await updateScanStatus(scanId, 'failed', 'Unable to reach the n8n workflow');
    return res.status(502).json({ error: 'Unable to reach the n8n webhook. Check that n8n is running and the workflow is active.' });
  }
});

app.get('/api/scans/:id', async (req, res) => {
  try {
    const scan = await getScan(req.params.id);
    if (!scan) return res.status(404).json({ error: 'assessment not found' });
    return res.json(scan);
  } catch {
    return res.status(503).json({ error: 'unable to read assessment status' });
  }
});

app.get('/api/internal/scans/:id', async (req, res) => {
  if (!hasValidInternalToken(req)) return res.status(401).json({ error: 'unauthorized scanner request' });
  try {
    const scan = await getScan(req.params.id);
    if (!scan) return res.status(404).json({ error: 'assessment not found' });
    return res.json({ id: scan.id, status: scan.status, target: scan.target });
  } catch {
    return res.status(503).json({ error: 'unable to verify assessment job' });
  }
});

app.post('/api/internal/scans/:id/results', async (req, res) => {
  if (!hasValidInternalToken(req)) {
    return res.status(401).json({ error: 'unauthorized scanner callback' });
  }

  const { status, findings: zapFindings, error } = req.body ?? {};
  if (!['completed', 'failed'].includes(status) || (status === 'completed' && !Array.isArray(zapFindings))) {
    return res.status(400).json({ error: 'invalid scanner result' });
  }

  try {
    const scan = await getScan(req.params.id);
    if (!scan) return res.status(404).json({ error: 'assessment not found' });
    const findings = status === 'completed'
      ? zapFindings.slice(0, 500).map((finding, index) => ({
        id: `ZAP-${finding.pluginId || 'alert'}-${index + 1}`,
        title: String(finding.title || 'OWASP ZAP alert').slice(0, 300),
        severity: ({ CRITICAL: 'CRITICAL', HIGH: 'HIGH', MEDIUM: 'MEDIUM', LOW: 'LOW', INFORMATIONAL: 'INFO', INFO: 'INFO' })[String(finding.severity).toUpperCase()] || 'INFO',
        status: 'UNVERIFIED',
        lifecycle: 'OPEN',
        endpoint: String(finding.endpoint || AUTHORIZED_LAB_URL).slice(0, 2048),
        cwe: finding.cwe && finding.cwe !== '-1' ? `CWE-${finding.cwe}` : 'N/A',
        owasp: 'OWASP ZAP Baseline',
        cvss_score: 0,
        cvss_vector: 'Not scored by passive baseline',
        business_impact: String(finding.description || '').slice(0, 4000),
        remediation: String(finding.remediation || '').slice(0, 4000),
        cert_in: 'Not assessed',
        dpdp_relevant: false,
        discovered_at: new Date().toISOString(),
        module: 'OWASP ZAP Baseline',
      }))
      : [];
    await finishScan(req.params.id, status, findings, status === 'failed' ? String(error || 'baseline scan failed') : null);
    return res.status(202).json({ status: 'stored', scanId: req.params.id, findingCount: findings.length });
  } catch {
    return res.status(503).json({ error: 'unable to persist scanner results' });
  }
});

app.post('/api/scope/kill-switch', async (req, res) => {
  if (typeof req.body?.active !== 'boolean') {
    return res.status(400).json({ error: 'active must be a boolean' });
  }
  try {
    await setKillSwitch(req.body.active);
    return res.json({ killSwitch: req.body.active });
  } catch {
    return res.status(503).json({ error: 'unable to persist kill switch state' });
  }
});

app.get('/api/overview', async (_req, res) => {
  try {
    const latestFindings = await getLatestCompletedFindings();
    if (latestFindings === null && !process.env.DATABASE_URL) {
      return res.json(overview);
    }

    const scans = await getCompletedScans();
    const findings = latestFindings ?? [];
    const severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    findings.forEach((finding) => {
      if (finding.severity in severityCounts) severityCounts[finding.severity]++;
    });
    const postureScore = findings.length
      ? Math.max(0, 100 - severityCounts.CRITICAL * 25 - severityCounts.HIGH * 12 - severityCounts.MEDIUM * 6 - severityCounts.LOW * 2)
      : 0;
    const grade = !findings.length ? 'N/A'
      : postureScore >= 90 ? 'A'
        : postureScore >= 75 ? 'B'
          : postureScore >= 60 ? 'C'
            : postureScore >= 40 ? 'D' : 'F';
    const scoreHistory = scans.reverse().map((scan) => {
      const scanFindings = scan.findings ?? [];
      const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
      scanFindings.forEach((finding) => {
        if (finding.severity in counts) counts[finding.severity]++;
      });
      const score = scanFindings.length
        ? Math.max(0, 100 - counts.CRITICAL * 25 - counts.HIGH * 12 - counts.MEDIUM * 6 - counts.LOW * 2)
        : 100;
      return {
        date: (scan.completedAt || scan.requestedAt).slice(5, 10),
        score,
        grade: score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F',
        delta: 0,
        confirmed_count: scanFindings.filter((finding) => finding.status === 'CONFIRMED').length,
      };
    });

    return res.json({
      ...overview,
      target: AUTHORIZED_LAB_URL || 'not configured',
      postureScore,
      grade,
      confirmedFindings: findings.filter((finding) => finding.status === 'CONFIRMED').length,
      unverifiedFindings: findings.filter((finding) => finding.status === 'UNVERIFIED').length,
      criticalFindings: severityCounts.CRITICAL,
      attackChains: 0,
      severityCounts,
      scoreHistory,
      hasScan: scans.length > 0,
    });
  } catch {
    return res.status(503).json({ error: 'unable to load persisted overview metrics' });
  }
});

app.get('/api/findings', async (_req, res) => {
  try {
    const latestFindings = await getLatestCompletedFindings();
    res.json(latestFindings ?? (process.env.DATABASE_URL ? [] : findings));
  } catch {
    res.status(503).json({ error: 'unable to read persisted findings' });
  }
});

app.get('/api/attack-chains', (_req, res) => {
  res.json(attackChains);
});

app.get('/api/evidence', (_req, res) => {
  res.json(evidence);
});

app.get('/api/scope/status', async (_req, res) => {
  const authorizationEnd = Date.parse(LAB_AUTHORIZATION_VALID_UNTIL);
  let killSwitch = true;
  try {
    killSwitch = await getKillSwitch();
  } catch {
    return res.status(503).json({ error: 'unable to read the scan kill switch' });
  }
  const authorized = Boolean(
    AUTHORIZED_LAB_URL && LAB_AUTHORIZATION_REF && Number.isFinite(authorizationEnd) && authorizationEnd > Date.now(),
  );
  res.json({
    active: authorized && !killSwitch,
    mode: authorized ? 'LAB_ONLY' : 'DISABLED',
    killSwitch,
    authorizedTargets: authorized ? [{
      id: 'scope-render-lab',
      name: 'Trovex Private Lab',
      hostname: AUTHORIZED_LAB_URL,
      environment: 'ISOLATED LAB',
      authorizationRef: LAB_AUTHORIZATION_REF,
      validFrom: new Date().toISOString(),
      validUntil: LAB_AUTHORIZATION_VALID_UNTIL,
      active: !killSwitch,
    }] : [],
    recentEvents: [],
  });
});

app.get('/api/methodology', (_req, res) => {
  res.json({
    phases: [
      'Scope validation',
      'Role matrix review',
      'API abuse testing',
      'AI prompt injection review',
      'Threat chaining and evidence validation',
    ],
  });
});

if (process.env.NODE_ENV === 'production') {
  app.use(express.static('dist'));
}

export function startServer(port = DEFAULT_PORT) {
  if (serverInstance) {
    return serverInstance;
  }

  serverInstance = app.listen(port, '0.0.0.0', () => {
    if (process.env.NODE_ENV !== 'test') {
      console.log(`Trovex API listening on http://localhost:${port}`);
    }
  });

  return serverInstance;
}

if (process.env.NODE_ENV !== 'test') {
  startServer();
}

export default app;
