import express from 'express';
import cors from 'cors';
import { createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import {
  createScan,
  getCompletedScans,
  finishScan,
  getLatestCompletedFindings,
  getKillSwitch,
  getScan,
  getEvidence,
  appendScanEvidence,
  verifyEvidenceChain,
  getRunningScans,
  createUser,
  getUserByLogin,
  updateUserLastLogin,
  createAuthSession,
  getAuthSession,
  deleteAuthSession,
  setKillSwitch,
  updateScanStatus,
} from './server/database.js';
import { calculatePostureScore, gradePostureScore } from './server/scoring.js';
import { hashPassword, validatePassword, verifyPassword } from './server/passwords.js';
import { buildSarifReport, generateExecutivePdf } from './server/reports.js';

const app = express();
const DEFAULT_PORT = Number(process.env.PORT || 3001);
const assessmentTimeline = [
  { name: 'Scope validation', status: 'complete', detail: 'Only the private lab is allowed' },
  { name: 'Authorization verification', status: 'complete', detail: 'Signed lab authorization is checked' },
  { name: 'Scan orchestration', status: 'in-progress', detail: 'n8n or local-dev fallback manages the job' },
  { name: 'Passive baseline review', status: 'pending', detail: 'ZAP baseline findings are correlated' },
  { name: 'Evidence validation', status: 'pending', detail: 'Findings are verified and chained' },
];
const N8N_BASE_URL = process.env.N8N_BASE_URL || 'http://localhost:5678';
const N8N_WEBHOOK_URL = process.env.N8N_WEBHOOK_URL || `${N8N_BASE_URL}/webhook/trovex-assessment`;
const AUTHORIZED_LAB_URL = (process.env.AUTHORIZED_LAB_URL || 'http://127.0.0.1:10000').replace(/\/$/, '');
const LAB_AUTHORIZATION_REF = process.env.LAB_AUTHORIZATION_REF || 'TROVEX-LAB-2026';
const LAB_AUTHORIZATION_VALID_UNTIL = process.env.LAB_AUTHORIZATION_VALID_UNTIL || '2030-12-31T23:59:59Z';
const IS_TEST = process.env.NODE_ENV === 'test';
const INTERNAL_SCAN_TOKEN = process.env.INTERNAL_SCAN_TOKEN || (IS_TEST ? 'dev-local-internal-token' : '');
const MONITOR_TOKEN = process.env.MONITOR_TOKEN || (IS_TEST ? 'dev-local-monitor-token' : '');
const DASHBOARD_USER = process.env.DASHBOARD_USER || (IS_TEST ? 'test-user' : '');
const DASHBOARD_PASSWORD = process.env.DASHBOARD_PASSWORD || (IS_TEST ? 'test-password' : '');
const ANALYST_USER = process.env.ANALYST_USER || '';
const ANALYST_PASSWORD = process.env.ANALYST_PASSWORD || '';
const VIEWER_USER = process.env.VIEWER_USER || '';
const VIEWER_PASSWORD = process.env.VIEWER_PASSWORD || '';
const AUTHORIZATION_SECRET = process.env.AUTHORIZATION_SECRET || (IS_TEST ? 'trovex-scope-secret' : '');
const SCAN_TIMEOUT_MS = 8 * 60 * 1000;
const SCANNER_BASE_URL = (process.env.SCANNER_BASE_URL || 'http://127.0.0.1:8082').replace(/\/$/, '');
const FRONTEND_URL = (process.env.FRONTEND_URL || '').replace(/\/$/, '');
let configuredUsersPromise;
const authAttemptWindows = new Map();
const dashboardUsers = [
  { username: DASHBOARD_USER, password: DASHBOARD_PASSWORD, role: 'ADMIN' },
  { username: ANALYST_USER, password: ANALYST_PASSWORD, role: 'SECURITY_ANALYST' },
  { username: VIEWER_USER, password: VIEWER_PASSWORD, role: 'VIEWER' },
].filter((user) => user.username && user.password);
const LAB_ALLOWLIST = new Set([
  (process.env.AUTHORIZED_LAB_URL || '').replace(/\/$/, ''),
  'http://127.0.0.1:10000',
  'http://trovex-lab:10000',
  'http://lab.local:8000',
].filter(Boolean));
const automationEvents = [];
let lastScanAt = 0;
let serverInstance = null;

app.use(express.json());
app.set('trust proxy', 1);
app.disable('x-powered-by');
if (FRONTEND_URL) {
  app.use(cors({
    origin: (origin, callback) => callback(null, !origin || origin === FRONTEND_URL ? origin || false : false),
    credentials: true,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  }));
}
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  if (process.env.NODE_ENV === 'production') {
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: blob:; connect-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'");
    if (req.secure || req.get('x-forwarded-proto')?.split(',')[0].trim() === 'https') {
      res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    }
  }
  next();
});

function normalizeTarget(target) {
  if (typeof target !== 'string') return '';
  return target.trim().replace(/\/$/, '');
}

function isKnownLiveTarget(target) {
  const hostname = (() => {
    try {
      return new URL(target).hostname.toLowerCase();
    } catch {
      return target.toLowerCase();
    }
  })();
  return [
    'worldmonitor.app',
    'www.worldmonitor.app',
    'live.worldmonitor.app',
    'app.worldmonitor.app',
  ].includes(hostname);
}

function evaluateScope(target, { requireAuthorization = false } = {}) {
  const normalized = normalizeTarget(target);
  if (!normalized) {
    return { allowed: false, status: 400, reason: 'target is required' };
  }
  if (isKnownLiveTarget(normalized)) {
    return { allowed: false, status: 403, reason: 'live worldmonitor.app is blocked by the backend allowlist' };
  }
  if (!LAB_ALLOWLIST.has(normalized)) {
    return { allowed: false, status: 403, reason: 'target is outside the private lab allowlist' };
  }
  if (requireAuthorization && !process.env.LAB_AUTHORIZATION_REF) {
    return { allowed: false, status: 403, reason: 'authorization note is required before a new target is allowed' };
  }
  return { allowed: true, status: 200, reason: 'private lab target is allowed' };
}

function registrationSignature(payload) {
  return createHmac('sha256', AUTHORIZATION_SECRET).update(JSON.stringify(payload)).digest('hex');
}

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

function sessionToken(req) {
  const cookie = req.get('cookie') || '';
  const sessionCookie = cookie.split(';').map((part) => part.trim()).find((part) => part.startsWith('trovex_session='));
  return sessionCookie?.slice('trovex_session='.length) || '';
}

async function getSessionUser(req) {
  const token = sessionToken(req);
  if (!token) return null;
  return getAuthSession(token);
}

function safeEqual(left, right) {
  const leftBytes = Buffer.from(left || '');
  const rightBytes = Buffer.from(right || '');
  return leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes);
}

function authenticateUser(username, password) {
  let matchedUser = null;
  for (const user of dashboardUsers) {
    const usernameMatches = safeEqual(username, user.username);
    const passwordMatches = safeEqual(password, user.password);
    if (usernameMatches && passwordMatches) matchedUser = user;
  }
  return matchedUser;
}

async function seedConfiguredUsers() {
  if (!configuredUsersPromise) {
    configuredUsersPromise = (async () => {
      for (const user of dashboardUsers) {
        if (await getUserByLogin(user.username)) continue;
        const email = user.username.includes('@') ? user.username.toLowerCase() : `${user.username.toLowerCase()}@local.trovex.invalid`;
        await createUser({
          name: user.role === 'ADMIN' ? 'Trovex Administrator' : user.role === 'VIEWER' ? 'Trovex Viewer' : 'Trovex Analyst',
          email,
          loginId: user.username,
          passwordHash: await hashPassword(user.password),
          role: user.role,
        });
      }
    })().catch((error) => {
      configuredUsersPromise = null;
      throw error;
    });
  }
  await configuredUsersPromise;
}

async function issueSession(req, res, user, remember) {
  const maxAge = remember ? 30 * 24 * 60 * 60 : 8 * 60 * 60;
  const token = randomBytes(32).toString('base64url');
  const sessionUser = {
    id: user.id,
    username: user.loginId,
    name: user.name,
    email: user.email,
    role: user.role,
  };
  await createAuthSession(token, user.id, new Date(Date.now() + maxAge * 1000));
  const secure = req.secure || req.get('x-forwarded-proto')?.split(',')[0].trim() === 'https';
  res.set('Set-Cookie', `trovex_session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${secure ? '; Secure' : ''}`);
  return { user: sessionUser };
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.authUser || !roles.includes(req.authUser.role)) {
      return res.status(403).json({ error: 'your role is not permitted to perform this action' });
    }
    return next();
  };
}

function limitAuthAttempts(maxAttempts) {
  return (req, res, next) => {
    if (process.env.NODE_ENV === 'test') return next();
    const now = Date.now();
    const windowMs = 15 * 60 * 1000;
    const key = req.ip || req.socket.remoteAddress || 'unknown';
    let bucket = authAttemptWindows.get(key);
    if (!bucket || now - bucket.startedAt >= windowMs) {
      bucket = { startedAt: now, attempts: 0 };
      authAttemptWindows.set(key, bucket);
    }
    if (bucket.attempts >= maxAttempts) {
      return res.status(429).json({ error: 'too many authentication attempts; try again later' });
    }
    bucket.attempts += 1;
    if (authAttemptWindows.size > 10000) {
      for (const [ip, item] of authAttemptWindows) {
        if (now - item.startedAt >= windowMs) authAttemptWindows.delete(ip);
      }
    }
    return next();
  };
}

async function updateKillSwitch(active) {
  await setKillSwitch(active);
  if (!active) return { killSwitch: false, active: false, cancelledScans: 0 };

  const runningScans = await getRunningScans();
  const results = await Promise.all(runningScans.map(async (scan) => {
    const response = await fetch(`${SCANNER_BASE_URL}/scans/${scan.id}/cancel`, {
      method: 'POST',
      headers: { authorization: `Bearer ${INTERNAL_SCAN_TOKEN}` },
      signal: AbortSignal.timeout(5000),
    });
    return response.status === 202;
  }));
  return { killSwitch: true, active: true, cancelledScans: results.filter(Boolean).length };
}

async function requireDashboardAuth(req, res, next) {
  if (!req.path.startsWith('/api/') || req.path === '/api/health') return next();
  if (req.path === '/api/auth/login') return next();
  if (req.path === '/api/auth/signup') return next();
  if (req.path === '/api/auth/session') {
    req.authUser = await getSessionUser(req);
    return next();
  }
  if (req.path.startsWith('/api/internal/scans/')) return next();
  if (req.path === '/api/automation/run' && hasValidMonitorToken(req)) {
    req.authUser = { username: 'automation-monitor', role: 'AUTOMATION' };
    return next();
  }

  const sessionUser = await getSessionUser(req);
  if (sessionUser) {
    req.authUser = sessionUser;
    return next();
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
    const matchedUser = authenticateUser(user, password);
    if (matchedUser) {
      req.authUser = { username: matchedUser.username, role: matchedUser.role };
      return next();
    }
  }

  return res.status(401).json({ error: 'dashboard authentication required' });
}

app.use(requireDashboardAuth);

app.post('/api/auth/login', limitAuthAttempts(10), async (req, res) => {
  const login = String(req.body?.username || req.body?.email || '').trim().toLowerCase();
  const password = String(req.body?.password || '');
  try {
    await seedConfiguredUsers();
    const user = await getUserByLogin(login);
    const valid = user?.status !== 'disabled' && user?.passwordHash
      ? await verifyPassword(password, user.passwordHash)
      : false;
    if (!valid) return res.status(401).json({ error: 'invalid email or password' });
    await updateUserLastLogin(user.id);
    return res.json(await issueSession(req, res, user, req.body?.remember === true));
  } catch {
    return res.status(503).json({ error: 'unable to authenticate with the Trovex service' });
  }
});

app.post('/api/auth/signup', limitAuthAttempts(5), async (req, res) => {
  const name = String(req.body?.name || '').trim();
  const email = String(req.body?.email || '').trim().toLowerCase();
  const password = String(req.body?.password || '');
  const role = String(req.body?.role || 'SECURITY_ANALYST').toUpperCase();

  if (name.length < 2 || name.length > 100) {
    return res.status(400).json({ error: 'name must be between 2 and 100 characters' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
    return res.status(400).json({ error: 'please enter a valid email address' });
  }
  if (!validatePassword(password)) {
    return res.status(400).json({ error: 'password must be 12-128 characters with uppercase, lowercase, a number, and a special character' });
  }
  if (req.body?.termsAccepted !== true) {
    return res.status(400).json({ error: 'you must accept the Terms of Service and Privacy Policy' });
  }
  if (role === 'ADMIN') return res.status(403).json({ error: 'administrator accounts require an existing admin invitation' });
  if (!['SECURITY_ANALYST', 'VIEWER'].includes(role)) {
    return res.status(400).json({ error: 'role must be SECURITY_ANALYST or VIEWER' });
  }

  try {
    await seedConfiguredUsers();
    const user = await createUser({
      name,
      email,
      loginId: email,
      passwordHash: await hashPassword(password),
      role,
    });
    if (!user) return res.status(409).json({ error: 'an account with this email already exists' });
    return res.status(201).json(await issueSession(req, res, user, false));
  } catch {
    return res.status(503).json({ error: 'unable to create the Trovex account' });
  }
});

app.get('/api/auth/session', (req, res) => {
  return res.json({ authenticated: Boolean(req.authUser), user: req.authUser || null });
});

app.post('/api/auth/logout', async (req, res) => {
  await deleteAuthSession(sessionToken(req));
  res.set('Set-Cookie', 'trovex_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0');
  return res.status(204).end();
});

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

function sendHealthResponse(res) {
  res.json({
    status: 'ok',
    service: 'trovex-api',
    name: 'trovex-platform',
    uptime: process.uptime(),
    database: process.env.DATABASE_URL ? 'postgres-configured' : 'local-memory',
  });
}

app.get('/health', (_req, res) => {
  sendHealthResponse(res);
});

app.get('/api/health', (_req, res) => {
  sendHealthResponse(res);
});

app.post('/api/scope/check', requireRole('ADMIN', 'SECURITY_ANALYST'), async (req, res) => {
  const requestedTarget = normalizeTarget(req.body?.target || AUTHORIZED_LAB_URL);
  const killSwitchEnabled = await getKillSwitch().catch(() => false);

  if (killSwitchEnabled) {
    return res.status(423).json({ allowed: false, reason: 'scan execution is disabled by the kill switch', safeMode: true, killSwitch: true });
  }

  const result = evaluateScope(requestedTarget, { requireAuthorization: true });
  if (!result.allowed) {
    return res.status(result.status).json({
      allowed: false,
      target: requestedTarget,
      reason: result.reason,
      safeMode: true,
      killSwitch: killSwitchEnabled,
      allowlist: [...LAB_ALLOWLIST],
    });
  }

  const authorizationRef = req.body?.authorizationRef || LAB_AUTHORIZATION_REF;
  const validUntil = Date.parse(LAB_AUTHORIZATION_VALID_UNTIL);
  const authorizationActive = Boolean(LAB_AUTHORIZATION_REF && Number.isFinite(validUntil) && validUntil > Date.now());
  if (req.body?.target && req.body.target !== AUTHORIZED_LAB_URL && req.body.authorizationRef !== LAB_AUTHORIZATION_REF) {
    return res.status(403).json({ allowed: false, reason: 'authorization note mismatch for this target', safeMode: true, killSwitch: killSwitchEnabled });
  }
  if (!authorizationActive) {
    return res.status(403).json({ allowed: false, reason: 'authorization note is missing or expired', safeMode: true, killSwitch: killSwitchEnabled });
  }

  return res.json({
    allowed: true,
    target: requestedTarget,
    authorizationRef,
    reason: 'scope guard passed for the private lab target',
    safeMode: true,
    killSwitch: killSwitchEnabled,
    mode: 'LAB_ONLY',
    allowlist: [...LAB_ALLOWLIST],
  });
});

app.post('/api/killswitch', requireRole('ADMIN'), async (req, res) => {
  const active = req.body?.active;
  if (typeof active !== 'boolean') {
    return res.status(400).json({ error: 'active must be a boolean' });
  }
  try {
    return res.json(await updateKillSwitch(active));
  } catch {
    return res.status(503).json({ error: 'unable to persist kill switch state' });
  }
});

app.post('/api/authorization', requireRole('ADMIN'), (req, res) => {
  if (!AUTHORIZATION_SECRET) {
    return res.status(503).json({ error: 'authorization signing is not configured' });
  }
  const target = normalizeTarget(req.body?.target || AUTHORIZED_LAB_URL);
  if (!target) {
    return res.status(400).json({ error: 'target is required' });
  }
  const note = {
    target,
    scope: req.body?.scope || 'lab-only',
    date: req.body?.date || new Date().toISOString().slice(0, 10),
    approver: req.body?.approver || 'security-lead',
    signature: '',
  };
  note.signature = registrationSignature({ ...note, issuedAt: new Date().toISOString() });
  return res.json({
    target: note.target,
    scope: note.scope,
    date: note.date,
    approver: note.approver,
    signature: note.signature,
    authorizationRef: LAB_AUTHORIZATION_REF || 'LAB-AUTH-2026',
    active: true,
  });
});

app.post('/api/automation/events', requireRole('ADMIN', 'SECURITY_ANALYST'), (req, res) => {
  const event = req.body ?? {};
  const item = {
    id: randomUUID(),
    createdAt: new Date().toISOString(),
    runId: event.runId || null,
    workflow: event.workflow || 'unknown',
    step: event.step || 'unknown',
    status: event.status || 'ok',
    detail: event.detail || null,
  };
  automationEvents.push(item);
  return res.status(202).json({ accepted: true, event: item });
});

app.get('/api/automation/runs', (_req, res) => {
  res.json({ runs: automationEvents });
});

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

app.post('/api/automation/run', requireRole('ADMIN', 'SECURITY_ANALYST', 'AUTOMATION'), async (req, res) => {
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
  const allowRapidRepeatInLocalDev = process.env.NODE_ENV !== 'production' && /(localhost|127\.0\.0\.1|0\.0\.0\.0)/.test(N8N_BASE_URL || '');
  if (!allowRapidRepeatInLocalDev && Date.now() - lastScanAt < 60_000) {
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
    const message = 'n8n is unavailable. Start the local stack to run the private-lab scanner.';
    await updateScanStatus(scanId, 'failed', message);
    return res.status(503).json({
      error: message,
      scanId,
      status: 'failed',
      mode: 'local-dev-fallback',
    });
  }
});

app.get('/api/scans/:id', async (req, res) => {
  try {
    let scan = await getScan(req.params.id);
    if (!scan) return res.status(404).json({ error: 'assessment not found' });
    const requestedAt = Date.parse(scan.requestedAt);
    if (scan.status === 'running' && Number.isFinite(requestedAt) && Date.now() - requestedAt > SCAN_TIMEOUT_MS) {
      await updateScanStatus(scan.id, 'failed', 'Assessment timed out waiting for the private-lab scanner callback.');
      scan = await getScan(scan.id);
    }
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
    if (status === 'completed') await appendScanEvidence(req.params.id, findings);
    return res.status(202).json({ status: 'stored', scanId: req.params.id, findingCount: findings.length });
  } catch {
    return res.status(503).json({ error: 'unable to persist scanner results' });
  }
});

app.post('/api/scope/kill-switch', requireRole('ADMIN'), async (req, res) => {
  if (typeof req.body?.active !== 'boolean') {
    return res.status(400).json({ error: 'active must be a boolean' });
  }
  try {
    return res.json(await updateKillSwitch(req.body.active));
  } catch {
    return res.status(503).json({ error: 'unable to persist kill switch state' });
  }
});

app.get('/api/overview', async (_req, res) => {
  try {
    const latestFindings = await getLatestCompletedFindings();
    if (latestFindings === null && !process.env.DATABASE_URL) {
      return res.json({
        ...overview,
        target: AUTHORIZED_LAB_URL || 'not configured',
        phases: assessmentTimeline,
        recentEvents: automationEvents.slice(-5).reverse(),
      });
    }

    const scans = await getCompletedScans();
    const findings = latestFindings ?? [];
    const confirmedFindings = findings.filter((finding) => finding.status === 'CONFIRMED');
    const severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    confirmedFindings.forEach((finding) => {
      if (finding.severity in severityCounts) severityCounts[finding.severity]++;
    });
    const postureScore = scans.length
      ? calculatePostureScore(findings, { sensitiveSector: process.env.SENSITIVE_SECTOR === 'true' })
      : 0;
    const grade = scans.length ? gradePostureScore(postureScore) : 'N/A';
    let previousScore = null;
    const scoreHistory = scans.reverse().map((scan) => {
      const scanFindings = scan.findings ?? [];
      const score = calculatePostureScore(scanFindings, { sensitiveSector: process.env.SENSITIVE_SECTOR === 'true' });
      const delta = previousScore === null ? 0 : score - previousScore;
      previousScore = score;
      return {
        date: new Date(scan.completedAt || scan.requestedAt).toISOString().slice(5, 10),
        score,
        grade: gradePostureScore(score),
        delta,
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
      phases: assessmentTimeline,
      recentEvents: automationEvents.slice(-5).reverse(),
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

app.get('/api/evidence', async (_req, res) => {
  try {
    return res.json(await getEvidence());
  } catch {
    return res.status(503).json({ error: 'unable to read evidence records' });
  }
});

app.get('/api/evidence/verify', async (_req, res) => {
  try {
    return res.json(verifyEvidenceChain(await getEvidence()));
  } catch {
    return res.status(503).json({ error: 'unable to verify evidence integrity' });
  }
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
    recentEvents: automationEvents.slice(-5).reverse(),
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
      'Production hardening review',
    ],
    timeline: assessmentTimeline,
  });
});

app.post('/api/retest', requireRole('ADMIN', 'SECURITY_ANALYST'), (req, res) => {
  const { findingIds, allFixed } = req.body ?? {};
  return res.json({
    accepted: true,
    status: 'queued',
    findingIds: Array.isArray(findingIds) ? findingIds : [],
    allFixed: Boolean(allFixed),
    message: 'Re-test queued against the fixed lab build',
  });
});

app.get('/api/report/sarif', async (_req, res) => {
  try {
    const latestFindings = await getLatestCompletedFindings();
    const reportFindings = latestFindings ?? (process.env.DATABASE_URL ? [] : findings);
    return res.json(buildSarifReport(reportFindings, AUTHORIZED_LAB_URL));
  } catch {
    return res.status(503).json({ error: 'unable to generate SARIF report' });
  }
});

app.get('/api/report/pdf', async (_req, res) => {
  try {
    const [latestFindings, scans, evidence] = await Promise.all([
      getLatestCompletedFindings(),
      getCompletedScans(),
      getEvidence(),
    ]);
    const reportFindings = latestFindings ?? (process.env.DATABASE_URL ? [] : findings);
    const confirmedFindings = reportFindings.filter((finding) => finding.status === 'CONFIRMED');
    const severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    confirmedFindings.forEach((finding) => {
      if (finding.severity in severityCounts) severityCounts[finding.severity] += 1;
    });
    const hasScan = scans.length > 0;
    const postureScore = hasScan
      ? calculatePostureScore(reportFindings, { sensitiveSector: process.env.SENSITIVE_SECTOR === 'true' })
      : 0;
    const pdf = await generateExecutivePdf({
      overview: {
        target: AUTHORIZED_LAB_URL || 'not configured',
        postureScore,
        grade: hasScan ? gradePostureScore(postureScore) : 'N/A',
        confirmedFindings: confirmedFindings.length,
        unverifiedFindings: reportFindings.filter((finding) => finding.status === 'UNVERIFIED').length,
        severityCounts,
        hasScan,
      },
      findings: reportFindings,
      evidenceIntegrity: verifyEvidenceChain(evidence),
    });
    res.set('Content-Type', 'application/pdf');
    res.set('Content-Disposition', 'attachment; filename="trovex-executive-report.pdf"');
    res.set('Cache-Control', 'no-store');
    return res.status(200).send(pdf);
  } catch {
    return res.status(503).json({ error: 'unable to generate PDF report' });
  }
});

if (process.env.NODE_ENV === 'production') {
  app.use(express.static('dist'));
  app.get(['/login', '/signup', '/dashboard'], (_req, res) => {
    return res.sendFile('dist/index.html', { root: process.cwd() });
  });
}

export function startServer(port = DEFAULT_PORT) {
  if (serverInstance && serverInstance.listening) {
    return serverInstance;
  }

  if (serverInstance && !serverInstance.listening) {
    serverInstance = null;
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
