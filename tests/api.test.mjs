import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { calculatePostureScore, gradePostureScore } from '../server/scoring.js';

process.env.NODE_ENV = 'test';
process.env.PORT = '3456';
process.env.AUTHORIZED_LAB_URL = 'http://127.0.0.1:10000';
process.env.LAB_AUTHORIZATION_REF = 'TEST-LAB-2026';
process.env.LAB_AUTHORIZATION_VALID_UNTIL = '2099-12-31T23:59:59Z';
process.env.INTERNAL_SCAN_TOKEN = 'test-callback-token';
process.env.MONITOR_TOKEN = 'test-monitor-token';
process.env.DASHBOARD_USER = 'test-user';
process.env.DASHBOARD_PASSWORD = 'test-password';
process.env.ANALYST_USER = 'analyst@example.test';
process.env.ANALYST_PASSWORD = 'analyst-test-password';
process.env.VIEWER_USER = 'viewer@example.test';
process.env.VIEWER_PASSWORD = 'viewer-test-password';

const port = Number(process.env.PORT);
const dashboardAuth = `Basic ${Buffer.from(`${process.env.DASHBOARD_USER}:${process.env.DASHBOARD_PASSWORD}`).toString('base64')}`;

test('backend health endpoint responds', async () => {
  const receivedEvents = [];
  const cancellationRequests = [];
  const scannerMock = createServer(async (req, res) => {
    if (req.method === 'POST' && req.url?.endsWith('/cancel')) {
      if (req.headers.authorization !== `Bearer ${process.env.INTERNAL_SCAN_TOKEN}`) {
        res.writeHead(401).end();
        return;
      }
      cancellationRequests.push(req.url.split('/')[2]);
      res.writeHead(202, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ status: 'cancelling' }));
      return;
    }
    res.writeHead(404).end();
  });
  const scannerListening = once(scannerMock, 'listening');
  scannerMock.listen(0, '127.0.0.1');
  await scannerListening;
  process.env.SCANNER_BASE_URL = `http://127.0.0.1:${scannerMock.address().port}`;

  const n8nMock = createServer(async (req, res) => {
    if (req.url === '/healthz') {
      res.writeHead(200).end();
      return;
    }

    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const receivedEvent = JSON.parse(Buffer.concat(chunks).toString());
    receivedEvents.push(receivedEvent);
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ status: 'accepted', scanId: receivedEvent.payload.scanId }));
  });
  const n8nListening = once(n8nMock, 'listening');
  n8nMock.listen(0, '127.0.0.1');
  await n8nListening;
  const n8nPort = n8nMock.address().port;
  process.env.N8N_BASE_URL = `http://127.0.0.1:${n8nPort}`;
  process.env.N8N_WEBHOOK_URL = `${process.env.N8N_BASE_URL}/webhook/trovex-assessment`;
  const { startServer } = await import('../server.js');
  const server = startServer(port);
  const apiFetch = (path, options = {}) => {
    const { headers = {}, ...rest } = options;
    return fetch(`http://localhost:${port}${path}`, {
      ...rest,
      headers: { authorization: dashboardAuth, ...headers },
    });
  };

  try {
    await once(server, 'listening');

    const res = await fetch(`http://localhost:${port}/api/health`);
    const body = await res.json();

    assert.equal(res.status, 200);
    assert.equal(body.status, 'ok');
    assert.equal(body.name, 'trovex-platform');
    assert.equal(body.service, 'trovex-api');
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(res.headers.get('x-frame-options'), 'DENY');
    assert.equal(res.headers.get('referrer-policy'), 'strict-origin-when-cross-origin');
    assert.equal(res.headers.get('x-powered-by'), null);

    const unauthorizedFindings = await fetch(`http://localhost:${port}/api/findings`);
    assert.equal(unauthorizedFindings.status, 401);

    const automationStatus = await apiFetch('/api/automation/status');
    assert.deepEqual(await automationStatus.json(), {
      configured: true,
      connected: true,
      workflowWebhook: '/webhook/trovex-assessment',
    });

    const automationRun = await apiFetch('/api/automation/run', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ event: 'assessment.started', payload: {} }),
    });
    assert.equal(automationRun.status, 202);
    const acceptedRun = await automationRun.json();
    assert.equal(acceptedRun.status, 'running');
    assert.equal((await apiFetch(`/api/scans/${acceptedRun.scanId}`)).status, 200);
    assert.deepEqual(receivedEvents[0], {
      event: 'assessment.started',
      payload: {
        scanId: acceptedRun.scanId,
        target: process.env.AUTHORIZED_LAB_URL,
        authorizationRef: process.env.LAB_AUTHORIZATION_REF,
      },
      source: 'trovex-platform',
    });

    const rejectedRun = await apiFetch('/api/automation/run', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        event: 'assessment.started',
        payload: { target: 'https://public.example', authorizationRef: process.env.LAB_AUTHORIZATION_REF },
      }),
    });
    assert.equal(rejectedRun.status, 403);
    assert.equal(receivedEvents.length, 1);

    const callback = await apiFetch(`/api/internal/scans/${acceptedRun.scanId}/results`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${process.env.INTERNAL_SCAN_TOKEN}`,
      },
      body: JSON.stringify({
        status: 'completed',
        findings: [{ pluginId: '10020', title: 'Missing security header', severity: 'MEDIUM', endpoint: 'http://127.0.0.1:10000/' }],
      }),
    });
    assert.equal(callback.status, 202);
    const scanResult = await (await apiFetch(`/api/scans/${acceptedRun.scanId}`)).json();
    assert.equal(scanResult.status, 'completed');
    assert.equal(scanResult.findings[0].title, 'Missing security header');
    const overview = await (await apiFetch('/api/overview')).json();
    assert.equal(overview.postureScore, 100);
    assert.equal(overview.grade, 'A');
    assert.equal(overview.severityCounts.MEDIUM, 0);
    const sarif = await (await apiFetch('/api/report/sarif')).json();
    assert.match(sarif.$schema, /sarif-2\.1\.0/);
    assert.equal(sarif.version, '2.1.0');
    assert.equal(sarif.runs[0].results.length, 1);
    assert.equal(sarif.runs[0].tool.driver.rules.length, 1);
    assert.equal(sarif.runs[0].results[0].properties.status, 'UNVERIFIED');
    assert.equal(sarif.runs[0].results[0].level, 'warning');
    assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, 'http://127.0.0.1:10000/');
    assert.match(sarif.runs[0].results[0].partialFingerprints.primaryLocationLineHash, /^[a-f0-9]{64}$/);
    const pdfResponse = await apiFetch('/api/report/pdf');
    assert.equal(pdfResponse.status, 200);
    assert.match(pdfResponse.headers.get('content-type'), /application\/pdf/);
    assert.match(pdfResponse.headers.get('content-disposition'), /trovex-executive-report\.pdf/);
    const pdfBytes = Buffer.from(await pdfResponse.arrayBuffer());
    assert.equal(pdfBytes.subarray(0, 5).toString(), '%PDF-');
    assert.ok(pdfBytes.length > 1000);

    const evidence = await (await apiFetch('/api/evidence')).json();
    assert.equal(evidence.length, 1);
    assert.equal(evidence[0].finding_id, scanResult.findings[0].id);
    const integrity = await (await apiFetch('/api/evidence/verify')).json();
    assert.deepEqual(integrity, {
      valid: true,
      verifiedCount: 1,
      recordCount: 1,
      failedRecordId: null,
    });
    const { verifyEvidenceChain } = await import('../server/database.js');
    const alteredEvidence = [{ ...evidence[0], payload: { ...evidence[0].payload, title: 'Tampered title' } }];
    assert.equal(verifyEvidenceChain(alteredEvidence).valid, false);

    const invalidRun = await apiFetch('/api/automation/run', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ payload: {} }),
    });
    assert.equal(invalidRun.status, 400);

    const enableKillSwitch = await apiFetch('/api/scope/kill-switch', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ active: true }),
    });
    assert.equal(enableKillSwitch.status, 200);
    const blockedRun = await apiFetch('/api/automation/run', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ event: 'assessment.started', payload: {} }),
    });
    assert.equal(blockedRun.status, 423);

    const cancellableRun = await apiFetch('/api/automation/run', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ event: 'assessment.started', payload: {} }),
    });
    assert.equal(cancellableRun.status, 423);

    const disableKillSwitch = await apiFetch('/api/scope/kill-switch', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ active: false }),
    });
    assert.equal(disableKillSwitch.status, 200);

    const activeRun = await apiFetch('/api/automation/run', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ event: 'assessment.started', payload: {} }),
    });
    assert.equal(activeRun.status, 202);
    const activeRunBody = await activeRun.json();
    const reenableKillSwitch = await apiFetch('/api/scope/kill-switch', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ active: true }),
    });
    assert.equal(reenableKillSwitch.status, 200);
    const killResult = await reenableKillSwitch.json();
    assert.equal(killResult.cancelledScans, 1);
    assert.deepEqual(cancellationRequests, [activeRunBody.scanId]);
    const cancelledCallback = await apiFetch(`/api/internal/scans/${activeRunBody.scanId}/results`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${process.env.INTERNAL_SCAN_TOKEN}`,
      },
      body: JSON.stringify({ status: 'failed', error: 'assessment cancelled by the kill switch' }),
    });
    assert.equal(cancelledCallback.status, 202);
    const releaseKillSwitch = await apiFetch('/api/scope/kill-switch', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ active: false }),
    });
    assert.equal(releaseKillSwitch.status, 200);

    const persistedFindings = await (await apiFetch('/api/findings')).json();
    assert.equal(persistedFindings[0].title, 'Missing security header');
  } finally {
    server.closeAllConnections();
    n8nMock.closeAllConnections();
    scannerMock.closeAllConnections();
    await new Promise((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
    await new Promise((resolve, reject) => {
      n8nMock.close((error) => (error ? reject(error) : resolve()));
    });
    await new Promise((resolve, reject) => {
      scannerMock.close((error) => (error ? reject(error) : resolve()));
    });
  }
});

test('posture scoring applies exact confirmed-only severity deductions', () => {
  const sample = [
    { severity: 'CRITICAL', status: 'CONFIRMED' },
    { severity: 'HIGH', status: 'CONFIRMED' },
    { severity: 'MEDIUM', status: 'CONFIRMED' },
    { severity: 'LOW', status: 'CONFIRMED' },
    { severity: 'INFO', status: 'CONFIRMED' },
    { severity: 'CRITICAL', status: 'UNVERIFIED' },
  ];

  assert.equal(calculatePostureScore(sample), 72);
  assert.equal(calculatePostureScore(sample, { sensitiveSector: true }), 59.7);
  assert.equal(calculatePostureScore(Array(10).fill({ severity: 'CRITICAL', status: 'CONFIRMED' })), 0);
  assert.equal(gradePostureScore(89), 'B');
  assert.equal(gradePostureScore(75), 'B');
  assert.equal(gradePostureScore(60), 'C');
  assert.equal(gradePostureScore(40), 'D');
});

test('scope guard blocks the live target and exposes the compatibility endpoints', async () => {
  const { startServer } = await import('../server.js');
  const server = startServer(3457);
  const apiFetch = (path, options = {}) => {
    const { headers = {}, ...rest } = options;
    return fetch(`http://localhost:3457${path}`, {
      ...rest,
      headers: { authorization: `Basic ${Buffer.from(`${process.env.DASHBOARD_USER}:${process.env.DASHBOARD_PASSWORD}`).toString('base64')}`, ...headers },
    });
  };

  try {
    await once(server, 'listening');

    const blocked = await apiFetch('/api/scope/check', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        target: 'https://worldmonitor.app',
        scope: 'full',
        allowUnsafe: false,
      }),
    });
    assert.equal(blocked.status, 403);
    const blockedBody = await blocked.json();
    assert.equal(blockedBody.allowed, false);
    assert.match(String(blockedBody.reason || ''), /worldmonitor|allowlist|lab/i);

    const allowed = await apiFetch('/api/scope/check', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        target: process.env.AUTHORIZED_LAB_URL,
        scope: 'lab',
        allowUnsafe: false,
      }),
    });
    assert.equal(allowed.status, 200);
    const allowedBody = await allowed.json();
    assert.equal(allowedBody.allowed, true);

    const kill = await apiFetch('/api/killswitch', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ active: true }),
    });
    assert.equal(kill.status, 200);
    const killBody = await kill.json();
    assert.equal(killBody.killSwitch, true);

    const authNote = await apiFetch('/api/authorization', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        target: process.env.AUTHORIZED_LAB_URL,
        scope: 'lab-only',
        date: '2026-09-30',
        approver: 'security-lead',
      }),
    });
    assert.equal(authNote.status, 200);
    const authBody = await authNote.json();
    assert.match(String(authBody.signature || ''), /[A-Fa-f0-9]{32,}/);
  } finally {
    server.closeAllConnections();
    await new Promise((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  }
});

test('assessment fails clearly in local mode when n8n is unavailable', async () => {
  const { startServer } = await import('../server.js');
  const server = startServer(3458);
  const apiFetch = (path, options = {}) => {
    const { headers = {}, ...rest } = options;
    return fetch(`http://localhost:3458${path}`, {
      ...rest,
      headers: { authorization: `Basic ${Buffer.from(`${process.env.DASHBOARD_USER}:${process.env.DASHBOARD_PASSWORD}`).toString('base64')}`, ...headers },
    });
  };

  try {
    await once(server, 'listening');
    await apiFetch('/api/scope/kill-switch', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ active: false }),
    });
    process.env.N8N_BASE_URL = 'http://127.0.0.1:65535';
    process.env.N8N_WEBHOOK_URL = `${process.env.N8N_BASE_URL}/webhook/trovex-assessment`;

    const run = await apiFetch('/api/automation/run', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ event: 'assessment.started', payload: {} }),
    });

    assert.equal(run.status, 503);
    const body = await run.json();
    assert.equal(body.status, 'failed');
    assert.ok(body.scanId);
    assert.match(body.error, /n8n is unavailable/i);
    const scan = await (await apiFetch(`/api/scans/${body.scanId}`)).json();
    assert.equal(scan.status, 'failed');
  } finally {
    server.closeAllConnections();
    await new Promise((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  }
});

test('methodology and scope status expose the assessment lifecycle and recent events', async () => {
  const { startServer } = await import('../server.js');
  const server = startServer(3459);
  const apiFetch = (path, options = {}) => {
    const { headers = {}, ...rest } = options;
    return fetch(`http://localhost:3459${path}`, {
      ...rest,
      headers: { authorization: `Basic ${Buffer.from(`${process.env.DASHBOARD_USER}:${process.env.DASHBOARD_PASSWORD}`).toString('base64')}`, ...headers },
    });
  };

  try {
    await once(server, 'listening');

    const methodology = await apiFetch('/api/methodology');
    assert.equal(methodology.status, 200);
    const methodologyBody = await methodology.json();
    assert.ok(Array.isArray(methodologyBody.phases));
    assert.ok(Array.isArray(methodologyBody.timeline));
    assert.equal(methodologyBody.timeline[0].name, 'Scope validation');

    const scopeStatus = await apiFetch('/api/scope/status');
    assert.equal(scopeStatus.status, 200);
    const scopeBody = await scopeStatus.json();
    assert.ok(Array.isArray(scopeBody.recentEvents));
  } finally {
    server.closeAllConnections();
    await new Promise((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  }
});

test('authorization, kill-switch, and automation event routes reject unauthenticated requests', async () => {
  const { startServer } = await import('../server.js');
  const server = startServer(3460);

  try {
    await once(server, 'listening');
    const authorization = await fetch(`http://localhost:3460/api/authorization`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ target: process.env.AUTHORIZED_LAB_URL }),
    });
    assert.equal(authorization.status, 401);

    const killSwitch = await fetch(`http://localhost:3460/api/killswitch`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ active: true }),
    });
    assert.equal(killSwitch.status, 401);

    const automationEvent = await fetch(`http://localhost:3460/api/automation/events`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ workflow: 'unauthorized' }),
    });
    assert.equal(automationEvent.status, 401);
  } finally {
    server.closeAllConnections();
    await new Promise((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  }
});

test('login sessions enforce analyst and viewer permissions on the backend', async () => {
  const { startServer } = await import('../server.js');
  const server = startServer(3461);
  const login = async (username, password) => fetch(`http://localhost:3461/api/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });

  try {
    await once(server, 'listening');

    const invalidLogin = await login(process.env.VIEWER_USER, 'wrong-password');
    assert.equal(invalidLogin.status, 401);

    const viewerLogin = await login(process.env.VIEWER_USER, process.env.VIEWER_PASSWORD);
    assert.equal(viewerLogin.status, 200);
    const viewerBody = await viewerLogin.json();
    assert.equal(viewerBody.user.role, 'VIEWER');
    const viewerCookie = viewerLogin.headers.get('set-cookie').split(';')[0];
    const viewerFetch = (path, options = {}) => fetch(`http://localhost:3461${path}`, {
      ...options,
      headers: { cookie: viewerCookie, ...options.headers },
    });

    const deniedRun = await viewerFetch('/api/automation/run', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ event: 'assessment.started', payload: {} }),
    });
    assert.equal(deniedRun.status, 403);

    const deniedAuthorization = await viewerFetch('/api/authorization', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({}),
    });
    assert.equal(deniedAuthorization.status, 403);

    const analystLogin = await login(process.env.ANALYST_USER, process.env.ANALYST_PASSWORD);
    assert.equal(analystLogin.status, 200);
    const analystCookie = analystLogin.headers.get('set-cookie').split(';')[0];
    const analystRetest = await fetch(`http://localhost:3461/api/retest`, {
      method: 'POST',
      headers: { cookie: analystCookie, 'content-type': 'application/json' },
      body: JSON.stringify({ findingIds: ['F-001'] }),
    });
    assert.equal(analystRetest.status, 200);

    const logout = await fetch(`http://localhost:3461/api/auth/logout`, {
      method: 'POST',
      headers: { cookie: analystCookie },
    });
    assert.equal(logout.status, 204);
    const invalidatedSession = await fetch('http://localhost:3461/api/auth/session', { headers: { cookie: analystCookie } });
    assert.equal((await invalidatedSession.json()).authenticated, false);
  } finally {
    server.closeAllConnections();
    await new Promise((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  }
});

test('sign-up hashes credentials, limits public roles, and logs the user in', async () => {
  const { startServer } = await import('../server.js');
  const server = startServer(3462);
  const register = (overrides = {}) => fetch('http://localhost:3462/api/auth/signup', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      name: 'New Trovex Analyst',
      email: 'New.Analyst@example.test',
      password: 'StrongPassword!42',
      role: 'SECURITY_ANALYST',
      termsAccepted: true,
      ...overrides,
    }),
  });

  try {
    await once(server, 'listening');

    const adminAttempt = await register({ email: 'admin-registration@example.test', role: 'ADMIN' });
    assert.equal(adminAttempt.status, 403);

    const weakPassword = await register({ email: 'weak-password@example.test', password: 'short' });
    assert.equal(weakPassword.status, 400);

    const registration = await register();
    assert.equal(registration.status, 201);
    const result = await registration.json();
    assert.equal(result.user.role, 'SECURITY_ANALYST');
    assert.equal(result.user.email, 'new.analyst@example.test');
    assert.equal(Object.hasOwn(result.user, 'password'), false);
    assert.equal(Object.hasOwn(result.user, 'password_hash'), false);

    const cookie = registration.headers.get('set-cookie').split(';')[0];
    const session = await fetch('http://localhost:3462/api/auth/session', { headers: { cookie } });
    assert.equal((await session.json()).authenticated, true);

    const duplicate = await register();
    assert.equal(duplicate.status, 409);
  } finally {
    server.closeAllConnections();
    await new Promise((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  }
});
