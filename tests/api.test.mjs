import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer } from 'node:http';

process.env.NODE_ENV = 'test';
process.env.PORT = '3456';
process.env.AUTHORIZED_LAB_URL = 'http://127.0.0.1:10000';
process.env.LAB_AUTHORIZATION_REF = 'TEST-LAB-2026';
process.env.LAB_AUTHORIZATION_VALID_UNTIL = '2099-12-31T23:59:59Z';
process.env.INTERNAL_SCAN_TOKEN = 'test-callback-token';
process.env.MONITOR_TOKEN = 'test-monitor-token';
process.env.DASHBOARD_USER = 'test-user';
process.env.DASHBOARD_PASSWORD = 'test-password';

const port = Number(process.env.PORT);
const dashboardAuth = `Basic ${Buffer.from(`${process.env.DASHBOARD_USER}:${process.env.DASHBOARD_PASSWORD}`).toString('base64')}`;

test('backend health endpoint responds', async () => {
  const receivedEvents = [];
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

    const disableKillSwitch = await apiFetch('/api/scope/kill-switch', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ active: false }),
    });
    assert.equal(disableKillSwitch.status, 200);

    const persistedFindings = await (await apiFetch('/api/findings')).json();
    assert.equal(persistedFindings[0].title, 'Missing security header');
  } finally {
    server.closeAllConnections();
    n8nMock.closeAllConnections();
    await new Promise((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
    await new Promise((resolve, reject) => {
      n8nMock.close((error) => (error ? reject(error) : resolve()));
    });
  }
});
