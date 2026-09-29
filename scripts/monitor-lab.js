const apiUrl = process.env.TROVEX_API_URL;
const monitorToken = process.env.MONITOR_TOKEN;
if (!apiUrl) throw new Error('TROVEX_API_URL is required');
if (!monitorToken) throw new Error('MONITOR_TOKEN is required');

const response = await fetch(`${apiUrl.replace(/\/$/, '')}/api/automation/run`, {
  method: 'POST',
  headers: {
    'content-type': 'application/json',
    authorization: `Bearer ${monitorToken}`,
  },
  body: JSON.stringify({ event: 'assessment.started', payload: { source: 'scheduled-monitor' } }),
  signal: AbortSignal.timeout(15000),
});

const body = await response.json().catch(() => ({}));
if (!response.ok) {
  throw new Error(`Scheduled lab assessment rejected: HTTP ${response.status} ${body.error || body.reason || ''}`);
}

console.log(`Scheduled assessment ${body.scanId} accepted`);