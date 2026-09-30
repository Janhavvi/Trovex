import { randomBytes } from 'node:crypto';
import { appendFile, open, readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const envPath = fileURLToPath(new URL('../.env', import.meta.url));
const secret = (bytes = 32) => randomBytes(bytes).toString('base64url');
const values = {
  FRONTEND_URL: 'http://localhost:8443',
  POSTGRES_PASSWORD: secret(),
  N8N_ENCRYPTION_KEY: randomBytes(32).toString('hex'),
  INTERNAL_SCAN_TOKEN: secret(),
  MONITOR_TOKEN: secret(),
  AUTHORIZATION_SECRET: secret(),
  DASHBOARD_USER: 'trovex-admin',
  DASHBOARD_PASSWORD: secret(),
  ANALYST_USER: 'trovex-analyst',
  ANALYST_PASSWORD: secret(),
  VIEWER_USER: 'trovex-viewer',
  VIEWER_PASSWORD: secret(),
  LAB_AUTHORIZATION_REF: 'TROVEX-LAB-2026',
  LAB_AUTHORIZATION_VALID_UNTIL: '2030-12-31T23:59:59Z',
};
const content = `${Object.entries(values).map(([key, value]) => `${key}=${value}`).join('\n')}\n`;

try {
  const file = await open(envPath, 'wx', 0o600);
  try {
    await file.writeFile(content, 'utf8');
  } finally {
    await file.close();
  }
  console.log('Created .env with locally generated credentials. Keep it private and do not commit it.');
} catch (error) {
  if (error.code === 'EEXIST') {
    const current = await readFile(envPath, 'utf8');
    const currentKeys = new Set(current.split(/\r?\n/).map((line) => line.trim().split('=', 1)[0]));
    const additions = Object.entries(values).filter(([key]) => !currentKeys.has(key));
    if (!additions.length) {
      console.log('.env already contains all local settings; no changes made.');
    } else {
      const prefix = current.endsWith('\n') ? '' : '\n';
      await appendFile(envPath, `${prefix}${additions.map(([key, value]) => `${key}=${value}`).join('\n')}\n`, 'utf8');
      console.log('Added missing local settings to .env without changing existing values. Secrets were not displayed.');
    }
  } else {
    throw error;
  }
}
