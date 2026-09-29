import { Pool } from 'pg';

const pool = process.env.DATABASE_URL
  ? new Pool({ connectionString: process.env.DATABASE_URL, max: 5 })
  : null;
const localScans = new Map();
let localKillSwitch = process.env.SCAN_KILL_SWITCH === 'true';
let schemaReady;

async function ensureSchema() {
  if (!pool) return;
  if (!schemaReady) {
    schemaReady = pool.query(`
      CREATE TABLE IF NOT EXISTS assessment_scans (
        id UUID PRIMARY KEY,
        target TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'failed')),
        requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        completed_at TIMESTAMPTZ,
        error TEXT,
        findings JSONB NOT NULL DEFAULT '[]'::jsonb
      );
      CREATE INDEX IF NOT EXISTS assessment_scans_requested_at_idx
        ON assessment_scans (requested_at DESC);
      CREATE TABLE IF NOT EXISTS system_controls (
        id SMALLINT PRIMARY KEY CHECK (id = 1),
        scan_kill_switch BOOLEAN NOT NULL DEFAULT FALSE,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
      INSERT INTO system_controls (id, scan_kill_switch)
        VALUES (1, ${process.env.SCAN_KILL_SWITCH === 'true' ? 'TRUE' : 'FALSE'})
        ON CONFLICT (id) DO NOTHING;
    `);
  }
  await schemaReady;
}

export async function createScan(scan) {
  if (!pool) {
    localScans.set(scan.id, { ...scan, requestedAt: new Date().toISOString(), findings: [] });
    return;
  }
  await ensureSchema();
  await pool.query(
    'INSERT INTO assessment_scans (id, target, status) VALUES ($1, $2, $3)',
    [scan.id, scan.target, scan.status],
  );
}

export async function updateScanStatus(id, status, error = null) {
  if (!pool) {
    const scan = localScans.get(id);
    if (scan && (status !== 'running' || scan.status === 'queued')) Object.assign(scan, { status, error });
    return;
  }
  await ensureSchema();
  await pool.query(
    `UPDATE assessment_scans SET status = $2, error = $3
     WHERE id = $1 AND ($2 <> 'running' OR status = 'queued')`,
    [id, status, error],
  );
}

export async function finishScan(id, status, findings = [], error = null) {
  const completedAt = new Date().toISOString();
  if (!pool) {
    const scan = localScans.get(id);
    if (scan) Object.assign(scan, { status, findings, error, completedAt });
    return;
  }
  await ensureSchema();
  await pool.query(
    `UPDATE assessment_scans
     SET status = $2, findings = $3::jsonb, error = $4, completed_at = $5
     WHERE id = $1`,
    [id, status, JSON.stringify(findings), error, completedAt],
  );
}

export async function getScan(id) {
  if (!pool) return localScans.get(id) ?? null;
  await ensureSchema();
  const { rows } = await pool.query(
    `SELECT id, target, status, requested_at AS "requestedAt",
            completed_at AS "completedAt", error, findings
     FROM assessment_scans WHERE id = $1`,
    [id],
  );
  return rows[0] ?? null;
}

export async function getLatestCompletedFindings() {
  if (!pool) {
    const latest = [...localScans.values()]
      .filter((scan) => scan.status === 'completed')
      .sort((left, right) => right.requestedAt.localeCompare(left.requestedAt))[0];
    return latest?.findings ?? null;
  }
  await ensureSchema();
  const { rows } = await pool.query(
    `SELECT findings FROM assessment_scans
     WHERE status = 'completed'
     ORDER BY requested_at DESC LIMIT 1`,
  );
  return rows[0]?.findings ?? null;
}

export async function getCompletedScans() {
  if (!pool) {
    return [...localScans.values()]
      .filter((scan) => scan.status === 'completed')
      .sort((left, right) => right.requestedAt.localeCompare(left.requestedAt))
      .slice(0, 7);
  }
  await ensureSchema();
  const { rows } = await pool.query(
    `SELECT id, target, status, requested_at AS "requestedAt",
            completed_at AS "completedAt", findings
     FROM assessment_scans WHERE status = 'completed'
     ORDER BY completed_at DESC LIMIT 7`,
  );
  return rows;
}

export async function getKillSwitch() {
  if (!pool) return localKillSwitch;
  await ensureSchema();
  const { rows } = await pool.query('SELECT scan_kill_switch FROM system_controls WHERE id = 1');
  return rows[0]?.scan_kill_switch ?? true;
}

export async function setKillSwitch(active) {
  if (!pool) {
    localKillSwitch = active;
    return;
  }
  await ensureSchema();
  await pool.query(
    `INSERT INTO system_controls (id, scan_kill_switch, updated_at)
     VALUES (1, $1, NOW())
     ON CONFLICT (id) DO UPDATE
     SET scan_kill_switch = EXCLUDED.scan_kill_switch, updated_at = NOW()`,
    [active],
  );
}

export async function closeDatabase() {
  await pool?.end();
}