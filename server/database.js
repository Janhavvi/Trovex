import { createHash, randomUUID } from 'node:crypto';
import { Pool } from 'pg';

const pool = process.env.DATABASE_URL
  ? new Pool({ connectionString: process.env.DATABASE_URL, max: 5 })
  : null;
const localScans = new Map();
const localEvidence = [];
const localUsersByLogin = new Map();
const localUsersById = new Map();
const localAuthSessions = new Map();
const EVIDENCE_GENESIS_HASH = '0'.repeat(64);
let localKillSwitch = process.env.SCAN_KILL_SWITCH === 'true';
let schemaReady;

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]));
  }
  return value;
}

function hashEvidenceRecord(record) {
  const content = {
    id: record.id,
    scan_id: record.scan_id,
    finding_id: record.finding_id,
    timestamp: new Date(record.timestamp).toISOString(),
    type: record.type,
    prev_hash: record.prev_hash,
    payload: canonicalize(record.payload),
  };
  return createHash('sha256').update(JSON.stringify(content)).digest('hex');
}

export function verifyEvidenceChain(records) {
  let previousHash = EVIDENCE_GENESIS_HASH;
  for (let index = 0; index < records.length; index += 1) {
    const record = records[index];
    if (record.prev_hash !== previousHash || record.record_hash !== hashEvidenceRecord(record)) {
      return {
        valid: false,
        verifiedCount: index,
        recordCount: records.length,
        failedRecordId: record.id,
      };
    }
    previousHash = record.record_hash;
  }
  return { valid: true, verifiedCount: records.length, recordCount: records.length, failedRecordId: null };
}

function makeEvidenceRecord(scanId, finding, previousHash) {
  const record = {
    id: randomUUID(),
    scan_id: scanId,
    finding_id: String(finding.id || 'unknown'),
    timestamp: new Date().toISOString(),
    type: 'scanner_finding',
    prev_hash: previousHash,
    payload: finding,
  };
  return { ...record, record_hash: hashEvidenceRecord(record) };
}

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
      CREATE TABLE IF NOT EXISTS assessment_evidence (
        sequence BIGSERIAL PRIMARY KEY,
        id UUID NOT NULL UNIQUE,
        scan_id UUID NOT NULL REFERENCES assessment_scans(id) ON DELETE CASCADE,
        finding_id TEXT NOT NULL,
        record_hash CHAR(64) NOT NULL,
        prev_hash CHAR(64) NOT NULL,
        created_at TIMESTAMPTZ NOT NULL,
        type TEXT NOT NULL,
        payload JSONB NOT NULL
      );
      CREATE INDEX IF NOT EXISTS assessment_evidence_scan_id_idx
        ON assessment_evidence (scan_id, sequence);
      CREATE TABLE IF NOT EXISTS user_accounts (
        id UUID PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        login_id TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK (role IN ('ADMIN', 'SECURITY_ANALYST', 'VIEWER')),
        status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        last_login_at TIMESTAMPTZ
      );
      CREATE TABLE IF NOT EXISTS auth_sessions (
        token_hash CHAR(64) PRIMARY KEY,
        user_id UUID NOT NULL REFERENCES user_accounts(id) ON DELETE CASCADE,
        expires_at TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS auth_sessions_expires_at_idx ON auth_sessions (expires_at);
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

export async function createUser(user) {
  const email = user.email.trim().toLowerCase();
  const loginId = user.loginId.trim().toLowerCase();
  if (!pool) {
    if (localUsersByLogin.has(loginId) || [...localUsersById.values()].some((existing) => existing.email === email)) return null;
    const created = {
      ...user,
      id: user.id || randomUUID(),
      email,
      loginId,
      status: 'active',
      createdAt: new Date().toISOString(),
      lastLoginAt: null,
    };
    localUsersByLogin.set(loginId, created);
    localUsersByLogin.set(email, created);
    localUsersById.set(created.id, created);
    return created;
  }

  await ensureSchema();
  try {
    const { rows } = await pool.query(
      `INSERT INTO user_accounts (id, name, email, login_id, password_hash, role)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, name, email, login_id AS "loginId", password_hash AS "passwordHash", role, status, created_at AS "createdAt"`,
      [user.id || randomUUID(), user.name, email, loginId, user.passwordHash, user.role],
    );
    return rows[0];
  } catch (error) {
    if (error.code === '23505') return null;
    throw error;
  }
}

export async function getUserByLogin(login) {
  const normalized = String(login || '').trim().toLowerCase();
  if (!pool) return localUsersByLogin.get(normalized) || null;
  await ensureSchema();
  const { rows } = await pool.query(
    `SELECT id, name, email, login_id AS "loginId", password_hash AS "passwordHash", role, status
     FROM user_accounts WHERE lower(email) = $1 OR lower(login_id) = $1 LIMIT 1`,
    [normalized],
  );
  return rows[0] || null;
}

export async function updateUserLastLogin(id) {
  if (!pool) {
    const user = localUsersById.get(id);
    if (user) user.lastLoginAt = new Date().toISOString();
    return;
  }
  await ensureSchema();
  await pool.query('UPDATE user_accounts SET last_login_at = NOW(), updated_at = NOW() WHERE id = $1', [id]);
}

function hashSessionToken(token) {
  return createHash('sha256').update(token).digest('hex');
}

export async function createAuthSession(token, userId, expiresAt) {
  const tokenHash = hashSessionToken(token);
  if (!pool) {
    localAuthSessions.set(tokenHash, { userId, expiresAt: new Date(expiresAt).toISOString() });
    return;
  }
  await ensureSchema();
  await pool.query('DELETE FROM auth_sessions WHERE expires_at <= NOW()');
  await pool.query(
    'INSERT INTO auth_sessions (token_hash, user_id, expires_at) VALUES ($1, $2, $3)',
    [tokenHash, userId, expiresAt],
  );
}

export async function getAuthSession(token) {
  const tokenHash = hashSessionToken(token);
  if (!pool) {
    const session = localAuthSessions.get(tokenHash);
    if (!session || Date.parse(session.expiresAt) <= Date.now()) {
      localAuthSessions.delete(tokenHash);
      return null;
    }
    const user = localUsersById.get(session.userId);
    return user?.status === 'active'
      ? { id: user.id, username: user.loginId, name: user.name, email: user.email, role: user.role }
      : null;
  }
  await ensureSchema();
  const { rows } = await pool.query(
    `SELECT users.id, users.login_id AS username, users.name, users.email, users.role
     FROM auth_sessions sessions
     JOIN user_accounts users ON users.id = sessions.user_id
     WHERE sessions.token_hash = $1 AND sessions.expires_at > NOW() AND users.status = 'active'`,
    [tokenHash],
  );
  return rows[0] || null;
}

export async function deleteAuthSession(token) {
  const tokenHash = hashSessionToken(token);
  if (!pool) {
    localAuthSessions.delete(tokenHash);
    return;
  }
  await ensureSchema();
  await pool.query('DELETE FROM auth_sessions WHERE token_hash = $1', [tokenHash]);
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

export async function getRunningScans() {
  if (!pool) {
    return [...localScans.values()].filter((scan) => scan.status === 'running');
  }
  await ensureSchema();
  const { rows } = await pool.query(
    `SELECT id, target, status, requested_at AS "requestedAt"
     FROM assessment_scans WHERE status = 'running' ORDER BY requested_at`,
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

export async function appendScanEvidence(scanId, findings) {
  if (!Array.isArray(findings) || findings.length === 0) return [];

  if (!pool) {
    const existing = localEvidence.filter((record) => record.scan_id === scanId);
    if (existing.length) return existing;
    let previousHash = localEvidence.at(-1)?.record_hash || EVIDENCE_GENESIS_HASH;
    const records = findings.map((finding) => {
      const record = makeEvidenceRecord(scanId, finding, previousHash);
      previousHash = record.record_hash;
      return record;
    });
    localEvidence.push(...records);
    return records;
  }

  await ensureSchema();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock($1, $2)', [62574, 1]);
    const existing = await client.query(
      `SELECT id, scan_id, finding_id, record_hash, prev_hash,
              created_at AS timestamp, type, payload
       FROM assessment_evidence WHERE scan_id = $1 ORDER BY sequence`,
      [scanId],
    );
    if (existing.rows.length) {
      await client.query('COMMIT');
      return existing.rows.map((record) => ({ ...record, timestamp: new Date(record.timestamp).toISOString() }));
    }

    const previous = await client.query(
      'SELECT record_hash FROM assessment_evidence ORDER BY sequence DESC LIMIT 1',
    );
    let previousHash = previous.rows[0]?.record_hash || EVIDENCE_GENESIS_HASH;
    const records = findings.map((finding) => {
      const record = makeEvidenceRecord(scanId, finding, previousHash);
      previousHash = record.record_hash;
      return record;
    });
    for (const record of records) {
      await client.query(
        `INSERT INTO assessment_evidence
           (id, scan_id, finding_id, record_hash, prev_hash, created_at, type, payload)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)`,
        [record.id, record.scan_id, record.finding_id, record.record_hash, record.prev_hash,
          record.timestamp, record.type, JSON.stringify(record.payload)],
      );
    }
    await client.query('COMMIT');
    return records;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

export async function getEvidence() {
  if (!pool) return [...localEvidence];
  await ensureSchema();
  const { rows } = await pool.query(
    `SELECT id, scan_id, finding_id, record_hash, prev_hash,
            created_at AS timestamp, type, payload
     FROM assessment_evidence ORDER BY sequence`,
  );
  return rows.map((record) => ({ ...record, timestamp: new Date(record.timestamp).toISOString() }));
}