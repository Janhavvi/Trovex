import { useEffect, useState } from 'react';

type EvidenceRecord = {
  id: string;
  finding_id: string;
  record_hash: string;
  prev_hash: string;
  timestamp: string;
  type: string;
  payload: Record<string, unknown>;
};

type IntegrityResult = {
  valid: boolean;
  verifiedCount: number;
  recordCount: number;
  failedRecordId: string | null;
};

export default function EvidenceVault() {
  const [records, setRecords] = useState<EvidenceRecord[]>([]);
  const [integrity, setIntegrity] = useState<IntegrityResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [verifying, setVerifying] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let isMounted = true;
    const loadEvidence = async () => {
      setLoading(true);
      setError(null);
      try {
        const response = await fetch('/api/evidence');
        if (!response.ok) throw new Error('Unable to load evidence records');
        const data: EvidenceRecord[] = await response.json();
        if (isMounted) setRecords(data);
      } catch (loadError) {
        if (isMounted) setError(loadError instanceof Error ? loadError.message : 'Evidence is unavailable');
      } finally {
        if (isMounted) setLoading(false);
      }
    };
    void loadEvidence();
    window.addEventListener('trovex-scan-completed', loadEvidence);
    return () => {
      isMounted = false;
      window.removeEventListener('trovex-scan-completed', loadEvidence);
    };
  }, []);

  const verifyIntegrity = async () => {
    setVerifying(true);
    setIntegrity(null);
    setError(null);
    try {
      const response = await fetch('/api/evidence/verify');
      if (!response.ok) throw new Error('Unable to verify evidence integrity');
      setIntegrity(await response.json());
    } catch (verifyError) {
      setError(verifyError instanceof Error ? verifyError.message : 'Integrity verification failed');
    } finally {
      setVerifying(false);
    }
  };

  return (
    <div style={{ padding: 24, color: '#e2eaf6' }}>
      <div style={{ marginBottom: 20 }}>
        <div style={{ fontSize: 9, letterSpacing: 2, textTransform: 'uppercase', color: '#3d5470', fontFamily: 'JetBrains Mono, monospace' }}>
          Evidence Vault
        </div>
        <h1 style={{ margin: 0, fontSize: 20, fontWeight: 600, color: '#e2eaf6' }}>Assessment artifacts</h1>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap', marginTop: 12 }}>
          <div role="status" style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: integrity?.valid === false ? '#ff3b3b' : integrity?.valid ? '#00e676' : '#6b8aac' }}>
            {integrity
              ? integrity.valid
                ? `${integrity.verifiedCount} records verified · hash chain valid`
                : `Integrity violation at ${integrity.failedRecordId}`
              : `${records.length} evidence records`}
          </div>
          <button
            onClick={verifyIntegrity}
            disabled={verifying || loading}
            style={{ padding: '7px 10px', borderRadius: 4, cursor: verifying || loading ? 'default' : 'pointer', background: '#0d1520', border: '1px solid #1e2f46', color: '#00d4ff', fontFamily: 'JetBrains Mono, monospace', fontSize: 9 }}
          >
            {verifying ? 'VERIFYING…' : 'VERIFY EVIDENCE INTEGRITY'}
          </button>
        </div>
      </div>

      {error && <div role="alert" style={{ color: '#ff8d8d', fontSize: 12, marginBottom: 14 }}>{error}</div>}
      {integrity?.valid === false && <div role="alert" style={{ color: '#ff8d8d', fontSize: 12, marginBottom: 14 }}>Record {integrity.failedRecordId} does not match the stored SHA-256 chain.</div>}
      {loading && <div role="status" style={{ color: '#6b8aac', fontSize: 12 }}>Loading evidence…</div>}
      {!loading && !records.length && !error && <div style={{ color: '#6b8aac', fontSize: 12 }}>No scanner evidence has been recorded yet.</div>}

      <div style={{ display: 'grid', gap: 12, maxWidth: 1100 }}>
        {records.map((item) => (
          <div key={item.id} style={{ background: '#0d1520', border: '1px solid #1e2f46', borderRadius: 6, padding: 16 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap', marginBottom: 10 }}>
              <div>
                <div style={{ fontSize: 9, letterSpacing: 1, color: '#3d5470', textTransform: 'uppercase', fontFamily: 'JetBrains Mono, monospace' }}>
                  {item.id} · {item.finding_id}
                </div>
                <div style={{ fontSize: 14, fontWeight: 600, color: '#e2eaf6', marginTop: 6 }}>
                  {String(item.payload.title || 'Scanner finding evidence')}
                </div>
              </div>
              <span style={{ alignSelf: 'flex-start', background: '#13263d', color: '#8cc8ff', borderRadius: 3, padding: '4px 8px', fontSize: 8, letterSpacing: 0.5, textTransform: 'uppercase', fontFamily: 'JetBrains Mono, monospace' }}>
                {item.type.replace(/_/g, ' ')}
              </span>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12, marginBottom: 10 }}>
              <div>
                <div style={{ fontSize: 9, textTransform: 'uppercase', letterSpacing: 1, color: '#3d5470', fontFamily: 'JetBrains Mono, monospace' }}>Captured</div>
                <div style={{ marginTop: 6, fontSize: 12, color: '#a0b8d4' }}>{new Date(item.timestamp).toLocaleString()}</div>
              </div>
              <div>
                <div style={{ fontSize: 9, textTransform: 'uppercase', letterSpacing: 1, color: '#3d5470', fontFamily: 'JetBrains Mono, monospace' }}>SHA-256</div>
                <div style={{ marginTop: 6, fontSize: 10, color: '#00d4ff', fontFamily: 'JetBrains Mono, monospace', overflowWrap: 'anywhere' }}>{item.record_hash}</div>
              </div>
            </div>

            <div style={{ fontSize: 12, lineHeight: 1.7, color: '#a0b8d4' }}>
              {String(item.payload.business_impact || item.payload.endpoint || 'Scanner output stored for this finding.')}
            </div>
            <div style={{ marginTop: 10, fontSize: 9, color: '#3d5470', fontFamily: 'JetBrains Mono, monospace', overflowWrap: 'anywhere' }}>
              PREVIOUS HASH · {item.prev_hash}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
