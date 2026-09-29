import { useEffect, useState } from 'react';

type ScopeStatus = {
  active: boolean;
  mode: string;
  killSwitch: boolean;
  authorizedTargets: Array<{
    id: string;
    name: string;
    hostname: string;
    environment: string;
    authorizationRef: string;
    validFrom: string;
    validUntil: string;
    active: boolean;
  }>;
  recentEvents: Array<{
    target: string;
    action: string;
    result: string;
    reason: string;
    user: string;
    timestamp: string;
  }>;
};

const fallbackScopeStatus: ScopeStatus = {
  active: false,
  mode: 'DISABLED',
  killSwitch: true,
  authorizedTargets: [],
  recentEvents: [],
};

export default function ScopeGuard() {
  const [status, setStatus] = useState<ScopeStatus | null>(fallbackScopeStatus);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let isMounted = true;

    const load = async () => {
      try {
        const res = await fetch('/api/scope/status');
        if (!res.ok) throw new Error('Scope service unavailable');
        const data = await res.json();
        if (isMounted) {
          setStatus(data);
          setLoading(false);
        }
      } catch (err) {
        if (isMounted) {
          setStatus(fallbackScopeStatus);
          setError(err instanceof Error ? err.message : 'Backend unavailable');
          setLoading(false);
        }
      }
    };

    void load();
    return () => { isMounted = false; };
  }, []);

  if (loading) return <div style={{ padding: 24 }}>Loading scope metadata…</div>;
  if (!status) return null;

  const statusMessage = error ? 'Scope service unavailable — showing cached lab scope' : '';

  return (
    <div style={{ padding: 24, display: 'grid', gap: 12 }}>
      <div>
        <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#3d5470', letterSpacing: 2, textTransform: 'uppercase', marginBottom: 4 }}>
          Scope Guard
        </div>
        <h1 style={{ margin: 0, fontSize: 20, fontWeight: 600, color: '#e2eaf6' }}>Authorized lab scope</h1>
        {statusMessage && (
          <div style={{ marginTop: 8, color: '#ffb4b4', fontSize: 9, fontFamily: 'JetBrains Mono, monospace' }}>
            {statusMessage}
          </div>
        )}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 10 }}>
        <div style={{ background: '#0d1520', border: '1px solid #1e2f46', borderRadius: 8, padding: 16 }}>
          <div style={{ fontSize: 9, letterSpacing: 1.5, color: '#3d5470', textTransform: 'uppercase', fontFamily: 'JetBrains Mono, monospace' }}>Status</div>
          <div style={{ marginTop: 8, fontSize: 16, fontWeight: 700, color: status.active ? '#00e676' : '#ff3b3b', fontFamily: 'JetBrains Mono, monospace' }}>{status.active ? 'ACTIVE' : 'INACTIVE'}</div>
        </div>
        <div style={{ background: '#0d1520', border: '1px solid #1e2f46', borderRadius: 8, padding: 16 }}>
          <div style={{ fontSize: 9, letterSpacing: 1.5, color: '#3d5470', textTransform: 'uppercase', fontFamily: 'JetBrains Mono, monospace' }}>Mode</div>
          <div style={{ marginTop: 8, fontSize: 16, fontWeight: 700, color: '#00d4ff', fontFamily: 'JetBrains Mono, monospace' }}>{status.mode}</div>
        </div>
        <div style={{ background: '#0d1520', border: '1px solid #1e2f46', borderRadius: 8, padding: 16 }}>
          <div style={{ fontSize: 9, letterSpacing: 1.5, color: '#3d5470', textTransform: 'uppercase', fontFamily: 'JetBrains Mono, monospace' }}>Kill Switch</div>
          <div style={{ marginTop: 8, fontSize: 16, fontWeight: 700, color: status.killSwitch ? '#ff3b3b' : '#00e676', fontFamily: 'JetBrains Mono, monospace' }}>{status.killSwitch ? 'ACTIVE' : 'READY'}</div>
        </div>
      </div>

      <div style={{ background: '#0d1520', border: '1px solid #1e2f46', borderRadius: 8, overflow: 'hidden' }}>
        <div style={{ padding: '12px 16px', borderBottom: '1px solid #1e2f46', fontFamily: 'JetBrains Mono, monospace', fontSize: 9, letterSpacing: 1, color: '#3d5470', textTransform: 'uppercase' }}>
          Authorized targets
        </div>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ background: '#080c14' }}>
              <th style={{ padding: '10px 12px', textAlign: 'left', fontSize: 9, color: '#3d5470', letterSpacing: 1, fontFamily: 'JetBrains Mono, monospace' }}>Target</th>
              <th style={{ padding: '10px 12px', textAlign: 'left', fontSize: 9, color: '#3d5470', letterSpacing: 1, fontFamily: 'JetBrains Mono, monospace' }}>Hostname</th>
              <th style={{ padding: '10px 12px', textAlign: 'left', fontSize: 9, color: '#3d5470', letterSpacing: 1, fontFamily: 'JetBrains Mono, monospace' }}>Environment</th>
              <th style={{ padding: '10px 12px', textAlign: 'left', fontSize: 9, color: '#3d5470', letterSpacing: 1, fontFamily: 'JetBrains Mono, monospace' }}>Auth Ref</th>
              <th style={{ padding: '10px 12px', textAlign: 'left', fontSize: 9, color: '#3d5470', letterSpacing: 1, fontFamily: 'JetBrains Mono, monospace' }}>Valid</th>
              <th style={{ padding: '10px 12px', textAlign: 'left', fontSize: 9, color: '#3d5470', letterSpacing: 1, fontFamily: 'JetBrains Mono, monospace' }}>Status</th>
            </tr>
          </thead>
          <tbody>
            {status.authorizedTargets.map((target) => (
              <tr key={target.id} style={{ borderTop: '1px solid #1e2f46' }}>
                <td style={{ padding: '10px 12px', color: '#e2eaf6', fontSize: 12 }}>{target.name}</td>
                <td style={{ padding: '10px 12px', color: '#a0b8d4', fontSize: 12 }}>{target.hostname}</td>
                <td style={{ padding: '10px 12px', color: '#a0b8d4', fontFamily: 'JetBrains Mono, monospace', fontSize: 11 }}>{target.environment}</td>
                <td style={{ padding: '10px 12px', color: '#00d4ff', fontFamily: 'JetBrains Mono, monospace', fontSize: 11 }}>{target.authorizationRef}</td>
                <td style={{ padding: '10px 12px', color: '#6b8aac', fontFamily: 'JetBrains Mono, monospace', fontSize: 11 }}>{target.validFrom.slice(0, 10)} → {target.validUntil.slice(0, 10)}</td>
                <td style={{ padding: '10px 12px', color: target.active ? '#00e676' : '#ff8d8d', fontWeight: 700, fontFamily: 'JetBrains Mono, monospace', fontSize: 10 }}>{target.active ? 'AUTHORIZED' : 'EXPIRED'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div style={{ background: '#0d1520', border: '1px solid #1e2f46', borderRadius: 8, overflow: 'hidden' }}>
        <div style={{ padding: '12px 16px', borderBottom: '1px solid #1e2f46', fontFamily: 'JetBrains Mono, monospace', fontSize: 9, letterSpacing: 1, color: '#3d5470', textTransform: 'uppercase' }}>
          Recent scope events
        </div>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ background: '#080c14' }}>
              <th style={{ padding: '10px 12px', textAlign: 'left', fontSize: 9, color: '#3d5470', fontFamily: 'JetBrains Mono, monospace' }}>Target</th>
              <th style={{ padding: '10px 12px', textAlign: 'left', fontSize: 9, color: '#3d5470', fontFamily: 'JetBrains Mono, monospace' }}>Action</th>
              <th style={{ padding: '10px 12px', textAlign: 'left', fontSize: 9, color: '#3d5470', fontFamily: 'JetBrains Mono, monospace' }}>Result</th>
              <th style={{ padding: '10px 12px', textAlign: 'left', fontSize: 9, color: '#3d5470', fontFamily: 'JetBrains Mono, monospace' }}>Reason</th>
              <th style={{ padding: '10px 12px', textAlign: 'left', fontSize: 9, color: '#3d5470', fontFamily: 'JetBrains Mono, monospace' }}>User</th>
              <th style={{ padding: '10px 12px', textAlign: 'left', fontSize: 9, color: '#3d5470', fontFamily: 'JetBrains Mono, monospace' }}>Timestamp</th>
            </tr>
          </thead>
          <tbody>
            {status.recentEvents.map((event, index) => (
              <tr key={`${event.target}-${index}`} style={{ borderTop: '1px solid #1e2f46' }}>
                <td style={{ padding: '10px 12px', color: '#a0b8d4', fontFamily: 'JetBrains Mono, monospace', fontSize: 11 }}>{event.target}</td>
                <td style={{ padding: '10px 12px', color: '#e2eaf6', fontFamily: 'JetBrains Mono, monospace', fontSize: 11 }}>{event.action}</td>
                <td style={{ padding: '10px 12px', color: event.result === 'BLOCKED' ? '#ff8d8d' : '#00e676', fontWeight: 700, fontFamily: 'JetBrains Mono, monospace', fontSize: 10 }}>{event.result}</td>
                <td style={{ padding: '10px 12px', color: '#6b8aac', fontSize: 12 }}>{event.reason}</td>
                <td style={{ padding: '10px 12px', color: '#a0b8d4', fontSize: 12 }}>{event.user}</td>
                <td style={{ padding: '10px 12px', color: '#6b8aac', fontFamily: 'JetBrains Mono, monospace', fontSize: 10 }}>{event.timestamp}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
