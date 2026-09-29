import { useEffect, useState } from 'react';
import { findings as mockFindings, type Finding, type Severity, type FindingStatus, type Lifecycle } from '../data/mockData';

const severityColors: Record<Severity, string> = {
  CRITICAL: '#ff3b3b', HIGH: '#ff6b2b', MEDIUM: '#ffc107', LOW: '#00d4ff', INFO: '#6b8aac',
};
const statusColors: Record<FindingStatus, string> = {
  CONFIRMED: '#ff3b3b', UNVERIFIED: '#ffc107', ERROR: '#ff6b2b',
};
const lifecycleColors: Record<Lifecycle, string> = {
  OPEN: '#ff3b3b', IN_PROGRESS: '#ffc107', FIXED: '#00e676', REGRESSED: '#ff6b2b',
};

function Badge({ label, color }: { label: string; color: string }) {
  return (
    <span style={{
      fontFamily: 'JetBrains Mono, monospace', fontSize: 9, letterSpacing: 0.8,
      color, background: `${color}18`, border: `1px solid ${color}44`,
      borderRadius: 3, padding: '2px 6px',
    }}>
      {label}
    </span>
  );
}

function FindingDrawer({ finding, onClose, onRetest }: { finding: Finding; onClose: () => void; onRetest: (id: string) => void }) {
  return (
    <div style={{
      position: 'fixed', right: 0, top: 0, bottom: 0, width: 480,
      background: '#0a1220', borderLeft: '1px solid #1e2f46',
      zIndex: 100, overflowY: 'auto', display: 'flex', flexDirection: 'column',
    }}>
      <div style={{ padding: '16px 20px', borderBottom: '1px solid #1e2f46', display: 'flex', alignItems: 'center', justifyContent: 'space-between', position: 'sticky', top: 0, background: '#0a1220' }}>
        <div>
          <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#3d5470', letterSpacing: 1, marginBottom: 4 }}>
            {finding.id} · {finding.module}
          </div>
          <div style={{ fontSize: 14, fontWeight: 600, color: '#e2eaf6' }}>{finding.title}</div>
        </div>
        <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#3d5470', padding: 4 }}>
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
          </svg>
        </button>
      </div>

      <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>
        {/* Badges */}
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
          <Badge label={finding.severity} color={severityColors[finding.severity]} />
          <Badge label={finding.status} color={statusColors[finding.status]} />
          <Badge label={finding.lifecycle} color={lifecycleColors[finding.lifecycle]} />
          {finding.dpdp_relevant && <Badge label="DPDP" color="#ffc107" />}
        </div>

        {/* CVSS */}
        <div style={{ background: '#080c14', border: '1px solid #1e2f46', borderRadius: 6, padding: 12 }}>
          <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#3d5470', letterSpacing: 1, marginBottom: 8 }}>CVSS SCORE</div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, marginBottom: 6 }}>
            <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 28, fontWeight: 700, color: severityColors[finding.severity] }}>{finding.cvss_score}</span>
            <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#3d5470' }}>/10</span>
          </div>
          <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#6b8aac', wordBreak: 'break-all' }}>{finding.cvss_vector}</div>
        </div>

        {/* Compliance tags */}
        <div style={{ background: '#080c14', border: '1px solid #1e2f46', borderRadius: 6, padding: 12 }}>
          <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#3d5470', letterSpacing: 1, marginBottom: 8 }}>COMPLIANCE</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6 }}>
            {[
              { label: 'CWE', value: finding.cwe },
              { label: 'OWASP', value: finding.owasp },
              { label: 'CERT-In', value: finding.cert_in.split(' ')[0] },
              { label: 'DPDP', value: finding.dpdp_relevant ? 'Relevant' : 'N/A' },
            ].map(row => (
              <div key={row.label}>
                <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 8, color: '#3d5470', marginBottom: 2 }}>{row.label}</div>
                <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: '#00d4ff' }}>{row.value}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Endpoint */}
        <div>
          <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#3d5470', letterSpacing: 1, marginBottom: 6 }}>ENDPOINT</div>
          <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: '#00d4ff', background: '#080c14', border: '1px solid #1e2f46', borderRadius: 4, padding: '6px 10px' }}>
            {finding.endpoint}
          </div>
        </div>

        {/* Business impact */}
        <div>
          <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#3d5470', letterSpacing: 1, marginBottom: 6 }}>BUSINESS IMPACT</div>
          <div style={{ fontSize: 12, color: '#a0b8d4', lineHeight: 1.6, background: '#080c14', border: '1px solid #1e2f46', borderRadius: 4, padding: '10px 12px' }}>
            {finding.business_impact}
          </div>
        </div>

        {/* Remediation */}
        <div>
          <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#3d5470', letterSpacing: 1, marginBottom: 6 }}>REMEDIATION</div>
          <div style={{ fontSize: 12, color: '#a0b8d4', lineHeight: 1.6, background: 'rgba(0, 230, 118, 0.04)', border: '1px solid rgba(0, 230, 118, 0.2)', borderRadius: 4, padding: '10px 12px' }}>
            {finding.remediation}
          </div>
        </div>

        {/* Actions */}
        <div style={{ display: 'flex', gap: 8, paddingTop: 4 }}>
          <button
            onClick={() => onRetest(finding.id)}
            style={{
              flex: 1, padding: '10px', borderRadius: 6, cursor: 'pointer',
              fontFamily: 'JetBrains Mono, monospace', fontSize: 10, letterSpacing: 0.5,
              background: 'rgba(0, 230, 118, 0.08)', border: '1px solid rgba(0, 230, 118, 0.3)',
              color: '#00e676',
            }}
          >
            ✓ MARK FIXED & RE-TEST
          </button>
          <button
            style={{
              padding: '10px 14px', borderRadius: 6, cursor: 'pointer',
              fontFamily: 'JetBrains Mono, monospace', fontSize: 10,
              background: 'rgba(0, 212, 255, 0.08)', border: '1px solid rgba(0, 212, 255, 0.3)',
              color: '#00d4ff',
            }}
          >
            VIEW EVIDENCE
          </button>
        </div>
      </div>
    </div>
  );
}

export default function FindingsScreen() {
  const [findings, setFindings] = useState<Finding[]>(mockFindings);
  const [selected, setSelected] = useState<Finding | null>(null);
  const [filterSev, setFilterSev] = useState<string>('ALL');
  const [filterStatus, setFilterStatus] = useState<string>('ALL');
  const [filterLife, setFilterLife] = useState<string>('ALL');
  const [retested, setRetested] = useState<Set<string>>(new Set());

  useEffect(() => {
    let isMounted = true;
    const loadFindings = () => {
      void fetch('/api/findings')
        .then((response) => {
          if (!response.ok) throw new Error('Findings unavailable');
          return response.json();
        })
        .then((data: Finding[]) => { if (isMounted) setFindings(data); })
        .catch(() => { if (isMounted) setFindings(mockFindings); });
    };
    loadFindings();
    window.addEventListener('trovex-scan-completed', loadFindings);
    return () => {
      isMounted = false;
      window.removeEventListener('trovex-scan-completed', loadFindings);
    };
  }, []);

  const filtered = findings.filter(f => {
    if (filterSev !== 'ALL' && f.severity !== filterSev) return false;
    if (filterStatus !== 'ALL' && f.status !== filterStatus) return false;
    if (filterLife !== 'ALL' && f.lifecycle !== filterLife) return false;
    return true;
  });

  const handleRetest = (id: string) => {
    setRetested(prev => new Set([...prev, id]));
  };

  const FilterBtn = ({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) => (
    <button onClick={onClick} style={{
      padding: '4px 10px', borderRadius: 4, cursor: 'pointer',
      fontFamily: 'JetBrains Mono, monospace', fontSize: 9, letterSpacing: 0.5,
      background: active ? 'rgba(0, 212, 255, 0.12)' : 'transparent',
      border: `1px solid ${active ? '#00d4ff44' : '#1e2f46'}`,
      color: active ? '#00d4ff' : '#3d5470',
    }}>{label}</button>
  );

  return (
    <div style={{ padding: 24, position: 'relative' }}>
      <div style={{ marginBottom: 20 }}>
        <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#3d5470', letterSpacing: 2, textTransform: 'uppercase', marginBottom: 4 }}>
          {filtered.length} findings
        </div>
        <h1 style={{ margin: 0, fontSize: 20, fontWeight: 600, color: '#e2eaf6' }}>Findings</h1>
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 16, flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#3d5470', marginRight: 4 }}>SEV:</span>
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => (
            <FilterBtn key={s} label={s} active={filterSev === s} onClick={() => setFilterSev(s)} />
          ))}
        </div>
        <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#3d5470', marginRight: 4 }}>STATUS:</span>
          {['ALL', 'CONFIRMED', 'UNVERIFIED'].map(s => (
            <FilterBtn key={s} label={s} active={filterStatus === s} onClick={() => setFilterStatus(s)} />
          ))}
        </div>
        <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#3d5470', marginRight: 4 }}>LIFECYCLE:</span>
          {['ALL', 'OPEN', 'IN_PROGRESS', 'FIXED'].map(s => (
            <FilterBtn key={s} label={s} active={filterLife === s} onClick={() => setFilterLife(s)} />
          ))}
        </div>
      </div>

      {/* Table */}
      <div style={{ background: '#0d1520', border: '1px solid #1e2f46', borderRadius: 8, overflow: 'hidden' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid #1e2f46' }}>
              {['ID', 'Title', 'Severity', 'Status', 'Lifecycle', 'CVSS', 'Module', ''].map(h => (
                <th key={h} style={{
                  padding: '10px 14px', textAlign: 'left',
                  fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#3d5470',
                  letterSpacing: 1, textTransform: 'uppercase', fontWeight: 500,
                  background: '#080c14',
                }}>
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map((f, i) => (
              <tr
                key={f.id}
                onClick={() => setSelected(f)}
                style={{
                  borderBottom: '1px solid #1e2f4640',
                  background: selected?.id === f.id ? 'rgba(0, 212, 255, 0.06)' : i % 2 === 0 ? 'transparent' : '#080c1408',
                  cursor: 'pointer',
                  transition: 'background 0.1s',
                }}
                onMouseEnter={e => { if (selected?.id !== f.id) (e.currentTarget as HTMLElement).style.background = '#1e2f4620'; }}
                onMouseLeave={e => { if (selected?.id !== f.id) (e.currentTarget as HTMLElement).style.background = i % 2 === 0 ? 'transparent' : '#080c1408'; }}
              >
                <td style={{ padding: '10px 14px', fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: '#3d5470' }}>{f.id}</td>
                <td style={{ padding: '10px 14px', fontSize: 12, color: retested.has(f.id) ? '#00e676' : '#e2eaf6', maxWidth: 260 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    {f.chain_id && <span title="Part of attack chain" style={{ color: '#ff6b2b', fontSize: 10 }}>⛓</span>}
                    {f.title}
                  </div>
                </td>
                <td style={{ padding: '10px 14px' }}>
                  <Badge label={f.severity} color={severityColors[f.severity]} />
                </td>
                <td style={{ padding: '10px 14px' }}>
                  <Badge label={f.status} color={statusColors[f.status]} />
                </td>
                <td style={{ padding: '10px 14px' }}>
                  <Badge label={retested.has(f.id) ? 'FIXED' : f.lifecycle} color={retested.has(f.id) ? '#00e676' : lifecycleColors[f.lifecycle]} />
                </td>
                <td style={{ padding: '10px 14px', fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: severityColors[f.severity] }}>
                  {f.cvss_score}
                </td>
                <td style={{ padding: '10px 14px', fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: '#6b8aac' }}>{f.module}</td>
                <td style={{ padding: '10px 14px' }}>
                  <button
                    onClick={e => { e.stopPropagation(); handleRetest(f.id); }}
                    style={{
                      padding: '4px 8px', borderRadius: 4, cursor: 'pointer',
                      fontFamily: 'JetBrains Mono, monospace', fontSize: 8,
                      background: retested.has(f.id) ? 'rgba(0, 230, 118, 0.1)' : 'rgba(0, 230, 118, 0.06)',
                      border: `1px solid ${retested.has(f.id) ? 'rgba(0,230,118,0.4)' : 'rgba(0,230,118,0.2)'}`,
                      color: '#00e676', whiteSpace: 'nowrap',
                    }}
                  >
                    {retested.has(f.id) ? '✓ FIXED' : 'FIX & RETEST'}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {selected && (
        <>
          <div
            onClick={() => setSelected(null)}
            style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', zIndex: 99 }}
          />
          <FindingDrawer finding={selected} onClose={() => setSelected(null)} onRetest={handleRetest} />
        </>
      )}
    </div>
  );
}
