import { roleMatrix } from '../data/mockData';

const roles = ['guest', 'viewer', 'analyst', 'admin'] as const;

const cellColor = (v: string) => {
  if (v === 'ESCALATION') return { bg: 'rgba(255,59,59,0.18)', border: 'rgba(255,59,59,0.5)', text: '#ff3b3b' };
  if (v === 'ALLOWED') return { bg: 'rgba(0,212,255,0.08)', border: 'rgba(0,212,255,0.25)', text: '#6b8aac' };
  return { bg: 'rgba(0,230,118,0.06)', border: 'rgba(0,230,118,0.2)', text: '#00e676' };
};

export default function RoleMatrix() {
  const escalationCount = roleMatrix.reduce((n, row) =>
    n + roles.filter(r => row[r] === 'ESCALATION').length, 0);

  return (
    <div style={{ padding: 24 }}>
      <div style={{ marginBottom: 20 }}>
        <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#3d5470', letterSpacing: 2, textTransform: 'uppercase', marginBottom: 4 }}>
          {escalationCount} escalation vectors detected
        </div>
        <h1 style={{ margin: 0, fontSize: 20, fontWeight: 600, color: '#e2eaf6' }}>Role Access Matrix</h1>
      </div>

      {/* Legend */}
      <div style={{ display: 'flex', gap: 16, marginBottom: 16 }}>
        {[
          { label: 'ESCALATION — confirmed privilege escalation', color: '#ff3b3b' },
          { label: 'ALLOWED — expected access', color: '#6b8aac' },
          { label: 'DENIED — correctly blocked', color: '#00e676' },
        ].map(l => (
          <div key={l.label} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <div style={{ width: 10, height: 10, borderRadius: 2, background: cellColor(l.label.split(' ')[0]).bg, border: `1px solid ${cellColor(l.label.split(' ')[0]).border}` }} />
            <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#6b8aac' }}>{l.label}</span>
          </div>
        ))}
      </div>

      <div style={{ background: '#0d1520', border: '1px solid #1e2f46', borderRadius: 8, overflow: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', minWidth: 600 }}>
          <thead>
            <tr style={{ borderBottom: '1px solid #1e2f46' }}>
              <th style={{ padding: '12px 16px', textAlign: 'left', fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#3d5470', letterSpacing: 1, background: '#080c14' }}>
                ENDPOINT
              </th>
              {roles.map(role => (
                <th key={role} style={{
                  padding: '12px 20px', textAlign: 'center', fontFamily: 'JetBrains Mono, monospace', fontSize: 9,
                  color: role === 'admin' ? '#00d4ff' : '#6b8aac', letterSpacing: 1.5, textTransform: 'uppercase',
                  background: '#080c14', minWidth: 100,
                }}>
                  {role}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {roleMatrix.map((row, i) => (
              <tr key={row.endpoint} style={{ borderBottom: '1px solid #1e2f4640', background: i % 2 === 0 ? 'transparent' : '#080c1408' }}>
                <td style={{ padding: '10px 16px', fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: '#a0b8d4' }}>
                  {row.endpoint}
                </td>
                {roles.map(role => {
                  const val = row[role];
                  const c = cellColor(val);
                  return (
                    <td key={role} style={{ padding: '8px', textAlign: 'center' }}>
                      <div style={{
                        display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
                        padding: '4px 8px', borderRadius: 4, minWidth: 80,
                        background: c.bg, border: `1px solid ${c.border}`,
                        fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: c.text, letterSpacing: 0.5,
                        boxShadow: val === 'ESCALATION' ? `0 0 8px ${c.border}` : 'none',
                      }}>
                        {val === 'ESCALATION' && <span style={{ marginRight: 4 }}>▲</span>}
                        {val}
                      </div>
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Summary cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12, marginTop: 16 }}>
        {[
          { label: 'Vertical Escalations', value: 5, desc: 'Analyst → Admin routes', color: '#ff3b3b' },
          { label: 'Horizontal Escalations', value: 2, desc: 'Cross-user object access', color: '#ff6b2b' },
          { label: 'Auth-free Routes', value: 3, desc: 'Guest accessible endpoints', color: '#ffc107' },
        ].map(c => (
          <div key={c.label} style={{ background: '#0d1520', border: '1px solid #1e2f46', borderRadius: 8, padding: 14 }}>
            <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#3d5470', letterSpacing: 1, marginBottom: 6 }}>{c.label}</div>
            <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 28, fontWeight: 700, color: c.color }}>{c.value}</div>
            <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#6b8aac', marginTop: 4 }}>{c.desc}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
