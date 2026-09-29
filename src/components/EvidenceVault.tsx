const evidence = [
  {
    id: 'EV-1042',
    title: 'Session token reuse sequence',
    type: 'API trace',
    owner: 'Auth module',
    created: '2026-09-30 10:14 UTC',
    summary: 'Repeated token issuance during a short-lived session shows replay behavior across the login flow.',
    confidence: 'High',
  },
  {
    id: 'EV-1047',
    title: 'IDOR validation screenshot',
    type: 'Evidence snapshot',
    owner: 'Role matrix',
    created: '2026-09-30 10:18 UTC',
    summary: 'Cross-role access check demonstrates that an unauthorised actor can query records outside their scope.',
    confidence: 'High',
  },
  {
    id: 'EV-1051',
    title: 'Prompt injection payload',
    type: 'Payload capture',
    owner: 'AI layer',
    created: '2026-09-30 10:31 UTC',
    summary: 'Injected prompt content bypasses safety guardrails and modifies downstream tool execution state.',
    confidence: 'Medium',
  },
];

export default function EvidenceVault() {
  return (
    <div style={{ padding: 24, color: '#e2eaf6' }}>
      <div style={{ marginBottom: 20 }}>
        <div style={{ fontSize: 9, letterSpacing: 2, textTransform: 'uppercase', color: '#3d5470', fontFamily: 'JetBrains Mono, monospace' }}>
          Evidence Vault
        </div>
        <h1 style={{ margin: 0, fontSize: 20, fontWeight: 600, color: '#e2eaf6' }}>Assessment artifacts</h1>
      </div>

      <div style={{ display: 'grid', gap: 16, maxWidth: 1100 }}>
        {evidence.map((item) => (
          <div
            key={item.id}
            style={{
              background: '#0d1520',
              border: '1px solid #1e2f46',
              borderRadius: 8,
              padding: 16,
              boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.02)',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap', marginBottom: 10 }}>
              <div>
                <div style={{ fontSize: 9, letterSpacing: 1, color: '#3d5470', textTransform: 'uppercase', fontFamily: 'JetBrains Mono, monospace' }}>
                  {item.id}
                </div>
                <div style={{ fontSize: 14, fontWeight: 600, color: '#e2eaf6', marginTop: 6 }}>{item.title}</div>
              </div>

              <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
                <span style={{
                  background: '#13263d',
                  color: '#8cc8ff',
                  borderRadius: 4,
                  padding: '4px 8px',
                  fontSize: 8,
                  letterSpacing: 0.5,
                  textTransform: 'uppercase',
                  fontFamily: 'JetBrains Mono, monospace',
                }}>
                  {item.type}
                </span>
                <span style={{
                  background: '#0f2d2c',
                  color: '#7ef7d8',
                  borderRadius: 4,
                  padding: '4px 8px',
                  fontSize: 8,
                  letterSpacing: 0.5,
                  textTransform: 'uppercase',
                  fontFamily: 'JetBrains Mono, monospace',
                }}>
                  {item.confidence}
                </span>
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12, marginBottom: 10 }}>
              <div>
                <div style={{ fontSize: 9, textTransform: 'uppercase', letterSpacing: 1, color: '#3d5470', fontFamily: 'JetBrains Mono, monospace' }}>Owner</div>
                <div style={{ marginTop: 6, fontSize: 12, color: '#a0b8d4' }}>{item.owner}</div>
              </div>
              <div>
                <div style={{ fontSize: 9, textTransform: 'uppercase', letterSpacing: 1, color: '#3d5470', fontFamily: 'JetBrains Mono, monospace' }}>Created</div>
                <div style={{ marginTop: 6, fontSize: 12, color: '#a0b8d4' }}>{item.created}</div>
              </div>
            </div>

            <div style={{ fontSize: 12, lineHeight: 1.7, color: '#a0b8d4' }}>{item.summary}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
