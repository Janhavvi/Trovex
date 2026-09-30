import { useEffect, useState } from 'react';

const modules = [
  { id: 1, name: 'Session / Auth', checks: ['Login rate limiting', 'Token expiry', 'Weak password acceptance', 'Brute-force detection'] },
  { id: 2, name: 'Role Matrix / IDOR', checks: ['Horizontal privilege escalation', 'Vertical privilege escalation', 'Object ownership checks', 'IDOR enumeration'] },
  { id: 3, name: 'API Audit', checks: ['Security headers (CSP, HSTS, X-Frame-Options)', 'CORS configuration', 'HTTP verb tampering', 'Error disclosure'] },
  { id: 4, name: 'Injection', checks: ['Reflected XSS (non-destructive PoC)', 'SQL error pattern detection', 'Template injection indicators', 'Header injection'] },
  { id: 5, name: 'Feed Poisoning', checks: ['Unsanitised content acceptance', 'Stored XSS vectors', 'SSRF via feed URLs', 'Content-type validation'] },
  { id: 6, name: 'AI Prompt Injection', checks: ['Instruction boundary bypass', 'System prompt leakage', 'Output manipulation', 'Hidden text in input'] },
  { id: 7, name: 'Client / CSP', checks: ['Content Security Policy audit', 'Subresource Integrity', 'Mixed content', 'Clickjacking headers'] },
  { id: 8, name: 'Transport / TLS', checks: ['HTTP fallback detection', 'HSTS presence and value', 'TLS version and cipher audit', 'Certificate validity'] },
  { id: 9, name: 'Storage / Privacy', checks: ['Debug endpoint exposure', 'PII over-exposure in API responses', 'Verbose error messages', 'Stack trace disclosure'] },
  { id: 10, name: 'Dependencies', checks: ['pip-audit CVE scan', 'npm audit', 'Outdated package detection', 'Known CVE matching'] },
  { id: 11, name: 'Mobile Static Analysis', checks: ['Hardcoded secrets regex', 'Cleartext traffic config', 'Exported component audit', 'Insecure storage patterns'] },
];

export default function Methodology() {
  const [phases, setPhases] = useState<string[]>([
    'Scope validation',
    'Role matrix review',
    'API abuse testing',
    'AI prompt injection review',
    'Threat chaining and evidence validation',
    'Production hardening review',
  ]);

  useEffect(() => {
    let isMounted = true;
    void fetch('/api/methodology')
      .then((response) => {
        if (!response.ok) throw new Error('Methodology unavailable');
        return response.json();
      })
      .then((data) => {
        if (isMounted && Array.isArray(data?.phases)) {
          setPhases(data.phases);
        }
      })
      .catch(() => {
        if (isMounted) {
          setPhases([
            'Scope validation',
            'Role matrix review',
            'API abuse testing',
            'AI prompt injection review',
            'Threat chaining and evidence validation',
            'Production hardening review',
          ]);
        }
      });

    return () => {
      isMounted = false;
    };
  }, []);

  return (
    <div style={{ padding: 24, maxWidth: 900 }}>
      <div style={{ marginBottom: 24 }}>
        <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#3d5470', letterSpacing: 2, textTransform: 'uppercase', marginBottom: 4 }}>
          SIH26163 · Trovex v1.0
        </div>
        <h1 style={{ margin: 0, fontSize: 20, fontWeight: 600, color: '#e2eaf6' }}>Assessment Methodology</h1>
      </div>

      {/* Scope statement — prominent */}
      <div style={{ background: 'rgba(0,230,118,0.06)', border: '1px solid rgba(0,230,118,0.25)', borderRadius: 8, padding: 20, marginBottom: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#00e676" strokeWidth="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            <path d="M9 12l2 2 4-4" />
          </svg>
          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: '#00e676', letterSpacing: 1 }}>SCOPE STATEMENT</span>
        </div>
        <div style={{ fontSize: 14, color: '#e2eaf6', lineHeight: 1.7, marginBottom: 10 }}>
          Trovex was tested <strong>only against our own lab target</strong> running at <code style={{ fontFamily: 'JetBrains Mono, monospace', background: '#080c14', padding: '1px 6px', borderRadius: 3, fontSize: 12 }}>lab.local:8000</code> (World Monitor Lab). The live production application at <code style={{ fontFamily: 'JetBrains Mono, monospace', background: '#080c14', padding: '1px 6px', borderRadius: 3, fontSize: 12 }}>worldmonitor.app</code> is <strong>permanently blocked by the scope guard</strong> — no request can be directed at it regardless of user input.
        </div>
        <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: '#6b8aac', lineHeight: 1.6 }}>
          Project: Smart India Hackathon SIH26163 · Authorisation: Lab Environment Only · All tests: non-destructive, PoC-only
        </div>
      </div>

      {/* Scope guard detail */}
      <div style={{ background: '#0d1520', border: '1px solid #1e2f46', borderRadius: 8, padding: 16, marginBottom: 16 }}>
        <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#3d5470', letterSpacing: 1, marginBottom: 10 }}>SCOPE GUARD IMPLEMENTATION</div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 10 }}>
          {[
            { title: 'Hardcoded Allowlist', desc: 'Backend rejects any target not in the predefined lab allowlist. The real worldmonitor.app domain is in the denylist.' },
            { title: 'Signed Auth Note', desc: 'A signed authorisation note (target, scope, date, approver) is required to unlock any new target.' },
            { title: 'Kill Switch', desc: 'A hardware-level kill switch immediately halts all in-progress scans. Accessible from every screen.' },
            { title: 'Safe Mode', desc: 'Default mode: read/observe probes only. State-changing checks require explicit opt-in and scope unlock.' },
            { title: 'Rate Limiting', desc: 'Independent per-run rate limit prevents scan flooding regardless of module configuration.' },
            { title: 'Audit Log', desc: 'Every rejected request is logged with timestamp, source IP, and reason. Alerts are raised for repeated violations.' },
          ].map(item => (
            <div key={item.title} style={{ background: '#080c14', border: '1px solid #1e2f46', borderRadius: 6, padding: 12 }}>
              <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#00d4ff', marginBottom: 4 }}>{item.title}</div>
              <div style={{ fontSize: 11, color: '#6b8aac', lineHeight: 1.6 }}>{item.desc}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Validation principle */}
      <div style={{ background: '#0d1520', border: '1px solid #ffc10733', borderRadius: 8, padding: 16, marginBottom: 16 }}>
        <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#ffc107', letterSpacing: 1, marginBottom: 8 }}>VALIDATION PRINCIPLE</div>
        <div style={{ fontSize: 14, color: '#e2eaf6', fontStyle: 'italic', borderLeft: '3px solid #ffc107', paddingLeft: 14, lineHeight: 1.6 }}>
          "A scanner alert is NOT a finding until it is validated and proven."
        </div>
        <div style={{ fontSize: 12, color: '#6b8aac', lineHeight: 1.7, marginTop: 10 }}>
          Each signal from the scanner undergoes a differential test: a baseline request is compared against a crafted request. Only when a measurable, reproducible difference is observed is the signal promoted to a CONFIRMED finding, PoC-captured, and added to the tamper-evident hash chain. Signals with no reliable difference remain UNVERIFIED in the manual triage queue and are excluded from the posture score.
        </div>
      </div>

      {/* Scanner modules */}
      <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#3d5470', letterSpacing: 1, marginBottom: 10, textTransform: 'uppercase' }}>
        Methodology Phases ({phases.length})
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 10, marginBottom: 18 }}>
        {phases.map((phase, index) => (
          <div key={`${phase}-${index}`} style={{ background: '#0d1520', border: '1px solid #1e2f46', borderRadius: 8, padding: 14 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
              <div style={{ width: 9, height: 9, borderRadius: '50%', background: index < 4 ? '#00d4ff' : '#00e676', boxShadow: '0 0 8px rgba(0,212,255,0.5)' }} />
              <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#00d4ff', letterSpacing: 1 }}>PHASE {String(index + 1).padStart(2, '0')}</div>
            </div>
            <div style={{ fontSize: 12, color: '#e2eaf6', lineHeight: 1.5 }}>{phase}</div>
          </div>
        ))}
      </div>

      <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#3d5470', letterSpacing: 1, marginBottom: 10, textTransform: 'uppercase' }}>
        Scanner Modules ({modules.length})
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))', gap: 10 }}>
        {modules.map(mod => (
          <div key={mod.id} style={{ background: '#0d1520', border: '1px solid #1e2f46', borderRadius: 8, padding: 14 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
              <div style={{
                fontFamily: 'JetBrains Mono, monospace', fontSize: 9,
                color: '#00d4ff', background: 'rgba(0,212,255,0.1)', border: '1px solid rgba(0,212,255,0.2)',
                borderRadius: 3, padding: '2px 6px',
              }}>
                MOD-{String(mod.id).padStart(2, '0')}
              </div>
              <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: '#a0b8d4', fontWeight: 600 }}>{mod.name}</div>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {mod.checks.map(check => (
                <div key={check} style={{ display: 'flex', alignItems: 'flex-start', gap: 6 }}>
                  <span style={{ color: '#3d5470', marginTop: 1, flexShrink: 0 }}>›</span>
                  <span style={{ fontSize: 11, color: '#6b8aac' }}>{check}</span>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
