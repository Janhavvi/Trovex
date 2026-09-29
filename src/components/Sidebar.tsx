import { useState } from 'react';

type Screen = 'overview' | 'findings' | 'roles' | 'chains' | 'mobile' | 'vault' | 'methodology' | 'scope';

interface SidebarProps {
  active: Screen;
  onNavigate: (s: Screen) => void;
  onKillSwitch: () => void;
  killActive: boolean;
}

const nav: { id: Screen; label: string; icon: string }[] = [
  { id: 'overview', label: 'Overview', icon: 'M3 3h7v7H3V3zm0 11h7v7H3v-7zm11-11h7v7h-7V3zm0 11h7v7h-7v-7z' },
  { id: 'findings', label: 'Findings', icon: 'M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5' },
  { id: 'roles', label: 'Role Matrix', icon: 'M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2M9 7a4 4 0 1 0 0 8 4 4 0 0 0 0-8zm14 4a4 4 0 0 1-4 4M23 3a4 4 0 0 1 0 8' },
  { id: 'chains', label: 'Attack Paths', icon: 'M5 12h14M12 5l7 7-7 7' },
  { id: 'mobile', label: 'Mobile', icon: 'M12 18h.01M8 21h8a2 2 0 0 0 2-2V5a2 2 0 0 0-2-2H8a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2z' },
  { id: 'vault', label: 'Evidence Vault', icon: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z' },
  { id: 'scope', label: 'Scope Guard', icon: 'M12 2l7 4v6c0 5.25-3.44 9.95-7 12-3.56-2.05-7-6.75-7-12V6l7-4zm0 5.5l-2.5 2.5 1.5 1.5L12 15l3.5-3.5L14 10l-2 2v-4.5z' },
  { id: 'methodology', label: 'Methodology', icon: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0 1 12 2.944a11.955 11.955 0 0 1-8.618 3.04A12.02 12.02 0 0 0 3 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z' },
];

export default function Sidebar({ active, onNavigate, onKillSwitch, killActive }: SidebarProps) {
  const [collapsed, setCollapsed] = useState(false);

  return (
    <aside
      style={{
        width: collapsed ? 56 : 220,
        transition: 'width 0.2s ease',
        background: '#0a1220',
        borderRight: '1px solid #1e2f46',
        display: 'flex',
        flexDirection: 'column',
        flexShrink: 0,
        height: '100vh',
        position: 'sticky',
        top: 0,
        zIndex: 10,
      }}
    >
      {/* Logo */}
      <div style={{ padding: '16px 12px', borderBottom: '1px solid #1e2f46', display: 'flex', alignItems: 'center', gap: 10 }}>
        <div style={{
          width: 32, height: 32, borderRadius: 6, flexShrink: 0,
          background: 'linear-gradient(135deg, #00d4ff22, #00d4ff44)',
          border: '1px solid #00d4ff55',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#00d4ff" strokeWidth="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
        </div>
        {!collapsed && (
          <div>
            <div style={{ fontFamily: 'JetBrains Mono, monospace', fontWeight: 700, fontSize: 15, color: '#00d4ff', letterSpacing: 2 }}>TROVEX</div>
            <div style={{ fontSize: 9, color: '#3d5470', letterSpacing: 1, textTransform: 'uppercase' }}>Safe. Proven. Fixed.</div>
          </div>
        )}
        <button
          onClick={() => setCollapsed(c => !c)}
          style={{ marginLeft: 'auto', background: 'none', border: 'none', cursor: 'pointer', color: '#3d5470', padding: 2 }}
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d={collapsed ? 'M9 18l6-6-6-6' : 'M15 18l-6-6 6-6'} />
          </svg>
        </button>
      </div>

      {/* Navigation */}
      <nav style={{ flex: 1, padding: '8px 0', overflowY: 'auto' }}>
        {nav.map(item => (
          <button
            key={item.id}
            onClick={() => onNavigate(item.id)}
            title={collapsed ? item.label : undefined}
            style={{
              width: '100%', display: 'flex', alignItems: 'center',
              gap: 10, padding: collapsed ? '10px 12px' : '10px 16px',
              background: active === item.id ? 'rgba(0, 212, 255, 0.08)' : 'transparent',
              border: 'none',
              borderLeft: active === item.id ? '2px solid #00d4ff' : '2px solid transparent',
              cursor: 'pointer',
              color: active === item.id ? '#00d4ff' : '#6b8aac',
              transition: 'all 0.15s ease',
              textAlign: 'left',
            }}
            onMouseEnter={e => { if (active !== item.id) (e.currentTarget as HTMLElement).style.color = '#a0b8d4'; }}
            onMouseLeave={e => { if (active !== item.id) (e.currentTarget as HTMLElement).style.color = '#6b8aac'; }}
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" style={{ flexShrink: 0 }}>
              <path d={item.icon} />
            </svg>
            {!collapsed && (
              <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, letterSpacing: 0.5, whiteSpace: 'nowrap' }}>
                {item.label}
              </span>
            )}
          </button>
        ))}
      </nav>

      {/* Kill switch */}
      <div style={{ padding: 12, borderTop: '1px solid #1e2f46' }}>
        <button
          onClick={onKillSwitch}
          title="Kill Switch — halt all scans"
          style={{
            width: '100%',
            padding: collapsed ? '8px' : '8px 12px',
            display: 'flex', alignItems: 'center', justifyContent: collapsed ? 'center' : 'flex-start',
            gap: 8,
            background: killActive ? 'rgba(255, 59, 59, 0.2)' : 'rgba(255, 59, 59, 0.08)',
            border: `1px solid ${killActive ? '#ff3b3b' : '#ff3b3b44'}`,
            borderRadius: 6,
            cursor: 'pointer',
            color: '#ff3b3b',
            transition: 'all 0.15s ease',
          }}
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ flexShrink: 0 }}>
            <rect x="3" y="3" width="18" height="18" rx="2" />
            <line x1="9" y1="9" x2="15" y2="15" />
            <line x1="15" y1="9" x2="9" y2="15" />
          </svg>
          {!collapsed && (
            <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, letterSpacing: 0.5 }}>
              {killActive ? 'KILLED' : 'KILL SWITCH'}
            </span>
          )}
        </button>
      </div>

      {/* Lab scope badge */}
      {!collapsed && (
        <div style={{ padding: '0 12px 12px' }}>
          <div style={{ background: 'rgba(0, 230, 118, 0.06)', border: '1px solid rgba(0, 230, 118, 0.2)', borderRadius: 4, padding: '6px 8px' }}>
            <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 8, color: '#00e676', letterSpacing: 1, textTransform: 'uppercase', marginBottom: 2 }}>■ Lab Scope Active</div>
            <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 8, color: '#3d5470' }}>SIH26163 · lab.local only</div>
          </div>
        </div>
      )}
    </aside>
  );
}
