import { useState, useEffect } from 'react';
import Sidebar from './components/Sidebar';
import Overview from './components/Overview';
import FindingsScreen from './components/Findings';
import RoleMatrix from './components/RoleMatrix';
import AttackPaths from './components/AttackPaths';
import Mobile from './components/Mobile';
import EvidenceVault from './components/EvidenceVault';
import Login from './components/Login';
import Methodology from './components/Methodology';
import Reports from './components/Reports';
import SignUp from './components/SignUp';
import ScopeGuard from './components/ScopeGuard';

type Screen = 'overview' | 'findings' | 'roles' | 'chains' | 'mobile' | 'vault' | 'methodology' | 'scope' | 'reports';
type AuthPage = 'login' | 'signup';
type SessionUser = { username: string; role: 'ADMIN' | 'SECURITY_ANALYST' | 'VIEWER' };

function ScanProgress({ scanId, onComplete, onFailure }: { scanId: string | null; onComplete: () => void; onFailure: (message: string) => void }) {
  const [phase, setPhase] = useState('Submitting assessment to the private lab…');

  useEffect(() => {
    if (!scanId) return;
    let cancelled = false;
    let timer: number | undefined;

    const poll = async () => {
      try {
        const response = await fetch(`/api/scans/${scanId}`);
        if (!response.ok) throw new Error('Unable to read assessment status');
        const scan = await response.json();
        if (cancelled) return;
        if (scan.status === 'completed') {
          setPhase('Passive ZAP baseline complete. Findings saved.');
          timer = window.setTimeout(onComplete, 700);
          return;
        }
        if (scan.status === 'failed') {
          onFailure(scan.error || 'The passive baseline scan failed.');
          return;
        }
        setPhase(scan.status === 'queued' ? 'Waiting for the scanner…' : 'Running passive OWASP ZAP baseline on the private lab…');
        timer = window.setTimeout(poll, 2000);
      } catch (error) {
        if (!cancelled) onFailure(error instanceof Error ? error.message : 'Assessment status unavailable');
      }
    };

    void poll();
    return () => {
      cancelled = true;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [scanId, onComplete, onFailure]);

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 200,
      background: 'rgba(8, 12, 20, 0.95)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }}>
      <div style={{ width: 480, textAlign: 'center' }}>
        {/* Radar animation */}
        <div style={{ position: 'relative', width: 120, height: 120, margin: '0 auto 24px' }}>
          <svg width="120" height="120" viewBox="0 0 120 120">
            <circle cx="60" cy="60" r="55" fill="none" stroke="#1e2f46" strokeWidth="1" />
            <circle cx="60" cy="60" r="38" fill="none" stroke="#1e2f46" strokeWidth="1" />
            <circle cx="60" cy="60" r="20" fill="none" stroke="#1e2f46" strokeWidth="1" />
            <line x1="60" y1="5" x2="60" y2="115" stroke="#1e2f46" strokeWidth="1" />
            <line x1="5" y1="60" x2="115" y2="60" stroke="#1e2f46" strokeWidth="1" />
            <g style={{ transformOrigin: '60px 60px', animation: 'spin 2s linear infinite' }}>
              <path d="M 60 60 L 60 5 A 55 55 0 0 1 113 78 Z" fill="url(#radarFill)" opacity="0.7" />
              <line x1="60" y1="60" x2="60" y2="5" stroke="#00d4ff" strokeWidth="1.5" />
            </g>
            <defs>
              <radialGradient id="radarFill" cx="60" cy="60" r="55" gradientUnits="userSpaceOnUse">
                <stop offset="0%" stopColor="#00d4ff" stopOpacity="0.4" />
                <stop offset="100%" stopColor="#00d4ff" stopOpacity="0" />
              </radialGradient>
            </defs>
          </svg>
          <style>{`@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
        </div>

        <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 20, fontWeight: 700, color: '#00d4ff', marginBottom: 6, letterSpacing: 2 }}>
          TROVEX
        </div>
        <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: '#6b8aac', marginBottom: 24 }}>
          {phase}
        </div>

        {/* Progress bar */}
        <div style={{ background: '#1e2f46', borderRadius: 4, height: 4, overflow: 'hidden', marginBottom: 10 }}>
          <div style={{
            height: '100%', borderRadius: 4,
            background: 'linear-gradient(90deg, #00d4ff, #00a855)',
            width: scanId ? '62%' : '24%',
            transition: 'width 0.25s ease',
            boxShadow: '0 0 8px #00d4ff88',
          }} />
        </div>
        <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: '#3d5470' }}>LIVE JOB STATUS</div>
      </div>
    </div>
  );
}

function TopBar({ screen, scanning, user, onLogout }: { screen: Screen; scanning: boolean; user: SessionUser; onLogout: () => void }) {
  const labels: Record<Screen, string> = {
    overview: 'Overview', findings: 'Findings', roles: 'Role Matrix',
    chains: 'Attack Paths', mobile: 'Mobile Module', vault: 'Evidence Vault', methodology: 'Methodology', scope: 'Scope Guard', reports: 'Reports',
  };
  return (
    <div className="trovex-topbar" style={{
      height: 44, borderBottom: '1px solid #1e2f46',
      display: 'flex', alignItems: 'center', paddingRight: 20, gap: 12,
      background: '#080c14', flexShrink: 0,
    }}>
      <div style={{ flex: 1, paddingLeft: 20 }}>
        <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#6b8aac', letterSpacing: 1 }}>{labels[screen]}</span>
        {scanning && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span className="scan-line" style={{ display: 'inline-block', width: 6, height: 6, borderRadius: '50%', background: '#00d4ff' }} />
            <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#00d4ff', letterSpacing: 1 }}>SCAN RUNNING</span>
          </div>
        )}
      </div>
      <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#3d5470', letterSpacing: 1 }}>
        lab.local:8000 · SIH26163
      </div>
      <div style={{ width: 1, height: 18, background: '#1e2f46' }} />
      <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#6b8aac' }}>
        {new Date().toISOString().slice(0, 16).replace('T', ' ')} UTC
      </div>
      <div style={{ width: 1, height: 18, background: '#1e2f46' }} />
      <div style={{ textAlign: 'right' }}>
        <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#e2eaf6' }}>{user.username}</div>
        <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 8, color: '#00d4ff' }}>{user.role.replace('_', ' ')}</div>
      </div>
      <button onClick={onLogout} title="Sign out" aria-label="Sign out" style={{ border: '1px solid #1e2f46', borderRadius: 4, background: 'transparent', color: '#9cb1c9', padding: '6px 9px', cursor: 'pointer', fontSize: 10 }}>LOG OUT</button>
    </div>
  );
}

export default function App() {
  const [authUser, setAuthUser] = useState<SessionUser | null>(null);
  const [authChecked, setAuthChecked] = useState(false);
  const [authPage, setAuthPage] = useState<AuthPage>(() => window.location.pathname === '/signup' ? 'signup' : 'login');
  const [screen, setScreen] = useState<Screen>('overview');
  const [scanning, setScanning] = useState(false);
  const [showScan, setShowScan] = useState(false);
  const [killActive, setKillActive] = useState(false);
  const [killSwitchPending, setKillSwitchPending] = useState(false);
  const [runError, setRunError] = useState<string | null>(null);
  const [scanId, setScanId] = useState<string | null>(null);

  useEffect(() => {
    let isMounted = true;
    fetch('/api/auth/session')
      .then((response) => {
        if (!response.ok) throw new Error('Session status unavailable');
        return response.json();
      })
      .then((result) => {
        if (!isMounted) return;
        if (result.authenticated) {
          setAuthUser(result.user);
          window.history.replaceState({}, '', '/dashboard');
        } else {
          setAuthUser(null);
          const authPath = window.location.pathname === '/signup' ? 'signup' : 'login';
          setAuthPage(authPath);
          if (!['/login', '/signup'].includes(window.location.pathname)) window.history.replaceState({}, '', '/login');
        }
      })
      .catch(() => { if (isMounted) setAuthUser(null); })
      .finally(() => { if (isMounted) setAuthChecked(true); });
    return () => { isMounted = false; };
  }, []);

  useEffect(() => {
    const syncAuthPage = () => {
      setAuthPage(window.location.pathname === '/signup' ? 'signup' : 'login');
    };
    window.addEventListener('popstate', syncAuthPage);
    return () => window.removeEventListener('popstate', syncAuthPage);
  }, []);

  useEffect(() => {
    if (!authUser) return;
    let isMounted = true;
    fetch('/api/scope/status')
      .then((response) => {
        if (!response.ok) throw new Error('Scope status unavailable');
        return response.json();
      })
      .then((status) => { if (isMounted) setKillActive(status.killSwitch); })
      .catch(() => { if (isMounted) setKillActive(true); });
    return () => { isMounted = false; };
  }, [authUser]);

  const handleLogin = async (username: string, password: string, remember: boolean) => {
    const response = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username, password, remember }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Sign-in failed');
    setAuthUser(result.user);
    window.history.replaceState({}, '', '/dashboard');
  };

  const handleSignUp = async (input: { name: string; email: string; password: string; role: string; termsAccepted: boolean }) => {
    const response = await fetch('/api/auth/signup', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(input),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Something went wrong while creating your account. Please try again.');
    setAuthUser(result.user);
    window.history.replaceState({}, '', '/dashboard');
  };

  const navigateAuthPage = (page: AuthPage) => {
    window.history.pushState({}, '', `/${page}`);
    setAuthPage(page);
  };

  const handleLogout = async () => {
    await fetch('/api/auth/logout', { method: 'POST' }).catch(() => undefined);
    setAuthUser(null);
    window.history.replaceState({}, '', '/login');
    setAuthPage('login');
    setScanning(false);
    setShowScan(false);
    setScanId(null);
  };

  const handleRun = async () => {
    if (!authUser || authUser.role === 'VIEWER' || killActive || scanning) return;
    setRunError(null);
    setScanning(true);
    setScanId(null);
    setShowScan(true);

    try {
      const response = await fetch('/api/automation/run', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          event: 'assessment.started',
          payload: { source: 'dashboard' },
        }),
      });

      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'n8n did not accept the assessment event');
      setScanId(result.scanId);
    } catch (error) {
      setScanning(false);
      setShowScan(false);
      setRunError(error instanceof Error ? error.message : 'Assessment was not started.');
    }
  };

  const handleScanComplete = () => {
    setShowScan(false);
    setScanning(false);
    setScanId(null);
    window.dispatchEvent(new Event('trovex-scan-completed'));
  };

  const handleScanFailure = (message: string) => {
    setShowScan(false);
    setScanning(false);
    setScanId(null);
    setRunError(message);
  };

  const handleKillSwitch = async () => {
    if (authUser?.role !== 'ADMIN') return;
    if (killSwitchPending) return;
    setKillSwitchPending(true);
    try {
      const response = await fetch('/api/scope/kill-switch', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ active: !killActive }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'Unable to update kill switch');
      setKillActive(result.killSwitch);
    } catch {
      setRunError('Unable to update the server kill switch. Scan state was not changed.');
    } finally {
      setKillSwitchPending(false);
    }
  };

  if (!authChecked) {
    return <div style={{ minHeight: '100vh', display: 'grid', placeItems: 'center', background: '#080c14', color: '#6b8aac', fontFamily: 'JetBrains Mono, monospace', fontSize: 11 }}>CHECKING SESSION…</div>;
  }
  if (!authUser) {
    return authPage === 'signup'
      ? <SignUp onSignUp={handleSignUp} onNavigateLogin={() => navigateAuthPage('login')} />
      : <Login onLogin={handleLogin} onNavigateSignup={() => navigateAuthPage('signup')} />;
  }

  const screenEl = {
    overview: <Overview onRunAssessment={handleRun} scanning={scanning} runError={runError} canRunAssessment={authUser.role !== 'VIEWER'} />,
    findings: <FindingsScreen />,
    roles: <RoleMatrix />,
    chains: <AttackPaths />,
    mobile: <Mobile />,
    vault: <EvidenceVault />,
    methodology: <Methodology />,
    scope: <ScopeGuard />,
    reports: <Reports />,
  }[screen];

  return (
    <div style={{ display: 'flex', height: '100vh', overflow: 'hidden', background: '#080c14' }}>
      <Sidebar
        active={screen}
        onNavigate={setScreen}
        onKillSwitch={handleKillSwitch}
        killActive={killActive}
        canKillSwitch={authUser.role === 'ADMIN'}
      />
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <TopBar screen={screen} scanning={scanning} user={authUser} onLogout={handleLogout} />
        <main style={{ flex: 1, overflowY: 'auto' }}>
          {screenEl}
        </main>
      </div>
      {showScan && <ScanProgress scanId={scanId} onComplete={handleScanComplete} onFailure={handleScanFailure} />}
    </div>
  );
}
