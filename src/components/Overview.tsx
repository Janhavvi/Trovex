import { useEffect, useState } from 'react';
import {
  AreaChart, Area, BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, Cell,
} from 'recharts';
import { currentScore, currentGrade, scoreHistory, getSeverityCount, findings } from '../data/mockData';

const severityColors = {
  CRITICAL: '#ff3b3b',
  HIGH: '#ff6b2b',
  MEDIUM: '#ffc107',
  LOW: '#00d4ff',
  INFO: '#6b8aac',
};

type PhaseStatus = {
  name: string;
  status: 'complete' | 'in-progress' | 'pending';
  detail: string;
};

type EventItem = {
  id: string;
  step: string;
  status: string;
  createdAt: string;
  detail?: string | null;
};

function PostureGauge({ score, grade }: { score: number; grade: string }) {
  const angle = -135 + (score / 100) * 270;
  const gradeColor = grade === 'A' ? '#00e676' : grade === 'B' ? '#00d4ff' : grade === 'C' ? '#ffc107' : grade === 'D' ? '#ff6b2b' : '#ff3b3b';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8 }}>
      <svg width="180" height="120" viewBox="0 0 180 120">
        {/* Track */}
        <path d="M 20 110 A 70 70 0 1 1 160 110" fill="none" stroke="#1e2f46" strokeWidth="12" strokeLinecap="round" />
        {/* Fill */}
        <path
          d="M 20 110 A 70 70 0 1 1 160 110"
          fill="none"
          stroke={gradeColor}
          strokeWidth="12"
          strokeLinecap="round"
          strokeDasharray={`${(score / 100) * 220} 220`}
          style={{ transition: 'stroke-dasharray 1s ease, stroke 0.5s ease', filter: `drop-shadow(0 0 6px ${gradeColor}88)` }}
        />
        {/* Needle */}
        <g transform={`rotate(${angle}, 90, 110)`}>
          <line x1="90" y1="110" x2="90" y2="48" stroke={gradeColor} strokeWidth="2" strokeLinecap="round" />
          <circle cx="90" cy="110" r="5" fill={gradeColor} />
        </g>
        {/* Score */}
        <text x="90" y="95" textAnchor="middle" fill={gradeColor} fontSize="26" fontFamily="JetBrains Mono, monospace" fontWeight="700">{score}</text>
        <text x="90" y="108" textAnchor="middle" fill="#3d5470" fontSize="10" fontFamily="JetBrains Mono, monospace">POSTURE SCORE</text>
      </svg>
      <div style={{
        fontFamily: 'JetBrains Mono, monospace', fontSize: 36, fontWeight: 700,
        color: gradeColor, lineHeight: 1,
        textShadow: `0 0 20px ${gradeColor}66`,
      }}>
        {grade}
      </div>
      <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: '#3d5470', letterSpacing: 1 }}>
        SECURITY GRADE
      </div>
    </div>
  );
}

const CustomTooltip = ({ active, payload, label }: { active?: boolean; payload?: { value: number; name?: string; color?: string }[]; label?: string }) => {
  if (active && payload && payload.length) {
    return (
      <div style={{ background: '#0d1520', border: '1px solid #1e2f46', borderRadius: 4, padding: '8px 12px', fontFamily: 'JetBrains Mono, monospace', fontSize: 11 }}>
        <div style={{ color: '#6b8aac', marginBottom: 4 }}>{label}</div>
        {payload.map((p, i) => (
          <div key={i} style={{ color: p.color || '#00d4ff' }}>
            {p.name ? `${p.name}: ` : ''}{p.value}
          </div>
        ))}
      </div>
    );
  }
  return null;
};

export default function Overview({ onRunAssessment, scanning, runError, canRunAssessment }: { onRunAssessment: () => void; scanning: boolean; runError: string | null; canRunAssessment: boolean }) {
  const [verifying, setVerifying] = useState(false);
  const [verified, setVerified] = useState<boolean | null>(null);
  const [verifyError, setVerifyError] = useState<string | null>(null);
  const [liveOverview, setLiveOverview] = useState<{
    target: string;
    postureScore: number;
    grade: string;
    confirmedFindings: number;
    unverifiedFindings: number;
    criticalFindings: number;
    attackChains: number;
    severityCounts: Record<string, number>;
    scoreHistory: typeof scoreHistory;
    hasScan: boolean;
    phases?: PhaseStatus[];
    recentEvents?: EventItem[];
  } | null>(null);

  useEffect(() => {
    let isMounted = true;
    const loadOverview = () => {
      void fetch('/api/overview')
        .then((response) => {
          if (!response.ok) throw new Error('Overview unavailable');
          return response.json();
        })
        .then((data) => { if (isMounted) setLiveOverview(data); })
        .catch(() => { if (isMounted) setLiveOverview(null); });
    };
    loadOverview();
    window.addEventListener('trovex-scan-completed', loadOverview);
    return () => {
      isMounted = false;
      window.removeEventListener('trovex-scan-completed', loadOverview);
    };
  }, []);

  const counts = liveOverview?.severityCounts ?? getSeverityCount();
  const confirmedCount = liveOverview?.confirmedFindings ?? findings.filter(f => f.status === 'CONFIRMED').length;
  const unverifiedCount = liveOverview?.unverifiedFindings ?? findings.filter(f => f.status === 'UNVERIFIED').length;
  const postureScore = liveOverview?.postureScore ?? currentScore;
  const postureGrade = liveOverview?.grade ?? currentGrade;
  const chartHistory = liveOverview?.scoreHistory ?? scoreHistory;
  const phases = liveOverview?.phases ?? [
    { name: 'Scope validation', status: 'complete', detail: 'Private lab is enforced' },
    { name: 'Authorization verification', status: 'complete', detail: 'Signed auth is checked' },
    { name: 'Scan orchestration', status: 'in-progress', detail: 'Automation is running' },
    { name: 'Evidence validation', status: 'pending', detail: 'Findings are chained to evidence' },
  ];
  const recentEvents = liveOverview?.recentEvents ?? [
    { id: 'evt-1', step: 'assessment.started', status: 'accepted', createdAt: new Date().toISOString(), detail: 'Dashboard assessment request accepted' },
  ];

  const severityBarData = Object.entries(counts).map(([sev, count]) => ({ name: sev, count, color: severityColors[sev as keyof typeof severityColors] }));

  const handleVerify = async () => {
    setVerifying(true);
    setVerified(null);
    setVerifyError(null);
    try {
      const response = await fetch('/api/evidence/verify');
      if (!response.ok) throw new Error('Evidence integrity verification is unavailable');
      const result = await response.json();
      setVerified(result.valid === true);
      if (!result.valid) setVerifyError(`Integrity violation at ${result.failedRecordId}`);
    } catch (error) {
      setVerifyError(error instanceof Error ? error.message : 'Unable to verify evidence integrity');
    } finally {
      setVerifying(false);
    }
  };

  return (
    <div style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 20, fontFamily: 'Inter, sans-serif' }}>
      {/* Header row */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
        <div>
          <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: '#3d5470', letterSpacing: 2, textTransform: 'uppercase', marginBottom: 4 }}>
            Assessment · {liveOverview?.target || 'lab.local:8000'}
          </div>
          <h1 style={{ margin: 0, fontSize: 20, fontWeight: 600, color: '#e2eaf6', letterSpacing: -0.5, fontFamily: 'Inter, sans-serif' }}>
            Security Overview
          </h1>
          {runError && (
            <div role="alert" style={{ marginTop: 6, color: '#ff8d8d', fontFamily: 'JetBrains Mono, monospace', fontSize: 9 }}>
              {runError}
            </div>
          )}
          {verifyError && <div role="alert" style={{ marginTop: 6, color: '#ff8d8d', fontFamily: 'JetBrains Mono, monospace', fontSize: 9 }}>{verifyError}</div>}
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <button
            onClick={handleVerify}
            disabled={verifying}
            style={{
              padding: '8px 14px', borderRadius: 6, cursor: verifying ? 'default' : 'pointer',
              fontFamily: 'JetBrains Mono, monospace', fontSize: 11, letterSpacing: 0.5,
              background: 'rgba(0, 230, 118, 0.08)', border: '1px solid rgba(0, 230, 118, 0.3)',
              color: verified === true ? '#00e676' : '#00a855',
              display: 'flex', alignItems: 'center', gap: 6,
            }}
          >
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              {verified === true && <path d="M9 12l2 2 4-4" />}
            </svg>
            {verifying ? 'VERIFYING…' : verified === true ? 'CHAIN INTACT' : verified === false ? 'INTEGRITY ISSUE' : 'VERIFY EVIDENCE'}
          </button>
          <button
            onClick={onRunAssessment}
            disabled={scanning || !canRunAssessment}
            style={{
              padding: '8px 16px', borderRadius: 6, cursor: scanning || !canRunAssessment ? 'default' : 'pointer',
              fontFamily: 'JetBrains Mono, monospace', fontSize: 11, letterSpacing: 0.5,
              background: scanning || !canRunAssessment ? 'rgba(0, 212, 255, 0.05)' : 'rgba(0, 212, 255, 0.12)',
              border: `1px solid ${scanning || !canRunAssessment ? '#00d4ff44' : '#00d4ff66'}`,
              color: canRunAssessment ? '#00d4ff' : '#6b8aac',
              display: 'flex', alignItems: 'center', gap: 6,
            }}
          >
            {!canRunAssessment ? (
              'VIEW ONLY'
            ) : scanning ? (
              <>
                <span className="scan-line" style={{ display: 'inline-block', width: 8, height: 8, borderRadius: '50%', background: '#00d4ff' }} />
                SCANNING…
              </>
            ) : (
              <>
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="10" /><polygon points="10 8 16 12 10 16 10 8" fill="currentColor" />
                </svg>
                RUN ASSESSMENT
              </>
            )}
          </button>
        </div>
      </div>

      {/* Stat cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(120px, 1fr))', gap: 10 }}>
        {[
          { label: 'Posture Score', value: liveOverview?.hasScan ? postureScore : liveOverview ? 'N/A' : currentScore, sub: liveOverview?.hasScan ? `Grade ${postureGrade}` : liveOverview ? 'awaiting first scan' : `Grade ${currentGrade}`, color: '#ff3b3b' },
          { label: 'Confirmed', value: confirmedCount, sub: 'findings', color: '#ff3b3b' },
          { label: 'Unverified', value: unverifiedCount, sub: 'pending triage', color: '#ffc107' },
          { label: 'Critical', value: counts.CRITICAL, sub: 'findings', color: '#ff3b3b' },
          { label: 'Attack Chains', value: liveOverview?.attackChains ?? 2, sub: 'active paths', color: '#ff6b2b' },
        ].map(card => (
          <div key={card.label} style={{
            background: '#0d1520', border: '1px solid #1e2f46', borderRadius: 8,
            padding: '12px 14px',
          }}>
            <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 8, color: '#3d5470', letterSpacing: 1.5, textTransform: 'uppercase', marginBottom: 5 }}>
              {card.label}
            </div>
            <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 22, fontWeight: 700, color: card.color, lineHeight: 1 }}>
              {card.value}
            </div>
            <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 8, color: '#6b8aac', marginTop: 4 }}>
              {card.sub}
            </div>
          </div>
        ))}
      </div>

      {/* Charts row */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: 16 }}>
        {/* Gauge */}
        <div style={{ background: '#0d1520', border: '1px solid #1e2f46', borderRadius: 8, padding: '16px 14px', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6 }}>
          <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#3d5470', letterSpacing: 1.5, textTransform: 'uppercase', alignSelf: 'flex-start', marginBottom: 4 }}>
            Security Posture
          </div>
          <PostureGauge score={liveOverview && !liveOverview.hasScan ? 0 : postureScore} grade={liveOverview && !liveOverview.hasScan ? 'N/A' : postureGrade} />
          <div style={{ width: '100%', marginTop: 8 }}>
            {['A ≥ 90', 'B ≥ 75', 'C ≥ 60', 'D ≥ 40', 'F < 40'].map((g, i) => {
              const colors = ['#00e676', '#00d4ff', '#ffc107', '#ff6b2b', '#ff3b3b'];
              const grades = ['A', 'B', 'C', 'D', 'F'];
              return (
                <div key={g} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '3px 0', borderBottom: '1px solid #1e2f4620' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <div style={{ width: 6, height: 6, borderRadius: '50%', background: colors[i] }} />
                    <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: postureGrade === grades[i] ? colors[i] : '#3d5470' }}>
                      Grade {grades[i]}
                    </span>
                  </div>
                  <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#3d5470' }}>{g.split(' ')[1]}</span>
                </div>
              );
            })}
          </div>
        </div>

        {/* Score over time */}
        <div style={{ background: '#0d1520', border: '1px solid #1e2f46', borderRadius: 8, padding: '16px' }}>
          <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#3d5470', letterSpacing: 1.5, textTransform: 'uppercase', marginBottom: 16 }}>
            Score History — 7 Days
          </div>
          <ResponsiveContainer width="100%" height={180}>
            <AreaChart data={chartHistory} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="scoreGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#00d4ff" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#00d4ff" stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="date" tick={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, fill: '#3d5470' }} axisLine={false} tickLine={false} />
              <YAxis domain={[0, 100]} tick={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, fill: '#3d5470' }} axisLine={false} tickLine={false} />
              <Tooltip content={<CustomTooltip />} />
              <Area type="monotone" dataKey="score" stroke="#00d4ff" strokeWidth={2} fill="url(#scoreGrad)" dot={{ fill: '#00d4ff', r: 3 }} name="Score" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.8fr', gap: 16 }}>
        <div style={{ background: '#0d1520', border: '1px solid #1e2f46', borderRadius: 8, padding: 16 }}>
          <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#3d5470', letterSpacing: 1.5, textTransform: 'uppercase', marginBottom: 12 }}>
            Assessment Phase Timeline
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {phases.map((phase, index) => (
              <div key={`${phase.name}-${index}`} style={{ display: 'flex', gap: 12, alignItems: 'flex-start' }}>
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', marginTop: 2 }}>
                  <div style={{
                    width: 12, height: 12, borderRadius: '50%',
                    background: phase.status === 'complete' ? '#00e676' : phase.status === 'in-progress' ? '#00d4ff' : '#1e2f46',
                    border: `1px solid ${phase.status === 'complete' ? '#00e676' : phase.status === 'in-progress' ? '#00d4ff' : '#3d5470'}`,
                    boxShadow: phase.status === 'in-progress' ? '0 0 10px rgba(0,212,255,0.6)' : 'none',
                  }} />
                  {index < phases.length - 1 && <div style={{ width: 1, height: 18, background: '#1e2f46', marginTop: 4 }} />}
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, marginBottom: 2 }}>
                    <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: '#e2eaf6' }}>{phase.name}</span>
                    <span style={{
                      fontFamily: 'JetBrains Mono, monospace', fontSize: 9,
                      color: phase.status === 'complete' ? '#00e676' : phase.status === 'in-progress' ? '#00d4ff' : '#6b8aac',
                      textTransform: 'uppercase',
                    }}>
                      {phase.status}
                    </span>
                  </div>
                  <div style={{ fontSize: 11, color: '#6b8aac', lineHeight: 1.5 }}>{phase.detail}</div>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div style={{ background: '#0d1520', border: '1px solid #1e2f46', borderRadius: 8, padding: 16 }}>
          <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#3d5470', letterSpacing: 1.5, textTransform: 'uppercase', marginBottom: 12 }}>
            Recent Automation Events
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {recentEvents.map((event) => (
              <div key={event.id} style={{ background: '#080c14', border: '1px solid #1e2f46', borderRadius: 6, padding: 10 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginBottom: 4 }}>
                  <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#00d4ff' }}>{event.step}</span>
                  <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 8, color: event.status === 'accepted' ? '#00e676' : '#ffc107', textTransform: 'uppercase' }}>{event.status}</span>
                </div>
                <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 8, color: '#3d5470' }}>{new Date(event.createdAt).toISOString().slice(0, 16).replace('T', ' ')} UTC</div>
                {event.detail && <div style={{ marginTop: 6, fontSize: 11, color: '#6b8aac', lineHeight: 1.5 }}>{event.detail}</div>}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Severity distribution */}
      <div style={{ background: '#0d1520', border: '1px solid #1e2f46', borderRadius: 8, padding: 16 }}>
        <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#3d5470', letterSpacing: 1.5, textTransform: 'uppercase', marginBottom: 12 }}>
          Severity Distribution (Confirmed Only)
        </div>
        <div style={{ display: 'flex', gap: 16, alignItems: 'flex-end' }}>
          <div style={{ flex: 1 }}>
            <ResponsiveContainer width="100%" height={100}>
              <BarChart data={severityBarData} barCategoryGap="30%">
                <XAxis dataKey="name" tick={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, fill: '#3d5470' }} axisLine={false} tickLine={false} />
                <YAxis hide />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="count" radius={[3, 3, 0, 0]}>
                  {severityBarData.map((entry, i) => (
                    <Cell key={i} fill={entry.color} fillOpacity={0.85} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, paddingBottom: 8 }}>
            {Object.entries(counts).map(([sev, count]) => (
              <div key={sev} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <div style={{ width: 8, height: 8, borderRadius: 1, background: severityColors[sev as keyof typeof severityColors] }} />
                <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: '#6b8aac', width: 70 }}>{sev}</span>
                <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 12, color: severityColors[sev as keyof typeof severityColors], fontWeight: 600 }}>{count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
