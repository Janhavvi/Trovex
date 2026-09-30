import { useEffect, useState } from 'react';

type ReportOverview = {
  target: string;
  postureScore: number;
  grade: string;
  confirmedFindings: number;
  unverifiedFindings: number;
  severityCounts: Record<string, number>;
  hasScan: boolean;
};

type ReportFinding = {
  id: string;
  title: string;
  severity: string;
  status: string;
  endpoint: string;
};

export default function Reports() {
  const [overview, setOverview] = useState<ReportOverview | null>(null);
  const [findings, setFindings] = useState<ReportFinding[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);

  useEffect(() => {
    let isMounted = true;
    Promise.all([fetch('/api/overview'), fetch('/api/findings')])
      .then(async ([overviewResponse, findingsResponse]) => {
        if (!overviewResponse.ok || !findingsResponse.ok) throw new Error('Report data is unavailable');
        const [overviewData, findingsData] = await Promise.all([overviewResponse.json(), findingsResponse.json()]);
        if (isMounted) {
          setOverview(overviewData);
          setFindings(findingsData);
        }
      })
      .catch((loadError) => {
        if (isMounted) setError(loadError instanceof Error ? loadError.message : 'Unable to load report data');
      });
    return () => { isMounted = false; };
  }, []);

  const downloadReport = async (path: string, filename: string, format: string) => {
    setExporting(true);
    setError(null);
    try {
      const response = await fetch(path);
      if (!response.ok) throw new Error(`Unable to generate ${format} report`);
      const report = await response.blob();
      const url = URL.createObjectURL(report);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      document.body.append(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (exportError) {
      setError(exportError instanceof Error ? exportError.message : `${format} export failed`);
    } finally {
      setExporting(false);
    }
  };

  return (
    <div className="report-page" style={{ padding: 24, maxWidth: 1200, color: '#e2eaf6' }}>
      <div className="report-actions" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, flexWrap: 'wrap', marginBottom: 18 }}>
        <div>
          <div style={{ color: '#3d5470', fontFamily: 'JetBrains Mono, monospace', fontSize: 9, letterSpacing: 1.5 }}>ASSESSMENT OUTPUT</div>
          <h1 style={{ margin: '5px 0 0', fontSize: 20 }}>Reports</h1>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button onClick={() => void downloadReport('/api/report/pdf', 'trovex-executive-report.pdf', 'PDF')} disabled={exporting} style={{ padding: '8px 11px', background: '#0d1520', border: '1px solid #1e2f46', borderRadius: 4, color: '#a0b8d4', cursor: exporting ? 'wait' : 'pointer', fontFamily: 'JetBrains Mono, monospace', fontSize: 9 }}>{exporting ? 'GENERATING…' : 'DOWNLOAD PDF'}</button>
          <button onClick={() => void downloadReport('/api/report/sarif', 'trovex-report.sarif', 'SARIF')} disabled={exporting} style={{ padding: '8px 11px', background: 'rgba(0,212,255,0.12)', border: '1px solid #00d4ff66', borderRadius: 4, color: '#00d4ff', cursor: exporting ? 'wait' : 'pointer', fontFamily: 'JetBrains Mono, monospace', fontSize: 9 }}>{exporting ? 'GENERATING…' : 'DOWNLOAD SARIF'}</button>
        </div>
      </div>

      {error && <div role="alert" style={{ marginBottom: 14, color: '#ff8d8d', fontSize: 12 }}>{error}</div>}
      {overview && (
        <>
          <section style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(145px, 1fr))', gap: 10, marginBottom: 18 }}>
            {[
              ['Target', overview.target],
              ['Posture', overview.hasScan ? `${overview.postureScore} / 100 · ${overview.grade}` : 'No assessment'],
              ['Confirmed', String(overview.confirmedFindings)],
              ['Unverified', String(overview.unverifiedFindings)],
            ].map(([label, value]) => (
              <div key={label} style={{ padding: 14, background: '#0d1520', border: '1px solid #1e2f46', borderRadius: 5 }}>
                <div style={{ color: '#6b8aac', font: '9px JetBrains Mono, monospace', textTransform: 'uppercase', marginBottom: 6 }}>{label}</div>
                <div style={{ color: '#e2eaf6', fontSize: 13, overflowWrap: 'anywhere' }}>{value}</div>
              </div>
            ))}
          </section>
          <section style={{ marginBottom: 18 }}>
            <h2 style={{ fontSize: 12, fontWeight: 600, margin: '0 0 8px' }}>Confirmed severity</h2>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
              {Object.entries(overview.severityCounts).map(([severity, count]) => (
                <span key={severity} style={{ padding: '5px 8px', border: '1px solid #1e2f46', borderRadius: 3, color: '#a0b8d4', font: '9px JetBrains Mono, monospace' }}>{severity} {count}</span>
              ))}
            </div>
          </section>
        </>
      )}

      <section>
        <h2 style={{ fontSize: 12, fontWeight: 600, margin: '0 0 8px' }}>Latest assessment findings</h2>
        <div style={{ overflowX: 'auto', border: '1px solid #1e2f46', borderRadius: 5 }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
            <thead><tr style={{ textAlign: 'left', color: '#6b8aac', font: '9px JetBrains Mono, monospace' }}>
              <th style={{ padding: 10 }}>ID</th><th style={{ padding: 10 }}>Finding</th><th style={{ padding: 10 }}>Severity</th><th style={{ padding: 10 }}>Status</th><th style={{ padding: 10 }}>Endpoint</th>
            </tr></thead>
            <tbody>{findings.map((finding) => (
              <tr key={finding.id} style={{ borderTop: '1px solid #1e2f46', color: '#a0b8d4' }}>
                <td style={{ padding: 10, fontFamily: 'JetBrains Mono, monospace' }}>{finding.id}</td><td style={{ padding: 10 }}>{finding.title}</td><td style={{ padding: 10 }}>{finding.severity}</td><td style={{ padding: 10 }}>{finding.status}</td><td style={{ padding: 10, overflowWrap: 'anywhere' }}>{finding.endpoint}</td>
              </tr>
            ))}</tbody>
          </table>
          {!findings.length && <div style={{ padding: 14, color: '#6b8aac', fontSize: 12 }}>No findings available for reporting.</div>}
        </div>
      </section>
    </div>
  );
}
