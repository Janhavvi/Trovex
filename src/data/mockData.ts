export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type FindingStatus = 'CONFIRMED' | 'UNVERIFIED' | 'ERROR';
export type Lifecycle = 'OPEN' | 'IN_PROGRESS' | 'FIXED' | 'REGRESSED';

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  status: FindingStatus;
  lifecycle: Lifecycle;
  endpoint: string;
  cwe: string;
  owasp: string;
  cvss_score: number;
  cvss_vector: string;
  business_impact: string;
  remediation: string;
  chain_id?: string;
  cert_in: string;
  dpdp_relevant: boolean;
  discovered_at: string;
  module: string;
}

export interface AttackChain {
  id: string;
  title: string;
  narrative: string;
  business_impact: string;
  nodes: { id: string; label: string; role: string; type: 'entry' | 'pivot' | 'impact' | 'actor' }[];
  edges: { source: string; target: string; label: string }[];
  severity: Severity;
}

export interface EvidenceEntry {
  id: string;
  finding_id: string;
  record_hash: string;
  prev_hash: string;
  timestamp: string;
  type: 'request_response' | 'screenshot' | 'log';
  integrity: 'VALID' | 'TAMPERED';
}

export interface ScoreHistory {
  date: string;
  score: number;
  grade: string;
  delta: number;
  confirmed_count: number;
}

export interface RoleMatrixEntry {
  endpoint: string;
  guest: 'ALLOWED' | 'DENIED' | 'ESCALATION';
  viewer: 'ALLOWED' | 'DENIED' | 'ESCALATION';
  analyst: 'ALLOWED' | 'DENIED' | 'ESCALATION';
  admin: 'ALLOWED' | 'DENIED' | 'ESCALATION';
}

export const findings: Finding[] = [
  {
    id: 'F-001',
    title: 'Reflected XSS in Search Parameter',
    severity: 'HIGH',
    status: 'CONFIRMED',
    lifecycle: 'OPEN',
    endpoint: '/dashboard?search=',
    cwe: 'CWE-79',
    owasp: 'A03:2021',
    cvss_score: 7.4,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N',
    business_impact: 'An attacker can inject malicious JavaScript into any analyst\'s browser session, steal session tokens, and gain full analyst-tier access to live monitoring data.',
    remediation: 'HTML-encode all user-supplied values before rendering. Use a CSP header with \'unsafe-inline\' removed. Validate and sanitise the `search` parameter server-side.',
    chain_id: 'AC-001',
    cert_in: 'CERT-In Advisory CI-24-0091',
    dpdp_relevant: true,
    discovered_at: '2024-11-28T09:12:00Z',
    module: 'Injection',
  },
  {
    id: 'F-002',
    title: 'IDOR on Telemetry Records',
    severity: 'HIGH',
    status: 'CONFIRMED',
    lifecycle: 'OPEN',
    endpoint: '/api/telemetry/{id}',
    cwe: 'CWE-639',
    owasp: 'A01:2021',
    cvss_score: 7.1,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
    business_impact: 'Any authenticated user can access telemetry records owned by other users by iterating numeric IDs, exposing potentially classified monitoring data.',
    remediation: 'Implement object-level authorisation. Check that the requesting user owns or has explicit permission to access the requested resource before returning it.',
    chain_id: 'AC-001',
    cert_in: 'CERT-In Advisory CI-24-0112',
    dpdp_relevant: true,
    discovered_at: '2024-11-28T09:18:00Z',
    module: 'Role Matrix',
  },
  {
    id: 'F-003',
    title: 'Admin Routes Accessible by Analyst Token',
    severity: 'CRITICAL',
    status: 'CONFIRMED',
    lifecycle: 'OPEN',
    endpoint: '/api/admin/*',
    cwe: 'CWE-285',
    owasp: 'A01:2021',
    cvss_score: 9.1,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
    business_impact: 'An analyst can perform every admin action — user management, configuration changes, data deletion — without any additional privilege escalation.',
    remediation: 'Add role-based middleware to all /api/admin/* routes. Return 403 for non-admin tokens. Add integration tests for each admin endpoint.',
    chain_id: 'AC-001',
    cert_in: 'CERT-In Advisory CI-24-0098',
    dpdp_relevant: false,
    discovered_at: '2024-11-28T09:31:00Z',
    module: 'Role Matrix',
  },
  {
    id: 'F-004',
    title: 'SQL Injection via Report Filter',
    severity: 'CRITICAL',
    status: 'CONFIRMED',
    lifecycle: 'IN_PROGRESS',
    endpoint: '/api/reports/filter',
    cwe: 'CWE-89',
    owasp: 'A03:2021',
    cvss_score: 9.8,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    business_impact: 'An unauthenticated attacker can read, modify, or delete all data from the monitoring database including user credentials and operational intelligence records.',
    remediation: 'Use parameterised queries or an ORM. Never concatenate user input into SQL strings. Add a WAF rule as a secondary defence.',
    cert_in: 'CERT-In Advisory CI-24-0101',
    dpdp_relevant: true,
    discovered_at: '2024-11-28T10:02:00Z',
    module: 'Injection',
  },
  {
    id: 'F-005',
    title: 'Debug Endpoint Exposes Environment Variables',
    severity: 'CRITICAL',
    status: 'CONFIRMED',
    lifecycle: 'OPEN',
    endpoint: '/api/debug/env',
    cwe: 'CWE-200',
    owasp: 'A05:2021',
    cvss_score: 9.1,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    business_impact: 'API keys, database credentials, and third-party service secrets are exposed to any unauthenticated request, enabling full system compromise.',
    remediation: 'Remove or disable the /api/debug/env endpoint entirely in production. Never expose environment variables through HTTP. Use secrets management (Vault, AWS Secrets Manager).',
    cert_in: 'CERT-In Advisory CI-24-0087',
    dpdp_relevant: true,
    discovered_at: '2024-11-28T10:15:00Z',
    module: 'Storage/Privacy',
  },
  {
    id: 'F-006',
    title: 'AI Summary Prompt Injection via Feed',
    severity: 'HIGH',
    status: 'CONFIRMED',
    lifecycle: 'OPEN',
    endpoint: '/api/summary/generate',
    cwe: 'CWE-77',
    owasp: 'A03:2021',
    cvss_score: 7.5,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N',
    business_impact: 'A threat actor can plant hidden text in a feed item that hijacks the AI summary generation, producing false intelligence reports delivered to analysts as trusted briefings.',
    remediation: 'Sanitise feed content before passing to the LLM. Use a system prompt boundary and user-content delimiter. Implement output validation to detect anomalous instructions.',
    chain_id: 'AC-002',
    cert_in: 'CERT-In Advisory CI-24-0145',
    dpdp_relevant: false,
    discovered_at: '2024-11-28T11:00:00Z',
    module: 'AI Prompt Injection',
  },
  {
    id: 'F-007',
    title: 'Session Token Non-Expiring',
    severity: 'HIGH',
    status: 'CONFIRMED',
    lifecycle: 'OPEN',
    endpoint: '/api/login',
    cwe: 'CWE-613',
    owasp: 'A07:2021',
    cvss_score: 6.5,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
    business_impact: 'A stolen session token provides permanent access with no expiry. Credential theft from any vector (XSS, shoulder surfing, log exposure) grants indefinite access.',
    remediation: 'Set JWT exp claim to ≤15 minutes for access tokens. Issue refresh tokens with idle timeout. Implement server-side session revocation.',
    cert_in: 'CERT-In Advisory CI-24-0078',
    dpdp_relevant: false,
    discovered_at: '2024-11-28T11:22:00Z',
    module: 'Session/Auth',
  },
  {
    id: 'F-008',
    title: 'Wildcard CORS Policy',
    severity: 'MEDIUM',
    status: 'CONFIRMED',
    lifecycle: 'OPEN',
    endpoint: 'All API routes',
    cwe: 'CWE-942',
    owasp: 'A05:2021',
    cvss_score: 5.3,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
    business_impact: 'Any origin can make credentialed cross-origin requests to the API, enabling CSRF-style attacks from attacker-controlled web pages.',
    remediation: 'Replace Access-Control-Allow-Origin: * with an explicit allowlist of trusted origins. Never combine * with Allow-Credentials: true.',
    cert_in: 'CERT-In Advisory CI-24-0083',
    dpdp_relevant: false,
    discovered_at: '2024-11-28T11:45:00Z',
    module: 'API Audit',
  },
  {
    id: 'F-009',
    title: 'Cookie Missing Security Attributes',
    severity: 'MEDIUM',
    status: 'CONFIRMED',
    lifecycle: 'OPEN',
    endpoint: 'Set-Cookie header',
    cwe: 'CWE-1004',
    owasp: 'A02:2021',
    cvss_score: 4.3,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N',
    business_impact: 'Session cookies without HttpOnly are readable by JavaScript (amplifies XSS impact). Without Secure flag, cookies transmit over HTTP. Without SameSite, CSRF is viable.',
    remediation: 'Add HttpOnly, Secure, and SameSite=Strict to all session cookies.',
    cert_in: 'CERT-In Advisory CI-24-0071',
    dpdp_relevant: false,
    discovered_at: '2024-11-28T12:00:00Z',
    module: 'Client/CSP',
  },
  {
    id: 'F-010',
    title: 'Hardcoded API Key in Mobile Client',
    severity: 'HIGH',
    status: 'CONFIRMED',
    lifecycle: 'OPEN',
    endpoint: 'mobile_stub/config.js',
    cwe: 'CWE-798',
    owasp: 'A02:2021',
    cvss_score: 7.5,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    business_impact: 'The API key embedded in the mobile bundle can be extracted from any distributed APK/IPA, granting backend API access without authentication.',
    remediation: 'Move API keys to a secure backend proxy. Use certificate pinning and runtime attestation. Never ship secrets in client bundles.',
    cert_in: 'CERT-In Advisory CI-24-0132',
    dpdp_relevant: true,
    discovered_at: '2024-11-28T12:30:00Z',
    module: 'Mobile',
  },
  {
    id: 'F-011',
    title: 'HTTP Transport Allowed (No HSTS)',
    severity: 'MEDIUM',
    status: 'CONFIRMED',
    lifecycle: 'OPEN',
    endpoint: 'Transport layer',
    cwe: 'CWE-311',
    owasp: 'A02:2021',
    cvss_score: 5.9,
    cvss_vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N',
    business_impact: 'Plaintext HTTP connections expose credentials, session tokens, and operational data to network-level interception on any untrusted network.',
    remediation: 'Redirect all HTTP to HTTPS with a 301. Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload header.',
    cert_in: 'CERT-In Advisory CI-24-0088',
    dpdp_relevant: false,
    discovered_at: '2024-11-28T13:00:00Z',
    module: 'Transport/TLS',
  },
  {
    id: 'F-012',
    title: 'Outdated Dependency with Known CVE',
    severity: 'HIGH',
    status: 'UNVERIFIED',
    lifecycle: 'OPEN',
    endpoint: 'requirements.txt: flask==2.0.1',
    cwe: 'CWE-1035',
    owasp: 'A06:2021',
    cvss_score: 7.5,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    business_impact: 'Flask 2.0.1 is affected by CVE-2023-30861 (cookie session disclosure). Upgrade is blocked pending integration test coverage.',
    remediation: 'Upgrade to Flask ≥2.3.2. Run pip-audit as a CI gate. Add Dependabot for automated PRs.',
    cert_in: 'CERT-In Advisory CI-24-0119',
    dpdp_relevant: false,
    discovered_at: '2024-11-28T13:45:00Z',
    module: 'Dependencies',
  },
];

export const attackChains: AttackChain[] = [
  {
    id: 'AC-001',
    title: 'Guest → Poisoned Feed → XSS → Token Theft → Admin Takeover',
    narrative: 'An unauthenticated attacker plants a malicious payload in /api/feed/ingest. When an analyst browses the dashboard, the XSS fires, exfiltrating the non-expiring session token stored in localStorage. The attacker then replays the token and accesses /api/admin/* — reachable without elevated privilege — achieving full platform takeover.',
    business_impact: 'Complete compromise of the World Monitor Lab platform. An adversary can read all operational intelligence, alter monitoring configurations, and cover their tracks by deleting audit logs.',
    severity: 'CRITICAL',
    nodes: [
      { id: 'n1', label: 'Attacker\n(Guest)', role: 'Unauthenticated actor', type: 'actor' },
      { id: 'n2', label: 'Feed Ingest\n/api/feed/ingest', role: 'F-005 · XSS payload planted', type: 'entry' },
      { id: 'n3', label: 'Analyst\nDashboard', role: 'XSS executes in browser', type: 'pivot' },
      { id: 'n4', label: 'Token in\nlocalStorage', role: 'F-007 · non-expiring token', type: 'pivot' },
      { id: 'n5', label: 'Admin API\n/api/admin/*', role: 'F-003 · no role check', type: 'impact' },
      { id: 'n6', label: 'Full Platform\nTakeover', role: 'Read / modify / delete all data', type: 'impact' },
    ],
    edges: [
      { source: 'n1', target: 'n2', label: 'injects payload' },
      { source: 'n2', target: 'n3', label: 'rendered by analyst' },
      { source: 'n3', target: 'n4', label: 'XSS reads token' },
      { source: 'n4', target: 'n5', label: 'replays token' },
      { source: 'n5', target: 'n6', label: 'unrestricted access' },
    ],
  },
  {
    id: 'AC-002',
    title: 'Feed Poisoning → AI Prompt Injection → False Intel Report',
    narrative: 'A feed item contains hidden prompt-injection text instructing the AI summary model to fabricate a threat intelligence briefing. Analysts receive AI-generated reports they trust as authoritative, leading to incorrect incident response decisions.',
    business_impact: 'Operational intelligence is compromised. Analysts may deprioritise or misclassify real threats. The platform\'s core value proposition — trusted threat summaries — is undermined.',
    severity: 'HIGH',
    nodes: [
      { id: 'n1', label: 'Attacker\n(Guest)', role: 'Unauthenticated actor', type: 'actor' },
      { id: 'n2', label: 'Feed Ingest\n/api/feed/ingest', role: 'Unsanitised content accepted', type: 'entry' },
      { id: 'n3', label: 'AI Summary\n/api/summary/generate', role: 'F-006 · no instruction boundary', type: 'pivot' },
      { id: 'n4', label: 'False Intel\nReport', role: 'Analyst trusts fabricated briefing', type: 'impact' },
    ],
    edges: [
      { source: 'n1', target: 'n2', label: 'plants hidden instruction' },
      { source: 'n2', target: 'n3', label: 'injected into LLM prompt' },
      { source: 'n3', target: 'n4', label: 'fabricated output delivered' },
    ],
  },
];

export const evidenceEntries: EvidenceEntry[] = [
  { id: 'E-001', finding_id: 'F-001', record_hash: 'a3f9c2e1b4d8f7a6c5e9d0b2f1a4c7e8b3d6f9a0c2e5b8d1f4a7c0e3b6d9f2', prev_hash: '0000000000000000000000000000000000000000000000000000000000000000', timestamp: '2024-11-28T09:12:00Z', type: 'request_response', integrity: 'VALID' },
  { id: 'E-002', finding_id: 'F-001', record_hash: 'b7e4d1c8f5a2e9d6c3b0f7a4d1e8c5b2f9a6d3e0c7b4f1a8e5d2c9b6f3a0e7', prev_hash: 'a3f9c2e1b4d8f7a6c5e9d0b2f1a4c7e8b3d6f9a0c2e5b8d1f4a7c0e3b6d9f2', timestamp: '2024-11-28T09:12:05Z', type: 'screenshot', integrity: 'VALID' },
  { id: 'E-003', finding_id: 'F-002', record_hash: 'c9b6f3a0e7d4c1b8f5a2e9d6c3b0f7a4d1e8c5b2f9a6d3e0c7b4f1a8e5d2c9', prev_hash: 'b7e4d1c8f5a2e9d6c3b0f7a4d1e8c5b2f9a6d3e0c7b4f1a8e5d2c9b6f3a0e7', timestamp: '2024-11-28T09:18:00Z', type: 'request_response', integrity: 'VALID' },
  { id: 'E-004', finding_id: 'F-003', record_hash: 'd1e8c5b2f9a6d3e0c7b4f1a8e5d2c9b6f3a0e7d4c1b8f5a2e9d6c3b0f7a4d1', prev_hash: 'c9b6f3a0e7d4c1b8f5a2e9d6c3b0f7a4d1e8c5b2f9a6d3e0c7b4f1a8e5d2c9', timestamp: '2024-11-28T09:31:00Z', type: 'request_response', integrity: 'VALID' },
  { id: 'E-005', finding_id: 'F-004', record_hash: 'e5d2c9b6f3a0e7d4c1b8f5a2e9d6c3b0f7a4d1e8c5b2f9a6d3e0c7b4f1a8e5', prev_hash: 'd1e8c5b2f9a6d3e0c7b4f1a8e5d2c9b6f3a0e7d4c1b8f5a2e9d6c3b0f7a4d1', timestamp: '2024-11-28T10:02:00Z', type: 'request_response', integrity: 'VALID' },
  { id: 'E-006', finding_id: 'F-005', record_hash: 'f9a6d3e0c7b4f1a8e5d2c9b6f3a0e7d4c1b8f5a2e9d6c3b0f7a4d1e8c5b2f9', prev_hash: 'e5d2c9b6f3a0e7d4c1b8f5a2e9d6c3b0f7a4d1e8c5b2f9a6d3e0c7b4f1a8e5', timestamp: '2024-11-28T10:15:00Z', type: 'request_response', integrity: 'VALID' },
];

export const scoreHistory: ScoreHistory[] = [
  { date: 'Nov 21', score: 82, grade: 'B', delta: 0, confirmed_count: 3 },
  { date: 'Nov 22', score: 74, grade: 'C', delta: -8, confirmed_count: 5 },
  { date: 'Nov 23', score: 74, grade: 'C', delta: 0, confirmed_count: 5 },
  { date: 'Nov 24', score: 68, grade: 'C', delta: -6, confirmed_count: 7 },
  { date: 'Nov 25', score: 52, grade: 'D', delta: -16, confirmed_count: 9 },
  { date: 'Nov 26', score: 52, grade: 'D', delta: 0, confirmed_count: 9 },
  { date: 'Nov 27', score: 47, grade: 'D', delta: -5, confirmed_count: 10 },
  { date: 'Nov 28', score: 31, grade: 'F', delta: -16, confirmed_count: 12 },
];

export const roleMatrix: RoleMatrixEntry[] = [
  { endpoint: 'GET /api/telemetry/{id}', guest: 'DENIED', viewer: 'ALLOWED', analyst: 'ESCALATION', admin: 'ALLOWED' },
  { endpoint: 'POST /api/reports/filter', guest: 'DENIED', viewer: 'DENIED', analyst: 'ALLOWED', admin: 'ALLOWED' },
  { endpoint: 'GET /api/admin/users', guest: 'DENIED', viewer: 'DENIED', analyst: 'ESCALATION', admin: 'ALLOWED' },
  { endpoint: 'POST /api/admin/config', guest: 'DENIED', viewer: 'DENIED', analyst: 'ESCALATION', admin: 'ALLOWED' },
  { endpoint: 'DELETE /api/admin/logs', guest: 'DENIED', viewer: 'DENIED', analyst: 'ESCALATION', admin: 'ALLOWED' },
  { endpoint: 'GET /api/users', guest: 'DENIED', viewer: 'ALLOWED', analyst: 'ALLOWED', admin: 'ALLOWED' },
  { endpoint: 'GET /api/debug/env', guest: 'ALLOWED', viewer: 'ALLOWED', analyst: 'ALLOWED', admin: 'ALLOWED' },
  { endpoint: 'POST /api/feed/ingest', guest: 'ALLOWED', viewer: 'ALLOWED', analyst: 'ALLOWED', admin: 'ALLOWED' },
  { endpoint: 'GET /api/summary/generate', guest: 'DENIED', viewer: 'ALLOWED', analyst: 'ALLOWED', admin: 'ALLOWED' },
  { endpoint: 'GET /api/login', guest: 'ALLOWED', viewer: 'ALLOWED', analyst: 'ALLOWED', admin: 'ALLOWED' },
];

export const currentScore = 31;
export const currentGrade = 'F';

export function getSeverityCount() {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  findings.filter(f => f.status === 'CONFIRMED').forEach(f => counts[f.severity]++);
  return counts;
}
