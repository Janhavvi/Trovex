const mobileFindings = [
  {
    id: 'MOB-001',
    title: 'Hardcoded API Key',
    file: 'mobile_stub/config.js:14',
    snippet: 'const API_KEY = "sk-lab-9a2f8e1c4b7d0e3a6f5c8b2e1d4a7f0c";',
    severity: 'HIGH',
    detail: 'The API key is embedded in the client bundle. Any user with the APK can extract it via apktool or jadx.',
    fix: 'Move to a secure backend proxy. Use Android Keystore / iOS Secure Enclave for runtime secrets.',
  },
  {
    id: 'MOB-002',
    title: 'Cleartext Traffic Allowed',
    file: 'mobile_stub/AndroidManifest.xml:8',
    snippet: '<uses-permission android:name="android.permission.INTERNET"/>\nandroid:usesCleartextTraffic="true"',
    severity: 'MEDIUM',
    detail: 'The app permits unencrypted HTTP connections, allowing traffic to be intercepted on local networks.',
    fix: 'Set android:usesCleartextTraffic="false" and add a Network Security Config restricting plaintext.',
  },
  {
    id: 'MOB-003',
    title: 'Token Stored in SharedPreferences Plaintext',
    file: 'mobile_stub/AuthManager.js:31',
    snippet: 'await AsyncStorage.setItem("auth_token", token);',
    severity: 'MEDIUM',
    detail: 'Authentication tokens stored in AsyncStorage / SharedPreferences are readable on rooted devices without any encryption.',
    fix: 'Use react-native-keychain or Android EncryptedSharedPreferences to store tokens under hardware-backed keys.',
  },
  {
    id: 'MOB-004',
    title: 'Exported Activity Without Permission',
    file: 'mobile_stub/AndroidManifest.xml:22',
    snippet: '<activity android:name=".DeepLinkActivity" android:exported="true"/>',
    severity: 'LOW',
    detail: 'The DeepLinkActivity is exported without a required permission, allowing other apps to trigger it with crafted intents.',
    fix: 'Add android:exported="false" or define a custom android:permission for the activity.',
  },
];

const severityColors: Record<string, string> = {
  HIGH: '#ff6b2b', MEDIUM: '#ffc107', LOW: '#00d4ff', CRITICAL: '#ff3b3b',
};

export default function Mobile() {
  return (
    <div style={{ padding: 24 }}>
      <div style={{ marginBottom: 20 }}>
        <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#3d5470', letterSpacing: 2, textTransform: 'uppercase', marginBottom: 4 }}>
          Static analysis · mobile_stub/
        </div>
        <h1 style={{ margin: 0, fontSize: 20, fontWeight: 600, color: '#e2eaf6' }}>Mobile Module</h1>
      </div>

      {/* Overview bar */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10, marginBottom: 20 }}>
        {[
          { label: 'Files Scanned', value: 12, color: '#6b8aac' },
          { label: 'High', value: 1, color: '#ff6b2b' },
          { label: 'Medium', value: 2, color: '#ffc107' },
          { label: 'Low', value: 1, color: '#00d4ff' },
        ].map(s => (
          <div key={s.label} style={{ background: '#0d1520', border: '1px solid #1e2f46', borderRadius: 8, padding: '12px 14px' }}>
            <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#3d5470', marginBottom: 4 }}>{s.label}</div>
            <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 24, fontWeight: 700, color: s.color }}>{s.value}</div>
          </div>
        ))}
      </div>

      {/* Findings */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        {mobileFindings.map(f => (
          <div key={f.id} style={{ background: '#0d1520', border: '1px solid #1e2f46', borderRadius: 8, overflow: 'hidden' }}>
            <div style={{ padding: '12px 16px', borderBottom: '1px solid #1e2f46', display: 'flex', alignItems: 'center', gap: 10 }}>
              <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#3d5470' }}>{f.id}</span>
              <span style={{
                fontFamily: 'JetBrains Mono, monospace', fontSize: 9,
                color: severityColors[f.severity], background: `${severityColors[f.severity]}18`,
                border: `1px solid ${severityColors[f.severity]}44`, borderRadius: 3, padding: '2px 6px',
              }}>
                {f.severity}
              </span>
              <span style={{ fontSize: 13, fontWeight: 600, color: '#e2eaf6' }}>{f.title}</span>
              <span style={{ marginLeft: 'auto', fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#6b8aac' }}>{f.file}</span>
            </div>
            <div style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>
              <pre style={{
                margin: 0, padding: '10px 12px',
                fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: '#00d4ff',
                background: '#080c14', border: '1px solid #1e2f46', borderRadius: 4,
                overflowX: 'auto', lineHeight: 1.6,
              }}>
                {f.snippet}
              </pre>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <div>
                  <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#3d5470', marginBottom: 4 }}>DETAIL</div>
                  <div style={{ fontSize: 12, color: '#a0b8d4', lineHeight: 1.6 }}>{f.detail}</div>
                </div>
                <div>
                  <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#00e676', marginBottom: 4 }}>FIX</div>
                  <div style={{ fontSize: 12, color: '#a0b8d4', lineHeight: 1.6 }}>{f.fix}</div>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
