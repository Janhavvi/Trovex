import type { ReactNode } from 'react';

export default function AuthLayout({ children, mode }: { children: ReactNode; mode: 'login' | 'signup' }) {
  return (
    <main className="auth-shell">
      <section className="auth-brand" aria-label="Trovex security assessment platform">
        <div className="auth-branding">
          <div className="auth-mark" aria-hidden="true">T</div>
          <div>
            <div className="auth-wordmark">TROVEX</div>
            <div className="auth-tagline">SAFE. PROVEN. FIXED.</div>
          </div>
        </div>
        <div className="auth-brand-copy">
          <div className="auth-eyebrow">SECURITY ASSESSMENT PLATFORM</div>
          <h1>Find the signal.<br />Prove what matters.</h1>
          <p>Evidence-first security assessment for discovering, validating, fixing, and re-testing security findings.</p>
        </div>
        <ol className="auth-workflow" aria-label="Trovex assessment workflow">
          {['Discover', 'Validate', 'Prove', 'Fix', 'Re-test'].map((step, index) => (
            <li key={step} className={index === (mode === 'login' ? 0 : 1) ? 'auth-workflow-active' : ''}>
              <span className="auth-workflow-node" aria-hidden="true">{String(index + 1).padStart(2, '0')}</span>
              <span>{step}</span>
            </li>
          ))}
        </ol>
        <div className="auth-brand-foot">SIH26163 <span>·</span> LAB-FIRST SECURITY</div>
      </section>
      <section className="auth-main" aria-label={mode === 'login' ? 'Sign in' : 'Create account'}>
        <div className="auth-card">{children}</div>
      </section>
    </main>
  );
}
