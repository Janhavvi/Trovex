import { useState, type FormEvent } from 'react';
import AuthLayout from './AuthLayout';

type SignUpProps = {
  onSignUp: (input: { name: string; email: string; password: string; role: string; termsAccepted: boolean }) => Promise<void>;
  onNavigateLogin: () => void;
};

const passwordChecks = [
  { label: 'At least 12 characters', test: (value: string) => value.length >= 12 },
  { label: 'Uppercase and lowercase letters', test: (value: string) => /[A-Z]/.test(value) && /[a-z]/.test(value) },
  { label: 'At least one number', test: (value: string) => /\d/.test(value) },
  { label: 'At least one special character', test: (value: string) => /[^A-Za-z0-9]/.test(value) },
];

export default function SignUp({ onSignUp, onNavigateLogin }: SignUpProps) {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [role, setRole] = useState('SECURITY_ANALYST');
  const [termsAccepted, setTermsAccepted] = useState(false);
  const [passwordVisible, setPasswordVisible] = useState(false);
  const [confirmationVisible, setConfirmationVisible] = useState(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const passedChecks = passwordChecks.filter((check) => check.test(password)).length;
  const strength = passedChecks === 4 ? 'Strong' : passedChecks >= 2 ? 'Medium' : password ? 'Weak' : '';

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError(null);
    const cleanName = name.trim();
    const cleanEmail = email.trim().toLowerCase();
    if (cleanName.length < 2 || cleanName.length > 100) return setError('Enter your name (2 to 100 characters).');
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) return setError('Please enter a valid email address.');
    if (passedChecks !== 4) return setError('Choose a stronger password that meets every requirement.');
    if (password !== confirmation) return setError('Passwords do not match.');
    if (!termsAccepted) return setError('Accept the Terms of Service and Privacy Policy to continue.');

    setPending(true);
    try {
      await onSignUp({ name: cleanName, email: cleanEmail, password, role, termsAccepted });
    } catch (signupError) {
      setError(signupError instanceof TypeError
        ? 'Unable to connect to the Trovex server. Check your connection and try again.'
        : signupError instanceof Error ? signupError.message : 'Something went wrong while creating your account. Please try again.');
    } finally {
      setPending(false);
    }
  };

  return (
    <AuthLayout mode="signup">
      <div className="auth-eyebrow">NEW WORKSPACE ACCESS</div>
      <h2 className="auth-title">Create your Trovex account</h2>
      <p className="auth-subtitle">Start building an evidence-first security assessment workflow.</p>

      <form onSubmit={submit} noValidate>
        <label className="auth-label" htmlFor="signup-name">Full Name</label>
        <input id="signup-name" className="auth-input" autoComplete="name" maxLength={100} required value={name} onChange={(event) => setName(event.target.value)} />

        <label className="auth-label" htmlFor="signup-email">Email Address</label>
        <input id="signup-email" className="auth-input" type="email" autoComplete="email" maxLength={254} required value={email} onChange={(event) => setEmail(event.target.value)} />

        <label className="auth-label" htmlFor="signup-password">Password</label>
        <div className="auth-password-wrap">
          <input id="signup-password" className="auth-input" type={passwordVisible ? 'text' : 'password'} autoComplete="new-password" maxLength={128} required value={password} onChange={(event) => setPassword(event.target.value)} aria-describedby="password-strength password-rules" />
          <button className="auth-password-toggle" type="button" onClick={() => setPasswordVisible((visible) => !visible)} aria-label={passwordVisible ? 'Hide password' : 'Show password'}>{passwordVisible ? 'Hide' : 'Show'}</button>
        </div>
        <div id="password-strength" className="auth-strength-row" aria-live="polite">
          <span>Password strength {strength && <strong>{strength}</strong>}</span>
          <span className="auth-strength-bars" aria-hidden="true">{passwordChecks.map((check, index) => <i key={check.label} className={index < passedChecks ? 'auth-strength-filled' : ''} />)}</span>
        </div>
        <ul id="password-rules" className="auth-password-rules">
          {passwordChecks.map((check) => <li key={check.label} className={check.test(password) ? 'auth-rule-valid' : ''}>{check.test(password) ? '✓' : '·'} {check.label}</li>)}
        </ul>

        <label className="auth-label" htmlFor="signup-confirm">Confirm Password</label>
        <div className="auth-password-wrap">
          <input id="signup-confirm" className="auth-input" type={confirmationVisible ? 'text' : 'password'} autoComplete="new-password" maxLength={128} required value={confirmation} onChange={(event) => setConfirmation(event.target.value)} />
          <button className="auth-password-toggle" type="button" onClick={() => setConfirmationVisible((visible) => !visible)} aria-label={confirmationVisible ? 'Hide confirmation password' : 'Show confirmation password'}>{confirmationVisible ? 'Hide' : 'Show'}</button>
        </div>

        <label className="auth-label" htmlFor="signup-role">Role</label>
        <select id="signup-role" className="auth-input auth-select" value={role} onChange={(event) => setRole(event.target.value)}>
          <option value="SECURITY_ANALYST">Security Analyst</option>
          <option value="VIEWER">Viewer</option>
        </select>

        <label className="auth-terms">
          <input type="checkbox" checked={termsAccepted} onChange={(event) => setTermsAccepted(event.target.checked)} />
          <span>I agree to the Terms of Service and Privacy Policy.</span>
        </label>

        {error && <div className="auth-error" role="alert">{error}{error.includes('already exists') && <button type="button" onClick={onNavigateLogin}>Sign in instead</button>}</div>}
        <button className="auth-submit" type="submit" disabled={pending}>{pending ? 'CREATING ACCOUNT…' : 'CREATE ACCOUNT'}</button>
      </form>

      <p className="auth-footer">Already have an account? <a href="/login" onClick={(event) => { event.preventDefault(); onNavigateLogin(); }}>Sign in</a></p>
    </AuthLayout>
  );
}
