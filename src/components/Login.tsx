import { useState, type FormEvent } from 'react';
import AuthLayout from './AuthLayout';

type LoginProps = {
  onLogin: (username: string, password: string, remember: boolean) => Promise<void>;
  onNavigateSignup: () => void;
};

export default function Login({ onLogin, onNavigateSignup }: LoginProps) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [remember, setRemember] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setPending(true);
    setError(null);
    try {
      await onLogin(username.trim(), password, remember);
    } catch (loginError) {
      setError(loginError instanceof TypeError
        ? 'Unable to connect to the Trovex server. Check your connection and try again.'
        : loginError instanceof Error ? loginError.message : 'Something went wrong. Please try again.');
    } finally {
      setPending(false);
    }
  };

  return (
    <AuthLayout mode="login">
      <div className="auth-eyebrow">SECURE WORKSPACE ACCESS</div>
      <h2 className="auth-title">Welcome back</h2>
      <p className="auth-subtitle">Sign in to continue to your Trovex security workspace.</p>

      <form onSubmit={submit} noValidate>
        <label className="auth-label" htmlFor="login-username">Email Address or Username</label>
        <input id="login-username" className="auth-input" autoComplete="username" required value={username} onChange={(event) => setUsername(event.target.value)} />

        <label className="auth-label" htmlFor="login-password">Password</label>
        <div className="auth-password-wrap">
          <input id="login-password" className="auth-input" type={showPassword ? 'text' : 'password'} autoComplete="current-password" required value={password} onChange={(event) => setPassword(event.target.value)} />
          <button className="auth-password-toggle" type="button" onClick={() => setShowPassword((visible) => !visible)} aria-label={showPassword ? 'Hide password' : 'Show password'}>{showPassword ? 'Hide' : 'Show'}</button>
        </div>

        <div className="auth-login-options">
          <label className="auth-remember"><input type="checkbox" checked={remember} onChange={(event) => setRemember(event.target.checked)} /> Remember me</label>
        </div>
        {error && <div className="auth-error" role="alert">{error}</div>}
        <button className="auth-submit" type="submit" disabled={pending}>{pending ? 'SIGNING IN…' : 'SIGN IN'}</button>
      </form>

      <p className="auth-footer">Don’t have an account? <a href="/signup" onClick={(event) => { event.preventDefault(); onNavigateSignup(); }}>Create account</a></p>
    </AuthLayout>
  );
}
