import { useState } from 'react';
import { useAuth } from '../lib/auth';
import { Lock, AlertCircle } from 'lucide-react';

export default function LoginPage() {
  const { login } = useAuth();
  const [key, setKey] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!key.trim()) { setError('Please enter an API key'); return; }
    setLoading(true);
    setError('');
    try {
      await login(key.trim());
    } catch {
      setError('Invalid API key. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-surface flex items-center justify-center p-4">
      <div className="w-full max-w-sm">
        {/* Logo */}
        <div className="flex flex-col items-center mb-8">
          <div className="w-12 h-12 bg-accent rounded-xl flex items-center justify-center mb-4">
            <span className="text-bg-primary font-bold text-xl">S</span>
          </div>
          <h1 className="text-xl font-bold">suppline</h1>
          <p className="text-sm text-text-secondary mt-1">Container Image Security Gateway</p>
        </div>

        {/* Card */}
        <div className="bg-bg-primary border border-border rounded-xl p-6">
          <div className="flex items-center gap-2 mb-4">
            <Lock className="w-4 h-4 text-text-secondary" />
            <h2 className="text-sm font-semibold">API Authentication</h2>
          </div>
          <p className="text-xs text-text-secondary mb-5">Enter your API key to access the dashboard.</p>

          <form onSubmit={handleSubmit} className="space-y-4">
            <input
              type="password"
              value={key}
              onChange={e => setKey(e.target.value)}
              placeholder="Enter API key"
              autoFocus
              className="w-full px-3 py-2.5 bg-bg-secondary border border-border rounded-lg text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent/50 focus:ring-1 focus:ring-accent/20 transition-colors"
            />
            {error && (
              <div className="flex items-center gap-2 text-danger text-xs">
                <AlertCircle className="w-3.5 h-3.5" />
                {error}
              </div>
            )}
            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 bg-accent text-bg-primary rounded-lg text-sm font-medium hover:bg-accent-hover disabled:opacity-50 transition-colors"
            >
              {loading ? 'Authenticating…' : 'Sign in'}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
