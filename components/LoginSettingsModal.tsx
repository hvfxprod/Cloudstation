import React, { useState, useEffect } from 'react';
import { createPortal } from 'react-dom';
import { Lock, X } from 'lucide-react';
import { useOSStore } from '../store';

interface LoginSettingsModalProps {
  onClose: () => void;
}

const LoginSettingsModal: React.FC<LoginSettingsModalProps> = ({ onClose }) => {
  const { addNotification } = useOSStore();
  const [authEnabled, setAuthEnabled] = useState(false);
  const [passwordSet, setPasswordSet] = useState(true);
  const [loading, setLoading] = useState(true);
  const [showSetPassword, setShowSetPassword] = useState(false);
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    let cancelled = false;
    fetch('/api/auth/status', { credentials: 'include' })
      .then((res) => res.json())
      .then((data) => {
        if (cancelled) return;
        setAuthEnabled(Boolean(data.authEnabled));
        setPasswordSet(Boolean(data.passwordSet));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => { cancelled = true; };
  }, []);

  const handleToggleLogin = async () => {
    if (authEnabled) {
      try {
        const res = await fetch('/api/auth/config', {
          method: 'PUT',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ enabled: false }),
        });
        if (!res.ok) throw new Error();
        setAuthEnabled(false);
        addNotification('Login disabled', 'CloudStation is open to everyone.', 'success');
      } catch {
        addNotification('Error', 'Failed to disable login.', 'error');
      }
    } else {
      setShowSetPassword(true);
    }
  };

  const handleSetPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (newPassword.length < 6) {
      setError('Password must be at least 6 characters.');
      return;
    }
    if (newPassword !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }
    setSaving(true);
    try {
      const res = await fetch('/api/auth/setup', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ newPassword }),
      });
      const d = await res.json().catch(() => ({}));
      if (res.ok && d.ok) {
        setAuthEnabled(true);
        setPasswordSet(true);
        setShowSetPassword(false);
        setNewPassword('');
        setConfirmPassword('');
        addNotification('Login required', 'Sign-in is now required to use CloudStation.', 'success');
      } else {
        setError(d.error || 'Failed to save.');
      }
    } catch {
      setError('Network error.');
    }
    setSaving(false);
  };

  const content = (
    <div
      className="fixed inset-0 z-[11000] flex items-center justify-center p-4"
      style={{ minWidth: '100vw', minHeight: '100dvh', backgroundColor: 'rgba(0,0,0,0.5)' }}
      onClick={onClose}
    >
      <div
        className="bg-white dark:bg-slate-800 rounded-2xl shadow-xl max-w-md w-full p-6 border border-slate-200 dark:border-slate-700"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-xl font-bold text-slate-800 dark:text-slate-100 flex items-center gap-2">
            <Lock size={22} /> Require login
          </h2>
          <button
            type="button"
            onClick={onClose}
            className="p-2 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-700 text-slate-600 dark:text-slate-400"
            aria-label="Close"
          >
            <X size={20} />
          </button>
        </div>

        {loading ? (
          <p className="text-slate-500 dark:text-slate-400 text-sm">Loading…</p>
        ) : showSetPassword ? (
          <form onSubmit={handleSetPassword}>
            <p className="text-sm text-slate-600 dark:text-slate-400 mb-4">
              Enter the password to use when signing in to CloudStation (min 6 characters).
            </p>
            <input
              type="password"
              value={newPassword}
              onChange={(e) => { setNewPassword(e.target.value); setError(''); }}
              placeholder="New password (min 6 characters)"
              className="w-full px-4 py-2 border border-slate-200 dark:border-slate-600 rounded-lg text-sm mb-2 bg-white dark:bg-slate-700 text-slate-900 dark:text-slate-100"
            />
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => { setConfirmPassword(e.target.value); setError(''); }}
              placeholder="Confirm password"
              className="w-full px-4 py-2 border border-slate-200 dark:border-slate-600 rounded-lg text-sm mb-2 bg-white dark:bg-slate-700 text-slate-900 dark:text-slate-100"
            />
            {error && <p className="text-sm text-red-600 dark:text-red-400 mb-2">{error}</p>}
            <div className="flex gap-2 justify-end mt-4">
              <button
                type="button"
                onClick={() => { setShowSetPassword(false); setError(''); setNewPassword(''); setConfirmPassword(''); }}
                className="px-4 py-2 rounded-lg border border-slate-200 dark:border-slate-600 text-sm font-medium text-slate-700 dark:text-slate-300"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={saving}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700 disabled:opacity-50"
              >
                {saving ? 'Saving…' : authEnabled ? 'Change password' : 'Enable & require login'}
              </button>
            </div>
          </form>
        ) : (
          <>
            <p className="text-sm text-slate-600 dark:text-slate-400 mb-4">
              {authEnabled
                ? 'Sign-in is required to use CloudStation.'
                : 'Require sign-in to use CloudStation? When enabled, users must enter a password to access.'}
            </p>
            <label className="flex items-center gap-3 cursor-pointer">
              <span className="text-sm font-medium text-slate-700 dark:text-slate-300">
                Require login to use CloudStation
              </span>
              <button
                type="button"
                role="switch"
                aria-checked={authEnabled}
                className={`relative inline-flex h-6 w-11 flex-shrink-0 rounded-full border-2 border-transparent transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 ${authEnabled ? 'bg-blue-600' : 'bg-slate-200 dark:bg-slate-600'}`}
                onClick={handleToggleLogin}
              >
                <span
                  className={`pointer-events-none inline-block h-5 w-5 rounded-full bg-white shadow ring-0 transition-transform ${authEnabled ? 'translate-x-5' : 'translate-x-1'}`}
                />
              </button>
              <span className="text-sm text-slate-500 dark:text-slate-400">{authEnabled ? 'Yes' : 'No'}</span>
            </label>
            {authEnabled && passwordSet && (
              <button
                type="button"
                onClick={() => setShowSetPassword(true)}
                className="mt-4 text-sm font-medium text-blue-600 dark:text-blue-400 hover:underline"
              >
                Change password
              </button>
            )}
          </>
        )}
      </div>
    </div>
  );

  return createPortal(content, document.body);
};

export default LoginSettingsModal;
