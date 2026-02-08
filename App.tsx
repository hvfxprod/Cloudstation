import React, { useState, useEffect } from 'react';
import Desktop from './components/Desktop';
import WindowManager from './components/WindowManager';
import StartMenu from './components/StartMenu';
import WidgetStack from './components/WidgetStack';
import LoginScreen from './components/LoginScreen';
import Toast from './components/Toast';
import { useOSStore } from './store';
import { getDesktopBackgroundStyle, getOverlayOpacity } from './lib/customization';

const App: React.FC = () => {
  const theme = useOSStore((s) => s.theme);
  const background = useOSStore((s) => s.background);
  const backgroundCustomUrl = useOSStore((s) => s.backgroundCustomUrl);
  const resolvedTheme = theme === 'dynamic' ? (typeof window !== 'undefined' && window.matchMedia?.('(prefers-color-scheme: dark)')?.matches ? 'dark' : 'light') : theme;
  const overlayClass = getOverlayOpacity(resolvedTheme);
  const backgroundStyle = getDesktopBackgroundStyle(background, backgroundCustomUrl);

  const [authChecked, setAuthChecked] = useState(false);
  const [loggedIn, setLoggedIn] = useState(true);
  const [authEnabled, setAuthEnabled] = useState(false);
  const [passwordSet, setPasswordSet] = useState(true);

  useEffect(() => {
    let cancelled = false;
    fetch('/api/auth/status', { credentials: 'include' })
      .then((res) => res.json())
      .then((data) => {
        if (cancelled) return;
        setAuthEnabled(Boolean(data.authEnabled));
        setPasswordSet(Boolean(data.passwordSet));
        setLoggedIn(Boolean(data.loggedIn));
      })
      .catch(() => {
        if (!cancelled) setLoggedIn(true);
      })
      .finally(() => {
        if (!cancelled) setAuthChecked(true);
      });
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    let cancelled = false;
    fetch('/api/settings/general', { credentials: 'include' })
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (!cancelled && data) {
          if (data.timezone) useOSStore.getState().setTimezone(data.timezone);
          if (data.language) useOSStore.getState().setLanguage(data.language);
        }
      })
      .catch(() => {});
    return () => { cancelled = true; };
  }, []);

  if (!authChecked) {
    return (
      <div className="h-screen w-screen flex items-center justify-center bg-slate-100 dark:bg-slate-900" style={backgroundStyle} data-theme={resolvedTheme}>
        <div className="text-slate-500 dark:text-slate-400">Loading…</div>
      </div>
    );
  }

  if (authEnabled && !loggedIn) {
    return (
      <LoginScreen
        mode="login"
        onSuccess={() => setLoggedIn(true)}
        authEnabled={authEnabled}
        passwordSet={passwordSet}
      />
    );
  }

  return (
    <div
      className="h-screen w-screen relative overflow-hidden transition-[background] duration-300"
      style={backgroundStyle}
      data-theme={resolvedTheme}
    >
      <div className={`absolute inset-0 pointer-events-none ${overlayClass}`} />

      {/* Desktop Icons */}
      <Desktop />
      
      {/* Active Application Windows */}
      <WindowManager />
      
      {/* Mini Widget Stack (Right Side) */}
      <WidgetStack />
      
      {/* Start Menu Overlay */}
      <StartMenu />

      {/* Toast (e.g. share link created) */}
      <Toast />
    </div>
  );
};

export default App;
