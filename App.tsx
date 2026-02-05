import React from 'react';
import Desktop from './components/Desktop';
import WindowManager from './components/WindowManager';
import StartMenu from './components/StartMenu';
import WidgetStack from './components/WidgetStack';
import { useOSStore } from './store';
import { getDesktopBackgroundStyle, getOverlayOpacity } from './lib/customization';

const App: React.FC = () => {
  const theme = useOSStore((s) => s.theme);
  const background = useOSStore((s) => s.background);
  const backgroundCustomUrl = useOSStore((s) => s.backgroundCustomUrl);
  const resolvedTheme = theme === 'dynamic' ? (typeof window !== 'undefined' && window.matchMedia?.('(prefers-color-scheme: dark)')?.matches ? 'dark' : 'light') : theme;
  const overlayClass = getOverlayOpacity(resolvedTheme);
  const backgroundStyle = getDesktopBackgroundStyle(background, backgroundCustomUrl);

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
    </div>
  );
};

export default App;
