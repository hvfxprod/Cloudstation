
import React from 'react';
import Desktop from './components/Desktop';
import WindowManager from './components/WindowManager';
import StartMenu from './components/StartMenu';
import WidgetStack from './components/WidgetStack';

const App: React.FC = () => {
  return (
    <div className="h-screen w-screen relative overflow-hidden bg-[url('https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?auto=format&fit=crop&q=80&w=2564')] bg-cover bg-center">
      {/* Background overlay for better contrast */}
      <div className="absolute inset-0 bg-black/10 pointer-events-none" />

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
