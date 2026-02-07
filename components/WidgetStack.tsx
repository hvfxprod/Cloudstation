import React from 'react';
import { LogOut } from 'lucide-react';
import WidgetClock from './widgets/WidgetClock';
import WidgetResources from './widgets/WidgetResources';
import WidgetNotifications from './widgets/WidgetNotifications';

const WidgetStack: React.FC = () => {
  return (
    <div className="absolute bottom-0 left-0 right-0 w-full md:top-0 md:right-0 md:bottom-0 md:left-auto md:w-80 p-4 flex flex-col gap-4 z-[5000] pointer-events-none overflow-hidden">
      <div className="flex-1 flex flex-col gap-3 md:gap-4 pointer-events-auto overflow-y-auto no-scrollbar py-2 max-h-[40vh] md:max-h-none">
        <WidgetClock />
        <div className="hidden md:flex flex-col gap-4">
          <WidgetResources />
          <WidgetNotifications />
        </div>
        {/* Logout — right below clock (mobile) or below notification dashboard (desktop) */}
        <button
          type="button"
          onClick={async () => {
            try {
              await fetch('/api/auth/logout', { method: 'POST', credentials: 'include' });
              window.location.reload();
            } catch {
              window.location.reload();
            }
          }}
          className="w-full flex items-center justify-center gap-2 py-2.5 rounded-[1.5rem] md:rounded-[2rem] bg-blue-500/90 hover:bg-blue-600 text-white text-sm font-medium transition-colors border border-blue-400/50 shadow-xl shrink-0"
          title="Log out"
        >
          <LogOut size={16} />
          Logout
        </button>
      </div>
      <div className="h-4 md:h-8 pointer-events-none" />
    </div>
  );
};

export default WidgetStack;
