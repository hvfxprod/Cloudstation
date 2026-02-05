
import React from 'react';
import WidgetClock from './widgets/WidgetClock';
import WidgetResources from './widgets/WidgetResources';
import WidgetNotifications from './widgets/WidgetNotifications';

const WidgetStack: React.FC = () => {
  return (
    <div className="absolute bottom-0 left-0 right-0 w-full md:top-0 md:right-0 md:bottom-0 md:left-auto md:w-80 p-4 flex flex-col gap-4 z-[5000] pointer-events-none overflow-hidden">
      <div className="flex-1 flex flex-col gap-3 md:gap-4 pointer-events-auto overflow-y-auto no-scrollbar py-2 max-h-[40vh] md:max-h-none">
        {/* Clock is always visible */}
        <WidgetClock />
        
        {/* Resources and Notifications are only visible on tablet/desktop (md and up) */}
        <div className="hidden md:flex flex-col gap-4">
          <WidgetResources />
          <WidgetNotifications />
        </div>
      </div>

      {/* Bottom area spacer */}
      <div className="h-4 md:h-14 pointer-events-none" />
    </div>
  );
};

export default WidgetStack;
