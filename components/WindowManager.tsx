
import React from 'react';
import { useOSStore } from '../store';
import Window from './Window';
import FileExplorer from './apps/FileExplorer';
import AISearch from './apps/AISearch';
import SharedLinks from './apps/SharedLinks';
import ControlPanel from './apps/ControlPanel';
import { Settings as SettingsIcon } from 'lucide-react';

const WindowManager: React.FC = () => {
  const windows = useOSStore((state) => state.windows);

  const renderAppContent = (id: string) => {
    switch (id) {
      case 'file-explorer':
        return <FileExplorer />;
      case 'ai-assistant':
        return <AISearch />;
      case 'shared-links':
        return <SharedLinks />;
      case 'control-panel':
        return <ControlPanel />;
      default:
        return (
          <div className="flex flex-col items-center justify-center h-full text-slate-400 p-10 text-center">
            <SettingsIcon size={48} className="opacity-10 mb-4" />
            <p className="font-medium">The "{id}" application is under development.</p>
            <p className="text-sm">Check for system updates in the Control Panel.</p>
          </div>
        );
    }
  };

  return (
    <>
      {windows.map((win) => (
        <Window
          key={win.id}
          windowState={win}
        >
          {renderAppContent(win.id)}
        </Window>
      ))}
    </>
  );
};

export default WindowManager;
