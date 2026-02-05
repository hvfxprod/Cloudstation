
import React from 'react';
import { 
  FolderOpen, 
  Share2, 
  Cpu,
  Bot
} from 'lucide-react';
import { useOSStore } from '../store';
import { AppID } from '../types';

interface DesktopIconProps {
  id: AppID;
  label: string;
  icon: React.ReactNode;
  color: string;
}

const DesktopIcon: React.FC<DesktopIconProps> = ({ id, label, icon, color }) => {
  const openWindow = useOSStore((state) => state.openWindow);
  
  return (
    <button 
      onDoubleClick={() => openWindow(id, label)}
      className="flex flex-col items-center gap-1 p-2 md:p-3 rounded-lg hover:bg-white/10 transition-colors w-auto md:w-24 group outline-none"
    >
      <div className={`w-12 h-12 md:w-14 md:h-14 rounded-2xl flex items-center justify-center shadow-lg group-active:scale-95 transition-transform ${color}`}>
        {React.cloneElement(icon as React.ReactElement, { size: 28, className: 'text-white md:w-8 md:h-8' })}
      </div>
      <span className="text-white text-[10px] md:text-xs font-medium drop-shadow-[0_1px_2px_rgba(0,0,0,0.8)] text-center break-words max-w-[70px] md:max-w-none">
        {label}
      </span>
    </button>
  );
};

const Desktop: React.FC = () => {
  const icons: DesktopIconProps[] = [
    { id: 'file-explorer', label: 'File Station', icon: <FolderOpen />, color: 'bg-blue-500' },
    { id: 'control-panel', label: 'Control Panel', icon: <Cpu />, color: 'bg-slate-700' },
    { id: 'shared-links', label: 'Shared Links', icon: <Share2 />, color: 'bg-emerald-500' },
    { id: 'ai-assistant', label: 'AI Assistant', icon: <Bot />, color: 'bg-purple-600' },
  ];

  return (
    <div className="absolute inset-0 p-4 md:p-6 md:pr-80 flex flex-col pointer-events-auto transition-all">
      {/* Mobile Grid (4 columns) / Desktop Flex (column) */}
      <div className="grid grid-cols-4 md:flex md:flex-col md:flex-wrap gap-2 md:gap-4 content-start">
        {icons.map((icon) => (
          <DesktopIcon key={icon.id} {...icon} />
        ))}
      </div>
    </div>
  );
};

export default Desktop;
