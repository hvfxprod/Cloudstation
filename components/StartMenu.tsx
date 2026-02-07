
import React, { useState } from 'react';
import { 
  FolderOpen, Share2, Cpu, Bot, Search, LogOut, Power, User, Lock
} from 'lucide-react';
import { useOSStore } from '../store';
import { AppID } from '../types';
import LoginSettingsModal from './LoginSettingsModal';

const StartMenu: React.FC = () => {
  const { isStartMenuOpen, toggleStartMenu, openWindow } = useOSStore();
  const [showLoginSettings, setShowLoginSettings] = useState(false);

  if (!isStartMenuOpen) return null;

  const apps: { id: AppID, label: string, icon: React.ReactNode, color: string }[] = [
    { id: 'file-explorer', label: 'File Station', icon: <FolderOpen />, color: 'bg-blue-500' },
    { id: 'control-panel', label: 'Control Panel', icon: <Cpu />, color: 'bg-slate-700' },
    { id: 'shared-links', label: 'Shared Links', icon: <Share2 />, color: 'bg-emerald-500' },
    { id: 'ai-assistant', label: 'AI Assistant', icon: <Bot />, color: 'bg-purple-600' },
  ];

  return (
    <div 
      className="fixed inset-0 z-[10000] flex items-center justify-center p-8 bg-black/20 backdrop-blur-md animate-in fade-in zoom-in duration-200"
      onClick={toggleStartMenu}
    >
      <div 
        className="w-full max-w-4xl bg-white/10 backdrop-blur-2xl rounded-3xl p-12 border border-white/20 shadow-2xl relative overflow-hidden"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between mb-12">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-full bg-blue-600 flex items-center justify-center text-white font-bold text-xl border-2 border-white/20 shadow-lg">
              <User size={24} />
            </div>
            <div>
              <h2 className="text-white text-2xl font-bold">Admin</h2>
              <p className="text-white/60 text-sm">CloudStation Pro OS v4.2</p>
            </div>
          </div>
          
          <div className="flex items-center gap-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-white/40" size={18} />
              <input 
                type="text" 
                placeholder="Search applications..." 
                className="bg-white/10 border border-white/10 rounded-xl py-2 pl-10 pr-4 text-white text-sm outline-none focus:ring-2 focus:ring-blue-500 w-64 transition-all"
                autoFocus
              />
            </div>
            <button
              type="button"
              className="p-3 bg-white/5 hover:bg-white/10 rounded-xl transition-colors text-white"
              title="Require login"
              onClick={() => setShowLoginSettings(true)}
            >
              <Lock size={20} />
            </button>
            <button
              type="button"
              className="p-3 bg-white/5 hover:bg-white/10 rounded-xl transition-colors text-white"
              title="Log out"
              onClick={async () => {
                try {
                  await fetch('/api/auth/logout', { method: 'POST', credentials: 'include' });
                  window.location.reload();
                } catch {
                  window.location.reload();
                }
              }}
            >
              <LogOut size={20} />
            </button>
            <button className="p-3 bg-red-500/20 hover:bg-red-500/40 rounded-xl transition-colors text-red-500" title="Shut Down">
              <Power size={20} />
            </button>
          </div>
        </div>

        <div className="grid grid-cols-4 md:grid-cols-6 gap-8">
          {apps.map((app) => (
            <button
              key={app.id}
              onClick={() => openWindow(app.id, app.label)}
              className="flex flex-col items-center gap-3 group"
            >
              <div className={`w-20 h-20 rounded-2xl flex items-center justify-center shadow-2xl transition-all duration-300 group-hover:scale-110 group-hover:-translate-y-1 group-active:scale-95 ${app.color}`}>
                {React.cloneElement(app.icon as React.ReactElement, { size: 40, className: 'text-white' })}
              </div>
              <span className="text-white text-sm font-medium opacity-80 group-hover:opacity-100 transition-opacity">
                {app.label}
              </span>
            </button>
          ))}
        </div>
        
        <div className="absolute -bottom-24 -right-24 w-96 h-96 bg-blue-500/20 blur-[100px] rounded-full pointer-events-none" />
        <div className="absolute -top-24 -left-24 w-96 h-96 bg-purple-500/20 blur-[100px] rounded-full pointer-events-none" />
      </div>
      {showLoginSettings && (
        <LoginSettingsModal onClose={() => setShowLoginSettings(false)} />
      )}
    </div>
  );
};

export default StartMenu;
