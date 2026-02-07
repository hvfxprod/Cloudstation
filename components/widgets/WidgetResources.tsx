import React, { useState, useEffect } from 'react';
import { Cpu, Database, Activity, FolderOpen, Share2, Bot, Calendar } from 'lucide-react';
import { useOSStore } from '../../store';
import type { AppID } from '../../types';

const APP_ICONS: Record<AppID, { Icon: React.ComponentType<{ size?: number; className?: string }>; color: string }> = {
  'file-explorer': { Icon: FolderOpen, color: 'bg-blue-500' },
  'control-panel': { Icon: Cpu, color: 'bg-slate-700' },
  'shared-links': { Icon: Share2, color: 'bg-emerald-500' },
  'ai-assistant': { Icon: Bot, color: 'bg-purple-600' },
  'calendar': { Icon: Calendar, color: 'bg-amber-500' },
};

const WidgetResources: React.FC = () => {
  const [cpuPercent, setCpuPercent] = useState<number | null>(null);
  const [ramPercent, setRamPercent] = useState<number | null>(null);
  const { windows, focusWindow, activeWindowId } = useOSStore();

  useEffect(() => {
    const fetchSystem = async () => {
      try {
        const res = await fetch('/api/system');
        if (!res.ok) return;
        const data = await res.json();
        const cpu = data.cpu?.percent ?? null;
        const memTotal = data.memory?.totalBytes ?? null;
        const memUsed = data.memory?.usedBytes ?? null;
        if (cpu != null) setCpuPercent(cpu);
        if (memTotal != null && memUsed != null && memTotal > 0) {
          setRamPercent((memUsed / memTotal) * 100);
        }
      } catch {
        // keep previous values
      }
    };
    fetchSystem();
    const interval = setInterval(fetchSystem, 10000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="glass rounded-[1.5rem] md:rounded-[2rem] p-4 md:p-6 shadow-xl border border-white/40 space-y-3 md:space-y-5 animate-in fade-in slide-in-from-bottom-4 md:slide-in-from-right-4 duration-500 delay-75">
      <div className="flex items-center justify-between">
        <h3 className="text-[9px] md:text-[10px] font-black text-slate-400 uppercase tracking-[0.2em] flex items-center gap-2">
          <Activity size={12} /> Resource Monitor
        </h3>
        <span className="text-[9px] md:text-[10px] font-bold text-emerald-500 bg-emerald-50 px-2 py-0.5 rounded-full">Normal</span>
      </div>

      <div className="space-y-3 md:space-y-4">
        <div className="space-y-1">
          <div className="flex justify-between items-center text-[9px] md:text-[10px] font-bold text-slate-600">
            <span className="flex items-center gap-1.5"><Cpu size={10} className="text-orange-500" /> CPU</span>
            <span>{cpuPercent != null ? `${cpuPercent.toFixed(1)}%` : '—'}</span>
          </div>
          <div className="h-1 md:h-1.5 w-full bg-slate-200/50 rounded-full overflow-hidden">
            <div className="h-full bg-orange-500 transition-all duration-1000" style={{ width: `${Math.min(100, Math.max(0, cpuPercent ?? 0))}%` }} />
          </div>
        </div>

        <div className="space-y-1">
          <div className="flex justify-between items-center text-[9px] md:text-[10px] font-bold text-slate-600">
            <span className="flex items-center gap-1.5"><Database size={10} className="text-blue-500" /> RAM</span>
            <span>{ramPercent != null ? `${ramPercent.toFixed(1)}%` : '—'}</span>
          </div>
          <div className="h-1 md:h-1.5 w-full bg-slate-200/50 rounded-full overflow-hidden">
            <div className="h-full bg-blue-500 transition-all duration-500" style={{ width: `${Math.min(100, Math.max(0, ramPercent ?? 0))}%` }} />
          </div>
        </div>
      </div>

      {windows.length > 0 && (
        <div className="pt-2 md:pt-4 border-t border-white/20">
          <div className="flex flex-wrap gap-2">
            {windows.map((win) => {
              const app = APP_ICONS[win.id as AppID];
              const Icon = app?.Icon;
              const isActive = activeWindowId === win.id;
              return (
                <button
                  key={win.id}
                  onClick={() => focusWindow(win.id)}
                  className={`w-6 h-6 md:w-8 md:h-8 rounded-lg flex items-center justify-center transition-all ${
                    isActive ? 'ring-2 ring-blue-500 ring-offset-2 scale-110 shadow-lg' : 'hover:opacity-90'
                  } ${Icon ? app.color : 'bg-slate-400'} text-white`}
                  title={win.title}
                >
                  {Icon ? <Icon size={14} className="md:w-4 md:h-4" /> : <div className="w-1.5 h-1.5 rounded-full bg-white" />}
                </button>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};

export default WidgetResources;
