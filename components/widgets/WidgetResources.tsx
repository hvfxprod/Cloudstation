
import React, { useState, useEffect } from 'react';
import { Cpu, Database, HardDrive, Activity } from 'lucide-react';
import { useOSStore } from '../../store';

const WidgetResources: React.FC = () => {
  const [cpu, setCpu] = useState(18);
  const [ram] = useState(44);
  const { windows, focusWindow, activeWindowId } = useOSStore();

  useEffect(() => {
    const interval = setInterval(() => {
      setCpu(prev => Math.min(100, Math.max(5, prev + (Math.random() * 6 - 3))));
    }, 2000);
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
            <span>{cpu.toFixed(0)}%</span>
          </div>
          <div className="h-1 md:h-1.5 w-full bg-slate-200/50 rounded-full overflow-hidden">
            <div className="h-full bg-orange-500 transition-all duration-1000" style={{ width: `${cpu}%` }} />
          </div>
        </div>

        <div className="space-y-1">
          <div className="flex justify-between items-center text-[9px] md:text-[10px] font-bold text-slate-600">
            <span className="flex items-center gap-1.5"><Database size={10} className="text-blue-500" /> RAM</span>
            <span>{ram}%</span>
          </div>
          <div className="h-1 md:h-1.5 w-full bg-slate-200/50 rounded-full overflow-hidden">
            <div className="h-full bg-blue-500 transition-all duration-500" style={{ width: `${ram}%` }} />
          </div>
        </div>
      </div>

      {windows.length > 0 && (
        <div className="pt-2 md:pt-4 border-t border-white/20">
          <div className="flex flex-wrap gap-2">
            {windows.map(win => (
              <button
                key={win.id}
                onClick={() => focusWindow(win.id)}
                className={`w-6 h-6 md:w-8 md:h-8 rounded-lg flex items-center justify-center transition-all ${
                  activeWindowId === win.id ? 'bg-blue-600 text-white scale-110 shadow-lg' : 'bg-white/50 text-slate-600 hover:bg-white'
                }`}
                title={win.title}
              >
                <div className="w-1 md:w-1.5 h-1 md:h-1.5 bg-current rounded-full" />
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default WidgetResources;
