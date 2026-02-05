
import React from 'react';
import { Bell, X, Info, CheckCircle, AlertCircle } from 'lucide-react';
import { useOSStore } from '../../store';

const WidgetNotifications: React.FC = () => {
  const { notifications, removeNotification } = useOSStore();

  return (
    <div className="flex-1 glass rounded-[1.5rem] md:rounded-[2rem] p-4 md:p-6 shadow-xl border border-white/40 flex flex-col min-h-[120px] md:min-h-[200px] animate-in fade-in slide-in-from-bottom-4 md:slide-in-from-right-4 duration-500 delay-150">
      <div className="flex items-center justify-between mb-2 md:mb-4">
        <h3 className="text-[9px] md:text-[10px] font-black text-slate-400 uppercase tracking-[0.2em] flex items-center gap-2">
          <Bell size={12} /> Notification Center
        </h3>
        {notifications.length > 0 && (
          <span className="w-4 h-4 md:w-5 md:h-5 bg-red-500 text-white text-[8px] md:text-[10px] font-black flex items-center justify-center rounded-full animate-pulse">
            {notifications.length}
          </span>
        )}
      </div>

      <div className="flex-1 overflow-y-auto no-scrollbar space-y-2 md:space-y-3">
        {notifications.length > 0 ? (
          notifications.map((n) => (
            <div 
              key={n.id} 
              className="bg-white/40 hover:bg-white/60 p-2 md:p-3 rounded-xl md:rounded-2xl border border-white/20 transition-all group relative animate-in fade-in"
            >
              <div className="flex gap-2 md:gap-3">
                <div className="pt-0.5 shrink-0">
                  {n.type === 'info' && <Info size={12} className="text-blue-500" />}
                  {n.type === 'success' && <CheckCircle size={12} className="text-emerald-500" />}
                  {n.type === 'warning' && <AlertCircle size={12} className="text-amber-500" />}
                </div>
                <div className="min-w-0">
                  <p className="text-[10px] md:text-xs font-bold text-slate-800 truncate">{n.title}</p>
                  <p className="text-[8px] md:text-[10px] text-slate-500 line-clamp-1 md:line-clamp-2 mt-0.5 leading-relaxed">{n.message}</p>
                </div>
              </div>
              <button 
                onClick={() => removeNotification(n.id)}
                className="absolute top-1 right-1 p-1 opacity-0 group-hover:opacity-100 hover:bg-red-500 hover:text-white rounded-md transition-all text-slate-400"
              >
                <X size={8} />
              </button>
            </div>
          ))
        ) : (
          <div className="h-full flex flex-col items-center justify-center text-slate-400 py-4 md:py-10 opacity-30">
            <Bell size={24} className="md:size-32 mb-2" />
            <p className="text-[8px] md:text-[10px] font-bold uppercase tracking-widest">All Clear</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default WidgetNotifications;
