import React, { useEffect } from 'react';
import { X, CheckCircle, Info, AlertCircle } from 'lucide-react';
import { useOSStore } from '../store';

const TOAST_DURATION_MS = 4000;

const Toast: React.FC = () => {
  const { toast, clearToast } = useOSStore();

  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(clearToast, TOAST_DURATION_MS);
    return () => clearTimeout(t);
  }, [toast, clearToast]);

  if (!toast) return null;

  const Icon = toast.type === 'success' ? CheckCircle : toast.type === 'warning' ? AlertCircle : Info;
  const iconColor = toast.type === 'success' ? 'text-emerald-500' : toast.type === 'warning' ? 'text-amber-500' : 'text-blue-500';

  return (
    <div
      className="fixed bottom-6 right-6 z-[9999] pointer-events-auto max-w-sm animate-in fade-in slide-in-from-right-6 duration-300"
      role="alert"
    >
      <div className="glass rounded-2xl shadow-xl border border-white/50 p-4 pr-10 flex gap-3">
        <div className={`shrink-0 pt-0.5 ${iconColor}`}>
          <Icon size={20} />
        </div>
        <div className="min-w-0">
          <p className="text-sm font-bold text-slate-800">{toast.title}</p>
          <p className="text-xs text-slate-600 mt-0.5 leading-relaxed whitespace-pre-wrap">{toast.message}</p>
        </div>
        <button
          onClick={clearToast}
          className="absolute top-2 right-2 p-1.5 rounded-lg text-slate-400 hover:text-slate-600 hover:bg-white/50 transition-colors"
          aria-label="Dismiss"
        >
          <X size={14} />
        </button>
      </div>
    </div>
  );
};

export default Toast;
