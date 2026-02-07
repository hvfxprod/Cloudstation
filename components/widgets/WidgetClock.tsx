import React, { useState, useEffect } from 'react';
import { useOSStore } from '../../store';

function getTimezoneLabel(tz: string): string {
  if (!tz || tz === 'UTC') return 'UTC';
  try {
    const formatter = new Intl.DateTimeFormat('en-GB', {
      timeZone: tz,
      timeZoneName: 'shortOffset',
    });
    const parts = formatter.formatToParts(new Date());
    const tzName = parts.find((p) => p.type === 'timeZoneName')?.value ?? '';
    const offset = tzName.replace(/^GMT/, 'UTC');
    const city = tz.split('/').pop() ?? tz;
    return `${offset} (${city})`;
  } catch {
    return tz;
  }
}

const WidgetClock: React.FC = () => {
  const timezone = useOSStore((s) => s.timezone);
  const [time, setTime] = useState(new Date());
  const tzLabel = getTimezoneLabel(timezone);

  useEffect(() => {
    const timer = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  const opts = { timeZone: timezone || 'UTC', hour12: false } as const;
  const dateOpts = { timeZone: timezone || 'UTC' } as const;

  return (
    <div className="glass rounded-[1.5rem] md:rounded-[2rem] p-4 md:p-6 shadow-xl border border-white/40 flex flex-col items-center justify-center animate-in fade-in slide-in-from-bottom-4 md:slide-in-from-right-4 duration-500">
      <h2 className="text-3xl md:text-5xl font-black text-slate-800 tracking-tighter">
        {time.toLocaleTimeString('en-GB', { ...opts, hour: '2-digit', minute: '2-digit' })}
      </h2>
      <div className="mt-1 md:mt-2 flex flex-col items-center">
        <p className="text-[10px] md:text-sm font-black text-blue-600 uppercase tracking-[0.2em]">
          {time.toLocaleDateString('en-US', { ...dateOpts, weekday: 'long' })}
        </p>
        <p className="text-[9px] md:text-xs font-bold text-slate-500 mt-0.5">
          {time.toLocaleDateString('en-US', { ...dateOpts, month: 'long', day: 'numeric' })}
        </p>
        <p className="text-[9px] md:text-xs font-medium text-slate-400 mt-1">
          {tzLabel}
        </p>
      </div>
    </div>
  );
};

export default WidgetClock;
