
import React, { useState, useEffect } from 'react';

const WidgetClock: React.FC = () => {
  const [time, setTime] = useState(new Date());

  useEffect(() => {
    const timer = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  return (
    <div className="glass rounded-[1.5rem] md:rounded-[2rem] p-4 md:p-6 shadow-xl border border-white/40 flex flex-col items-center justify-center animate-in fade-in slide-in-from-bottom-4 md:slide-in-from-right-4 duration-500">
      <h2 className="text-3xl md:text-5xl font-black text-slate-800 tracking-tighter">
        {time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false })}
      </h2>
      <div className="mt-1 md:mt-2 flex flex-col items-center">
        <p className="text-[10px] md:text-sm font-black text-blue-600 uppercase tracking-[0.2em]">
          {time.toLocaleDateString('ko-KR', { weekday: 'long' })}
        </p>
        <p className="text-[9px] md:text-xs font-bold text-slate-500 mt-0.5">
          {time.toLocaleDateString('ko-KR', { month: 'long', day: 'numeric' })}
        </p>
      </div>
    </div>
  );
};

export default WidgetClock;
