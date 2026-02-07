import React, { useRef, useCallback } from 'react';
import { X, Minus, Square } from 'lucide-react';
import { useOSStore } from '../store';
import { WindowState } from '../types';

interface WindowProps {
  windowState: WindowState;
  children: React.ReactNode;
}

const Window: React.FC<WindowProps> = ({ windowState, children }) => {
  const { closeWindow, minimizeWindow, maximizeWindow, focusWindow, updateWindowPosition, activeWindowId } = useOSStore();
  const boxRef = useRef<HTMLDivElement>(null);

  const isActive = activeWindowId === windowState.id;
  const isMobile = typeof window !== 'undefined' && window.innerWidth < 768;
  const isFullscreen = windowState.isMaximized || isMobile;

  const position = windowState.position;
  const styleLeft = isFullscreen ? '0' : position != null ? `${position.x}px` : '8%';
  const styleTop = isFullscreen ? '0' : position != null ? `${position.y}px` : '8%';

  const handleTitleMouseDown = useCallback(
    (e: React.MouseEvent) => {
      if (isFullscreen || e.button !== 0) return;
      if ((e.target as HTMLElement).closest('button')) return;
      e.preventDefault();
      focusWindow(windowState.id);
      const startX = e.clientX;
      const startY = e.clientY;
      const rect = boxRef.current?.getBoundingClientRect();
      if (!rect) return;
      const startLeft = rect.left;
      const startTop = rect.top;

      const onMove = (moveEvent: MouseEvent) => {
        const dx = moveEvent.clientX - startX;
        const dy = moveEvent.clientY - startY;
        let x = startLeft + dx;
        let y = startTop + dy;
        const vw = window.innerWidth;
        const vh = window.innerHeight;
        const w = rect.width;
        const h = rect.height;
        x = Math.max(0, Math.min(vw - w, x));
        y = Math.max(0, Math.min(vh - h, y));
        updateWindowPosition(windowState.id, x, y);
      };

      const onUp = () => {
        document.removeEventListener('mousemove', onMove);
        document.removeEventListener('mouseup', onUp);
      };

      document.addEventListener('mousemove', onMove);
      document.addEventListener('mouseup', onUp);
    },
    [windowState.id, isFullscreen, focusWindow, updateWindowPosition]
  );

  if (windowState.isMinimized) return null;

  return (
    <div
      ref={boxRef}
      onClick={() => focusWindow(windowState.id)}
      style={{
        zIndex: windowState.zIndex,
        left: styleLeft,
        top: styleTop,
        width: isFullscreen ? '100%' : '60%',
        height: isFullscreen ? '100%' : '75%',
        transition: isFullscreen ? 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)' : 'box-shadow 0.2s, border-color 0.2s',
      }}
      className={`absolute glass rounded-3xl overflow-hidden flex flex-col shadow-2xl border border-white/40 ${
        isActive ? 'ring-2 ring-blue-500/30' : 'opacity-95'
      } ${isFullscreen ? 'rounded-none' : ''}`}
    >
      {/* Title Bar - drag to move window */}
      <div
        onMouseDown={handleTitleMouseDown}
        className={`h-10 md:h-12 flex items-center justify-between px-4 md:px-6 select-none ${
          isFullscreen ? 'cursor-default' : 'cursor-grab active:cursor-grabbing'
        } ${isActive ? 'bg-white/40' : 'bg-white/10'}`}
      >
        <div className="flex items-center gap-2">
          <span className="text-xs md:text-sm font-bold text-slate-800">{windowState.title}</span>
        </div>

        <div className="flex items-center gap-1 md:gap-2">
          <button
            onClick={(e) => { e.stopPropagation(); minimizeWindow(windowState.id); }}
            className="w-6 h-6 md:w-7 md:h-7 flex items-center justify-center hover:bg-black/5 rounded-full transition-colors"
          >
            <Minus size={12} className="text-slate-600" />
          </button>
          {!isMobile && (
            <button
              onClick={(e) => { e.stopPropagation(); maximizeWindow(windowState.id); }}
              className="w-7 h-7 flex items-center justify-center hover:bg-black/5 rounded-full transition-colors"
            >
              <Square size={12} className="text-slate-600" />
            </button>
          )}
          <button
            onClick={(e) => { e.stopPropagation(); closeWindow(windowState.id); }}
            className="w-6 h-6 md:w-7 md:h-7 flex items-center justify-center hover:bg-red-500 hover:text-white rounded-full transition-all"
          >
            <X size={12} />
          </button>
        </div>
      </div>

      {/* Content Area */}
      <div className="flex-1 overflow-hidden bg-white/90">
        {children}
      </div>
    </div>
  );
};

export default Window;
