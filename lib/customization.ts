import type { CSSProperties } from 'react';

/** DSM-style desktop background presets */
export const BACKGROUND_PRESETS: { id: string; label: string; style: CSSProperties }[] = [
  {
    id: 'default',
    label: 'Default',
    style: {
      backgroundImage: `url('https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?auto=format&fit=crop&q=80&w=2564')`,
      backgroundSize: 'cover',
      backgroundPosition: 'center',
    },
  },
  {
    id: 'gradient-purple',
    label: 'Purple',
    style: { background: 'linear-gradient(135deg, #7c3aed 0%, #4f46e5 50%, #1e1b4b 100%)' },
  },
  {
    id: 'gradient-blue',
    label: 'Ocean',
    style: { background: 'linear-gradient(135deg, #0ea5e9 0%, #0369a1 50%, #0c4a6e 100%)' },
  },
  {
    id: 'gradient-sunset',
    label: 'Sunset',
    style: { background: 'linear-gradient(135deg, #fb923c 0%, #ea580c 50%, #9f1239 100%)' },
  },
  {
    id: 'gradient-forest',
    label: 'Forest',
    style: { background: 'linear-gradient(135deg, #15803d 0%, #166534 50%, #14532d 100%)' },
  },
  {
    id: 'solid-slate',
    label: 'Dark Slate',
    style: { background: '#1e293b' },
  },
  {
    id: 'solid-navy',
    label: 'Navy',
    style: { background: '#0f172a' },
  },
  {
    id: 'solid-light',
    label: 'Light',
    style: { background: '#e2e8f0' },
  },
];

export function getDesktopBackgroundStyle(
  backgroundId: string,
  customUrl: string
): CSSProperties {
  if (backgroundId === 'custom' && customUrl.trim()) {
    return {
      backgroundImage: `url(${customUrl.trim()})`,
      backgroundSize: 'cover',
      backgroundPosition: 'center',
    };
  }
  const preset = BACKGROUND_PRESETS.find((p) => p.id === backgroundId);
  return preset?.style ?? BACKGROUND_PRESETS[0].style;
}

/** Overlay opacity by theme for readability */
export function getOverlayOpacity(theme: 'light' | 'dark' | 'dynamic'): string {
  if (theme === 'dark') return 'bg-black/20';
  if (theme === 'dynamic') return 'bg-black/15';
  return 'bg-black/10';
}
