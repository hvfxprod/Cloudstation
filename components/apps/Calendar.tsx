import React, { useState, useEffect } from 'react';
import { ChevronLeft, ChevronRight, Plus, Trash2, X, Clock, Calendar as CalendarIcon } from 'lucide-react';
import { useOSStore } from '../../store';

const WEEKDAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const EVENT_COLORS = ['bg-blue-500', 'bg-emerald-500', 'bg-amber-500', 'bg-rose-500', 'bg-violet-500'];

/** Pastel preview style per color (background + title + subtitle) */
const PASTEL_PREVIEW: Record<string, { bg: string; title: string; sub: string }> = {
  'bg-blue-500': { bg: 'bg-blue-100', title: 'text-blue-900', sub: 'text-blue-600' },
  'bg-emerald-500': { bg: 'bg-emerald-100', title: 'text-emerald-900', sub: 'text-emerald-600' },
  'bg-amber-500': { bg: 'bg-amber-100', title: 'text-amber-900', sub: 'text-amber-600' },
  'bg-rose-500': { bg: 'bg-rose-100', title: 'text-rose-900', sub: 'text-rose-600' },
  'bg-violet-500': { bg: 'bg-violet-100', title: 'text-violet-900', sub: 'text-violet-600' },
};

function getEventPreviewStyle(color: string | null | undefined) {
  return PASTEL_PREVIEW[color || 'bg-blue-500'] || PASTEL_PREVIEW['bg-blue-500'];
}

/** Format time input as user types: digits only, max 4, auto-insert ":" → HH:MM */
function formatTimeInput(value: string): string {
  const digits = value.replace(/\D/g, '').slice(0, 4);
  if (digits.length <= 2) return digits;
  return `${digits.slice(0, 2)}:${digits.slice(2)}`;
}

/** Normalize to HH:MM for API (e.g. "16:0" → "16:00") */
function normalizeTime(value: string | null | undefined): string | null {
  if (!value || !value.trim()) return null;
  const digits = value.replace(/\D/g, '').slice(0, 4);
  if (digits.length < 2) return null;
  const h = digits.slice(0, 2);
  const m = digits.slice(2, 4).padEnd(2, '0');
  return `${h}:${m}`;
}

interface CalendarEvent {
  id: string;
  title: string;
  date: string;
  startTime?: string | null;
  endTime?: string | null;
  color?: string | null;
  description?: string | null;
}

const Calendar: React.FC = () => {
  const timezone = useOSStore((s) => s.timezone) || 'UTC';
  const [current, setCurrent] = useState(() => {
    const d = new Date();
    return { year: d.getFullYear(), month: d.getMonth() };
  });
  const [events, setEvents] = useState<CalendarEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [modal, setModal] = useState<{ type: 'add' | 'view'; date?: string; event?: CalendarEvent } | null>(null);
  const [selectedEvent, setSelectedEvent] = useState<CalendarEvent | null>(null);
  const [formTitle, setFormTitle] = useState('');
  const [formDate, setFormDate] = useState('');
  const [formStartTime, setFormStartTime] = useState('');
  const [formEndTime, setFormEndTime] = useState('');
  const [formColor, setFormColor] = useState(EVENT_COLORS[0]);
  const [formDescription, setFormDescription] = useState('');
  const [saving, setSaving] = useState(false);
  const [detailMemo, setDetailMemo] = useState('');
  const [savingMemo, setSavingMemo] = useState(false);

  const fetchEvents = async () => {
    const year = current.year;
    const month = current.month;
    const from = `${year}-${String(month + 1).padStart(2, '0')}-01`;
    const lastDay = new Date(year, month + 1, 0).getDate();
    const to = `${year}-${String(month + 1).padStart(2, '0')}-${String(lastDay).padStart(2, '0')}`;
    try {
      const res = await fetch(`/api/calendar/events?from=${from}&to=${to}`, { credentials: 'include' });
      if (!res.ok) return;
      const data = await res.json();
      setEvents(Array.isArray(data.events) ? data.events : []);
    } catch {
      setEvents([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    setLoading(true);
    fetchEvents();
  }, [current.year, current.month]);

  const firstDay = new Date(current.year, current.month, 1).getDay();
  const daysInMonth = new Date(current.year, current.month + 1, 0).getDate();
  const prevMonth = () => setCurrent((c) => (c.month === 0 ? { year: c.year - 1, month: 11 } : { year: c.year, month: c.month - 1 }));
  const nextMonth = () => setCurrent((c) => (c.month === 11 ? { year: c.year + 1, month: 0 } : { year: c.year, month: c.month + 1 }));

  const monthLabel = new Date(current.year, current.month).toLocaleString('en-US', { month: 'long', year: 'numeric', timeZone: timezone });

  const getEventsForDay = (day: number) => {
    const dateStr = `${current.year}-${String(current.month + 1).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
    return events.filter((e) => e.date === dateStr);
  };

  const openAdd = (dateStr?: string) => {
    const d = dateStr ? new Date(dateStr + 'T12:00:00') : new Date();
    setFormDate(dateStr || `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`);
    setFormTitle('');
    setFormStartTime('');
    setFormEndTime('');
    setFormColor(EVENT_COLORS[0]);
    setFormDescription('');
    setModal({ type: 'add', date: undefined });
  };

  const handleSaveEvent = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formTitle.trim() || !formDate) return;
    setSaving(true);
    try {
      const res = await fetch('/api/calendar/events', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: formTitle.trim(),
          date: formDate,
          startTime: normalizeTime(formStartTime),
          endTime: normalizeTime(formEndTime),
          color: formColor,
          description: formDescription.trim() || null,
        }),
      });
      if (!res.ok) throw new Error('Failed');
      setModal(null);
      fetchEvents();
    } catch {
      // ignore
    }
    setSaving(false);
  };

  const handleDeleteEvent = async (id: string) => {
    try {
      const res = await fetch(`/api/calendar/events/${id}`, { method: 'DELETE', credentials: 'include' });
      if (!res.ok) return;
      setModal(null);
      setSelectedEvent(null);
      fetchEvents();
    } catch {
      // ignore
    }
  };

  const handleSaveMemo = async () => {
    if (!selectedEvent || savingMemo) return;
    const value = detailMemo.trim();
    setSavingMemo(true);
    try {
      const res = await fetch(`/api/calendar/events/${selectedEvent.id}`, {
        method: 'PATCH',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ description: value || null }),
      });
      if (!res.ok) return;
      const data = await res.json();
      const updated = data.event || { ...selectedEvent, description: value || null };
      setSelectedEvent(updated);
      setEvents((prev) => prev.map((e) => (e.id === selectedEvent.id ? updated : e)));
    } catch {
      // ignore
    }
    setSavingMemo(false);
  };

  useEffect(() => {
    if (selectedEvent) setDetailMemo(selectedEvent.description ?? '');
  }, [selectedEvent?.id, selectedEvent?.description]);

  const pad = firstDay;
  const totalCells = pad + daysInMonth;
  const rows = Math.ceil(totalCells / 7);

  return (
    <div className="h-full flex flex-col bg-slate-50 overflow-auto">
      <div className="p-6 border-b border-slate-200 bg-white shrink-0">
        <div className="flex items-center justify-between flex-wrap gap-4">
          <h1 className="text-2xl font-bold text-slate-800">Calendar</h1>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => openAdd()}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-amber-500 hover:bg-amber-600 text-white text-sm font-medium"
            >
              <Plus size={18} />
              Add event
            </button>
          </div>
        </div>
        <div className="flex items-center gap-4 mt-4">
          <button type="button" onClick={prevMonth} className="p-2 rounded-lg hover:bg-slate-100 text-slate-600">
            <ChevronLeft size={20} />
          </button>
          <h2 className="text-lg font-semibold text-slate-800 min-w-[200px] text-center">{monthLabel}</h2>
          <button type="button" onClick={nextMonth} className="p-2 rounded-lg hover:bg-slate-100 text-slate-600">
            <ChevronRight size={20} />
          </button>
        </div>
      </div>

      <div className="flex-1 p-6 min-h-0 overflow-auto">
        <div className="h-full min-h-0 flex bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
          <div className="flex-1 min-w-0 flex flex-col min-h-0">
            <div className="grid grid-cols-7 border-b border-slate-200 bg-slate-50 shrink-0">
              {WEEKDAYS.map((d) => (
                <div key={d} className="py-2 text-center text-xs font-bold text-slate-500 uppercase">
                  {d}
                </div>
              ))}
            </div>
            <div
              className="grid grid-cols-7 flex-1 min-h-0 w-full"
              style={{ gridTemplateRows: `repeat(${rows}, minmax(88px, 1fr))` }}
            >
              {Array.from({ length: pad }, (_, i) => (
                <div key={`pad-${i}`} className="border-b border-r border-slate-100 bg-slate-50/50 p-1 min-h-0" />
              ))}
              {Array.from({ length: daysInMonth }, (_, i) => {
                const day = i + 1;
                const dateStr = `${current.year}-${String(current.month + 1).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
                const dayEvents = getEventsForDay(day);
                const isToday =
                  new Date().getFullYear() === current.year &&
                  new Date().getMonth() === current.month &&
                  new Date().getDate() === day;
                return (
                  <div
                    key={day}
                    className={`min-h-0 border-b border-r border-slate-100 p-1.5 flex flex-col ${
                      isToday ? 'bg-amber-50/80' : 'bg-white'
                    }`}
                  >
                    <div className="flex items-center justify-between shrink-0">
                      <span className={`text-sm font-semibold ${isToday ? 'text-amber-700' : 'text-slate-700'}`}>{day}</span>
                      <button
                        type="button"
                        onClick={() => openAdd(dateStr)}
                        className="opacity-0 hover:opacity-100 p-0.5 rounded text-slate-400 hover:text-amber-600 transition-opacity"
                        title="Add event"
                      >
                        <Plus size={14} />
                      </button>
                    </div>
                    <div className="flex-1 min-h-0 overflow-y-auto space-y-1 mt-1">
                      {dayEvents.map((ev) => {
                        const style = getEventPreviewStyle(ev.color);
                        const subtitle = [ev.startTime, ev.endTime].filter(Boolean).join(' – ') || (ev.description ? ev.description.slice(0, 24) + (ev.description.length > 24 ? '…' : '') : null);
                        return (
                          <button
                            key={ev.id}
                            type="button"
                            onClick={() => setSelectedEvent(ev)}
                            className={`w-full text-left rounded-lg px-2 py-1.5 ${style.bg} hover:opacity-90 transition-opacity border border-white/60 shadow-sm ${selectedEvent?.id === ev.id ? 'ring-2 ring-amber-500 ring-offset-1' : ''}`}
                            title={ev.title}
                          >
                            <p className={`text-[11px] md:text-xs font-semibold leading-tight truncate ${style.title}`}>
                              {ev.title}
                            </p>
                            {subtitle && (
                              <p className={`text-[9px] md:text-[10px] mt-0.5 truncate ${style.sub}`}>
                                {subtitle}
                              </p>
                            )}
                          </button>
                        );
                      })}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
          <div className="w-[320px] md:w-[360px] shrink-0 border-l border-slate-200 flex flex-col min-h-[280px] overflow-hidden">
          {selectedEvent ? (
            <>
              <div className="p-4 border-b border-slate-100 flex items-start justify-between gap-2">
                <div className="min-w-0 flex-1">
                  <h3 className="text-lg font-bold text-slate-800 truncate">{selectedEvent.title}</h3>
                  <p className="text-sm text-slate-500 mt-0.5 flex items-center gap-1.5">
                    <CalendarIcon size={14} className="shrink-0" />
                    {selectedEvent.date}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => setSelectedEvent(null)}
                  className="p-1.5 rounded-lg hover:bg-slate-100 text-slate-500"
                  title="Close"
                >
                  <X size={18} />
                </button>
              </div>
              <div className="p-4 space-y-3 flex-1 min-h-0 flex flex-col">
                {(selectedEvent.startTime || selectedEvent.endTime) && (
                  <div className="flex items-center gap-2 text-slate-600">
                    <Clock size={16} className="shrink-0 text-slate-400" />
                    <span className="text-sm">
                      {[selectedEvent.startTime, selectedEvent.endTime].filter(Boolean).join(' – ') || '—'}
                    </span>
                  </div>
                )}
                <div className="flex-1 min-h-0 flex flex-col">
                  <label className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-1.5 block">Memo / Notes</label>
                  <textarea
                    value={detailMemo}
                    onChange={(e) => setDetailMemo(e.target.value)}
                    onBlur={handleSaveMemo}
                    placeholder="Add notes or description..."
                    rows={4}
                    className="w-full px-3 py-2 border border-slate-200 rounded-xl text-sm text-slate-700 placeholder:text-slate-400 resize-y min-h-[100px]"
                  />
                  <button
                    type="button"
                    onClick={handleSaveMemo}
                    disabled={savingMemo}
                    className="mt-2 px-3 py-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-700 text-sm font-medium disabled:opacity-50"
                  >
                    {savingMemo ? 'Saving…' : 'Save memo'}
                  </button>
                </div>
                <button
                  type="button"
                  onClick={() => handleDeleteEvent(selectedEvent.id)}
                  className="flex items-center gap-2 px-3 py-2 rounded-xl border border-red-200 text-red-600 text-sm font-medium hover:bg-red-50 w-full justify-center"
                >
                  <Trash2 size={16} />
                  Delete event
                </button>
              </div>
            </>
          ) : (
            <div className="flex-1 flex flex-col items-center justify-center p-6 text-center text-slate-400">
              <CalendarIcon size={40} className="mb-3 opacity-50" />
              <p className="text-sm font-medium text-slate-500">Select a date or event</p>
              <p className="text-xs mt-1">Click an event on the calendar to view details and edit memo here.</p>
            </div>
          )}
          </div>
        </div>
      </div>

      {modal?.type === 'add' && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" onClick={() => setModal(null)}>
          <form
            className="bg-white rounded-2xl shadow-xl w-full max-w-md p-6 overflow-hidden min-w-0"
            onClick={(e) => e.stopPropagation()}
            onSubmit={handleSaveEvent}
          >
            <h3 className="text-lg font-bold text-slate-800 mb-4">Add event</h3>
            <input
              type="text"
              value={formTitle}
              onChange={(e) => setFormTitle(e.target.value)}
              placeholder="Title"
              className="w-full px-4 py-2 border border-slate-200 rounded-lg text-sm mb-3"
              required
            />
            <input
              type="date"
              value={formDate}
              onChange={(e) => setFormDate(e.target.value)}
              className="w-full px-4 py-2 border border-slate-200 rounded-lg text-sm mb-3"
            />
            <div className="flex gap-2 mb-3 min-w-0">
              <input
                type="text"
                value={formStartTime}
                onChange={(e) => setFormStartTime(formatTimeInput(e.target.value))}
                placeholder="Start (e.g. 09:00)"
                className="flex-1 min-w-0 px-4 py-2 border border-slate-200 rounded-lg text-sm"
              />
              <input
                type="text"
                value={formEndTime}
                onChange={(e) => setFormEndTime(formatTimeInput(e.target.value))}
                placeholder="End (e.g. 18:00)"
                className="flex-1 min-w-0 px-4 py-2 border border-slate-200 rounded-lg text-sm"
              />
            </div>
            <textarea
              value={formDescription}
              onChange={(e) => setFormDescription(e.target.value)}
              placeholder="Memo / Notes (optional)"
              rows={2}
              className="w-full px-4 py-2 border border-slate-200 rounded-lg text-sm mb-3 resize-y"
            />
            <div className="flex gap-2 mb-4">
              {EVENT_COLORS.map((c) => (
                <button
                  key={c}
                  type="button"
                  onClick={() => setFormColor(c)}
                  className={`w-8 h-8 rounded-full ${c} ${formColor === c ? 'ring-2 ring-offset-2 ring-slate-400' : ''}`}
                />
              ))}
            </div>
            <div className="flex gap-2 justify-end">
              <button type="button" onClick={() => setModal(null)} className="px-4 py-2 rounded-lg border border-slate-200 text-sm">
                Cancel
              </button>
              <button type="submit" disabled={saving} className="px-4 py-2 rounded-lg bg-amber-500 text-white text-sm font-medium disabled:opacity-50">
                {saving ? 'Saving…' : 'Save'}
              </button>
            </div>
          </form>
        </div>
      )}

    </div>
  );
};

export default Calendar;
