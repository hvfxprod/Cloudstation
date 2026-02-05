const API_BASE = '';

export async function getGeminiKeySet(): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE}/api/settings/gemini-key`);
    if (!res.ok) return false;
    const data = (await res.json()) as { set?: boolean };
    return !!data.set;
  } catch {
    return false;
  }
}

export async function saveGeminiKey(key: string): Promise<void> {
  const res = await fetch(`${API_BASE}/api/settings/gemini-key`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ key: key.trim() }),
  });
  if (!res.ok) {
    const err = (await res.json().catch(() => ({}))) as { error?: string };
    throw new Error(err.error || 'Failed to save');
  }
}

export async function sendAiMessage(message: string): Promise<string> {
  const res = await fetch(`${API_BASE}/api/ai/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message }),
  });
  const data = (await res.json()) as { text?: string; error?: string };
  if (!res.ok) throw new Error(data.error || 'AI request failed');
  return data.text ?? '';
}
