const API_BASE = '';

export interface FsItem {
  id: string;
  name: string;
  type: 'file' | 'folder';
  size?: string;
  lastModified: string;
}

export interface FsListResponse {
  path: string;
  items: FsItem[];
}

export async function listDir(relativePath: string): Promise<FsListResponse> {
  const pathEnc = encodeURIComponent(relativePath);
  const res = await fetch(`${API_BASE}/api/fs?path=${pathEnc}`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error((err as { error?: string }).error || res.statusText);
  }
  return res.json();
}

export function downloadUrl(relativePath: string): string {
  return `${API_BASE}/api/fs/download?path=${encodeURIComponent(relativePath)}`;
}

export async function createFolder(relativePath: string): Promise<void> {
  const res = await fetch(`${API_BASE}/api/fs/folder`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ path: relativePath }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error((err as { error?: string }).error || res.statusText);
  }
}

// ---------- 파일 공유 (실제 공유 링크) ----------
export interface ShareItem {
  id: string;
  token: string;
  path: string;
  fileName: string;
  isDir: boolean;
  expiresAt: string | null;
  isExpired: boolean;
  accessCount: number;
  createdAt: string;
  url: string;
}

export async function getShares(): Promise<ShareItem[]> {
  const res = await fetch(`${API_BASE}/api/shares`, { credentials: 'include' });
  if (!res.ok) throw new Error('Failed to load shares');
  const data = await res.json();
  return (data as { shares?: ShareItem[] }).shares ?? [];
}

export async function createShare(path: string, isDir: boolean, expiresInDays?: number): Promise<{ url: string; token: string }> {
  const res = await fetch(`${API_BASE}/api/shares`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ path, isDir, expiresInDays }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error((err as { error?: string }).error || 'Failed to create share');
  }
  const data = await res.json() as { url: string; token: string };
  return { url: data.url, token: data.token };
}

export async function deleteShare(id: string): Promise<void> {
  const res = await fetch(`${API_BASE}/api/shares/${encodeURIComponent(id)}`, { method: 'DELETE', credentials: 'include' });
  if (!res.ok) throw new Error('Failed to delete share');
}

/** 공유 링크 전체 URL (같은 오리진이면 그대로, 아니면 절대 경로) */
export function shareFullUrl(urlPath: string): string {
  if (typeof window !== 'undefined') {
    return urlPath.startsWith('http') ? urlPath : `${window.location.origin}${urlPath}`;
  }
  return urlPath;
}
