import React, { useState, useEffect } from 'react';
import { Link2, Copy, Trash2, ExternalLink, ShieldCheck, Loader2 } from 'lucide-react';
import { useOSStore } from '../../store';
import { getShares, deleteShare, shareFullUrl, type ShareItem } from '../../lib/api';

async function safeCopyToClipboard(text: string): Promise<boolean> {
  if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // fall through
    }
  }
  if (typeof document !== 'undefined') {
    try {
      const textarea = document.createElement('textarea');
      textarea.value = text;
      textarea.style.position = 'fixed';
      textarea.style.opacity = '0';
      textarea.style.left = '-9999px';
      document.body.appendChild(textarea);
      textarea.focus();
      textarea.select();
      const ok = typeof document.execCommand === 'function'
        ? document.execCommand('copy')
        : false;
      document.body.removeChild(textarea);
      if (ok) return true;
    } catch {
      // ignore
    }
  }
  return false;
}

const SharedLinks: React.FC = () => {
  const { addNotification } = useOSStore();
  const [shares, setShares] = useState<ShareItem[]>([]);
  const [loading, setLoading] = useState(true);

  const load = async () => {
    setLoading(true);
    try {
      const list = await getShares();
      setShares(list);
    } catch {
      addNotification('Error', 'Failed to load shared links', 'warning');
      setShares([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const copyToClipboard = async (text: string) => {
    const copied = await safeCopyToClipboard(text);
    if (copied) {
      addNotification('Copied', 'Link copied to clipboard', 'info');
    } else {
      addNotification('Copied', `Copy this link manually:\n${text}`, 'info');
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await deleteShare(id);
      setShares((prev) => prev.filter((s) => s.id !== id));
      addNotification('Revoked', 'Shared link has been revoked', 'info');
    } catch {
      addNotification('Error', 'Failed to revoke link', 'warning');
    }
  };

  const expiryLabel = (s: ShareItem) => {
    if (s.isExpired) return 'Expired';
    if (s.expiresAt) return `Expires ${new Date(s.expiresAt).toLocaleDateString('ko-KR')}`;
    return 'Permanent';
  };

  return (
    <div className="flex flex-col h-full bg-slate-50 p-6 overflow-auto">
      <div className="mb-8">
        <h2 className="text-2xl font-bold text-slate-800 flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-emerald-100 flex items-center justify-center text-emerald-600">
            <Link2 size={24} />
          </div>
          Shared Links Manager
        </h2>
        <p className="text-sm text-slate-500 mt-2">Manage access and track downloads for your shared content.</p>
      </div>

      {loading && (
        <div className="flex items-center justify-center py-12 gap-2 text-slate-500">
          <Loader2 size={24} className="animate-spin" /> Loading...
        </div>
      )}

      {!loading && (
        <div className="grid gap-4 max-w-4xl">
          {shares.map((link) => {
            const fullUrl = shareFullUrl(link.url);
            return (
              <div key={link.id} className="bg-white p-5 rounded-2xl border border-slate-200 shadow-sm hover:shadow-md transition-all group">
                <div className="flex items-start justify-between mb-4">
                  <div className="flex items-center gap-4">
                    <div className="w-12 h-12 rounded-xl bg-slate-100 flex items-center justify-center text-slate-400 group-hover:bg-emerald-50 group-hover:text-emerald-500 transition-colors">
                      <ExternalLink size={24} />
                    </div>
                    <div>
                      <h4 className="font-bold text-slate-800 text-lg">{link.fileName}</h4>
                      <div className="flex items-center gap-3 text-xs text-slate-500 mt-1">
                        <span className="flex items-center gap-1.5 px-2 py-0.5 bg-slate-100 rounded-full font-medium">
                          <ShieldCheck size={12} /> Public Link
                        </span>
                        <span>{expiryLabel(link)}</span>
                        {link.isDir && <span className="px-2 py-0.5 bg-blue-100 text-blue-700 rounded-full">Folder</span>}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => copyToClipboard(fullUrl)}
                      className="p-2.5 hover:bg-emerald-50 hover:text-emerald-600 rounded-xl transition-all text-slate-500"
                      title="Copy Link"
                    >
                      <Copy size={18} />
                    </button>
                    <button
                      onClick={() => handleDelete(link.id)}
                      className="p-2.5 hover:bg-red-50 hover:text-red-600 rounded-xl transition-all text-slate-500"
                      title="Revoke Access"
                    >
                      <Trash2 size={18} />
                    </button>
                  </div>
                </div>
                <div className="flex items-center gap-4 p-2 bg-slate-50 rounded-xl border border-slate-100">
                  <div className="flex-1 px-2 text-xs font-mono text-slate-400 truncate">{fullUrl}</div>
                  <div className="text-xs font-bold text-slate-600 bg-white px-3 py-1 rounded-lg border border-slate-200">
                    {link.accessCount} Hits
                  </div>
                  <a
                    href={link.url}
                    target="_blank"
                    rel="noreferrer"
                    className="p-1.5 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
                  >
                    <ExternalLink size={16} />
                  </a>
                </div>
              </div>
            );
          })}
          {shares.length === 0 && (
            <div className="flex flex-col items-center justify-center py-24 text-slate-400 border-2 border-dashed border-slate-200 rounded-3xl bg-slate-50/50">
              <Link2 size={64} className="opacity-5 mb-4" />
              <p className="text-lg font-medium">No links are currently active</p>
              <p className="text-sm mt-1">In File Station, open My Drive and use Share on a file or folder to create a link.</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default SharedLinks;
