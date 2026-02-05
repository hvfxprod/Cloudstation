import React, { useState, useRef, useMemo, useEffect } from 'react';
import { 
  Search, 
  Plus, 
  Upload, 
  Download, 
  Share2, 
  Trash2, 
  File as FileIcon, 
  Folder, 
  Star,
  Clock,
  HardDrive,
  RotateCcw,
  ChevronRight,
  Loader2,
  Home
} from 'lucide-react';
import { useOSStore } from '../../store';
import { listDir, downloadUrl, createFolder, createShare, shareFullUrl, type FsItem } from '../../lib/api';

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

type NavTab = 'drive' | 'favorites' | 'recent' | 'recycle';

const FileExplorer: React.FC = () => {
  const { files, deleteFile, restoreFile, permanentlyDeleteFile, addFile, toggleFavorite, createSharedLink, addNotification } = useOSStore();
  const [shareLoadingId, setShareLoadingId] = useState<string | null>(null);
  const [activeNav, setActiveNav] = useState<NavTab>('drive');
  const [selectedFileId, setSelectedFileId] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // My Drive (API) — 서버 마운트 경로 연동
  const [drivePath, setDrivePath] = useState('');
  const [driveItems, setDriveItems] = useState<FsItem[]>([]);
  const [driveLoading, setDriveLoading] = useState(false);
  const [driveError, setDriveError] = useState<string | null>(null);

  const loadDrive = async (path: string) => {
    setDriveLoading(true);
    setDriveError(null);
    try {
      const data = await listDir(path);
      setDriveItems(data.items);
    } catch (e) {
      setDriveError(e instanceof Error ? e.message : 'Failed to load');
      setDriveItems([]);
    } finally {
      setDriveLoading(false);
    }
  };

  useEffect(() => {
    if (activeNav === 'drive') loadDrive(drivePath);
  }, [activeNav, drivePath]);

  const driveBreadcrumbs = useMemo(() => {
    const parts = drivePath ? drivePath.replace(/\\/g, '/').split('/').filter(Boolean) : [];
    return [{ name: 'My Drive', path: '' }, ...parts.map((name, i) => ({ name, path: parts.slice(0, i + 1).join('/') }))];
  }, [drivePath]);

  const filteredFiles = useMemo(() => {
    switch (activeNav) {
      case 'favorites':
        return files.filter(f => f.isFavorite && !f.isDeleted);
      case 'recent':
        return [...files].filter(f => !f.isDeleted).sort((a, b) => new Date(b.lastModified).getTime() - new Date(a.lastModified).getTime());
      case 'recycle':
        return files.filter(f => f.isDeleted);
      default:
        return files.filter(f => !f.isDeleted);
    }
  }, [files, activeNav]);

  const displayItems = activeNav === 'drive' ? driveItems : filteredFiles;
  const isDrive = activeNav === 'drive';

  const handleUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      addFile({
        name: file.name,
        type: 'file',
        size: `${(file.size / (1024 * 1024)).toFixed(1)} MB`
      });
      addNotification('File Uploaded', `${file.name} added to My Drive`, 'success');
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  const createNewFolder = () => {
    const name = prompt('Folder name:', 'New Folder');
    if (!name) return;
    if (isDrive) {
      const newPath = drivePath ? `${drivePath}/${name}` : name;
      createFolder(newPath).then(() => {
        addNotification('Folder Created', `Folder "${name}" created.`, 'info');
        loadDrive(drivePath);
      }).catch((e) => addNotification('Error', e.message, 'warning'));
    } else {
      addFile({ name, type: 'folder' });
      addNotification('Folder Created', `Folder "${name}" created.`, 'info');
    }
  };

  const handleDriveRowClick = (item: FsItem) => {
    if (item.type === 'folder') {
      const newPath = drivePath ? `${drivePath}/${item.name}` : item.name;
      setDrivePath(newPath);
    }
    setSelectedFileId(item.id);
  };

  const handleDownload = (item: { id: string; name: string; type: string }) => {
    if (isDrive && item.type === 'file') {
      window.open(downloadUrl(item.id), '_blank');
    }
  };

  const handleShareDrive = async (item: FsItem) => {
    setShareLoadingId(item.id);
    try {
      const { url } = await createShare(item.id, item.type === 'folder', 7);
      const full = shareFullUrl(url);
      const copied = await safeCopyToClipboard(full);
      if (copied) {
        addNotification('공유 링크 생성', '링크가 클립보드에 복사되었습니다. Shared Links에서 관리할 수 있습니다.', 'success');
      } else {
        addNotification('공유 링크 생성', `링크가 생성되었습니다.\n${full}`, 'info');
      }
    } catch (e) {
      addNotification('공유 실패', e instanceof Error ? e.message : 'Failed to create share', 'warning');
    } finally {
      setShareLoadingId(null);
    }
  };

  const getIcon = (type: string) => {
    return type === 'folder' 
      ? <Folder className="text-blue-500 fill-blue-500/20" size={20} /> 
      : <FileIcon className="text-slate-400" size={20} />;
  };

  return (
    <div className="flex h-full text-slate-700">
      <input 
        type="file" 
        ref={fileInputRef} 
        className="hidden" 
        onChange={handleUpload} 
      />
      
      {/* Sidebar */}
      <div className="w-64 border-r border-black/5 bg-slate-50/50 p-4 space-y-6 shrink-0">
        <div>
          <h3 className="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-2 px-2">Navigation</h3>
          <nav className="space-y-1">
            <button 
              onClick={() => { setActiveNav('drive'); setDrivePath(''); }}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg transition-colors font-medium ${activeNav === 'drive' ? 'bg-blue-500/10 text-blue-600' : 'hover:bg-black/5'}`}
            >
              <HardDrive size={18} /> My Drive
            </button>
            <button 
              onClick={() => setActiveNav('favorites')}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg transition-colors font-medium ${activeNav === 'favorites' ? 'bg-blue-500/10 text-blue-600' : 'hover:bg-black/5'}`}
            >
              <Star size={18} /> Favorites
            </button>
            <button 
              onClick={() => setActiveNav('recent')}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg transition-colors font-medium ${activeNav === 'recent' ? 'bg-blue-500/10 text-blue-600' : 'hover:bg-black/5'}`}
            >
              <Clock size={18} /> Recent
            </button>
            <button 
              onClick={() => setActiveNav('recycle')}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg transition-colors font-medium ${activeNav === 'recycle' ? 'bg-blue-500/10 text-blue-600' : 'hover:bg-black/5'}`}
            >
              <Trash2 size={18} /> Recycle Bin
            </button>
          </nav>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex flex-col min-w-0 bg-white">
        <div className="h-12 border-b border-black/5 flex items-center justify-between px-4 shrink-0">
          <div className="flex items-center gap-2">
            {isDrive && (
              <div className="flex items-center gap-1 text-sm text-slate-600 min-w-0">
                {driveBreadcrumbs.map((b, i) => (
                  <span key={b.path} className="flex items-center gap-1 min-w-0">
                    {i > 0 && <ChevronRight size={14} className="text-slate-400 shrink-0" />}
                    <button
                      type="button"
                      onClick={() => setDrivePath(b.path)}
                      className={`flex items-center gap-1 truncate max-w-[120px] ${i === 0 ? 'font-medium' : ''} hover:text-blue-600`}
                    >
                      {i === 0 && <Home size={14} />}
                      <span className="truncate">{b.name}</span>
                    </button>
                  </span>
                ))}
              </div>
            )}
            {activeNav !== 'recycle' && !isDrive && (
              <>
                <button 
                  onClick={createNewFolder}
                  className="flex items-center gap-2 px-3 py-1.5 bg-blue-600 text-white rounded-md text-sm font-medium hover:bg-blue-700 transition-colors"
                >
                  <Plus size={16} /> New
                </button>
                <button 
                  onClick={() => fileInputRef.current?.click()}
                  className="flex items-center gap-2 px-3 py-1.5 border border-slate-200 rounded-md text-sm font-medium hover:bg-slate-50 transition-colors"
                >
                  <Upload size={16} /> Upload
                </button>
              </>
            )}
            {isDrive && (
              <>
                <button 
                  onClick={createNewFolder}
                  className="flex items-center gap-2 px-3 py-1.5 bg-blue-600 text-white rounded-md text-sm font-medium hover:bg-blue-700 transition-colors"
                >
                  <Plus size={16} /> New
                </button>
              </>
            )}
            {activeNav === 'recycle' && filteredFiles.length > 0 && (
              <p className="text-xs text-slate-400 font-medium px-2">Items in Recycle Bin are kept for 30 days.</p>
            )}
          </div>

          <div className="flex items-center gap-4">
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" size={16} />
              <input 
                type="text" 
                placeholder="Search files..."
                className="pl-9 pr-4 py-1.5 bg-slate-100 border-none rounded-md text-sm w-48 focus:ring-2 focus:ring-blue-500 outline-none transition-all focus:w-64"
              />
            </div>
          </div>
        </div>

        <div className="flex-1 overflow-auto p-4">
          {isDrive && driveLoading && (
            <div className="flex items-center justify-center py-24 gap-2 text-slate-500">
              <Loader2 size={24} className="animate-spin" /> Loading...
            </div>
          )}
          {isDrive && driveError && !driveLoading && (
            <div className="flex flex-col items-center justify-center py-24 text-amber-600">
              <p className="font-medium">Could not load folder</p>
              <p className="text-sm">{driveError}</p>
            </div>
          )}
          {(!isDrive || (!driveLoading && !driveError)) && (
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="text-[11px] font-bold text-slate-400 uppercase tracking-wider border-b border-black/5">
                  <th className="px-4 py-2 font-semibold">Name</th>
                  {!isDrive && <th className="px-4 py-2 font-semibold text-center">Favorite</th>}
                  <th className="px-4 py-2 font-semibold">Size</th>
                  <th className="px-4 py-2 font-semibold">Last Modified</th>
                  <th className="px-4 py-2 font-semibold text-right">Action</th>
                </tr>
              </thead>
              <tbody>
                {displayItems.map((file) => (
                  <tr 
                    key={file.id}
                    onClick={() => isDrive ? handleDriveRowClick(file as FsItem) : setSelectedFileId(file.id)}
                    className={`group border-b border-black/5 hover:bg-blue-50/50 cursor-pointer transition-colors ${
                      selectedFileId === file.id ? 'bg-blue-50' : ''
                    }`}
                  >
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-3">
                        {getIcon(file.type)}
                        <span className="text-sm font-medium truncate max-w-[300px]">{file.name}</span>
                      </div>
                    </td>
                    {!isDrive && (
                      <td className="px-4 py-3 text-center">
                        <button 
                          onClick={(e) => { e.stopPropagation(); toggleFavorite(file.id); }}
                          className={`transition-colors p-1 rounded-full hover:bg-slate-100 ${file.isFavorite ? 'text-amber-500' : 'text-slate-200 hover:text-slate-300'}`}
                        >
                          <Star size={16} fill={file.isFavorite ? "currentColor" : "none"} />
                        </button>
                      </td>
                    )}
                    <td className="px-4 py-3 text-sm text-slate-500">{file.size ?? '--'}</td>
                    <td className="px-4 py-3 text-sm text-slate-500">{file.lastModified}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center justify-end gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                        {isDrive ? (
                          <>
                            <button
                              onClick={(e) => { e.stopPropagation(); handleShareDrive(file as FsItem); }}
                              disabled={shareLoadingId === file.id}
                              className="p-1.5 hover:text-blue-600 transition-colors disabled:opacity-50"
                              title="Share"
                            >
                              {shareLoadingId === file.id ? <Loader2 size={16} className="animate-spin" /> : <Share2 size={16} />}
                            </button>
                            {file.type === 'file' && (
                              <a
                                href={downloadUrl(file.id)}
                                target="_blank"
                                rel="noopener noreferrer"
                                onClick={(e) => e.stopPropagation()}
                                className="p-1.5 hover:text-blue-600 transition-colors"
                                title="Download"
                              >
                                <Download size={16} />
                              </a>
                            )}
                          </>
                        ) : activeNav !== 'recycle' ? (
                          <>
                            {file.type === 'file' && (
                              <button 
                                onClick={(e) => { e.stopPropagation(); createSharedLink(file.name); }}
                                className="p-1.5 hover:text-blue-600 transition-colors" 
                                title="Share"
                              >
                                <Share2 size={16} />
                              </button>
                            )}
                            <button 
                              onClick={(e) => { e.stopPropagation(); handleDownload(file); }}
                              className="p-1.5 hover:text-blue-600 transition-colors" 
                              title="Download"
                            >
                              <Download size={16} />
                            </button>
                            <button 
                              onClick={(e) => { e.stopPropagation(); deleteFile(file.id); }}
                              className="p-1.5 hover:text-red-600 transition-colors" 
                              title="Move to Recycle Bin"
                            >
                              <Trash2 size={16} />
                            </button>
                          </>
                        ) : (
                          <>
                            <button 
                              onClick={(e) => { e.stopPropagation(); restoreFile(file.id); }}
                              className="p-1.5 hover:text-blue-600 transition-colors" 
                              title="Restore"
                            >
                              <RotateCcw size={16} />
                            </button>
                            <button 
                              onClick={(e) => { e.stopPropagation(); permanentlyDeleteFile(file.id); }}
                              className="p-1.5 hover:text-red-600 transition-colors" 
                              title="Permanently Delete"
                            >
                              <Trash2 size={16} />
                            </button>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          
          {!isDrive && displayItems.length === 0 && (
            <div className="flex flex-col items-center justify-center py-24 text-slate-400">
              <Folder size={64} className="mb-4 opacity-10" />
              <p className="text-lg font-medium">Empty View</p>
              <p className="text-sm">Nothing found in {activeNav}</p>
            </div>
          )}
          {isDrive && !driveLoading && !driveError && displayItems.length === 0 && (
            <div className="flex flex-col items-center justify-center py-24 text-slate-400">
              <Folder size={64} className="mb-4 opacity-10" />
              <p className="text-lg font-medium">Empty folder</p>
              <p className="text-sm">This folder is empty.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default FileExplorer;
