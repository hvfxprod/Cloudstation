
import { create } from 'zustand';
import { AppID, WindowState, FileItem, SharedLink, Notification } from './types';

interface OSState {
  windows: WindowState[];
  activeWindowId: AppID | null;
  files: FileItem[];
  sharedLinks: SharedLink[];
  notifications: Notification[];
  isStartMenuOpen: boolean;
  
  toggleStartMenu: () => void;
  openWindow: (id: AppID, title: string) => void;
  closeWindow: (id: AppID) => void;
  minimizeWindow: (id: AppID) => void;
  maximizeWindow: (id: AppID) => void;
  focusWindow: (id: AppID) => void;
  updateWindowPosition: (id: AppID, x: number, y: number) => void;
  
  addFile: (file: Omit<FileItem, 'id' | 'lastModified'>) => void;
  toggleFavorite: (id: string) => void;
  deleteFile: (id: string) => void;
  restoreFile: (id: string) => void;
  permanentlyDeleteFile: (id: string) => void;
  
  createSharedLink: (fileName: string) => void;
  deleteSharedLink: (id: string) => void;
  
  addNotification: (title: string, message: string, type?: Notification['type']) => void;
  removeNotification: (id: string) => void;
}

export const useOSStore = create<OSState>((set) => ({
  windows: [],
  activeWindowId: null,
  isStartMenuOpen: false,
  files: [],
  sharedLinks: [],
  notifications: [],

  toggleStartMenu: () => set((state) => ({ isStartMenuOpen: !state.isStartMenuOpen })),

  openWindow: (id, title) => set((state) => {
    const maxZ = Math.max(...state.windows.map(win => win.zIndex), 0);
    const existing = state.windows.find(w => w.id === id);
    
    if (existing) {
      return { 
        activeWindowId: id,
        isStartMenuOpen: false,
        windows: state.windows.map(w => w.id === id 
          ? { ...w, isMinimized: false, zIndex: maxZ + 1 } 
          : w
        )
      };
    }
    
    const newWindow: WindowState = {
      id,
      title,
      isOpen: true,
      isMinimized: false,
      isMaximized: false,
      zIndex: maxZ + 1,
    };
    
    return {
      windows: [...state.windows, newWindow],
      activeWindowId: id,
      isStartMenuOpen: false,
    };
  }),

  closeWindow: (id) => set((state) => ({
    windows: state.windows.filter(w => w.id !== id),
    activeWindowId: state.activeWindowId === id ? null : state.activeWindowId,
  })),

  minimizeWindow: (id) => set((state) => ({
    windows: state.windows.map(w => w.id === id ? { ...w, isMinimized: true } : w),
    activeWindowId: state.activeWindowId === id ? null : state.activeWindowId,
  })),

  maximizeWindow: (id) => set((state) => ({
    windows: state.windows.map(w => w.id === id ? { ...w, isMaximized: !w.isMaximized } : w),
  })),

  focusWindow: (id) => set((state) => ({
    activeWindowId: id,
    windows: state.windows.map(w => ({
      ...w,
      zIndex: w.id === id ? Math.max(...state.windows.map(win => win.zIndex), 0) + 1 : w.zIndex
    }))
  })),

  updateWindowPosition: (id, x, y) => set((state) => ({
    windows: state.windows.map(w => w.id === id ? { ...w, position: { x, y } } : w)
  })),

  addFile: (file) => set((state) => {
    const newFile: FileItem = {
      ...file,
      id: Math.random().toString(36).substr(2, 9),
      lastModified: new Date().toISOString().split('T')[0],
      isDeleted: false,
      isFavorite: false
    };
    return { files: [newFile, ...state.files] };
  }),

  toggleFavorite: (id) => set((state) => ({
    files: state.files.map(f => f.id === id ? { ...f, isFavorite: !f.isFavorite } : f)
  })),

  deleteFile: (id) => set((state) => ({
    files: state.files.map(f => f.id === id ? { ...f, isDeleted: true } : f)
  })),

  restoreFile: (id) => set((state) => ({
    files: state.files.map(f => f.id === id ? { ...f, isDeleted: false } : f)
  })),

  permanentlyDeleteFile: (id) => set((state) => ({
    files: state.files.filter(f => f.id !== id)
  })),

  createSharedLink: (fileName) => set((state) => {
    const newLink: SharedLink = {
      id: Math.random().toString(36).substr(2, 9),
      fileName,
      url: `https://cloud.share/${Math.random().toString(36).substr(2, 5)}`,
      expiry: '30 days',
      downloads: 0
    };
    
    const notification: Notification = {
      id: Math.random().toString(36).substr(2, 9),
      title: 'Link Created',
      message: `Shared link for ${fileName} is ready.`,
      type: 'success'
    };

    return {
      sharedLinks: [newLink, ...state.sharedLinks],
      notifications: [notification, ...state.notifications]
    };
  }),

  deleteSharedLink: (id) => set((state) => ({
    sharedLinks: state.sharedLinks.filter(l => l.id !== id)
  })),

  addNotification: (title, message, type = 'info') => set((state) => ({
    notifications: [{ id: Math.random().toString(36).substr(2, 9), title, message, type }, ...state.notifications]
  })),

  removeNotification: (id) => set((state) => ({
    notifications: state.notifications.filter(n => n.id !== id)
  })),
}));
