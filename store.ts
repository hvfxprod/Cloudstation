
import { create } from 'zustand';
import { AppID, WindowState, FileItem, SharedLink, Notification, RecentItem, FavoriteDriveItem } from './types';

export type ThemeMode = 'light' | 'dark' | 'dynamic';
export type BackgroundPreset = string;

const CUSTOMIZATION_KEY = 'cloudstation-customization';
const FILES_KEY = 'cloudstation-files';
const RECENT_KEY = 'cloudstation-recent';
const FAVORITE_DRIVE_KEY = 'cloudstation-favorite-drive';

interface CustomizationState {
  theme: ThemeMode;
  background: BackgroundPreset;
  backgroundCustomUrl: string;
}

function loadCustomization(): CustomizationState {
  try {
    const raw = localStorage.getItem(CUSTOMIZATION_KEY);
    if (raw) {
      const p = JSON.parse(raw) as Partial<CustomizationState>;
      return {
        theme: p.theme === 'dark' || p.theme === 'dynamic' ? p.theme : 'light',
        background: typeof p.background === 'string' ? p.background : 'default',
        backgroundCustomUrl: typeof p.backgroundCustomUrl === 'string' ? p.backgroundCustomUrl : '',
      };
    }
  } catch {
    // ignore
  }
  return { theme: 'light', background: 'default', backgroundCustomUrl: '' };
}

function saveCustomization(s: CustomizationState) {
  try {
    localStorage.setItem(CUSTOMIZATION_KEY, JSON.stringify(s));
  } catch {
    // ignore
  }
}

function loadFiles(): FileItem[] {
  try {
    const raw = localStorage.getItem(FILES_KEY);
    if (raw) {
      const arr = JSON.parse(raw);
      return Array.isArray(arr) ? arr : [];
    }
  } catch {
    // ignore
  }
  return [];
}

function saveFiles(files: FileItem[]) {
  try {
    localStorage.setItem(FILES_KEY, JSON.stringify(files));
  } catch {
    // ignore
  }
}

function loadRecent(): RecentItem[] {
  try {
    const raw = localStorage.getItem(RECENT_KEY);
    if (raw) {
      const arr = JSON.parse(raw);
      return Array.isArray(arr) ? arr : [];
    }
  } catch {
    // ignore
  }
  return [];
}

function saveRecent(items: RecentItem[]) {
  try {
    localStorage.setItem(RECENT_KEY, JSON.stringify(items.slice(0, 100)));
  } catch {
    // ignore
  }
}

function loadFavoriteDrive(): FavoriteDriveItem[] {
  try {
    const raw = localStorage.getItem(FAVORITE_DRIVE_KEY);
    if (raw) {
      const arr = JSON.parse(raw);
      return Array.isArray(arr) ? arr : [];
    }
  } catch {
    // ignore
  }
  return [];
}

function saveFavoriteDrive(items: FavoriteDriveItem[]) {
  try {
    localStorage.setItem(FAVORITE_DRIVE_KEY, JSON.stringify(items));
  } catch {
    // ignore
  }
}

interface OSState extends CustomizationState {
  windows: WindowState[];
  activeWindowId: AppID | null;
  files: FileItem[];
  recentItems: RecentItem[];
  favoriteDriveItems: FavoriteDriveItem[];
  sharedLinks: SharedLink[];
  notifications: Notification[];
  isStartMenuOpen: boolean;
  timezone: string;
  language: string;

  setTheme: (theme: ThemeMode) => void;
  setBackground: (background: BackgroundPreset) => void;
  setBackgroundCustomUrl: (url: string) => void;
  setTimezone: (tz: string) => void;
  setLanguage: (lang: string) => void;
  toggleStartMenu: () => void;
  openWindow: (id: AppID, title: string) => void;
  closeWindow: (id: AppID) => void;
  minimizeWindow: (id: AppID) => void;
  maximizeWindow: (id: AppID) => void;
  focusWindow: (id: AppID) => void;
  updateWindowPosition: (id: AppID, x: number, y: number) => void;

  addFile: (file: Omit<FileItem, 'id' | 'lastModified'>) => void;
  toggleFavorite: (id: string) => void;
  addToRecent: (item: { id: string; path?: string; name: string; type: 'file' | 'folder' }) => void;
  toggleDriveFavorite: (path: string, name: string) => void;
  deleteFile: (id: string) => void;
  restoreFile: (id: string) => void;
  permanentlyDeleteFile: (id: string) => void;

  createSharedLink: (fileName: string) => void;
  deleteSharedLink: (id: string) => void;

  addNotification: (title: string, message: string, type?: Notification['type']) => void;
  removeNotification: (id: string) => void;
}

const initialCustom = loadCustomization();

export const useOSStore = create<OSState>((set, get) => ({
  ...initialCustom,
  windows: [],
  activeWindowId: null,
  isStartMenuOpen: false,
  files: loadFiles(),
  recentItems: loadRecent(),
  favoriteDriveItems: loadFavoriteDrive(),
  sharedLinks: [],
  notifications: [],
  timezone: 'UTC',
  language: 'en',

  setTheme: (theme) => {
    set({ theme });
    const s = get();
    saveCustomization({ theme: s.theme, background: s.background, backgroundCustomUrl: s.backgroundCustomUrl });
  },
  setBackground: (background) => {
    set({ background });
    const s = get();
    saveCustomization({ theme: s.theme, background: s.background, backgroundCustomUrl: s.backgroundCustomUrl });
  },
  setBackgroundCustomUrl: (url) => {
    set({ backgroundCustomUrl: url });
    const s = get();
    saveCustomization({ theme: s.theme, background: s.background, backgroundCustomUrl: url });
  },
  setTimezone: (tz) => set({ timezone: typeof tz === 'string' && tz.trim() ? tz.trim() : 'UTC' }),
  setLanguage: (lang) => set({ language: (lang === 'ko' || lang === 'en') ? lang : 'en' }),
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
      lastModified: new Date().toISOString(),
      isDeleted: false,
      isFavorite: false
    };
    const next = { files: [newFile, ...state.files] };
    saveFiles(next.files);
    return next;
  }),

  toggleFavorite: (id) => set((state) => {
    const files = state.files.map(f => f.id === id ? { ...f, isFavorite: !f.isFavorite } : f);
    saveFiles(files);
    return { files };
  }),

  addToRecent: (item) => set((state) => {
    const now = new Date().toISOString();
    const existing = state.recentItems.find(r => r.id === item.id);
    const rest = state.recentItems.filter(r => r.id !== item.id);
    const next: RecentItem = {
      id: item.id,
      path: item.path,
      name: item.name,
      type: item.type,
      lastAccessed: now
    };
    const recentItems = [next, ...rest].slice(0, 100);
    saveRecent(recentItems);
    return { recentItems };
  }),

  toggleDriveFavorite: (path, name) => set((state) => {
    const exists = state.favoriteDriveItems.some(f => f.path === path);
    const favoriteDriveItems = exists
      ? state.favoriteDriveItems.filter(f => f.path !== path)
      : [...state.favoriteDriveItems, { path, name }];
    saveFavoriteDrive(favoriteDriveItems);
    return { favoriteDriveItems };
  }),

  deleteFile: (id) => set((state) => {
    const files = state.files.map(f => f.id === id ? { ...f, isDeleted: true } : f);
    saveFiles(files);
    return { files };
  }),

  restoreFile: (id) => set((state) => {
    const files = state.files.map(f => f.id === id ? { ...f, isDeleted: false } : f);
    saveFiles(files);
    return { files };
  }),

  permanentlyDeleteFile: (id) => set((state) => {
    const files = state.files.filter(f => f.id !== id);
    saveFiles(files);
    return { files };
  }),

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
