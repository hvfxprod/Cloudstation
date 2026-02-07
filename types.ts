
export type AppID = 'file-explorer' | 'control-panel' | 'ai-assistant' | 'shared-links' | 'calendar';

export interface WindowState {
  id: AppID;
  title: string;
  isOpen: boolean;
  isMinimized: boolean;
  isMaximized: boolean;
  zIndex: number;
  /** 창 위치(px). 없으면 기본 8% 8% */
  position?: { x: number; y: number };
}

export interface FileItem {
  id: string;
  name: string;
  type: 'file' | 'folder';
  size?: string;
  lastModified: string;
  extension?: string;
  isFavorite?: boolean;
  isDeleted?: boolean;
}

export interface SharedLink {
  id: string;
  fileName: string;
  url: string;
  expiry: string;
  downloads: number;
}

export interface Notification {
  id: string;
  title: string;
  message: string;
  type: 'info' | 'success' | 'warning';
}
