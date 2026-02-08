import express from 'express';
import cors from 'cors';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import { createReadStream, readFileSync } from 'fs';
import { execSync } from 'child_process';
import archiver from 'archiver';
import crypto from 'crypto';
import os from 'os';
import checkDiskSpace from 'check-disk-space';
import Docker from 'dockerode';
import session from 'express-session';
import speakeasy from 'speakeasy';
import QRCode from 'qrcode';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 9000;

const DATA_PATH = process.env.DATA_PATH || path.join(__dirname, 'data');
/** File Station "My Drive" root (MOUNT_PATH in container). Falls back to DATA_PATH when not set. */
const DRIVE_ROOT = process.env.DRIVE_PATH || DATA_PATH;
const SECURITY_FILE = path.join(DATA_PATH, 'security.json');
const SHARES_FILE = process.env.SHARES_FILE || path.join(__dirname, 'shares.json');
const SFTP_USERS_FILE = process.env.SFTP_USERS_FILE || path.join(DATA_PATH, '.sftp_users.json');
const SFTP_CONTAINER_NAME = process.env.SFTP_CONTAINER_NAME || 'cloudstation-sftp';
const SFTP_HOST_MOUNT_ROOT = process.env.SFTP_HOST_MOUNT_ROOT || DATA_PATH;
const GENERAL_FILE = path.join(DATA_PATH, 'general.json');
const CALENDAR_FILE = path.join(DATA_PATH, 'calendar.json');
const ENCRYPTION_SECRET = process.env.ENCRYPTION_SECRET || 'cloudstation-gemini-key-secret-change-in-production';
/** TrueNAS: env only */
const TRUENAS_URL = (process.env.TRUENAS_URL || '').replace(/\/$/, '');
const TRUENAS_API_KEY = process.env.TRUENAS_API_KEY || '';
/** AI Assistant: env only */
const GEMINI_API_KEY = (process.env.GEMINI_API_KEY || '').trim();
/** Browse root for mount path picker (server filesystem) */
const BROWSE_ROOT = process.env.MOUNT_BROWSE_ROOT || (path.sep === '\\' ? 'C:\\' : '/');

const ALGO = 'aes-256-gcm';
const IV_LEN = 16;
const AUTH_TAG_LEN = 16;
const KEY_LEN = 32;

// In-memory log buffer for System Log tab (last 500 entries)
const LOG_BUFFER_MAX = 500;
const logBuffer = [];
function formatLogArgs(args) {
  return args.map((a) => (typeof a === 'object' ? JSON.stringify(a) : String(a))).join(' ');
}
function pushLog(level, args) {
  const text = formatLogArgs(args);
  logBuffer.push({ time: new Date().toISOString(), level, text });
  if (logBuffer.length > LOG_BUFFER_MAX) logBuffer.shift();
}
(function patchConsole() {
  const origLog = console.log;
  const origWarn = console.warn;
  const origError = console.error;
  console.log = (...args) => { origLog.apply(console, args); pushLog('log', args); };
  console.warn = (...args) => { origWarn.apply(console, args); pushLog('warn', args); };
  console.error = (...args) => { origError.apply(console, args); pushLog('error', args); };
})();

function getEncryptionKey() {
  const buf = crypto.createHash('sha256').update(ENCRYPTION_SECRET, 'utf8').digest();
  return buf;
}

function encryptKey(plaintext) {
  const key = getEncryptionKey();
  const iv = crypto.randomBytes(IV_LEN);
  const cipher = crypto.createCipheriv(ALGO, key, iv);
  const enc = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([iv, authTag, enc]).toString('base64');
}

function decryptKey(blob) {
  const key = getEncryptionKey();
  const buf = Buffer.from(blob, 'base64');
  if (buf.length < IV_LEN + AUTH_TAG_LEN) throw new Error('Invalid blob');
  const iv = buf.subarray(0, IV_LEN);
  const authTag = buf.subarray(IV_LEN, IV_LEN + AUTH_TAG_LEN);
  const enc = buf.subarray(IV_LEN + AUTH_TAG_LEN);
  const decipher = crypto.createDecipheriv(ALGO, key, iv);
  decipher.setAuthTag(authTag);
  return decipher.update(enc) + decipher.final('utf8');
}

async function readGeneralConfig() {
  try {
    const raw = await fs.readFile(GENERAL_FILE, 'utf8');
    const data = JSON.parse(raw);
    return typeof data === 'object' && data !== null ? data : {};
  } catch {
    return {};
  }
}

async function writeGeneralConfig(obj) {
  await fs.mkdir(path.dirname(GENERAL_FILE), { recursive: true }).catch(() => {});
  await fs.writeFile(GENERAL_FILE, JSON.stringify(obj, null, 2), 'utf8');
}

/** TrueNAS URL + API key: env only (TRUENAS_URL, TRUENAS_API_KEY) */
function getTrueNASConfig() {
  return { url: TRUENAS_URL, key: TRUENAS_API_KEY };
}

function resolveSafe(relativePath) {
  const normalized = path.normalize(relativePath || '').replace(/^(\.\.(\/|\\|$))+/, '');
  const full = path.resolve(DATA_PATH, normalized);
  if (!full.startsWith(path.resolve(DATA_PATH))) {
    return null;
  }
  return full;
}

/** Resolve path under DRIVE_ROOT (for File Station "My Drive"). */
function resolveDriveSafe(relativePath) {
  const normalized = path.normalize(relativePath || '').replace(/^(\.\.(\/|\\|$))+/, '');
  const full = path.resolve(DRIVE_ROOT, normalized);
  if (!full.startsWith(path.resolve(DRIVE_ROOT))) {
    return null;
  }
  return full;
}

async function readShares() {
  try {
    const raw = await fs.readFile(SHARES_FILE, 'utf8');
    const data = JSON.parse(raw);
    return Array.isArray(data) ? data : [];
  } catch {
    return [];
  }
}

async function writeShares(shares) {
  await fs.writeFile(SHARES_FILE, JSON.stringify(shares, null, 2), 'utf8');
}

// ---------- SFTP Store (users + pending + delete_pending + port) ----------
const USERNAME_RE = /^[A-Za-z0-9._-]+$/;
async function readSftpStore() {
  try {
    const raw = await fs.readFile(SFTP_USERS_FILE, 'utf8');
    const data = JSON.parse(raw);
    return {
      users: Array.isArray(data.users) ? data.users : [],
      pending: Array.isArray(data.pending) ? data.pending : [],
      delete_pending: Array.isArray(data.delete_pending) ? data.delete_pending : [],
      meta: data.meta && typeof data.meta === 'object' ? data.meta : { updated: '', port: 1014 },
    };
  } catch {
    return { users: [], pending: [], delete_pending: [], meta: { updated: '', port: 1014 } };
  }
}

async function writeSftpStore(state) {
  const doc = {
    users: state.users || [],
    pending: state.pending || [],
    delete_pending: state.delete_pending || [],
    meta: state.meta || { updated: '', port: 1014 },
  };
  doc.meta.updated = new Date().toISOString();
  await fs.mkdir(path.dirname(SFTP_USERS_FILE), { recursive: true }).catch(() => {});
  await fs.writeFile(SFTP_USERS_FILE, JSON.stringify(doc, null, 2), 'utf8');
}

// ---------- Security (Firewall + 2FA + Login) ----------
const defaultSecurity = {
  firewall: { enabled: false, rules: [] },
  twoFa: { enabled: false, secretEncrypted: null },
  auth: { enabled: false, passwordHash: null, salt: null },
};

let securityConfigCache = null;
let securityConfigCacheTs = 0;
const SECURITY_CACHE_MS = 5000;

async function loadSecurityConfig() {
  if (securityConfigCache && Date.now() - securityConfigCacheTs < SECURITY_CACHE_MS) {
    return securityConfigCache;
  }
  try {
    const raw = await fs.readFile(SECURITY_FILE, 'utf8');
    const data = JSON.parse(raw);
    // 2FA is only "enabled" when we have a secret (avoid lockout if enabled but never set up)
    const hasSecret = Boolean(data.twoFa?.secretEncrypted);
    securityConfigCache = {
      firewall: {
        enabled: Boolean(data.firewall?.enabled),
        rules: Array.isArray(data.firewall?.rules) ? data.firewall.rules : [],
      },
      twoFa: {
        enabled: Boolean(data.twoFa?.enabled && hasSecret),
        secretEncrypted: data.twoFa?.secretEncrypted ?? null,
      },
      auth: {
        enabled: Boolean(data.auth?.enabled),
        passwordHash: data.auth?.passwordHash ?? null,
        salt: data.auth?.salt ?? null,
      },
    };
  } catch {
    securityConfigCache = { ...defaultSecurity };
  }
  securityConfigCacheTs = Date.now();
  return securityConfigCache;
}

async function saveSecurityConfig(config) {
  await fs.mkdir(path.dirname(SECURITY_FILE), { recursive: true }).catch(() => {});
  await fs.writeFile(SECURITY_FILE, JSON.stringify(config, null, 2), 'utf8');
  securityConfigCache = config;
  securityConfigCacheTs = Date.now();
}

function getClientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string') {
    const first = xff.split(',')[0].trim();
    if (first) return first;
  }
  return req.socket?.remoteAddress ?? req.ip ?? '127.0.0.1';
}

function ipToBits(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length === 4 && parts.every(Number.isFinite)) {
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
  }
  return null;
}

function ipMatchRule(clientIp, rule) {
  const value = (rule.value || rule.ip || '').trim();
  if (!value) return false;
  if (value.includes('/')) {
    const [cidrIp, prefixStr] = value.split('/');
    const prefix = parseInt(prefixStr, 10);
    if (!Number.isFinite(prefix) || prefix < 0 || prefix > 32) return false;
    const clientBits = ipToBits(clientIp);
    const cidrBits = ipToBits(cidrIp);
    if (clientBits == null || cidrBits == null) return false;
    const mask = prefix === 0 ? 0 : ~((1 << (32 - prefix)) - 1) >>> 0;
    return (clientBits & mask) === (cidrBits & mask);
  }
  return clientIp === value;
}

async function firewallMiddleware(req, res, next) {
  const config = await loadSecurityConfig();
  if (!config.firewall?.enabled || !config.firewall.rules?.length) return next();
  const clientIp = getClientIp(req);
  for (const rule of config.firewall.rules) {
    if (rule.type === 'block' && ipMatchRule(clientIp, rule)) {
      return res.status(403).json({ error: 'Access denied by firewall' });
    }
  }
  const hasAllow = config.firewall.rules.some((r) => r.type === 'allow');
  if (hasAllow) {
    const allowed = config.firewall.rules.some((r) => r.type === 'allow' && ipMatchRule(clientIp, r));
    if (!allowed) return res.status(403).json({ error: 'Access denied by firewall' });
  }
  next();
}

async function require2FAMiddleware(req, res, next) {
  const config = await loadSecurityConfig();
  if (!config.twoFa?.enabled) return next();
  if (req.session?.twoFaVerified) return next();
  const path = (req.path || '').toLowerCase();
  if (path === '/api/security/2fa/status' || path === '/api/security/2fa/verify' || path === '/api/security/2fa/setup') return next();
  return res.status(401).json({ error: '2FA required', code: '2FA_REQUIRED' });
}

const AUTH_SALT_LEN = 16;
const AUTH_KEY_LEN = 64;
function hashPassword(password, salt) {
  const s = Buffer.isBuffer(salt) ? salt : (salt ? Buffer.from(salt, 'base64') : crypto.randomBytes(AUTH_SALT_LEN));
  const h = crypto.scryptSync(String(password), s, AUTH_KEY_LEN);
  return { hash: h.toString('base64'), salt: s.toString('base64') };
}
function verifyPassword(password, saltB64, hashB64) {
  if (!saltB64 || !hashB64) return false;
  try {
    const salt = Buffer.from(saltB64, 'base64');
    const expected = Buffer.from(hashB64, 'base64');
    const actual = crypto.scryptSync(String(password), salt, AUTH_KEY_LEN);
    return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

async function requireAuthMiddleware(req, res, next) {
  const config = await loadSecurityConfig();
  if (!config.auth?.enabled) return next();
  if (req.session?.user) return next();
  const p = (req.path || req.url || '').split('?')[0];
  if (/^\/auth\//.test(p.replace(/^\/api/, ''))) return next();
  return res.status(401).json({ error: 'Login required', code: 'LOGIN_REQUIRED' });
}

function getDocker() {
  try {
    return new Docker({ socketPath: '/var/run/docker.sock' });
  } catch (e) {
    return null;
  }
}

async function removeSftpContainer(docker) {
  try {
    const c = docker.getContainer(SFTP_CONTAINER_NAME);
    await c.remove({ force: true });
  } catch (e) {
    if (e.statusCode !== 404) throw e;
  }
}

async function createAndStartSftp(users, port) {
  const docker = getDocker();
  if (!docker) throw new Error('Docker socket not available');
  await removeSftpContainer(docker);
  const enabled = users.filter((u) => u.enabled !== false);
  if (enabled.length === 0) return;
  const general = await readGeneralConfig();
  const mountRoot = (general.mountPath && String(general.mountPath).trim()) || SFTP_HOST_MOUNT_ROOT;
  const commandLines = enabled.map((u) => `${u.name}:${u.password || ''}:::data`);
  const binds = enabled.map((u) => {
    const m = (u.mount || '').trim();
    const hostPath = m.startsWith('/') ? m : path.join(mountRoot, m).replace(/\\/g, '/');
    return `${hostPath}:/home/${u.name}/data:rw`;
  });
  await docker.createContainer({
    name: SFTP_CONTAINER_NAME,
    Image: 'atmoz/sftp:latest',
    Cmd: commandLines,
    HostConfig: {
      PortBindings: { '22/tcp': [{ HostPort: String(port) }] },
      Binds: binds,
      RestartPolicy: { Name: 'always' },
    },
  });
  const c = docker.getContainer(SFTP_CONTAINER_NAME);
  await c.start();
}

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

app.use(
  session({
    secret: ENCRYPTION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000, sameSite: 'lax' },
  })
);
app.use(firewallMiddleware);

// 정적 파일 (Vite 빌드 결과)
app.use(express.static(path.join(__dirname, '..', 'dist'), { index: 'index.html' }));

// 2FA required for /api except security endpoints
app.use('/api', (req, res, next) => {
  const p = (req.path || req.url || '').split('?')[0];
  if (/\/security\/2fa\/(status|verify|setup|disable)$/.test(p)) return next();
  if (req.method === 'GET' && /\/security\/firewall$/.test(p)) return next();
  return require2FAMiddleware(req, res, next);
});

// Login required for /api when auth is enabled (except auth endpoints)
app.use('/api', (req, res, next) => {
  const p = (req.path || req.url || '').split('?')[0];
  if (/\/auth\//.test(p)) return next();
  return requireAuthMiddleware(req, res, next);
});

// ---------- Auth (Login) ----------
app.get('/api/auth/status', async (req, res) => {
  try {
    const config = await loadSecurityConfig();
    const authEnabled = Boolean(config.auth?.enabled);
    const loggedIn = authEnabled ? Boolean(req.session?.user) : true;
    res.json({ loggedIn, authEnabled, passwordSet: Boolean(config.auth?.passwordHash) });
  } catch (err) {
    res.status(500).json({ error: err.message, loggedIn: false, authEnabled: false });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const config = await loadSecurityConfig();
    if (!config.auth?.enabled) return res.status(400).json({ error: 'Login is not enabled' });
    const { username, password } = req.body || {};
    if (!password || String(password).length < 1) return res.status(400).json({ error: 'Password required' });
    const allowedUser = 'admin';
    if (username !== undefined && username !== null && String(username).trim() !== '' && String(username).trim().toLowerCase() !== allowedUser) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }
    if (!verifyPassword(password, config.auth.salt, config.auth.passwordHash)) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }
    req.session.user = allowedUser;
    res.json({ ok: true, user: allowedUser });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.clearCookie('connect.sid');
    res.json({ ok: true });
  });
});

app.post('/api/auth/setup', async (req, res) => {
  try {
    const config = await loadSecurityConfig();
    const { newPassword } = req.body || {};
    if (!newPassword || String(newPassword).length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    const alreadyLoggedIn = Boolean(req.session?.user);
    const authCurrentlyEnabled = Boolean(config.auth?.enabled);
    if (authCurrentlyEnabled && !alreadyLoggedIn) {
      return res.status(403).json({ error: 'Must be logged in to change password' });
    }
    const { hash, salt } = hashPassword(newPassword, null);
    config.auth = config.auth || {};
    config.auth.passwordHash = hash;
    config.auth.salt = salt;
    if (!authCurrentlyEnabled) config.auth.enabled = true;
    await saveSecurityConfig(config);
    if (!alreadyLoggedIn) req.session.user = 'admin';
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/auth/config', async (req, res) => {
  try {
    const config = await loadSecurityConfig();
    if (!req.session?.user) return res.status(401).json({ error: 'Login required' });
    const { enabled } = req.body || {};
    if (typeof enabled !== 'boolean') return res.status(400).json({ error: 'enabled must be boolean' });
    config.auth = config.auth || {};
    config.auth.enabled = enabled;
    if (!enabled) { config.auth.passwordHash = null; config.auth.salt = null; }
    await saveSecurityConfig(config);
    res.json({ ok: true, enabled });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 디렉터리 목록
app.get('/api/fs', async (req, res) => {
  try {
    const relativePath = (req.query.path || '').toString();
    const dirPath = resolveDriveSafe(relativePath);
    if (!dirPath) {
      return res.status(400).json({ error: 'Invalid path' });
    }
    const stat = await fs.stat(dirPath);
    if (!stat.isDirectory()) {
      return res.status(400).json({ error: 'Not a directory' });
    }
    const entries = await fs.readdir(dirPath, { withFileTypes: true });
    const items = await Promise.all(
      entries.map(async (ent) => {
        const full = path.join(dirPath, ent.name);
        const s = await fs.stat(full).catch(() => null);
        const type = s?.isDirectory() ? 'folder' : 'file';
        let size, lastModified;
        if (s) {
          lastModified = s.mtime.toISOString().split('T')[0];
          if (s.isFile()) size = s.size;
        }
        return {
          id: path.join(relativePath, ent.name).replace(/\\/g, '/'),
          name: ent.name,
          type,
          size: type === 'file' && size != null ? formatSize(size) : undefined,
          lastModified: lastModified || '--',
        };
      })
    );
    res.json({ path: relativePath, items });
  } catch (err) {
    if (err.code === 'ENOENT') return res.status(404).json({ error: 'Not found' });
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// 파일 다운로드
app.get('/api/fs/download', async (req, res) => {
  try {
    const relativePath = (req.query.path || '').toString();
    const filePath = resolveDriveSafe(relativePath);
    if (!filePath) return res.status(400).json({ error: 'Invalid path' });
    const stat = await fs.stat(filePath);
    if (!stat.isFile()) return res.status(400).json({ error: 'Not a file' });
    const name = path.basename(filePath);
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(name)}"`);
    res.setHeader('Content-Type', 'application/octet-stream');
    const stream = (await import('fs')).createReadStream(filePath);
    stream.pipe(res);
  } catch (err) {
    if (err.code === 'ENOENT') return res.status(404).json({ error: 'Not found' });
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// 폴더 생성 (선택)
app.post('/api/fs/folder', async (req, res) => {
  try {
    const relativePath = (req.body?.path || '').toString();
    const dirPath = resolveDriveSafe(relativePath);
    if (!dirPath) return res.status(400).json({ error: 'Invalid path' });
    await fs.mkdir(dirPath, { recursive: true });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

/** TrueNAS API로 호스트 네트워크 설정(호스트명, DNS, 인터페이스) 가져오기 */
async function getTrueNASNetworkInfo() {
  const { url, key } = getTrueNASConfig();
  if (!url || !key) return null;
  const opts = { method: 'GET', headers: TRUENAS_HEADERS(url, key), signal: AbortSignal.timeout(10000) };
  try {
    const [configRes, ifaceRes] = await Promise.all([
      fetch(`${url}/api/v2.0/network/configuration`, opts),
      fetch(`${url}/api/v2.0/interface`, opts),
    ]);
    if (!configRes.ok || !ifaceRes.ok) return null;
    const config = await configRes.json();
    const ifaces = await ifaceRes.json();
    const hostname =
      [config.hostname, config.domain].filter(Boolean).join('.') ||
      config.hostname ||
      config.hostname_local ||
      'TrueNAS';
    let dns = [config.nameserver1, config.nameserver2, config.nameserver3].filter(Boolean);
    if (dns.length === 0 && Array.isArray(config.nameservers)) dns = config.nameservers.filter(Boolean);
    const interfaces = [];
    const list = Array.isArray(ifaces) ? ifaces : ifaces?.data ?? [];
    for (const iface of list) {
      const name = iface.name ?? iface.id ?? iface.type ?? 'unknown';
      const addrs = iface.state?.addresses ?? iface.ipv4_addresses ?? iface.addresses ?? [];
      const arr = Array.isArray(addrs) ? addrs : [];
      for (const a of arr) {
        const address = typeof a === 'string' ? a : (a.address ?? a.addr ?? a);
        if (address && (typeof a !== 'object' || (a.type !== 'inet6' && !String(address).includes(':')))) {
          interfaces.push({ name, address: String(address).split('/')[0], family: 'IPv4', mac: iface.physical_address ?? iface.mac ?? null });
          break;
        }
      }
      if (interfaces.filter((i) => i.name === name).length === 0) {
        const addr = iface.address ?? iface.ipv4_address ?? (Array.isArray(iface.ipv4_addresses) ? iface.ipv4_addresses[0] : null);
        if (addr) {
          const str = typeof addr === 'object' ? (addr.address ?? addr.addr ?? addr) : addr;
          if (str) interfaces.push({ name, address: String(str).split('/')[0], family: 'IPv4', mac: iface.physical_address ?? iface.mac ?? null });
        }
      }
    }
    return { hostname: hostname || 'TrueNAS', interfaces, dns, source: 'truenas' };
  } catch {
    return null;
  }
}

/** Well-known port → service name (for "This Container" LISTEN list) */
const PORT_SERVICE_NAMES = {
  22: 'SSH',
  80: 'HTTP',
  81: 'Nginx Admin',
  443: 'HTTPS',
  1080: 'Kitsu',
  3000: 'Fenrus',
  3306: 'MySQL',
  5432: 'PostgreSQL',
  8065: 'Mattermost',
  8088: 'SFTP Panel',
  9000: 'PHP-FPM',
  9999: 'CloudStation',
  31015: 'Portainer',
  30020: 'Nginx Proxy Manager',
};

/** Linux: /proc/net/tcp, tcp6에서 LISTEN 상태 포트 번호 목록 반환 (중복 제거, 정렬) */
function getListeningPorts() {
  if (process.platform !== 'linux') return [];
  const ports = new Set();
  try {
    for (const name of ['/proc/net/tcp', '/proc/net/tcp6']) {
      try {
        const raw = readFileSync(name, 'utf8');
        const lines = raw.split('\n').slice(1);
        for (const line of lines) {
          const cols = line.trim().split(/\s+/);
          if (cols.length < 4) continue;
          const st = cols[3];
          if (st !== '0A') continue; // 0A = LISTEN
          const local = cols[1];
          const portHex = local.split(':')[1];
          if (!portHex) continue;
          const port = parseInt(portHex, 16);
          if (Number.isFinite(port) && port > 0 && port < 65536) ports.add(port);
        }
      } catch (_) {
        // ignore missing or unreadable
      }
    }
    return [...ports].sort((a, b) => a - b);
  } catch (e) {
    return [];
  }
}

/** LISTEN 포트 목록에 서비스 이름을 붙여 반환. [{ port, name }, ...] */
function getListeningPortsWithNames() {
  const ports = getListeningPorts();
  return ports.map((port) => ({
    port,
    name: PORT_SERVICE_NAMES[port] ?? 'Internal',
  }));
}

/** Linux: lsblk로 물리 디스크 정보 (모델, 용량, 타입) 반환. 실패 시 빈 배열 */
function getDiskHardwareInfo() {
  if (process.platform !== 'linux') return [];
  try {
    const out = execSync('lsblk -J -o NAME,MODEL,SIZE,TYPE,TRAN', { encoding: 'utf8', timeout: 5000 });
    const data = JSON.parse(out);
    const blockdevices = data?.blockdevices;
    if (!Array.isArray(blockdevices)) return [];
    return blockdevices
      .filter((d) => d?.type === 'disk')
      .map((d) => ({
        name: d.name || '',
        model: (d.model || '').trim() || null,
        size: d.size || null,
        type: d.type || 'disk',
        transport: d.tran || null,
      }))
      .filter((d) => d.name);
  } catch (e) {
    return [];
  }
}

// ---------- 시스템 정보 (TrueNAS API 우선, 없으면 OS + checkDiskSpace) ----------
app.get('/api/system', async (req, res) => {
  try {
    let payload = await getSystemFromTrueNAS();
    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const usedMem = totalMem - freeMem;
    const cpus = os.cpus?.() || [];
    const load = os.loadavg?.()[0] ?? 0;
    const cpuPercent = cpus.length ? Math.max(0, Math.min(100, (load / cpus.length) * 100)) : null;
    if (!payload) {
      payload = { cpu: null, memory: null, storage: null, disks: null, source: null };
    }
    const memory = payload.memory ?? { totalBytes: totalMem, usedBytes: usedMem };
    const cpu = payload.cpu ?? { percent: cpuPercent };

    let disks = payload.disks ?? null;
    let storage = payload.storage ?? null;
    if (storage == null) {
      const pathToCheck = DRIVE_ROOT && DRIVE_ROOT !== DATA_PATH ? DRIVE_ROOT : DATA_PATH;
      try {
        const info = await checkDiskSpace(pathToCheck);
        const usedBytes = info.size - info.free;
        storage = {
          path: pathToCheck,
          totalBytes: info.size,
          usedBytes,
        };
      } catch (e) {
        if (pathToCheck !== DATA_PATH) {
          try {
            const info = await checkDiskSpace(DATA_PATH);
            storage = { path: DATA_PATH, totalBytes: info.size, usedBytes: info.size - info.free };
          } catch (e2) {
            console.warn('Failed to read disk space for', pathToCheck, e?.message ?? e);
          }
        } else {
          console.warn('Failed to read disk space for', DATA_PATH, e?.message ?? e);
        }
      }
    }

    const uptimeSeconds = typeof os.uptime === 'function' ? os.uptime() : undefined;
    const loadAvg = typeof os.loadavg === 'function' ? os.loadavg() : undefined;
    const cpuInfo = {
      ...cpu,
      ...(cpus.length > 0 && {
        model: cpus[0]?.model ?? null,
        cores: cpus.length,
      }),
    };
    res.json({
      storage,
      memory,
      cpu: cpuInfo,
      ...(uptimeSeconds != null && Number.isFinite(uptimeSeconds) && { uptimeSeconds }),
      ...(Array.isArray(loadAvg) && loadAvg.length > 0 && { loadAverage: loadAvg }),
      ...(disks != null && { disks }),
      ...(payload.source && { source: payload.source }),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/logs', (req, res) => {
  try {
    const limit = Math.min(Number(req.query.limit) || 200, 500);
    const slice = logBuffer.slice(-limit);
    res.json({ logs: slice });
  } catch (err) {
    res.status(500).json({ error: err.message, logs: [] });
  }
});

// ---------- Security API ----------
app.get('/api/security/firewall', async (req, res) => {
  try {
    const config = await loadSecurityConfig();
    res.json({
      enabled: config.firewall.enabled,
      rules: config.firewall.rules,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/security/firewall', async (req, res) => {
  try {
    const config = await loadSecurityConfig();
    const { enabled, rules } = req.body || {};
    if (typeof enabled === 'boolean') config.firewall.enabled = enabled;
    if (Array.isArray(rules)) {
      config.firewall.rules = rules
        .filter((r) => r && (r.type === 'allow' || r.type === 'block') && (r.value || r.ip))
        .map((r) => ({ type: r.type, value: (r.value || r.ip || '').trim() }));
    }
    await saveSecurityConfig(config);
    res.json({ enabled: config.firewall.enabled, rules: config.firewall.rules });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/security/2fa/status', async (req, res) => {
  try {
    const config = await loadSecurityConfig();
    const hasSecret = Boolean(config.twoFa?.secretEncrypted);
    const enabled = Boolean(config.twoFa?.enabled && hasSecret);
    res.json({
      enabled,
      verified: Boolean(req.session?.twoFaVerified),
    });
  } catch (err) {
    res.status(500).json({ error: err.message, enabled: false, verified: false });
  }
});

app.post('/api/security/2fa/setup', async (req, res) => {
  try {
    const config = await loadSecurityConfig();
    const secret = speakeasy.generateSecret({ name: 'CloudStation Pro', length: 20 });
    config.twoFa.secretEncrypted = encryptKey(secret.base32);
    config.twoFa.enabled = true;
    await saveSecurityConfig(config);
    const otpauth = secret.otpauth_url;
    const qrDataUrl = otpauth ? await QRCode.toDataURL(otpauth, { width: 200, margin: 1 }) : null;
    res.json({ secret: secret.base32, qrDataUrl });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/security/2fa/verify', async (req, res) => {
  try {
    const { code } = req.body || {};
    const config = await loadSecurityConfig();
    if (!config.twoFa.enabled || !config.twoFa.secretEncrypted) {
      return res.status(400).json({ error: '2FA not enabled' });
    }
    const secret = decryptKey(config.twoFa.secretEncrypted);
    const valid = speakeasy.totp.verify({ secret, encoding: 'base32', token: String(code || '').trim(), window: 1 });
    if (!valid) return res.status(401).json({ error: 'Invalid code' });
    req.session.twoFaVerified = true;
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/security/2fa/disable', async (req, res) => {
  try {
    const config = await loadSecurityConfig();
    config.twoFa.enabled = false;
    config.twoFa.secretEncrypted = null;
    await saveSecurityConfig(config);
    if (req.session) req.session.twoFaVerified = false;
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/ports', async (req, res) => {
  try {
    const [container, docker, truenas] = await Promise.all([
      Promise.resolve(getListeningPortsWithNames()),
      getDockerPorts(),
      getTrueNASPorts(),
    ]);
    res.json({ container, docker, truenas });
  } catch (err) {
    res.status(500).json({ error: err.message, container: [], docker: [], truenas: [] });
  }
});

app.get('/api/disks/info', (req, res) => {
  try {
    const disks = getDiskHardwareInfo();
    res.json({ ok: true, disks });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message, disks: [] });
  }
});

const TRUENAS_HEADERS = (url, key) =>
  url && key
    ? { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' }
    : null;

/** 풀 topology에서 RAID 타입·디스크 목록 추출 */
function parsePoolTopology(topology) {
  if (!topology || !Array.isArray(topology.data)) return [];
  return topology.data.map((vdev) => ({
    type: vdev.type ?? 'STRIPE',
    disks: Array.isArray(vdev.disks) ? vdev.disks : [],
  }));
}

/** TrueNAS REST API로 스토리지 풀 목록·상세(토폴로지) 조회 */
async function getTrueNASPoolStatus() {
  const { url: baseUrl, key } = getTrueNASConfig();
  if (!baseUrl || !key) return [];
  const url = `${baseUrl}/api/v2.0/pool`;
  try {
    const res = await fetch(url, {
      method: 'GET',
      headers: TRUENAS_HEADERS(baseUrl, key),
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) return [];
    const data = await res.json();
    if (!Array.isArray(data)) return [];
    const pools = data.map((p) => ({
      name: p.name ?? String(p.id ?? ''),
      status: p.status ?? null,
      healthy: Boolean(p.healthy),
      id: p.id,
      topology: parsePoolTopology(p.topology),
    }));
    // 목록에 topology가 없으면 풀별 상세 조회
    const withTopology = await Promise.all(
      pools.map(async (p) => {
        if ((p.topology?.length ?? 0) > 0) return p;
        try {
          const r = await fetch(`${baseUrl}/api/v2.0/pool/${p.id}`, {
            method: 'GET',
            headers: TRUENAS_HEADERS(baseUrl, key),
            signal: AbortSignal.timeout(5000),
          });
          if (!r.ok) return p;
          const detail = await r.json();
          const one = Array.isArray(detail) ? detail[0] : detail;
          if (one?.topology) p.topology = parsePoolTopology(one.topology);
        } catch {
          // ignore
        }
        return p;
      })
    );
    return withTopology;
  } catch (e) {
    return [];
  }
}

/** TrueNAS REST API로 풀/데이터셋 용량(used/available) 조회. disk.space 대체용. */
async function getTrueNASPoolDatasets() {
  const { url: baseUrl, key } = getTrueNASConfig();
  if (!baseUrl || !key) return null;
  try {
    const res = await fetch(`${baseUrl}/api/v2.0/pool/dataset`, {
      method: 'GET',
      headers: TRUENAS_HEADERS(baseUrl, key),
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) return null;
    const data = await res.json();
    const list = Array.isArray(data) ? data : (data?.list ?? data?.results ?? []);
    if (!list.length) return null;
    const out = [];
    for (const d of list) {
      const usedRaw = d.used?.raw ?? d.used;
      const availRaw = d.available?.raw ?? d.available;
      const used = typeof usedRaw === 'number' ? usedRaw : null;
      const avail = typeof availRaw === 'number' ? availRaw : null;
      const total = used != null && avail != null ? used + avail : null;
      const usedPercent = total != null && total > 0 && used != null ? (used / total) * 100 : null;
      const name = d.name ?? d.id ?? '';
      if (name) {
        out.push({
          chartId: name,
          mount: name,
          used: used != null ? used / (1024 * 1024) : 0,
          avail: avail != null ? avail / (1024 * 1024) : 0,
          total: total != null ? total / (1024 * 1024) : null,
          usedPercent,
          units: 'MiB',
        });
      }
    }
    return out.length ? out : null;
  } catch (e) {
    return null;
  }
}

/** TrueNAS API로 시스템 메트릭(스토리지·디스크) 가져오기. CPU/RAM은 REST로 제공 안 하므로 null. */
async function getSystemFromTrueNAS() {
  const { url: baseUrl, key } = getTrueNASConfig();
  if (!baseUrl || !key) return null;
  try {
    const [datasets, pools] = await Promise.all([
      getTrueNASPoolDatasets(),
      getTrueNASPoolStatus(),
    ]);
    let storage = null;
    if (Array.isArray(datasets) && datasets.length > 0) {
      let totalUsed = 0;
      let totalAvail = 0;
      for (const d of datasets) {
        const used = (d.used ?? 0) * 1024 * 1024;
        const avail = (d.avail ?? 0) * 1024 * 1024;
        totalUsed += used;
        totalAvail += avail;
      }
      const totalBytes = totalUsed + totalAvail;
      if (totalBytes > 0) {
        storage = { path: 'TrueNAS', totalBytes, usedBytes: totalUsed };
      }
    }
    const disks = datasets;
    return {
      cpu: null,
      memory: null,
      storage,
      disks: disks ?? null,
      source: 'truenas',
    };
  } catch (e) {
    return null;
  }
}

/** TrueNAS REST API로 디스크 목록 조회 (이름, 용량, 모델 등) */
async function getTrueNASDisks() {
  const { url: baseUrl, key } = getTrueNASConfig();
  if (!baseUrl || !key) return [];
  const url = `${baseUrl}/api/v2.0/disk`;
  try {
    const res = await fetch(url, {
      method: 'GET',
      headers: TRUENAS_HEADERS(baseUrl, key),
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) return [];
    const data = await res.json();
    if (!Array.isArray(data)) return [];
    return data.map((d) => ({
      name: d.name ?? d.devname ?? d.identifier ?? '',
      devname: d.devname ?? d.name ?? '',
      size: d.size ?? null,
      model: d.model ?? null,
      serial: d.serial ?? null,
      pool: d.pool ?? null,
      type: d.type ?? null,
    })).filter((d) => d.name);
  } catch (e) {
    return [];
  }
}

/** TrueNAS 시스템에서 사용 중인 포트 (서비스별). SSH, 앱 사용 포트 등 */
async function getTrueNASPorts() {
  const { url: baseUrl, key } = getTrueNASConfig();
  if (!baseUrl || !key) return [];
  const entries = [];
  const opts = { method: 'GET', headers: TRUENAS_HEADERS(baseUrl, key), signal: AbortSignal.timeout(8000) };

  try {
    const sshRes = await fetch(`${baseUrl}/api/v2.0/ssh`, opts);
    if (sshRes.ok) {
      const sshData = await sshRes.json();
      const cfg = Array.isArray(sshData) ? sshData[0] : sshData;
      const port = cfg?.tcpport ?? cfg?.port;
      if (Number.isFinite(port) && port > 0 && port < 65536) {
        entries.push({ source: 'TrueNAS', service: 'SSH', port });
      }
    }
  } catch (_) {}

  try {
    const appRes = await fetch(`${baseUrl}/api/v2.0/app/used_ports`, opts);
    if (appRes.ok) {
      const appData = await appRes.json();
      if (typeof appData === 'object' && appData !== null && !Array.isArray(appData)) {
        for (const [portStr, name] of Object.entries(appData)) {
          const port = parseInt(portStr, 10);
          if (Number.isFinite(port) && port > 0 && port < 65536) {
            entries.push({ source: 'TrueNAS', service: name ? String(name) : 'App', port });
          }
        }
      } else if (Array.isArray(appData)) {
        for (const item of appData) {
          const port = item?.port ?? item?.port_number;
          const name = item?.name ?? item?.service;
          if (Number.isFinite(port) && port > 0 && port < 65536) {
            entries.push({ source: 'TrueNAS', service: name ? String(name) : 'App', port });
          }
        }
      }
    }
  } catch (_) {}

  return entries;
}

/** Docker 소켓으로 호스트의 모든 컨테이너 포트 매핑 수집 (docker ps의 PORTS에 해당) */
async function getDockerPorts() {
  const docker = getDocker();
  if (!docker) return [];
  try {
    const containers = await docker.listContainers();
    const seen = new Set();
    const entries = [];
    for (const c of containers) {
      const name = (c.Names && c.Names[0]) ? c.Names[0].replace(/^\//, '') : c.Id?.slice(0, 12) || 'unknown';
      const ports = c.Ports || [];
      for (const p of ports) {
        const hostPort = p.PublicPort ?? p.publicPort;
        const containerPort = p.PrivatePort ?? p.privatePort;
        if (Number.isFinite(hostPort) && hostPort > 0 && hostPort < 65536) {
          const key = `${name}:${hostPort}:${containerPort}`;
          if (seen.has(key)) continue;
          seen.add(key);
          entries.push({
            source: 'Docker',
            service: name,
            port: hostPort,
            containerPort: Number.isFinite(containerPort) && containerPort > 0 ? containerPort : null,
          });
        }
      }
    }
    entries.sort((a, b) => a.port - b.port || (a.service || '').localeCompare(b.service || ''));
    return entries;
  } catch (e) {
    return [];
  }
}

// ---------- RAID 정보 (mdadm + TrueNAS 풀·디스크) ----------
app.get('/api/raid', async (req, res) => {
  try {
    const [truenasPools, truenasDisks] = await Promise.all([
      getTrueNASPoolStatus(),
      getTrueNASDisks(),
    ]);

    let arrays = [];
    try {
      const text = await fs.readFile('/proc/mdstat', 'utf8');
      const lines = text.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line || line.startsWith('Personalities') || line.startsWith('unused devices')) continue;
        const match = line.match(/^(md\S*) : .* (raid[0-9+]+)/);
        if (!match) continue;
        const name = match[1];
        const level = match[2];
        const detailLine = (lines[i + 1] || '').trim();
        arrays.push({
          name,
          level,
          summary: line,
          detail: detailLine,
        });
      }
    } catch {
      // 컨테이너/호스트에 mdadm이 없을 수 있음 (예: TrueNAS만 사용)
    }

    res.json({
      arrays,
      truenas_pools: truenasPools,
      truenas_disks: truenasDisks,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// ---------- AI Assistant: API key from env only ----------
app.get('/api/settings/gemini-key', (req, res) => {
  res.json({ set: !!GEMINI_API_KEY });
});

// ---------- Compose .env file (MOUNT_PATH, TRUENAS_*, GEMINI_*). Written to DATA_PATH/.env ----------
const ENV_FILE_PATH = path.join(DATA_PATH, '.env');
const ENV_KEYS = ['MOUNT_PATH', 'TRUENAS_URL', 'TRUENAS_API_KEY', 'GEMINI_API_KEY', 'NETDATA_URL'];
/** Project root (docker-compose.yml dir) mounted in container; used to sync MOUNT_PATH to host .env */
const PROJECT_ROOT = process.env.PROJECT_ROOT || '/project';

function parseEnvFile(content) {
  const vars = {};
  for (const line of (content || '').split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq > 0) {
      const key = trimmed.slice(0, eq).trim();
      let val = trimmed.slice(eq + 1).trim();
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) val = val.slice(1, -1);
      vars[key] = val;
    }
  }
  return vars;
}

function formatEnvFile(vars) {
  const lines = ['# CloudStation compose environment. Generated by Control Panel.', ''];
  for (const key of ENV_KEYS) {
    const v = vars[key];
    if (v != null && String(v).trim() !== '') lines.push(`${key}=${String(v).trim()}`);
  }
  return lines.join('\n') + '\n';
}

app.get('/api/settings/env-file', async (req, res) => {
  try {
    let content = '';
    try {
      content = await fs.readFile(ENV_FILE_PATH, 'utf8');
    } catch {
      // file may not exist yet
    }
    const vars = parseEnvFile(content);
    const out = {};
    for (const k of ENV_KEYS) out[k] = vars[k] ?? '';
    res.json({ path: ENV_FILE_PATH, vars: out });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

/** Merge MOUNT_PATH into project root .env so docker compose volume uses it on next up. */
async function syncMountPathToProjectEnv(mountPathValue) {
  const projectEnvPath = path.join(PROJECT_ROOT, '.env');
  try {
    await fs.access(PROJECT_ROOT);
  } catch {
    return;
  }
  let lines = [];
  try {
    const content = await fs.readFile(projectEnvPath, 'utf8');
    lines = content.split(/\r?\n/);
  } catch {
    // file may not exist
  }
  const value = String(mountPathValue ?? '').trim();
  const newLine = value ? `MOUNT_PATH=${value}` : 'MOUNT_PATH=';
  let found = false;
  const outLines = lines.map((line) => {
    const m = line.match(/^\s*MOUNT_PATH\s*=/);
    if (m) {
      found = true;
      return newLine;
    }
    return line;
  });
  if (!found) outLines.push(newLine);
  const out = outLines.join('\n').replace(/\n*$/, '\n');
  await fs.writeFile(projectEnvPath, out, 'utf8');
}

app.put('/api/settings/env-file', async (req, res) => {
  try {
    const vars = req.body?.vars || req.body || {};
    const out = {};
    for (const k of ENV_KEYS) {
      const v = vars[k];
      out[k] = v != null ? String(v).trim() : '';
    }
    await fs.mkdir(path.dirname(ENV_FILE_PATH), { recursive: true });
    await fs.writeFile(ENV_FILE_PATH, formatEnvFile(out), 'utf8');
    try {
      await syncMountPathToProjectEnv(out.MOUNT_PATH);
    } catch (e) {
      console.warn('Could not sync MOUNT_PATH to project .env:', e.message);
    }
    res.json({ ok: true, path: ENV_FILE_PATH });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// ---------- Drive root info (for File Station "My Drive" troubleshooting) ----------
app.get('/api/settings/drive-info', async (req, res) => {
  try {
    const driveRoot = process.env.DRIVE_PATH || DATA_PATH;
    res.json({
      driveRoot,
      hint: 'File Station "My Drive" shows the path mounted at this location. The volume is set when you run docker compose, using the .env in the same folder as docker-compose.yml (on the host). Add MOUNT_PATH=your/share/path there, then run: docker compose up -d',
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// ---------- General settings (language, timezone, mount path). TrueNAS/AI from env. ----------
app.get('/api/settings/general', async (req, res) => {
  try {
    const general = await readGeneralConfig();
    res.json({
      language: general.language ?? 'en',
      timezone: general.timezone ?? 'UTC',
      mountPath: general.mountPath ?? '',
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/settings/general', async (req, res) => {
  try {
    const general = await readGeneralConfig();
    const { language, timezone, mountPath } = req.body || {};
    if (language !== undefined) general.language = String(language || 'en').slice(0, 16);
    if (timezone !== undefined) general.timezone = String(timezone || 'UTC').trim().slice(0, 128);
    if (mountPath !== undefined) general.mountPath = String(mountPath || '').trim().slice(0, 1024);
    await writeGeneralConfig(general);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

/** Restart this container so env_file (e.g. .env) changes take effect. Requires Docker socket and CONTAINER_NAME. */
app.post('/api/settings/restart-container', async (req, res) => {
  try {
    const docker = getDocker();
    if (!docker) return res.status(503).json({ error: 'Docker not available' });
    const name = process.env.CONTAINER_NAME || 'cloudstation-pro';
    const container = docker.getContainer(name);
    res.json({ ok: true });
    setTimeout(() => {
      container.restart().catch((err) => console.error('Container restart failed:', err));
    }, 400);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// ---------- Browse server filesystem for mount path picker ----------
function resolveBrowsePath(relativePath) {
  const normalized = (relativePath || '')
    .replace(/\\/g, path.sep)
    .replace(new RegExp(`^${path.sep}+`), '');
  const full = path.join(BROWSE_ROOT, normalized);
  const resolved = path.resolve(full);
  const rootResolved = path.resolve(BROWSE_ROOT);
  if (!resolved.startsWith(rootResolved) && resolved !== rootResolved) return null;
  return resolved;
}

app.get('/api/browse', async (req, res) => {
  try {
    const relativePath = (req.query.path || '').toString();
    const dirPath = resolveBrowsePath(relativePath);
    if (!dirPath) return res.status(400).json({ error: 'Invalid path' });
    const stat = await fs.stat(dirPath);
    if (!stat.isDirectory()) return res.status(400).json({ error: 'Not a directory' });
    const entries = await fs.readdir(dirPath, { withFileTypes: true });
    const items = await Promise.all(
      entries.map(async (ent) => {
        const full = path.join(dirPath, ent.name);
        const s = await fs.stat(full).catch(() => null);
        const type = s?.isDirectory() ? 'folder' : 'file';
        return {
          name: ent.name,
          type,
          path: path.join(relativePath, ent.name).replace(/\\/g, '/'),
        };
      })
    );
    const folders = items.filter((i) => i.type === 'folder').sort((a, b) => a.name.localeCompare(b.name));
    const files = items.filter((i) => i.type === 'file').sort((a, b) => a.name.localeCompare(b.name));
    const rootNorm = BROWSE_ROOT.replace(/\\/g, '/').replace(/\/+$/, '') || '/';
    const isHostMount = rootNorm === '/host' || rootNorm.endsWith('/host');
    const root = isHostMount ? '' : rootNorm;
    const pathVal = (relativePath || '').replace(/\\/g, '/');
    res.json({ root, path: pathVal, items: [...folders, ...files] });
  } catch (err) {
    if (err.code === 'ENOENT') return res.status(404).json({ error: 'Not found' });
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/ai/chat', async (req, res) => {
  try {
    const { message } = req.body || {};
    if (!message || typeof message !== 'string') return res.status(400).json({ error: 'message required' });
    const apiKey = GEMINI_API_KEY;
    if (!apiKey) return res.status(400).json({ error: 'API key not set. Set GEMINI_API_KEY environment variable.' });
    const { GoogleGenAI } = await import('@google/genai');
    const ai = new GoogleGenAI({ apiKey });
    const response = await ai.models.generateContent({
      model: 'gemini-2.0-flash',
      contents: message,
      config: {
        systemInstruction: 'You are CloudStation Assistant, a helpful AI helper integrated into a Synology DSM-like web interface. Keep answers helpful and related to file management, productivity, or general queries.'
      }
    });
    const text = response.text || 'Sorry, I encountered an issue processing that.';
    res.json({ text });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || 'AI request failed' });
  }
});

// ---------- SFTP API ----------
app.get('/api/sftp/config', async (req, res) => {
  try {
    const state = await readSftpStore();
    const port = Number(state.meta.port) || 1014;
    res.json({
      ok: true,
      port,
      users: state.users,
      pending: state.pending,
      delete_pending: state.delete_pending || [],
      meta: state.meta,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/sftp/config/port', async (req, res) => {
  try {
    const port = Number(req.body?.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      return res.status(400).json({ error: 'Invalid port (1-65535)' });
    }
    const state = await readSftpStore();
    state.meta = state.meta || {};
    state.meta.port = port;
    await writeSftpStore(state);
    res.json({ ok: true, port });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/sftp/pending/add', async (req, res) => {
  try {
    const { name, password, mount } = req.body || {};
    const n = String(name || '').trim();
    if (!n || !USERNAME_RE.test(n)) return res.status(400).json({ error: 'Invalid username' });
    const m = String(mount || '').trim();
    if (!m) return res.status(400).json({ error: 'Mount path required' });
    const state = await readSftpStore();
    const existing = [...state.users, ...state.pending].find((u) => u.name === n);
    if (existing) return res.status(400).json({ error: 'User already exists' });
    state.pending.push({
      name: n,
      password: String(password || '').trim(),
      mount: m,
      enabled: true,
    });
    await writeSftpStore(state);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/sftp/pending/delete', express.json(), async (req, res) => {
  try {
    const name = String(req.body?.name || '').trim();
    if (!name) return res.status(400).json({ error: 'name required' });
    const state = await readSftpStore();
    state.pending = state.pending.filter((u) => u.name !== name);
    await writeSftpStore(state);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/sftp/pending/toggle', express.json(), async (req, res) => {
  try {
    const name = String(req.body?.name || '').trim();
    const state = await readSftpStore();
    const u = state.pending.find((x) => x.name === name);
    if (!u) return res.status(404).json({ error: 'Pending user not found' });
    u.enabled = !u.enabled;
    await writeSftpStore(state);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/sftp/users/toggle', async (req, res) => {
  try {
    const name = String(req.body?.name || '').trim();
    const state = await readSftpStore();
    const u = state.users.find((x) => x.name === name);
    if (!u) return res.status(404).json({ error: 'User not found' });
    u.enabled = !u.enabled;
    await writeSftpStore(state);
    const enabled = state.users.filter((x) => x.enabled);
    await createAndStartSftp(enabled, Number(state.meta?.port) || 1014);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/sftp/users/mark-delete', express.json(), async (req, res) => {
  try {
    const name = String(req.body?.name || '').trim();
    const state = await readSftpStore();
    if (!state.users.some((x) => x.name === name)) return res.status(404).json({ error: 'User not found' });
    state.delete_pending = state.delete_pending || [];
    if (!state.delete_pending.includes(name)) state.delete_pending.push(name);
    await writeSftpStore(state);
    res.json({ ok: true, delete_pending: state.delete_pending });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/sftp/users/unmark-delete', express.json(), async (req, res) => {
  try {
    const name = String(req.body?.name || '').trim();
    const state = await readSftpStore();
    state.delete_pending = (state.delete_pending || []).filter((x) => x !== name);
    await writeSftpStore(state);
    res.json({ ok: true, delete_pending: state.delete_pending });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/sftp/apply', async (req, res) => {
  try {
    const state = await readSftpStore();
    if (state.pending.length) {
      state.users = [...state.users, ...state.pending];
      state.pending = [];
    }
    const enabled = state.users.filter((u) => u.enabled);
    await writeSftpStore(state);
    await createAndStartSftp(enabled, Number(state.meta?.port) || 1014);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/sftp/restart', async (req, res) => {
  try {
    const state = await readSftpStore();
    state.users = state.users.filter((u) => !(state.delete_pending || []).includes(u.name));
    state.delete_pending = [];
    await writeSftpStore(state);
    const enabled = state.users.filter((u) => u.enabled);
    await createAndStartSftp(enabled, Number(state.meta?.port) || 1014);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// ---------- 파일 공유 (Studio Log 방식) ----------
// 공유 링크 목록
app.get('/api/shares', async (req, res) => {
  try {
    const shares = await readShares();
    const now = new Date().toISOString();
    const list = shares
      .filter((s) => !s.revokedAt)
      .map((s) => ({
        id: s.token,
        token: s.token,
        path: s.path,
        fileName: path.basename(s.path),
        isDir: s.isDir,
        expiresAt: s.expiresAt || null,
        isExpired: s.expiresAt ? s.expiresAt < now : false,
        accessCount: s.accessCount || 0,
        createdAt: s.createdAt,
        url: `/s/${s.token}`,
      }));
    res.json({ ok: true, shares: list });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// 공유 링크 생성 (My Drive 경로는 resolveDriveSafe 사용)
app.post('/api/shares', async (req, res) => {
  try {
    const { path: relativePath, isDir = false, expiresInDays } = req.body || {};
    const safePath = resolveDriveSafe(relativePath);
    if (!safePath) return res.status(400).json({ error: 'Invalid path' });
    const stat = await fs.stat(safePath).catch(() => null);
    if (!stat) return res.status(404).json({ error: 'File or folder not found' });
    const isDirectory = stat.isDirectory();
    if (isDirectory !== !!isDir) return res.status(400).json({ error: 'Path type mismatch' });

    let expiresAt = null;
    if (expiresInDays != null && expiresInDays > 0) {
      const d = new Date();
      d.setDate(d.getDate() + Number(expiresInDays));
      expiresAt = d.toISOString();
    }

    const token = crypto.randomBytes(32).toString('base64url');
    const shares = await readShares();
    const newShare = {
      token,
      path: relativePath,
      isDir: isDirectory,
      expiresAt,
      accessCount: 0,
      revokedAt: null,
      createdAt: new Date().toISOString(),
    };
    shares.push(newShare);
    await writeShares(shares);

    res.json({
      ok: true,
      token,
      url: `/s/${token}`,
      expiresAt,
      path: relativePath,
      isDir: isDirectory,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// 공유 링크 폐기
app.delete('/api/shares/:id', async (req, res) => {
  try {
    const token = req.params.id;
    const shares = await readShares();
    const idx = shares.findIndex((s) => s.token === token);
    if (idx === -1) return res.status(404).json({ error: 'Share not found' });
    shares[idx].revokedAt = new Date().toISOString();
    await writeShares(shares);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// 공유 다운로드 페이지 (로그인 불필요)
app.get('/s/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const shares = await readShares();
    const share = shares.find((s) => s.token === token && !s.revokedAt);
    if (!share) {
      return res.status(404).send(shareDownloadPage('Share link not found.'));
    }
    const now = new Date().toISOString();
    if (share.expiresAt && share.expiresAt < now) {
      return res.status(410).send(shareDownloadPage('This share link has expired.'));
    }
    const filePath = resolveDriveSafe(share.path);
    if (!filePath) return res.status(400).send(shareDownloadPage('Invalid path'));
    const stat = await fs.stat(filePath).catch(() => null);
    if (!stat) return res.status(404).send(shareDownloadPage('File or folder not found.'));
    const fileName = path.basename(filePath);
    let fileSize = null;
    if (!share.isDir && stat.isFile()) {
      fileSize = formatSize(stat.size);
    }
    const expiresLabel = share.expiresAt ? new Date(share.expiresAt).toLocaleString('ko-KR') : 'Permanent';
    res.send(shareDownloadPage(null, { fileName, path: share.path, fileSize, expiresLabel, accessCount: share.accessCount || 0, isDir: share.isDir }));
  } catch (err) {
    console.error(err);
    res.status(500).send(shareDownloadPage('A server error occurred.'));
  }
});

// 공유 파일/폴더 다운로드 (로그인 불필요)
app.get('/s/:token/download', async (req, res) => {
  try {
    const { token } = req.params;
    const shares = await readShares();
    const share = shares.find((s) => s.token === token && !s.revokedAt);
    if (!share) return res.status(404).send('Share link not found.');
    const now = new Date().toISOString();
    if (share.expiresAt && share.expiresAt < now) return res.status(410).send('This share link has expired.');
    const filePath = resolveDriveSafe(share.path);
    if (!filePath) return res.status(400).send('Invalid path');
    const stat = await fs.stat(filePath).catch(() => null);
    if (!stat) return res.status(404).send('File or folder not found.');

    share.accessCount = (share.accessCount || 0) + 1;
    await writeShares(shares);

    if (!share.isDir) {
      const name = path.basename(filePath);
      res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(name)}"`);
      res.setHeader('Content-Type', 'application/octet-stream');
      createReadStream(filePath).pipe(res);
      return;
    }

    const folderName = path.basename(filePath.replace(/[/\\]+$/, ''));
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(folderName)}.zip"`);
    res.setHeader('Content-Type', 'application/zip');
    const archive = archiver('zip', { zlib: { level: 9 } });
    archive.pipe(res);
    archive.directory(filePath, folderName);
    await archive.finalize();
  } catch (err) {
    console.error(err);
    res.status(500).send('An error occurred while downloading.');
  }
});

function shareDownloadPage(error, data = {}) {
  const { fileName = '', path: filePath = '', fileSize = '', expiresLabel = '', accessCount = 0, isDir = false } = data;
  const title = error ? 'Error' : 'Shared File Download';
  const escaped = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;');
  const svgCheck = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg>';
  const svgDoc = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>';
  const svgPin = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/></svg>';
  const svgCal = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>';
  const svgChart = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="20" x2="12" y2="10"/><line x1="18" y1="20" x2="18" y2="4"/><line x1="6" y1="20" x2="6" y2="16"/></svg>';
  const svgDownload = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>';
  const fileIconSvg = isDir
    ? '<svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>'
    : '<svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>';
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escaped(title)} - CloudStation Pro</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <style>
    * { box-sizing: border-box; }
    body, .card, .secure, .btn, .back, .footer, .detail-label, .detail-value, h1, .subtitle, .error {
      font-family: 'Inter', sans-serif;
    }
    body { margin: 0; min-height: 100vh; background: linear-gradient(180deg, #eef2ff 0%, #f8fafc 35%, #fff 100%); color: #1e293b; padding: 32px 24px 24px; display: flex; flex-direction: column; align-items: center; -webkit-font-smoothing: antialiased; -moz-osx-font-smoothing: grayscale; }
    .secure { display: flex; align-items: center; justify-content: center; gap: 10px; margin-bottom: 28px; font-size: 0.75rem; font-weight: 600; letter-spacing: 0.06em; color: #15803d; }
    .secure svg { flex-shrink: 0; }
    .secure-circle { width: 24px; height: 24px; border-radius: 50%; background: #15803d; color: #fff; display: flex; align-items: center; justify-content: center; }
    .card { max-width: 480px; width: 100%; background: #fff; border: 1px solid #e2e8f0; border-radius: 1.25rem; padding: 36px 32px 32px; box-shadow: 0 4px 24px rgba(0,0,0,0.06); text-align: center; }
    .hero-icon { width: 88px; height: 88px; margin: 0 auto 20px; border-radius: 50%; background: #fff; border: 1px solid #e2e8f0; display: flex; align-items: center; justify-content: center; color: #2563eb; }
    .hero-icon-inner { width: 56px; height: 56px; border-radius: 12px; background: #dbeafe; display: flex; align-items: center; justify-content: center; }
    h1 { margin: 0 0 8px; font-size: 1.5rem; font-weight: 700; color: #1e293b; letter-spacing: -0.02em; }
    .subtitle { color: #64748b; font-size: 0.875rem; margin: 0 0 28px; }
    .error { background: #fef2f2; color: #991b1b; padding: 14px 16px; border-radius: 10px; margin-bottom: 16px; border: 1px solid #fecaca; font-size: 0.875rem; text-align: left; }
    .detail { display: flex; align-items: center; gap: 12px; padding: 12px 0; border-bottom: 1px solid #f1f5f9; text-align: left; }
    .detail:last-of-type { border-bottom: none; }
    .detail-icon { color: #64748b; flex-shrink: 0; display: flex; align-items: center; justify-content: center; }
    .detail-label { color: #64748b; font-size: 0.8125rem; width: 110px; flex-shrink: 0; }
    .detail-value { color: #334155; font-size: 0.875rem; flex: 1; text-align: right; word-break: break-all; }
    .detail-value.num { color: #2563eb; font-weight: 600; }
    .btn { display: inline-flex; align-items: center; justify-content: center; gap: 10px; padding: 14px 28px; font-size: 1rem; font-weight: 600; background: #2563eb; color: #fff; border: none; border-radius: 0.75rem; cursor: pointer; margin-top: 24px; transition: background 0.2s; }
    .btn:hover { background: #1d4ed8; }
    .back { display: block; margin-top: 20px; font-size: 0.8125rem; color: #94a3b8; text-decoration: none; }
    .back:hover { color: #64748b; }
    .footer { margin-top: auto; padding-top: 32px; font-size: 0.6875rem; font-weight: 500; letter-spacing: 0.12em; color: #94a3b8; }
  </style>
</head>
<body>
  ${!error ? `<div class="secure"><span class="secure-circle">${svgCheck}</span> SECURE LINK VERIFIED BY CLOUDSTATION</div>` : ''}
  <div class="card">
    ${error ? `<div class="error">${escaped(error)}</div>` : `
    <div class="hero-icon"><div class="hero-icon-inner">${fileIconSvg}</div></div>
    <h1>File Download</h1>
    <p class="subtitle">Download shared files securely</p>
    <div class="detail"><span class="detail-icon">${svgDoc}</span><span class="detail-label">Filename</span><span class="detail-value">${escaped(fileName)}</span></div>
    <div class="detail"><span class="detail-icon">${svgPin}</span><span class="detail-label">Path</span><span class="detail-value">${escaped(filePath)}</span></div>
    <div class="detail"><span class="detail-icon">${svgCal}</span><span class="detail-label">Expires</span><span class="detail-value">${escaped(expiresLabel)}</span></div>
    <div class="detail"><span class="detail-icon">${svgChart}</span><span class="detail-label">Download count</span><span class="detail-value num">${escaped(String(accessCount))} times</span></div>
    <button class="btn" onclick="location.href=location.pathname+'/download'">${svgDownload} Start Download</button>
    <a class="back" href="javascript:if(window.history.length>1)history.back();else location.href='/';">&larr; Back to previous page</a>
    `}
  </div>
  <div class="footer">POWERED BY CLOUDSTATION PRO WEBOS</div>
</body>
</html>`;
}

function formatSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  return (bytes / (1024 * 1024 * 1024)).toFixed(1) + ' GB';
}

// ---------- Calendar events ----------
async function readCalendarEvents() {
  try {
    const raw = await fs.readFile(CALENDAR_FILE, 'utf8');
    const data = JSON.parse(raw);
    return Array.isArray(data.events) ? data.events : [];
  } catch {
    return [];
  }
}

async function writeCalendarEvents(events) {
  await fs.mkdir(path.dirname(CALENDAR_FILE), { recursive: true }).catch(() => {});
  await fs.writeFile(CALENDAR_FILE, JSON.stringify({ events }, null, 2), 'utf8');
}

app.get('/api/calendar/events', async (req, res) => {
  try {
    const events = await readCalendarEvents();
    const from = (req.query.from || '').toString();
    const to = (req.query.to || '').toString();
    let list = events;
    if (from && to) {
      list = events.filter((e) => e.date >= from && e.date <= to);
    }
    res.json({ events: list });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/calendar/events', async (req, res) => {
  try {
    const events = await readCalendarEvents();
    const { title, date, startTime, endTime, color, description } = req.body || {};
    if (!title || !date) return res.status(400).json({ error: 'title and date required' });
    const id = `ev-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
    const event = {
      id,
      title: String(title).trim().slice(0, 256),
      date: String(date).trim().slice(0, 10),
      startTime: startTime ? String(startTime).trim().slice(0, 16) : null,
      endTime: endTime ? String(endTime).trim().slice(0, 16) : null,
      color: color ? String(color).trim().slice(0, 32) : null,
      description: description ? String(description).trim().slice(0, 1024) : null,
    };
    events.push(event);
    await writeCalendarEvents(events);
    res.json({ ok: true, event });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/calendar/events/:id', async (req, res) => {
  try {
    const events = await readCalendarEvents();
    const id = (req.params.id || '').toString();
    const idx = events.findIndex((e) => e.id === id);
    if (idx === -1) return res.status(404).json({ error: 'Event not found' });
    const { title, date, startTime, endTime, color, description } = req.body || {};
    const ev = events[idx];
    if (title !== undefined) ev.title = String(title).trim().slice(0, 256);
    if (date !== undefined) ev.date = String(date).trim().slice(0, 10);
    if (startTime !== undefined) ev.startTime = startTime ? String(startTime).trim().slice(0, 16) : null;
    if (endTime !== undefined) ev.endTime = endTime ? String(endTime).trim().slice(0, 16) : null;
    if (color !== undefined) ev.color = color ? String(color).trim().slice(0, 32) : null;
    if (description !== undefined) ev.description = description ? String(description).trim().slice(0, 1024) : null;
    await writeCalendarEvents(events);
    res.json({ ok: true, event: ev });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/calendar/events/:id', async (req, res) => {
  try {
    const events = await readCalendarEvents();
    const id = (req.params.id || '').toString();
    const idx = events.findIndex((e) => e.id === id);
    if (idx === -1) return res.status(404).json({ error: 'Event not found' });
    events.splice(idx, 1);
    await writeCalendarEvents(events);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// SPA fallback (must be after all API routes)
app.get('*', (req, res) => {
  if (!req.path.startsWith('/api')) {
    res.sendFile(path.join(__dirname, '..', 'dist', 'index.html'));
  } else {
    res.status(404).json({ error: 'Not found' });
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`CloudStation server at http://0.0.0.0:${PORT}, DATA_PATH=${DATA_PATH}`);
});
