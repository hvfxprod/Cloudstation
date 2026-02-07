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
const SECURITY_FILE = path.join(DATA_PATH, 'security.json');
const SHARES_FILE = process.env.SHARES_FILE || path.join(__dirname, 'shares.json');
const SFTP_USERS_FILE = process.env.SFTP_USERS_FILE || path.join(DATA_PATH, '.sftp_users.json');
const SFTP_CONTAINER_NAME = process.env.SFTP_CONTAINER_NAME || 'cloudstation-sftp';
const SFTP_HOST_MOUNT_ROOT = process.env.SFTP_HOST_MOUNT_ROOT || DATA_PATH;
const GEMINI_KEY_FILE = process.env.GEMINI_KEY_FILE || path.join(__dirname, '.gemini_key.enc');
const GENERAL_FILE = path.join(DATA_PATH, 'general.json');
const CALENDAR_FILE = path.join(DATA_PATH, 'calendar.json');
const TRUENAS_KEY_FILE = path.join(DATA_PATH, '.truenas_key.enc');
const ENCRYPTION_SECRET = process.env.ENCRYPTION_SECRET || 'cloudstation-gemini-key-secret-change-in-production';
const NETDATA_URL = (process.env.NETDATA_URL || '').replace(/\/$/, '');
const TRUENAS_URL = (process.env.TRUENAS_URL || '').replace(/\/$/, '');
const TRUENAS_API_KEY = process.env.TRUENAS_API_KEY || '';

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

async function readGeminiKeyEncrypted() {
  try {
    const raw = await fs.readFile(GEMINI_KEY_FILE, 'utf8');
    return raw.trim();
  } catch {
    return null;
  }
}

async function getGeminiKeyDecrypted() {
  const blob = await readGeminiKeyEncrypted();
  if (!blob) return null;
  try {
    return decryptKey(blob);
  } catch {
    return null;
  }
}

async function writeGeminiKeyEncrypted(plainKey) {
  if (!plainKey || !plainKey.trim()) {
    await fs.unlink(GEMINI_KEY_FILE).catch(() => {});
    return;
  }
  const enc = encryptKey(plainKey.trim());
  await fs.writeFile(GEMINI_KEY_FILE, enc, 'utf8');
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

async function readTrueNASKeyEncrypted() {
  try {
    const raw = await fs.readFile(TRUENAS_KEY_FILE, 'utf8');
    return raw.trim();
  } catch {
    return null;
  }
}

async function getTrueNASKeyDecrypted() {
  const blob = await readTrueNASKeyEncrypted();
  if (!blob) return null;
  try {
    return decryptKey(blob);
  } catch {
    return null;
  }
}

async function writeTrueNASKeyEncrypted(plainKey) {
  if (!plainKey || !String(plainKey).trim()) {
    await fs.unlink(TRUENAS_KEY_FILE).catch(() => {});
    return;
  }
  const enc = encryptKey(String(plainKey).trim());
  await fs.mkdir(path.dirname(TRUENAS_KEY_FILE), { recursive: true }).catch(() => {});
  await fs.writeFile(TRUENAS_KEY_FILE, enc, 'utf8');
}

/** TrueNAS URL + API key: general.json + file first, then env */
async function getTrueNASConfig() {
  const general = await readGeneralConfig();
  const url = (general.truenasUrl || '').toString().replace(/\/$/, '') || TRUENAS_URL;
  const key = (url && (await getTrueNASKeyDecrypted())) || (url === TRUENAS_URL ? TRUENAS_API_KEY : '') || '';
  return { url, key };
}

function resolveSafe(relativePath) {
  const normalized = path.normalize(relativePath || '').replace(/^(\.\.(\/|\\|$))+/, '');
  const full = path.resolve(DATA_PATH, normalized);
  if (!full.startsWith(path.resolve(DATA_PATH))) {
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
    const dirPath = resolveSafe(relativePath);
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
    const filePath = resolveSafe(relativePath);
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
    const dirPath = resolveSafe(relativePath);
    if (!dirPath) return res.status(400).json({ error: 'Invalid path' });
    await fs.mkdir(dirPath, { recursive: true });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// ---------- Netdata API (선택) ----------
async function fetchNetdataJson(pathname) {
  if (!NETDATA_URL) return null;
  try {
    const url = `${NETDATA_URL}${pathname}`;
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 5000);
    const r = await fetch(url, { signal: ctrl.signal });
    clearTimeout(t);
    if (!r.ok) return null;
    return await r.json();
  } catch {
    return null;
  }
}

/** Netdata v1/data 응답: 첫 열이 시간이면 제외. [time, dim1, dim2, ...] — 라벨 또는 값으로 시간 열 판별 */
function netdataRowValues(labels, row) {
  if (!Array.isArray(labels) || !Array.isArray(row)) return { labels: [], values: [] };
  const firstVal = Number(row[0]);
  const looksLikeTime = Number.isFinite(firstVal) && firstVal > 1e9 && firstVal < 2e9;
  const labelIsTime = labels[0] != null && /^time$/i.test(String(labels[0]).trim());
  const offset = labelIsTime || looksLikeTime ? 1 : 0;
  return {
    labels: labels.slice(offset),
    values: row.slice(offset),
  };
}

function netdataLatestPair(res) {
  const names = res?.dimension_names || res?.labels || [];
  const latest = res?.latest_values;
  if (Array.isArray(latest) && Array.isArray(names)) {
    const skip = names[0] != null && /^time$/i.test(String(names[0]).trim()) ? 1 : 0;
    return { labels: names.slice(skip), values: latest.slice(skip) };
  }
  if (Array.isArray(res?.data) && res.data.length) {
    const last = res.data[res.data.length - 1];
    return netdataRowValues(names, Array.isArray(last) ? last : []);
  }
  return { labels: [], values: [] };
}

function pickDimension(labels, values, regexes) {
  for (let i = 0; i < labels.length; i++) {
    const name = String(labels[i] ?? '');
    if (regexes.some((r) => r.test(name))) {
      const v = Number(values[i]);
      if (Number.isFinite(v)) return v;
    }
  }
  return 0;
}

async function getDiskSpacesFromNetdata() {
  const chartsRes = await fetchNetdataJson('/api/v1/charts');
  const chartsObj = chartsRes?.charts;
  if (!chartsObj || typeof chartsObj !== 'object') return null;

  const diskCharts = Object.entries(chartsObj)
    .map(([id, info]) => ({ id, info }))
    .filter(({ info }) => String(info?.context || '').toLowerCase() === 'disk.space');

  if (!diskCharts.length) return null;

  // 너무 많은 마운트를 한 번에 가져오지 않도록 제한
  const targets = diskCharts.slice(0, 12);
  const results = await Promise.all(
    targets.map(async ({ id, info }) => {
      const r = await fetchNetdataJson(`/api/v1/data?chart=${encodeURIComponent(id)}&points=1&format=json&options=jsonwrap`);
      if (!r) return null;
      const { labels, values } = netdataLatestPair(r);
      if (!labels.length || !values.length) return null;

      // Netdata disk.space의 대표 dimension: used, avail(available), free 등 (환경에 따라 다름)
      const used = pickDimension(labels, values, [/^used$/i, /used/i]);
      const avail = pickDimension(labels, values, [/^avail$/i, /avail/i, /^available$/i, /free/i]);
      const total = used + avail;
      const usedPercent = total > 0 ? (used / total) * 100 : null;

      return {
        chartId: id,
        mount: info?.family || info?.title || id,
        used,
        avail,
        total: total || null,
        usedPercent,
        units: r?.units || info?.units || null,
      };
    })
  );

  const disks = results.filter(Boolean);
  return disks.length ? disks : null;
}

async function getDiskIOFromNetdata() {
  const chartsRes = await fetchNetdataJson('/api/v1/charts');
  const chartsObj = chartsRes?.charts;
  if (!chartsObj || typeof chartsObj !== 'object') return null;

  const ioCharts = Object.entries(chartsObj)
    .map(([id, info]) => ({ id, info }))
    .filter(({ info }) => String(info?.context || '').toLowerCase() === 'disk.io');

  if (!ioCharts.length) return null;

  const targets = ioCharts.slice(0, 12);
  const results = await Promise.all(
    targets.map(async ({ id, info }) => {
      const r = await fetchNetdataJson(`/api/v1/data?chart=${encodeURIComponent(id)}&points=1&format=json&options=jsonwrap`);
      if (!r) return null;
      const { labels, values } = netdataLatestPair(r);
      if (!labels.length || !values.length) return null;

      // 대표 dimension: read, write (환경에 따라 reads/writes, read KiB/s 등)
      const read = pickDimension(labels, values, [/^read$/i, /^reads$/i, /read/i]);
      const write = pickDimension(labels, values, [/^write$/i, /^writes$/i, /write/i]);

      return {
        chartId: id,
        device: info?.family || info?.title || id,
        read,
        write,
        units: r?.units || info?.units || null,
      };
    })
  );

  const diskIO = results.filter(Boolean);
  return diskIO.length ? diskIO : null;
}

/** Netdata에서 시스템 메트릭 가져오기. 실패 시 null. */
async function getSystemFromNetdata() {
  // jsonwrap 사용 시 latest_values / dimension_names 제공되면 시간 열 없이 사용 가능
  const [cpuRes, ramRes] = await Promise.all([
    fetchNetdataJson('/api/v1/data?context=system.cpu&points=1&format=json&options=jsonwrap'),
    fetchNetdataJson('/api/v1/data?context=system.ram&points=1&format=json&options=jsonwrap'),
  ]);

  const { labels: cpuLabels, values: cpuV } = netdataLatestPair(cpuRes);
  let totalCpu = 0;
  let idle = 0;
  cpuLabels.forEach((label, i) => {
    const v = Number(cpuV[i]);
    if (Number.isFinite(v)) {
      totalCpu += v;
      if (/idle/i.test(String(label))) idle = v;
    }
  });
  let cpuPercent = totalCpu > 0 ? Math.max(0, Math.min(100, 100 - (idle / totalCpu) * 100)) : null;
  if (cpuPercent != null && (cpuPercent >= 99.5 || cpuPercent <= 0.5)) cpuPercent = null;

  const { labels: ramLabels, values: ramV } = netdataLatestPair(ramRes);
  let usedBytes = 0;
  let freeBytes = 0;
  let cachedBytes = 0;
  ramLabels.forEach((label, i) => {
    const v = Number(ramV[i]);
    if (!Number.isFinite(v)) return;
    const l = String(label).toLowerCase().replace(/\s+/g, ' ');
    if (l === 'used' || l === 'used ram' || l === 'applications') usedBytes = v;
    else if (l === 'free') freeBytes = v;
    else if (l === 'cached') cachedBytes = v;
  });
  const toBytes = (x) => (x > 0 && x < 1e9 ? x * 1024 : x);
  usedBytes = toBytes(usedBytes);
  freeBytes = toBytes(freeBytes);
  cachedBytes = toBytes(cachedBytes);
  const totalBytes = usedBytes + freeBytes + cachedBytes || usedBytes + freeBytes;
  if (totalBytes === 0 || usedBytes === 0) return null;
  if (cpuPercent == null) return null;

  const disks = await getDiskSpacesFromNetdata().catch(() => null);
  const diskIO = await getDiskIOFromNetdata().catch(() => null);

  return {
    cpu: { percent: cpuPercent },
    memory: { totalBytes, usedBytes },
    storage: null,
    disks,
    diskIO,
    source: 'netdata',
  };
}

/** Netdata에서 네트워크 메트릭(옵션) 가져오기. hostname/인터페이스 목록은 os 기반 유지. */
async function getNetworkStatsFromNetdata() {
  const res = await fetchNetdataJson('/api/v1/data?context=net.net&points=1&format=json');
  if (!res?.data?.length || !Array.isArray(res.labels)) return null;
  const row = res.data[res.data.length - 1] || [];
  const labels = res.labels;
  const byInterface = {};
  labels.forEach((label, i) => {
    const v = Number(row[i]);
    if (Number.isFinite(v) && label) byInterface[label] = v;
  });
  return Object.keys(byInterface).length ? { byInterface, source: 'netdata' } : null;
}

/** TrueNAS API로 호스트 네트워크 설정(호스트명, DNS, 인터페이스) 가져오기 */
async function getTrueNASNetworkInfo() {
  const { url, key } = await getTrueNASConfig();
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
  19999: 'Netdata',
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

// ---------- 시스템 정보 ----------
app.get('/api/system', async (req, res) => {
  try {
    let payload = await getSystemFromNetdata();
    if (!payload) {
      const totalMem = os.totalmem();
      const freeMem = os.freemem();
      const usedMem = totalMem - freeMem;
      const cpus = os.cpus?.() || [];
      const load = os.loadavg?.()[0] ?? 0;
      const cpuPercent = cpus.length ? Math.max(0, Math.min(100, (load / cpus.length) * 100)) : null;
      payload = {
        cpu: { percent: cpuPercent },
        memory: { totalBytes: totalMem, usedBytes: usedMem },
        storage: null,
      };
    }

    // 시스템 메트릭이 OS 폴백이어도, 디스크 정보는 Netdata에서 별도로 시도
    let disks = payload.disks ?? null;
    let diskIO = payload.diskIO ?? null;
    if (disks == null) disks = await getDiskSpacesFromNetdata().catch(() => null);
    if (diskIO == null) diskIO = await getDiskIOFromNetdata().catch(() => null);

    let storage = payload.storage;
    if (storage == null) {
      try {
        const info = await checkDiskSpace(DATA_PATH);
        const usedBytes = info.size - info.free;
        storage = {
          path: DATA_PATH,
          totalBytes: info.size,
          usedBytes,
        };
      } catch (e) {
        console.warn('Failed to read disk space for', DATA_PATH, e?.message ?? e);
      }
    }

    const uptimeSeconds = typeof os.uptime === 'function' ? os.uptime() : undefined;
    const loadAvg = typeof os.loadavg === 'function' ? os.loadavg() : undefined;
    const cpus = typeof os.cpus === 'function' ? os.cpus() : [];
    const cpuInfo = {
      ...payload.cpu,
      ...(cpus.length > 0 && {
        model: cpus[0]?.model ?? null,
        cores: cpus.length,
      }),
    };
    res.json({
      storage,
      memory: payload.memory,
      cpu: cpuInfo,
      ...(uptimeSeconds != null && Number.isFinite(uptimeSeconds) && { uptimeSeconds }),
      ...(Array.isArray(loadAvg) && loadAvg.length > 0 && { loadAverage: loadAvg }),
      ...(disks != null && { disks }),
      ...(diskIO != null && { diskIO }),
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
  const { url: baseUrl, key } = await getTrueNASConfig();
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

/** TrueNAS REST API로 디스크 목록 조회 (이름, 용량, 모델 등) */
async function getTrueNASDisks() {
  const { url: baseUrl, key } = await getTrueNASConfig();
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
  const { url: baseUrl, key } = await getTrueNASConfig();
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

// ---------- 네트워크 정보 (TrueNAS 우선, 없으면 컨테이너 기준) ----------
app.get('/api/network', async (req, res) => {
  try {
    let payload = await getTrueNASNetworkInfo();
    if (!payload) {
      const hostname = os.hostname();
      const ifaces = os.networkInterfaces() || {};
      const interfaces = [];
      for (const [name, addrs] of Object.entries(ifaces)) {
        if (!Array.isArray(addrs)) continue;
        for (const a of addrs) {
          if (a.family === 'IPv4' && !a.internal) {
            interfaces.push({ name, address: a.address, family: a.family, mac: a.mac || null });
          }
        }
      }
      let dns = [];
      try {
        const resolv = await fs.readFile('/etc/resolv.conf', 'utf8');
        const lines = resolv.split('\n');
        for (const line of lines) {
          const m = line.trim().match(/^nameserver\s+(\S+)/i);
          if (m) dns.push(m[1]);
        }
      } catch {
        // Windows or no resolv.conf
      }
      payload = { hostname, interfaces, dns, source: 'container' };
    }
    const networkStats = await getNetworkStatsFromNetdata();
    if (networkStats) payload.networkStats = networkStats;
    res.json(payload);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// ---------- AI Assistant: API Key 암호화 저장 / 채팅 프록시 ----------
app.get('/api/settings/gemini-key', async (req, res) => {
  try {
    const blob = await readGeminiKeyEncrypted();
    res.json({ set: !!blob });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/settings/gemini-key', async (req, res) => {
  try {
    const { key } = req.body || {};
    if (key == null) return res.status(400).json({ error: 'key required' });
    await writeGeminiKeyEncrypted(String(key).trim());
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// ---------- General settings (language, timezone, TrueNAS, mount path) ----------
app.get('/api/settings/general', async (req, res) => {
  try {
    const general = await readGeneralConfig();
    const truenasApiKeySet = !!(await getTrueNASKeyDecrypted());
    res.json({
      language: general.language ?? 'en',
      timezone: general.timezone ?? 'UTC',
      truenasUrl: general.truenasUrl ?? '',
      truenasApiKeySet,
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
    const { language, timezone, truenasUrl, truenasApiKey, mountPath } = req.body || {};
    if (language !== undefined) general.language = String(language || 'en').slice(0, 16);
    if (timezone !== undefined) general.timezone = String(timezone || 'UTC').trim().slice(0, 128);
    if (truenasUrl !== undefined) general.truenasUrl = String(truenasUrl || '').replace(/\/$/, '').trim().slice(0, 512);
    if (truenasApiKey !== undefined) {
      const v = String(truenasApiKey || '').trim();
      await writeTrueNASKeyEncrypted(v || null);
    }
    if (mountPath !== undefined) general.mountPath = String(mountPath || '').trim().slice(0, 1024);
    await writeGeneralConfig(general);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/ai/chat', async (req, res) => {
  try {
    const { message } = req.body || {};
    if (!message || typeof message !== 'string') return res.status(400).json({ error: 'message required' });
    const apiKey = await getGeminiKeyDecrypted();
    if (!apiKey) return res.status(400).json({ error: 'API key not set. Configure in Control Panel → AI Assistant.' });
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

// 공유 링크 생성
app.post('/api/shares', async (req, res) => {
  try {
    const { path: relativePath, isDir = false, expiresInDays } = req.body || {};
    const safePath = resolveSafe(relativePath);
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
      return res.status(404).send(shareDownloadPage('공유 링크를 찾을 수 없습니다.'));
    }
    const now = new Date().toISOString();
    if (share.expiresAt && share.expiresAt < now) {
      return res.status(410).send(shareDownloadPage('공유 링크가 만료되었습니다.'));
    }
    const filePath = resolveSafe(share.path);
    if (!filePath) return res.status(400).send(shareDownloadPage('Invalid path'));
    const stat = await fs.stat(filePath).catch(() => null);
    if (!stat) return res.status(404).send(shareDownloadPage('파일 또는 폴더를 찾을 수 없습니다.'));
    const fileName = path.basename(filePath);
    let fileSize = null;
    if (!share.isDir && stat.isFile()) {
      fileSize = formatSize(stat.size);
    }
    const expiresLabel = share.expiresAt ? new Date(share.expiresAt).toLocaleString('ko-KR') : 'Permanent';
    res.send(shareDownloadPage(null, { fileName, path: share.path, fileSize, expiresLabel, accessCount: share.accessCount || 0, isDir: share.isDir }));
  } catch (err) {
    console.error(err);
    res.status(500).send(shareDownloadPage('서버 오류가 발생했습니다.'));
  }
});

// 공유 파일/폴더 다운로드 (로그인 불필요)
app.get('/s/:token/download', async (req, res) => {
  try {
    const { token } = req.params;
    const shares = await readShares();
    const share = shares.find((s) => s.token === token && !s.revokedAt);
    if (!share) return res.status(404).send('공유 링크를 찾을 수 없습니다.');
    const now = new Date().toISOString();
    if (share.expiresAt && share.expiresAt < now) return res.status(410).send('공유 링크가 만료되었습니다.');
    const filePath = resolveSafe(share.path);
    if (!filePath) return res.status(400).send('Invalid path');
    const stat = await fs.stat(filePath).catch(() => null);
    if (!stat) return res.status(404).send('파일 또는 폴더를 찾을 수 없습니다.');

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
    res.status(500).send('다운로드 중 오류가 발생했습니다.');
  }
});

function shareDownloadPage(error, data = {}) {
  const { fileName = '', path: filePath = '', fileSize = '', expiresLabel = '', accessCount = 0, isDir = false } = data;
  const title = error ? '오류' : '공유 파일 다운로드';
  const escaped = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;');
  return `<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escaped(title)} - CloudStation Pro</title>
  <style>
    body { font-family: system-ui, sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; background: #0f172a; color: #e2e8f0; padding: 20px; }
    .box { max-width: 520px; width: 100%; background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 28px; }
    h1 { margin: 0 0 8px 0; font-size: 22px; }
    .muted { color: #94a3b8; font-size: 14px; margin-bottom: 20px; }
    .error { background: #7f1d1d; color: #fecaca; padding: 14px; border-radius: 8px; margin-bottom: 16px; }
    .row { display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid #334155; }
    .row:last-child { border-bottom: none; }
    .label { color: #94a3b8; font-size: 14px; }
    .btn { display: inline-flex; align-items: center; gap: 8px; padding: 12px 24px; font-size: 16px; font-weight: 600; background: #2563eb; color: white; border: none; border-radius: 8px; cursor: pointer; margin-top: 16px; }
    .btn:hover { background: #1d4ed8; }
  </style>
</head>
<body>
  <div class="box">
    ${error ? `<div class="error">${escaped(error)}</div>` : `
    <h1>📥 파일 다운로드</h1>
    <p class="muted">공유된 파일을 다운로드하세요</p>
    <div class="row"><span class="label">파일명</span><span>${isDir ? '📁' : '📄'} ${escaped(fileName)}</span></div>
    ${fileSize ? `<div class="row"><span class="label">크기</span><span>${escaped(fileSize)}</span></div>` : ''}
    <div class="row"><span class="label">경로</span><span>${escaped(filePath)}</span></div>
    <div class="row"><span class="label">만료</span><span>${escaped(expiresLabel)}</span></div>
    <div class="row"><span class="label">다운로드 횟수</span><span>${accessCount}회</span></div>
    <button class="btn" onclick="location.href=location.pathname+'/download'">다운로드</button>
    `}
  </div>
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
