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

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 9000;

const DATA_PATH = process.env.DATA_PATH || path.join(__dirname, 'data');
const SHARES_FILE = process.env.SHARES_FILE || path.join(__dirname, 'shares.json');
const SFTP_USERS_FILE = process.env.SFTP_USERS_FILE || path.join(DATA_PATH, '.sftp_users.json');
const SFTP_CONTAINER_NAME = process.env.SFTP_CONTAINER_NAME || 'cloudstation-sftp';
const SFTP_HOST_MOUNT_ROOT = process.env.SFTP_HOST_MOUNT_ROOT || DATA_PATH;
const GEMINI_KEY_FILE = process.env.GEMINI_KEY_FILE || path.join(__dirname, '.gemini_key.enc');
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
  const commandLines = enabled.map((u) => `${u.name}:${u.password || ''}:::data`);
  const binds = enabled.map((u) => {
    const m = (u.mount || '').trim();
    const hostPath = m.startsWith('/') ? m : path.join(SFTP_HOST_MOUNT_ROOT, m).replace(/\\/g, '/');
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

app.use(cors());
app.use(express.json());

// 정적 파일 (Vite 빌드 결과)
app.use(express.static(path.join(__dirname, '..', 'dist'), { index: 'index.html' }));

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

app.get('/api/ports', async (req, res) => {
  try {
    const [container, docker, truenas] = await Promise.all([
      Promise.resolve(getListeningPorts()),
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
  if (!TRUENAS_URL || !TRUENAS_API_KEY) return [];
  const url = `${TRUENAS_URL}/api/v2.0/pool`;
  try {
    const res = await fetch(url, {
      method: 'GET',
      headers: TRUENAS_HEADERS(TRUENAS_URL, TRUENAS_API_KEY),
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
          const r = await fetch(`${TRUENAS_URL}/api/v2.0/pool/${p.id}`, {
            method: 'GET',
            headers: TRUENAS_HEADERS(TRUENAS_URL, TRUENAS_API_KEY),
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
  if (!TRUENAS_URL || !TRUENAS_API_KEY) return [];
  const url = `${TRUENAS_URL}/api/v2.0/disk`;
  try {
    const res = await fetch(url, {
      method: 'GET',
      headers: TRUENAS_HEADERS(TRUENAS_URL, TRUENAS_API_KEY),
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
  if (!TRUENAS_URL || !TRUENAS_API_KEY) return [];
  const entries = [];
  const opts = { method: 'GET', headers: TRUENAS_HEADERS(TRUENAS_URL, TRUENAS_API_KEY), signal: AbortSignal.timeout(8000) };

  try {
    const sshRes = await fetch(`${TRUENAS_URL}/api/v2.0/ssh`, opts);
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
    const appRes = await fetch(`${TRUENAS_URL}/api/v2.0/app/used_ports`, opts);
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

// ---------- 네트워크 정보 (서버 기준) ----------
app.get('/api/network', async (req, res) => {
  try {
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
    const networkStats = await getNetworkStatsFromNetdata();
    const payload = { hostname, interfaces, dns };
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

// SPA 폴백
app.get('*', (req, res) => {
  if (!req.path.startsWith('/api')) {
    res.sendFile(path.join(__dirname, '..', 'dist', 'index.html'));
  } else {
    res.status(404).json({ error: 'Not found' });
  }
});

function formatSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  return (bytes / (1024 * 1024 * 1024)).toFixed(1) + ' GB';
}

app.listen(PORT, '0.0.0.0', () => {
  console.log(`CloudStation server at http://0.0.0.0:${PORT}, DATA_PATH=${DATA_PATH}`);
});
