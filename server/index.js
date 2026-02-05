import express from 'express';
import cors from 'cors';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import { createReadStream } from 'fs';
import archiver from 'archiver';
import crypto from 'crypto';
import os from 'os';
import checkDiskSpace from 'check-disk-space';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 9000;

const DATA_PATH = process.env.DATA_PATH || path.join(__dirname, 'data');
const SHARES_FILE = process.env.SHARES_FILE || path.join(__dirname, 'shares.json');
const GEMINI_KEY_FILE = process.env.GEMINI_KEY_FILE || path.join(__dirname, '.gemini_key.enc');
const ENCRYPTION_SECRET = process.env.ENCRYPTION_SECRET || 'cloudstation-gemini-key-secret-change-in-production';
const NETDATA_URL = (process.env.NETDATA_URL || '').replace(/\/$/, '');

const ALGO = 'aes-256-gcm';
const IV_LEN = 16;
const AUTH_TAG_LEN = 16;
const KEY_LEN = 32;

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

/** Netdata에서 시스템 메트릭 가져오기. 실패 시 null. */
async function getSystemFromNetdata() {
  // jsonwrap 사용 시 latest_values / dimension_names 제공되면 시간 열 없이 사용 가능
  const [cpuRes, ramRes] = await Promise.all([
    fetchNetdataJson('/api/v1/data?context=system.cpu&points=1&format=json&options=jsonwrap'),
    fetchNetdataJson('/api/v1/data?context=system.ram&points=1&format=json&options=jsonwrap'),
  ]);

  const cpuNames = cpuRes?.dimension_names || cpuRes?.labels || [];
  const cpuValues = cpuRes?.latest_values ?? (cpuRes?.data?.length ? cpuRes.data[cpuRes.data.length - 1] : null);
  if (!Array.isArray(cpuValues)) return null;

  const cpuPair = Array.isArray(cpuRes?.latest_values)
    ? (() => {
        const names = cpuNames || [];
        const vals = cpuRes.latest_values;
        const skip = names[0] != null && /^time$/i.test(String(names[0])) ? 1 : 0;
        return { labels: names.slice(skip), values: vals.slice(skip) };
      })()
    : netdataRowValues(cpuNames, cpuValues);
  const { labels: cpuLabels, values: cpuV } = cpuPair;
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

  const ramNames = ramRes?.dimension_names || ramRes?.labels || [];
  const ramValues = ramRes?.latest_values ?? (ramRes?.data?.length ? ramRes.data[ramRes.data.length - 1] : null);
  if (!Array.isArray(ramValues)) return null;

  const ramPair = Array.isArray(ramRes?.latest_values)
    ? (() => {
        const names = ramNames || [];
        const vals = ramRes.latest_values;
        const skip = names[0] != null && /^time$/i.test(String(names[0])) ? 1 : 0;
        return { labels: names.slice(skip), values: vals.slice(skip) };
      })()
    : netdataRowValues(ramNames, ramValues);
  const { labels: ramLabels, values: ramV } = ramPair;
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

  return {
    cpu: { percent: cpuPercent },
    memory: { totalBytes, usedBytes },
    storage: null,
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

    res.json({
      storage,
      memory: payload.memory,
      cpu: payload.cpu,
      ...(payload.source && { source: payload.source }),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// ---------- RAID 정보 (/proc/mdstat 기반, Linux 전용) ----------
app.get('/api/raid', async (req, res) => {
  try {
    let text;
    try {
      text = await fs.readFile('/proc/mdstat', 'utf8');
    } catch {
      // 컨테이너/호스트에 mdadm 기반 소프트웨어 RAID가 없을 수 있음
      return res.json({ arrays: [] });
    }

    const lines = text.split('\n');
    const arrays = [];
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line || line.startsWith('Personalities') || line.startsWith('unused devices')) continue;
      // 예: md0 : active raid1 sda1[0] sdb1[1]
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

    res.json({ arrays });
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
