// index.js
const express = require('express');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const cookieParser = require('cookie-parser');
const sharp = require('sharp'); // 자동 썸네일 생성용
const { db, runMigrations } = require('./db');
const https = require('https');
const http = require('http');
const { URL } = require('url');

const app = express();
const PORT = 3000;

/* ================== 경로 상수 ================== */
const DATA_DIR = path.join(__dirname, 'data');
const MODELS_JSON = path.join(DATA_DIR, 'models.json');
const CATEGORIES_JSON = path.join(DATA_DIR, 'categories.json');

const UPLOADS_ROOT = path.join(__dirname, 'uploads');
const UPLOADS_MODELS_DIR = path.join(UPLOADS_ROOT, 'models'); // 모델 업로드(관리자용)
const UPLOADS_THUMBS_DIR = path.join(UPLOADS_ROOT, 'thumbs'); // 썸네일 저장 경로

// 디렉토리 보장
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOADS_ROOT, { recursive: true });
fs.mkdirSync(UPLOADS_MODELS_DIR, { recursive: true });
fs.mkdirSync(UPLOADS_THUMBS_DIR, { recursive: true });

/* ================== 초기 마이그레이션 ================== */
runMigrations();

/* ================== 미들웨어 ================== */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use('/uploads', express.static(UPLOADS_ROOT));
app.use(express.static(path.join(__dirname, 'public')));

/* ================== 업로드 설정 ================== */
const storageModel = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOADS_MODELS_DIR),
  filename: (_req, file, cb) => {
    const ts = Date.now();
    const safe = (file.originalname || 'file').replace(/\s+/g, '_');
    cb(null, `${ts}_${safe}`);
  }
});
const storageThumb = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOADS_THUMBS_DIR),
  filename: (_req, file, cb) => {
    const ts = Date.now();
    const safe = (file.originalname || 'image').replace(/\s+/g, '_');
    cb(null, `${ts}_${safe}`);
  }
});

const uploadModel = multer({ storage: storageModel, limits: { fileSize: 50 * 1024 * 1024 } }); // 50MB
const uploadThumb = multer({ storage: storageThumb, limits: { fileSize: 10 * 1024 * 1024 } });  // 10MB

/* ================== JSON 유틸 ================== */
function readJson(file, fallback = []) {
  try { return JSON.parse(fs.readFileSync(file, 'utf-8')); }
  catch { return fallback; }
}
function writeJson(file, data) {
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), 'utf-8');
  fs.renameSync(tmp, file);
}

/* ================== 토큰/권한 ================== */
const DEMO_SECRET = 'dev-secret';
function makeToken(username, role) {
  return Buffer.from(`${username}:${role}:${DEMO_SECRET}`).toString('base64');
}
function parseToken(token) {
  try {
    const raw = Buffer.from(token, 'base64').toString('utf-8');
    const [username, role, secret] = raw.split(':');
    if (secret !== DEMO_SECRET) return null;
    return { username, role };
  } catch { return null; }
}
function requireLogin(req, res, next) {
  const me = req.cookies?.ac_auth && parseToken(req.cookies.ac_auth);
  if (!me) return res.status(401).json({ error: 'UNAUTHORIZED' });
  req.user = me;
  next();
}
function requireAdmin(req, res, next) {
  const me = req.cookies?.ac_auth && parseToken(req.cookies.ac_auth);
  if (!me || me.role !== 'admin') return res.status(403).json({ error: 'admin 권한 필요' });
  req.user = me;
  next();
}

/* ================== 헬스체크 ================== */
app.get('/health', (_req, res) => res.json({ ok: true, now: new Date().toISOString() }));

/* ================== Auth ================== */
app.post('/api/auth/signup', (req, res) => {
  const { username, email, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username, password 필수' });

  const hashed = bcrypt.hashSync(password, 10);
  db.run(
    `INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, 'user')`,
    [username, email || null, hashed],
    function (err) {
      if (err) return res.status(400).json({ error: err.message });
      res.json({ ok: true, userId: this.lastID });
    }
  );
});

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body || {};
  db.get(
    `SELECT id, username, password, role FROM users WHERE username = ?`,
    [username],
    (err, row) => {
      if (err) return res.status(500).json({ error: err.message });
      if (!row) return res.status(401).json({ error: '존재하지 않는 계정' });
      if (!bcrypt.compareSync(password, row.password))
        return res.status(401).json({ error: '비밀번호 불일치' });

      const token = makeToken(row.username, row.role);
      res.cookie('ac_auth', token, { httpOnly: false }); // 데모: 프론트 디버깅 편의
      res.json({ ok: true, role: row.role });
    }
  );
});

app.get('/api/auth/whoami', (req, res) => {
  const me = req.cookies?.ac_auth ? parseToken(req.cookies.ac_auth) : null;
  res.json({ ok: !!me, user: me || null });
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('ac_auth');
  res.json({ ok: true });
});

/* ================== Models API ================== */
/** 목록: 프론트 기대형식 { items } */
app.get('/api/models', (req, res) => {
  const list = readJson(MODELS_JSON, []);
  const { category } = req.query || {};
  const filtered = category ? list.filter(m => m.categories?.includes(category)) : list;
  res.json({ items: filtered });
});

/** 상세 */
app.get('/api/models/:id', (req, res) => {
  const id = Number(req.params.id);
  const list = readJson(MODELS_JSON, []);
  const item = list.find(m => Number(m.id) === id);
  if (!item) return res.status(404).json({ error: 'not found' });
  res.json(item);
});

/* ---------- 자동 썸네일 생성 도우미 ---------- */
function hashCode(str) {
  let h = 0; for (let i = 0; i < str.length; i++) { h = ((h << 5) - h) + str.charCodeAt(i); h |= 0; }
  return Math.abs(h);
}
const PALETTE = [
  ['#4e77ba', '#bc2c3c'],
  ['#3aa675', '#0e7490'],
  ['#7c3aed', '#fb7185'],
  ['#f59e0b', '#ef4444'],
  ['#2563eb', '#16a34a'],
  ['#9333ea', '#3b82f6'],
  ['#0ea5e9', '#22c55e'],
  ['#ef4444', '#f97316'],
];
function makeSVG({ title = 'Untitled', description = '', key = 'x' }) {
  const idx = hashCode(String(key)) % PALETTE.length;
  const [c1, c2] = PALETTE[idx];
  const W = 640, H = 480;
  const safe = (s, max = 60) => (s || '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])).slice(0, max);
  const T1 = safe(title, 40);
  const D1 = safe(description, 60);
  return `
<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="${c1}"/>
      <stop offset="1" stop-color="${c2}"/>
    </linearGradient>
  </defs>
  <rect width="${W}" height="${H}" fill="url(#g)"/>
  <g fill="#fff" font-family="Pretendard, system-ui, -apple-system, Segoe UI, Roboto, Noto Sans KR">
    <text x="24" y="56" font-size="34" font-weight="700">${T1}</text>
    ${D1 ? `<text x="24" y="92" font-size="16" opacity="0.9">${D1}</text>` : ''}
  </g>
</svg>`;
}

/* ===== 원격 가져오기 유틸 ===== */
function downloadToFile(fileUrl, absDestPath) {
  return new Promise((resolve, reject) => {
    const u = new URL(fileUrl);
    const lib = u.protocol === 'https:' ? https : http;
    const req = lib.get({
      hostname: u.hostname,
      path: u.pathname + (u.search || ''),
      protocol: u.protocol,
      headers: {
        'User-Agent': 'ModelCatalogBot/1.0 (+https://example.local)',
        'Accept': 'image/*;q=0.9,*/*;q=0.1',
        'Accept-Encoding': 'identity'
      }
    }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return downloadToFile(res.headers.location, absDestPath).then(resolve).catch(reject);
      }
      if (res.statusCode !== 200) return reject(new Error('HTTP ' + res.statusCode));
      const file = fs.createWriteStream(absDestPath);
      res.pipe(file);
      file.on('finish', () => file.close(() => resolve(true)));
      file.on('error', reject);
    });
    req.on('error', reject);
  });
}

function getJson(urlStr) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlStr);
    const lib = u.protocol === 'https:' ? https : http;
    const req = lib.get({
      hostname: u.hostname,
      path: u.pathname + (u.search || ''),
      protocol: u.protocol,
      headers: {
        'User-Agent': 'ModelCatalogBot/1.0 (+https://example.local)',
        'Accept': 'application/json',
        'Accept-Encoding': 'identity'
      }
    }, (res) => {
      let data = '';
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return getJson(res.headers.location).then(resolve).catch(reject);
      }
      if (res.statusCode !== 200) return reject(new Error('HTTP ' + res.statusCode));
      res.setEncoding('utf8');
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
  });
}

/** Sketchfab URL에서 uid 추출 (…/3d-models/slug-<uid> or …/models/<uid>) */
function extractSketchfabUid(modelUrl) {
  try {
    const parts = modelUrl.split('/').filter(Boolean);
    const last = parts.pop() || '';
    if (last.includes('-')) return last.split('-').pop();
    return last;
  } catch { return null; }
}

/** [oEmbed] 썸네일 URL 얻기 — 원본 URL과 /models/{uid} 둘 다 시도 */
async function fetchSketchfabThumbnailUrl(modelUrl) {
  const uid = extractSketchfabUid(modelUrl);
  const candidates = [
    modelUrl, // 사용자가 준 원본 URL
    uid ? `https://sketchfab.com/models/${uid}` : null
  ].filter(Boolean);

  for (const pageUrl of candidates) {
    const oembedUrl = `https://sketchfab.com/oembed?format=json&url=${encodeURIComponent(pageUrl)}`;
    try {
      const data = await getJson(oembedUrl);
      const thumb = data.thumbnail_url || data.thumbnail_url_with_play_button || null;
      if (thumb) return thumb;
    } catch (e) {
      console.warn('[oEmbed fail]', pageUrl, e.message);
      continue;
    }
  }
  return null;
}

/**
 * 썸네일 경로 결정:
 * 1) 업로드 파일이 있으면 그걸 사용
 * 2) 업로드가 없다면 Sketchfab oEmbed에서 thumbnail_url을 받아 로컬에 저장
 * 3) 위가 실패하면 SVG→PNG 자동 생성(폴백)
 */
async function ensureAutoThumb({ uploadedPath, title, description, key, modelUrl }) {
  try {
    if (uploadedPath) return uploadedPath;

    if (modelUrl && /sketchfab\.com/i.test(modelUrl)) {
      const remote = await fetchSketchfabThumbnailUrl(modelUrl);
      if (remote) {
        const fname = `${Date.now()}_${Math.random().toString(36).slice(2)}.jpg`;
        const abs = path.join(UPLOADS_THUMBS_DIR, fname);
        await downloadToFile(remote, abs);
        return `/uploads/thumbs/${fname}`;
      }
    }
  } catch (e) {
    console.warn('[ensureAutoThumb:oEmbed]', e.message);
  }

  // 폴백: SVG 기반 자동 생성
  const svg = makeSVG({ title, description, key });
  const filename = `${Date.now()}_${Math.random().toString(36).slice(2)}.png`;
  const abs = path.join(UPLOADS_THUMBS_DIR, filename);
  await sharp(Buffer.from(svg)).png().toFile(abs);
  return `/uploads/thumbs/${filename}`;
}

/* ---------- (A) 일반 업로드: 프론트 폼과 호환 (/api/models) ---------- */
/**
 * 프론트에서 보내는 FormData:
 * - title, description, url, subject, (thumb: optional file)
 */
app.post('/api/models',
  requireLogin,
  uploadThumb.single('thumb'),
  async (req, res) => {
    try {
      const { title, description, url, subject } = req.body || {};
      if (!title || !description || !url) {
        return res.status(400).json({ error: 'REQUIRED_FIELDS' });
      }

      const list = readJson(MODELS_JSON, []);
      const nextId = (list.reduce((m, cur) => Math.max(m, cur.id || 0), 0) || 0) + 1;

      // 업로드 썸네일이 없으면 자동 생성 (Sketchfab oEmbed 우선)
      const uploadedThumbPath = req.file ? `/uploads/thumbs/${req.file.filename}` : null;
      const thumb = await ensureAutoThumb({
        uploadedPath: uploadedThumbPath,
        title,
        description,
        key: title || String(nextId),
        modelUrl: url
      });

      const item = {
        id: nextId,
        title,
        description,
        url,
        subject: subject || '',
        thumb
      };
      // 새 항목은 맨 앞에
      list.unshift(item);
      writeJson(MODELS_JSON, list);
      return res.json({ ok: true, item });
    } catch (e) {
      console.error('[UPLOAD /api/models]', e);
      return res.status(500).json({ error: 'SERVER_ERROR' });
    }
  }
);

/* ---------- (B) 관리자 업로드: 모델 파일 자체 업로드 (/api/admin/models) ---------- */
app.post('/api/admin/models',
  requireAdmin,
  uploadModel.single('model'),
  (req, res) => {
    const { title, author, categories } = req.body || {};
    if (!req.file) return res.status(400).json({ error: '파일(model) 누락' });
    if (!title) return res.status(400).json({ error: 'title 필수' });

    const list = readJson(MODELS_JSON, []);
    const nextId = (list.reduce((m, cur) => Math.max(m, cur.id || 0), 0) || 0) + 1;

    let cats = [];
    if (Array.isArray(categories)) cats = categories;
    else if (typeof categories === 'string' && categories.trim()) {
      cats = categories.split(',').map(s => s.trim()).filter(Boolean);
    }

    const now = new Date().toISOString();
    const record = {
      id: nextId,
      title,
      author: author || null,
      categories: cats,
      filename: req.file.filename,
      filesize: req.file.size,
      mimetype: req.file.mimetype,
      created_at: now,
      updated_at: now,
      enabled: true
    };

    list.unshift(record);
    writeJson(MODELS_JSON, list);
    res.json({ ok: true, id: nextId, filename: `/uploads/models/${req.file.filename}` });
  }
);

/* ---------- 삭제/정렬 ---------- */
// 일반 삭제(로그인 필요) — 프론트에서 쓰는 것
app.delete('/api/models/:id', requireLogin, async (req, res) => {
  const id = Number(req.params.id);
  const list = readJson(MODELS_JSON, []);
  const idx = list.findIndex(m => Number(m.id) === id);
  if (idx === -1) return res.status(404).json({ error: 'NOT_FOUND' });

  const [removed] = list.splice(idx, 1);
  writeJson(MODELS_JSON, list);

  // 업로드한 썸네일이면 파일 제거 시도
  if (removed?.thumb && removed.thumb.startsWith('/uploads/thumbs/')) {
    const abs = path.join(__dirname, removed.thumb.replace(/^\//, ''));
    fs.promises.unlink(abs).catch(() => {});
  }
  console.log(`[DELETE] 모델 ID ${id} 삭제 완료`);
  return res.json({ ok: true });
});

// 순서 재정렬(로그인 필요) — models.json 덮어쓰기
app.post('/api/models/reorder', requireLogin, (req, res) => {
  const { order } = req.body || {};
  if (!Array.isArray(order) || order.length === 0) {
    return res.status(400).json({ error: 'INVALID_ORDER' });
  }
  const current = readJson(MODELS_JSON, []);
  const map = new Map(current.map(m => [String(m.id), m]));
  const ordered = [];
  for (const id of order.map(String)) {
    if (map.has(id)) { ordered.push(map.get(id)); map.delete(id); }
  }
  for (const rest of map.values()) ordered.push(rest);

  try {
    writeJson(MODELS_JSON, ordered);
    return res.json({ ok: true, count: ordered.length });
  } catch (e) {
    console.error('[REORDER]', e);
    return res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

/* ---------- 카테고리 ---------- */
app.get('/api/categories', (_req, res) => {
  res.json(readJson(CATEGORIES_JSON, []));
});

/* ================== 서버 기동 ================== */
app.listen(PORT, () => {
  console.log(`Server → http://localhost:${PORT}`);
  if (!fs.existsSync(MODELS_JSON)) { writeJson(MODELS_JSON, []); console.log('ℹ️  data/models.json created.'); }
  if (!fs.existsSync(CATEGORIES_JSON)) { writeJson(CATEGORIES_JSON, []); console.log('ℹ️  data/categories.json created.'); }
});
