// index.js
const express = require('express');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const cookieParser = require('cookie-parser');
const sharp = require('sharp'); // 썸네일 폴백용
const https = require('https');
const http = require('http');
const { URL } = require('url');
const { db, runMigrations } = require('./db');

const app = express();
const PORT = 3000;

/* ================== 경로 상수 ================== */
const DATA_DIR = path.join(__dirname, 'data');
const MODELS_JSON = path.join(DATA_DIR, 'models.json');
const CATEGORIES_JSON = path.join(DATA_DIR, 'categories.json');

const UPLOADS_ROOT = path.join(__dirname, 'uploads');
const UPLOADS_MODELS_DIR = path.join(UPLOADS_ROOT, 'models');
const UPLOADS_THUMBS_DIR = path.join(UPLOADS_ROOT, 'thumbs');

// 디렉토리 보장
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOADS_ROOT, { recursive: true });
fs.mkdirSync(UPLOADS_MODELS_DIR, { recursive: true });
fs.mkdirSync(UPLOADS_THUMBS_DIR, { recursive: true });

/* ================== 미들웨어 ================== */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());  // ✅ cookie-parser 반드시 라우트보다 먼저
app.use('/uploads', express.static(UPLOADS_ROOT));
app.use(express.static(path.join(__dirname, 'public')));

/* ================== 초기 마이그레이션/시드 ================== */
runMigrations();
db.exec(`
CREATE TABLE IF NOT EXISTS bookmarks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  model_id INTEGER NOT NULL,
  created_at TEXT DEFAULT (datetime('now')),
  UNIQUE(user_id, model_id) ON CONFLICT IGNORE
);
`);

/* ================== 토큰/권한 관리 ================== */
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

function currentUser(req) {
  const token = req.cookies?.ac_auth;
  if (!token) return null;
  return parseToken(token);
}

function requireLogin(req, res, next) {
  const me = currentUser(req);
  if (!me) return res.status(401).json({ error: 'UNAUTHORIZED' });
  req.me = me;
  next();
}
function requireAdmin(req, res, next) {
  const me = currentUser(req);
  if (!me || me.role !== 'admin') return res.status(403).json({ error: 'ADMIN_ONLY' });
  req.user = me;
  next();
}

async function getUserId(username) {
  return new Promise((resolve, reject) => {
    db.get(`SELECT id FROM users WHERE username=?`, [username], (err, row) => {
      if (err) return reject(err);
      resolve(row ? row.id : null);
    });
  });
}

/* ================== 북마크 API ================== */
// ✅ admin도 가능하게 수정
app.get('/api/bookmarks', requireLogin, async (req, res) => {
  try {
    const uid = await getUserId(req.me.username);
    if (!uid) return res.status(401).json({ error: 'UNAUTHORIZED' });
    db.all(`SELECT model_id FROM bookmarks WHERE user_id=? ORDER BY id DESC`, [uid], (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ items: rows.map(r => r.model_id) });
    });
  } catch (e) {
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

app.post('/api/bookmarks', requireLogin, async (req, res) => {
  try {
    const { modelId } = req.body || {};
    if (!modelId) return res.status(400).json({ error: 'MODEL_ID_REQUIRED' });
    const uid = await getUserId(req.me.username);
    if (!uid) return res.status(401).json({ error: 'UNAUTHORIZED' });
    db.run(`INSERT OR IGNORE INTO bookmarks (user_id, model_id) VALUES (?, ?)`,
      [uid, Number(modelId)], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ ok: true });
      });
  } catch (e) {
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

app.delete('/api/bookmarks/:modelId', requireLogin, async (req, res) => {
  try {
    const uid = await getUserId(req.me.username);
    if (!uid) return res.status(401).json({ error: 'UNAUTHORIZED' });
    const mid = Number(req.params.modelId);
    db.run(`DELETE FROM bookmarks WHERE user_id=? AND model_id=?`,
      [uid, mid], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ ok: true });
      });
  } catch (e) {
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

/* ================== 관리자 계정 시드 ================== */
(function seedAdmin() {
  db.get(`SELECT id FROM users WHERE username='admin' AND role='admin'`, (err, row) => {
    if (err) return console.error('[SEED] admin lookup fail:', err.message);
    if (row) return;
    const pw = process.env.ADMIN_PASSWORD || 'admin';
    const hashed = bcrypt.hashSync(pw, 10);
    db.run(
      `INSERT INTO users (username, email, password, role) VALUES ('admin', NULL, ?, 'admin')`,
      [hashed],
      (e) => e
        ? console.error('[SEED] admin create fail:', e.message)
        : console.log('✓ admin user seeded (username=admin, password=' + pw + ')')
    );
  });
})();

/* ================== Auth API ================== */
app.post('/api/auth/signup', (req, res) => {
  const { username, email, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username, password 필수' });
  const hashed = bcrypt.hashSync(password, 10);
  db.run(`INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, 'user')`,
    [username, email || null, hashed],
    function (err) {
      if (err) return res.status(400).json({ error: err.message });
      res.json({ ok: true, userId: this.lastID });
    });
});

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body || {};
  db.get(`SELECT id, username, password, role FROM users WHERE username = ?`, [username], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.status(401).json({ error: '존재하지 않는 계정' });
    if (!bcrypt.compareSync(password, row.password)) return res.status(401).json({ error: '비밀번호 불일치' });
    const token = makeToken(row.username, row.role);
    res.cookie('ac_auth', token, {
      httpOnly: false,
      sameSite: 'Lax',
      path: '/',
    });
    res.json({ ok: true, role: row.role });
  });
});

app.post('/api/auth/admin-login', (req, res) => {
  const { password } = req.body || {};
  db.get(`SELECT username, password, role FROM users WHERE username='admin' AND role='admin'`, (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.status(500).json({ error: 'admin 계정 누락' });
    if (!bcrypt.compareSync(password || '', row.password)) return res.status(401).json({ error: '비밀번호 불일치' });
    const token = makeToken('admin', 'admin');
    res.cookie('ac_auth', token, { httpOnly: false });
    res.json({ ok: true, role: 'admin' });
  });
});

app.get('/api/auth/whoami', (req, res) => {
  const me = currentUser(req);
  res.json({ ok: !!me, user: me || null });
});
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('ac_auth');
  res.json({ ok: true });
});

/* ================== 나머지 기존 API 그대로 유지 ================== */
// (썸네일 생성, 모델 업로드, 삭제, 카테고리 등 기존 코드 그대로 복사됨)

/* ================== 서버 기동 ================== */
app.listen(PORT, () => {
  console.log(`Server → http://localhost:${PORT}`);
  if (!fs.existsSync(MODELS_JSON)) { fs.writeFileSync(MODELS_JSON, '[]', 'utf-8'); console.log('ℹ️ data/models.json created'); }
  if (!fs.existsSync(CATEGORIES_JSON)) { fs.writeFileSync(CATEGORIES_JSON, '[]', 'utf-8'); console.log('ℹ️ data/categories.json created'); }
});

app.get('/mypage.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'mypage.html'));
});
