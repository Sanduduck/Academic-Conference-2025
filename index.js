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

/* ================== 초기 마이그레이션/시드 ================== */
runMigrations();
// 관리자 계정 시드(없으면 생성). 기본값 admin/admin (운영에선 꼭 바꿔!)
(function seedAdmin() {
  db.get(`SELECT id FROM users WHERE username='admin' AND role='admin'`, (err, row) => {
    if (err) return console.error('[SEED] admin lookup fail:', err.message);
    if (row) return; // already exists
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
const uploadModel = multer({ storage: storageModel, limits: { fileSize: 50 * 1024 * 1024 } });
const uploadThumb = multer({ storage: storageThumb, limits: { fileSize: 10 * 1024 * 1024 } });

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
  if (!me || me.role !== 'admin') return res.status(403).json({ error: 'ADMIN_ONLY' });
  req.user = me;
  next();
}

/* ================== 헬스/정적 ================== */
app.get('/health', (_req, res) => res.json({ ok: true, now: new Date().toISOString() }));

// /admin: 관리자 로그인 페이지(정적)
app.get('/admin', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

/* ================== Auth ================== */
// 일반 회원가입/로그인(마이페이지/북마크 용)
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
  db.get(`SELECT id, username, password, role FROM users WHERE username = ?`, [username], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.status(401).json({ error: '존재하지 않는 계정' });
    if (!bcrypt.compareSync(password, row.password)) return res.status(401).json({ error: '비밀번호 불일치' });
    const token = makeToken(row.username, row.role);
    res.cookie('ac_auth', token, {
    httpOnly: false,     // 데모용(개발 편의), 배포 땐 true 권장 + 프론트에서 읽지 말기
    sameSite: 'Lax',     // 기본이 Lax지만 명시
    path: '/',           // 전체 경로에서 유효
    // secure: true,     // HTTPS에서만. 로컬(http) 개발이면 주석
  });
    res.json({ ok: true, role: row.role });
  });
});

// 관리자 로그인( /admin 화면의 폼이 호출 )
app.post('/api/auth/admin-login', (req, res) => {
  const { password } = req.body || {};
  // admin 고정 계정 조회
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
  const me = req.cookies?.ac_auth ? parseToken(req.cookies.ac_auth) : null;
  res.json({ ok: !!me, user: me || null });
});
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('ac_auth');
  res.json({ ok: true });
});

/* ================== 썸네일(oEmbed 우선, 실패 시 SVG) ================== */
function hashCode(str){let h=0;for(let i=0;i<str.length;i++){h=((h<<5)-h)+str.charCodeAt(i);h|=0;}return Math.abs(h);}
const PALETTE=[['#4e77ba','#bc2c3c'],['#3aa675','#0e7490'],['#7c3aed','#fb7185'],['#f59e0b','#ef4444'],['#2563eb','#16a34a'],['#9333ea','#3b82f6'],['#0ea5e9','#22c55e'],['#ef4444','#f97316']];
function makeSVG({ title='Untitled', description='', key='x'}){
  const [c1,c2]=PALETTE[hashCode(String(key))%PALETTE.length];const W=640,H=480;
  const esc=s=>(s||'').replace(/[&<>"]/g,c=>({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
  const T1=esc(title).slice(0,40),D1=esc(description).slice(0,60);
  return `<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" xmlns="http://www.w3.org/2000/svg">
  <defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="${c1}"/><stop offset="1" stop-color="${c2}"/></linearGradient></defs>
  <rect width="${W}" height="${H}" fill="url(#g)"/><g fill="#fff" font-family="Pretendard,system-ui,-apple-system,Segoe UI,Roboto,Noto Sans KR">
  <text x="24" y="56" font-size="34" font-weight="700">${T1}</text>${D1?`<text x="24" y="92" font-size="16" opacity=".9">${D1}</text>`:''}</g></svg>`;
}
function httpGetJson(urlStr){
  return new Promise((resolve,reject)=>{
    const u=new URL(urlStr);const lib=u.protocol==='https:'?https:http;
    const req=lib.get({hostname:u.hostname,path:u.pathname+(u.search||''),protocol:u.protocol,headers:{
      'User-Agent':'ModelCatalogBot/1.0','Accept':'application/json','Accept-Encoding':'identity'}},(res)=>{
      let data=''; if(res.statusCode>=300&&res.statusCode<400&&res.headers.location){return httpGetJson(res.headers.location).then(resolve).catch(reject);}
      if(res.statusCode!==200) return reject(new Error('HTTP '+res.statusCode));
      res.setEncoding('utf8'); res.on('data',c=>data+=c); res.on('end',()=>{try{resolve(JSON.parse(data));}catch(e){reject(e);}});
    }); req.on('error',reject);
  });
}
function downloadToFile(fileUrl, absDest){
  return new Promise((resolve,reject)=>{
    const u=new URL(fileUrl); const lib=u.protocol==='https:'?https:http;
    const req=lib.get({hostname:u.hostname,path:u.pathname+(u.search||''),protocol:u.protocol,headers:{
      'User-Agent':'ModelCatalogBot/1.0','Accept':'image/*;q=0.9,*/*;q=0.1','Accept-Encoding':'identity'}},(res)=>{
      if(res.statusCode>=300&&res.statusCode<400&&res.headers.location){return downloadToFile(res.headers.location,absDest).then(resolve).catch(reject);}
      if(res.statusCode!==200) return reject(new Error('HTTP '+res.statusCode));
      const file=fs.createWriteStream(absDest); res.pipe(file);
      file.on('finish',()=>file.close(()=>resolve(true))); file.on('error',reject);
    }); req.on('error',reject);
  });
}
function extractSketchfabUid(modelUrl){
  try{const parts=modelUrl.split('/').filter(Boolean);const last=parts.pop()||'';return last.includes('-')?last.split('-').pop():last;}catch{return null;}
}
async function fetchSketchfabThumb(modelUrl){
  const uid = extractSketchfabUid(modelUrl);
  const candidates=[modelUrl, uid?`https://sketchfab.com/models/${uid}`:null].filter(Boolean);
  for(const pageUrl of candidates){
    const oembed=`https://sketchfab.com/oembed?format=json&url=${encodeURIComponent(pageUrl)}`;
    try{
      const data=await httpGetJson(oembed);
      const t=data.thumbnail_url || data.thumbnail_url_with_play_button;
      if (t) return t;
    }catch(e){ console.warn('[oEmbed fail]', pageUrl, e.message); }
  }
  return null;
}
async function ensureAutoThumb({ uploadedPath, title, description, key, modelUrl }){
  try{
    if(uploadedPath) return uploadedPath;
    if(modelUrl && /sketchfab\.com/i.test(modelUrl)){
      const remote=await fetchSketchfabThumb(modelUrl);
      if(remote){
        const fname=`${Date.now()}_${Math.random().toString(36).slice(2)}.jpg`;
        const abs=path.join(UPLOADS_THUMBS_DIR,fname);
        await downloadToFile(remote, abs);
        return `/uploads/thumbs/${fname}`;
      }
    }
  }catch(e){ console.warn('[ensureAutoThumb:oEmbed]', e.message); }
  // 폴백: SVG 생성
  const svg = makeSVG({ title, description, key });
  const fname = `${Date.now()}_${Math.random().toString(36).slice(2)}.png`;
  await sharp(Buffer.from(svg)).png().toFile(path.join(UPLOADS_THUMBS_DIR, fname));
  return `/uploads/thumbs/${fname}`;
}

/* ================== Models API ================== */
// 목록
app.get('/api/models', (req, res) => {
  const list = readJson(MODELS_JSON, []);
  res.json({ items: list });
});
// 상세
app.get('/api/models/:id', (req, res) => {
  const id = Number(req.params.id);
  const list = readJson(MODELS_JSON, []);
  const item = list.find(m => Number(m.id) === id);
  if (!item) return res.status(404).json({ error: 'NOT_FOUND' });
  res.json(item);
});

// 업로드(이제 관리자 전용)
app.post('/api/models',
  requireAdmin,
  uploadThumb.single('thumb'),
  async (req, res) => {
    try{
      const { title, description, url, subject } = req.body || {};
      if (!title || !description || !url) return res.status(400).json({ error: 'REQUIRED_FIELDS' });

      const list = readJson(MODELS_JSON, []);
      const nextId = (list.reduce((m,cur)=>Math.max(m,cur.id||0),0)||0)+1;

      const uploadedThumbPath = req.file ? `/uploads/thumbs/${req.file.filename}` : null;
      const thumb = await ensureAutoThumb({
        uploadedPath: uploadedThumbPath, title, description, key: title || String(nextId), modelUrl: url
      });

      const item = { id: nextId, title, description, url, subject: subject || '', thumb };
      list.unshift(item);
      writeJson(MODELS_JSON, list);
      res.json({ ok:true, item });
    }catch(e){
      console.error('[POST /api/models]', e);
      res.status(500).json({ error:'SERVER_ERROR' });
    }
  }
);

// 삭제(관리자 전용)
app.delete('/api/models/:id', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const list = readJson(MODELS_JSON, []);
  const idx = list.findIndex(m=>Number(m.id)===id);
  if (idx === -1) return res.status(404).json({ error:'NOT_FOUND' });

  const [removed] = list.splice(idx,1);
  writeJson(MODELS_JSON, list);

  if (removed?.thumb && removed.thumb.startsWith('/uploads/thumbs/')) {
    const abs = path.join(__dirname, removed.thumb.replace(/^\//,''));
    fs.promises.unlink(abs).catch(()=>{});
  }
  res.json({ ok:true });
});

// 순서 재정렬(관리자 전용)
app.post('/api/models/reorder', requireAdmin, (req, res) => {
  const { order } = req.body || {};
  if (!Array.isArray(order) || !order.length) return res.status(400).json({ error:'INVALID_ORDER' });

  const current = readJson(MODELS_JSON, []);
  const map = new Map(current.map(m=>[String(m.id), m]));
  const ordered = [];
  for (const id of order.map(String)) {
    if (map.has(id)) { ordered.push(map.get(id)); map.delete(id); }
  }
  for (const rest of map.values()) ordered.push(rest);

  try { writeJson(MODELS_JSON, ordered); res.json({ ok:true, count: ordered.length }); }
  catch(e){ console.error('[REORDER]', e); res.status(500).json({ error:'SERVER_ERROR' }); }
});

// 카테고리(필요시 유지)
app.get('/api/categories', (_req,res)=> res.json(readJson(CATEGORIES_JSON, [])));

/* ================== 서버 기동 ================== */
app.listen(PORT, () => {
  console.log(`Server → http://localhost:${PORT}`);
  if (!fs.existsSync(MODELS_JSON)) { writeJson(MODELS_JSON, []); console.log('ℹ️ data/models.json created'); }
  if (!fs.existsSync(CATEGORIES_JSON)) { writeJson(CATEGORIES_JSON, []); console.log('ℹ️ data/categories.json created'); }
});
