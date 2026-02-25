const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const webpush = require('web-push');
const archiver = require('archiver');
const views = require('./views');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, '..', 'data');
const UPLOAD_DIR = path.join(DATA_DIR, '..', 'uploads');
const HEADER_DIR = path.join(UPLOAD_DIR, 'headers');
const DB_PATH = path.join(DATA_DIR, 'uploader.db');
let vapidPublicKey = process.env.VAPID_PUBLIC_KEY || '';
let vapidPrivateKey = process.env.VAPID_PRIVATE_KEY || '';
let vapidSubject = process.env.VAPID_SUBJECT || 'mailto:admin@example.com';
const AUTH_FAILURE_WINDOW_MINUTES = 15;
const AUTH_FAILURE_LIMIT = 8;
const AUTH_BLOCK_MINUTES = 20;
const UPLOAD_WINDOW_SHORT_MINUTES = 5;
const UPLOAD_WINDOW_LONG_MINUTES = 60;
const UPLOAD_ATTEMPT_LIMIT_SHORT = 6;
const UPLOAD_ATTEMPT_LIMIT_LONG = 20;

function configureWebPush() {
  if (vapidPublicKey && vapidPrivateKey) {
    webpush.setVapidDetails(vapidSubject || 'mailto:admin@example.com', vapidPublicKey, vapidPrivateKey);
  }
}

configureWebPush();

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });
fs.mkdirSync(HEADER_DIR, { recursive: true });

const db = new sqlite3.Database(DB_PATH);


async function getSetting(key) {
  const row = await get('SELECT value FROM app_settings WHERE key = ?', [key]);
  return row ? row.value : null;
}

async function setSetting(key, value) {
  await run(
    `INSERT INTO app_settings (key, value, updated_at)
     VALUES (?, ?, ?)
     ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
    [key, value, nowIso()],
  );
}

async function loadPushConfig() {
  const dbPublic = await getSetting('vapid_public_key');
  const dbPrivate = await getSetting('vapid_private_key');
  const dbSubject = await getSetting('vapid_subject');
  if (dbPublic !== null) vapidPublicKey = dbPublic;
  if (dbPrivate !== null) vapidPrivateKey = dbPrivate;
  if (dbSubject !== null) vapidSubject = dbSubject;
  configureWebPush();
}

function hasPushConfig() {
  return Boolean(vapidPublicKey && vapidPrivateKey);
}

function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function onRun(err) {
      if (err) return reject(err);
      return resolve(this);
    });
  });
}

function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => (err ? reject(err) : resolve(row)));
  });
}

function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => (err ? reject(err) : resolve(rows)));
  });
}

async function ensureColumn(table, column, definition) {
  const columns = await all(`PRAGMA table_info(${table})`);
  if (!columns.some((entry) => entry.name === column)) {
    await run(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
}

async function initDb() {
  await run(`CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    created_at TEXT NOT NULL
  )`);
  await run(`CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT UNIQUE NOT NULL,
    admin_id INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    FOREIGN KEY(admin_id) REFERENCES admins(id)
  )`);
  await run(`CREATE TABLE IF NOT EXISTS boxes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    description TEXT,
    allowed_extensions TEXT NOT NULL,
    max_file_size_mb INTEGER NOT NULL,
    max_files_per_upload INTEGER NOT NULL,
    password_hash TEXT,
    password_salt TEXT,
    discord_webhook_url TEXT,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_by_admin_id INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(created_by_admin_id) REFERENCES admins(id)
  )`);
  await run(`CREATE TABLE IF NOT EXISTS uploaded_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    box_id INTEGER NOT NULL,
    uploader_name TEXT,
    uploader_note TEXT,
    original_name TEXT NOT NULL,
    stored_name TEXT NOT NULL,
    mime_type TEXT,
    size_bytes INTEGER NOT NULL,
    uploader_ip TEXT,
    uploaded_at TEXT NOT NULL,
    FOREIGN KEY(box_id) REFERENCES boxes(id)
  )`);

  await run(`CREATE TABLE IF NOT EXISTS box_viewers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by_admin_id INTEGER,
    FOREIGN KEY(created_by_admin_id) REFERENCES admins(id)
  )`);
  await run(`CREATE TABLE IF NOT EXISTS viewer_box_permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    viewer_id INTEGER NOT NULL,
    box_id INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(viewer_id, box_id),
    FOREIGN KEY(viewer_id) REFERENCES box_viewers(id),
    FOREIGN KEY(box_id) REFERENCES boxes(id)
  )`);
  await run(`CREATE TABLE IF NOT EXISTS viewer_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT UNIQUE NOT NULL,
    viewer_id INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    FOREIGN KEY(viewer_id) REFERENCES box_viewers(id)
  )`);

  await run(`CREATE TABLE IF NOT EXISTS notification_subscriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_type TEXT NOT NULL,
    actor_id INTEGER NOT NULL,
    endpoint TEXT NOT NULL,
    p256dh TEXT NOT NULL,
    auth TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(actor_type, actor_id, endpoint)
  )`);
  await run(`CREATE TABLE IF NOT EXISTS notification_box_settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_type TEXT NOT NULL,
    actor_id INTEGER NOT NULL,
    box_id INTEGER NOT NULL,
    is_enabled INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL,
    UNIQUE(actor_type, actor_id, box_id)
  )`);
  await run(`CREATE TABLE IF NOT EXISTS upload_bans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_key TEXT UNIQUE NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    released_at TEXT
  )`);
  await run(`CREATE TABLE IF NOT EXISTS upload_violations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_key TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL
  )`);
  await run(`CREATE TABLE IF NOT EXISTS login_blocks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_key TEXT UNIQUE NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
  )`);
  await run(`CREATE TABLE IF NOT EXISTS login_violations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_key TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL
  )`);
  await run(`CREATE TABLE IF NOT EXISTS upload_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_key TEXT NOT NULL,
    box_id INTEGER,
    was_success INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    FOREIGN KEY(box_id) REFERENCES boxes(id)
  )`);
  await run(`CREATE TABLE IF NOT EXISTS analytics_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    box_id INTEGER,
    actor_role TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(box_id) REFERENCES boxes(id)
  )`);
  await run(`CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
  )`);

  await ensureColumn('boxes', 'header_image_path', 'TEXT');
  await ensureColumn('boxes', 'public_notice', 'TEXT');
  await ensureColumn('boxes', 'success_message', "TEXT DEFAULT 'アップロードありがとうございました。'");
  await ensureColumn('boxes', 'require_uploader_name', 'INTEGER NOT NULL DEFAULT 0');
  await ensureColumn('boxes', 'max_total_files', 'INTEGER');
  await ensureColumn('boxes', 'expires_at', 'TEXT');
  await ensureColumn('boxes', 'font_family', "TEXT DEFAULT 'system'");
  await ensureColumn('boxes', 'accent_color', "TEXT DEFAULT '#2563eb'");
  await ensureColumn('boxes', 'custom_css', 'TEXT');
  await ensureColumn('boxes', 'require_uploader_note', 'INTEGER NOT NULL DEFAULT 0');
  await ensureColumn('boxes', 'success_redirect_url', 'TEXT');
  await ensureColumn('boxes', 'max_file_size_bytes', 'INTEGER');

  await run('UPDATE boxes SET max_file_size_bytes = max_file_size_mb * 1024 * 1024 WHERE max_file_size_bytes IS NULL AND max_file_size_mb IS NOT NULL');
}

function nowIso() {
  return new Date().toISOString();
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  return { salt, hash: crypto.pbkdf2Sync(password, salt, 120000, 64, 'sha512').toString('hex') };
}

function normalizeUsername(raw) {
  return (raw || '').trim();
}

function isValidUsername(username) {
  return /^[a-zA-Z0-9_.-]{3,64}$/.test(username);
}

function isValidPassword(password) {
  return typeof password === 'string' && password.length >= 8 && password.length <= 128;
}

function safeCompare(a, b) {
  const aBuffer = Buffer.from(a, 'hex');
  const bBuffer = Buffer.from(b, 'hex');
  return aBuffer.length === bBuffer.length && crypto.timingSafeEqual(aBuffer, bBuffer);
}

function parseCookies(req) {
  const raw = req.headers.cookie || '';
  return raw.split(';').reduce((acc, item) => {
    const [key, ...rest] = item.trim().split('=');
    if (key) acc[key] = decodeURIComponent(rest.join('='));
    return acc;
  }, {});
}

function setCookie(res, name, value, maxAgeSeconds) {
  const prev = res.getHeader('Set-Cookie');
  const secureCookie = process.env.COOKIE_SECURE === '1' || process.env.NODE_ENV === 'production';
  const next = `${name}=${encodeURIComponent(value)}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${maxAgeSeconds}${secureCookie ? '; Secure' : ''}`;
  if (!prev) {
    res.setHeader('Set-Cookie', [next]);
    return;
  }
  res.setHeader('Set-Cookie', Array.isArray(prev) ? [...prev, next] : [prev, next]);
}

function clearCookie(res, name) {
  const prev = res.getHeader('Set-Cookie');
  const secureCookie = process.env.COOKIE_SECURE === '1' || process.env.NODE_ENV === 'production';
  const next = `${name}=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0${secureCookie ? '; Secure' : ''}`;
  if (!prev) {
    res.setHeader('Set-Cookie', [next]);
    return;
  }
  res.setHeader('Set-Cookie', Array.isArray(prev) ? [...prev, next] : [prev, next]);
}

async function createSession(table, ownerField, ownerId) {
  const token = crypto.randomBytes(32).toString('hex');
  await run(
    `INSERT INTO ${table} (token_hash, ${ownerField}, created_at, expires_at) VALUES (?, ?, ?, ?)`,
    [crypto.createHash('sha256').update(token).digest('hex'), ownerId, nowIso(), new Date(Date.now() + (1000 * 60 * 60 * 24 * 14)).toISOString()],
  );
  return token;
}

async function getAdminFromRequest(req) {
  const token = parseCookies(req).admin_session;
  if (!token) return null;
  const session = await get(
    'SELECT sessions.id AS session_id, sessions.expires_at, admins.id, admins.username FROM sessions INNER JOIN admins ON admins.id = sessions.admin_id WHERE sessions.token_hash = ?',
    [crypto.createHash('sha256').update(token).digest('hex')],
  );
  if (!session) return null;
  if (new Date(session.expires_at).getTime() < Date.now()) {
    await run('DELETE FROM sessions WHERE id = ?', [session.session_id]);
    return null;
  }
  return { id: session.id, username: session.username, role: 'admin' };
}

async function getViewerFromRequest(req) {
  const token = parseCookies(req).viewer_session;
  if (!token) return null;
  const session = await get(
    'SELECT viewer_sessions.id AS session_id, viewer_sessions.expires_at, box_viewers.id, box_viewers.username FROM viewer_sessions INNER JOIN box_viewers ON box_viewers.id = viewer_sessions.viewer_id WHERE viewer_sessions.token_hash = ?',
    [crypto.createHash('sha256').update(token).digest('hex')],
  );
  if (!session) return null;
  if (new Date(session.expires_at).getTime() < Date.now()) {
    await run('DELETE FROM viewer_sessions WHERE id = ?', [session.session_id]);
    return null;
  }
  return { id: session.id, username: session.username, role: 'viewer' };
}

function redirect(res, to) {
  res.status(302).set('Location', to).send();
}

function requireAdmin(handler) {
  return async (req, res) => {
    const admin = await getAdminFromRequest(req);
    if (!admin) return redirect(res, '/admin/login');
    return handler(req, res, admin);
  };
}

function uniqueSlug(text) {
  return text.toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || crypto.randomBytes(4).toString('hex');
}

function isBoxExpired(box) {
  if (!box.expires_at) return false;
  const t = new Date(box.expires_at).getTime();
  return Number.isFinite(t) && t < Date.now();
}

function getClientIp(req) {
  return req.headers['cf-connecting-ip'] || req.ip || '';
}

function hashKey(value) {
  return crypto.createHash('sha256').update(String(value || '')).digest('hex');
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function delayAuthFailureResponse() {
  await sleep(250 + Math.floor(Math.random() * 200));
}

function normalizeHexColor(value, fallback = '#2563eb') {
  return /^#[0-9a-fA-F]{6}$/.test(value || '') ? value : fallback;
}

function normalizeFontFamily(value) {
  return ['system', 'sans', 'serif', 'mono'].includes(value) ? value : 'system';
}

function normalizeBoxInput(body) {
  const extList = (body.allowedExtensions || '').split(',').map((v) => v.trim().toLowerCase().replace(/^\./, '')).filter((v) => /^[a-z0-9]+$/.test(v));
  const sizeUnits = { KB: 1024, MB: 1024 * 1024, GB: 1024 * 1024 * 1024, TB: 1024 * 1024 * 1024 * 1024 };
  const maxFileSizeUnit = String(body.maxFileSizeUnit || 'MB').toUpperCase();
  const maxFileSizeValue = toNonNegativeInt(body.maxFileSizeValue, 0);
  const multiplier = sizeUnits[maxFileSizeUnit] || sizeUnits.MB;
  const maxFileSizeBytes = maxFileSizeValue > 0 ? maxFileSizeValue * multiplier : 0;
  return {
    title: (body.title || '').trim(),
    description: (body.description || '').trim(),
    extList,
    maxFileSizeBytes,
    maxFilesPerUpload: Number.parseInt(body.maxFilesPerUpload, 10),
    maxTotalFiles: body.maxTotalFiles ? Number.parseInt(body.maxTotalFiles, 10) : null,
    boxPassword: (body.boxPassword || '').trim(),
    discordWebhookUrl: (body.discordWebhookUrl || '').trim(),
    publicNotice: (body.publicNotice || '').trim(),
    successMessage: (body.successMessage || 'アップロードありがとうございました。').trim(),
    requireUploaderName: body.requireUploaderName ? 1 : 0,
    requireUploaderNote: body.requireUploaderNote ? 1 : 0,
    expiresAt: (body.expiresAt || '').trim(),
    fontFamily: normalizeFontFamily(body.fontFamily),
    accentColor: normalizeHexColor(body.accentColor),
    customCss: (body.customCss || '').trim().slice(0, 1500),
    successRedirectUrl: (body.successRedirectUrl || '').trim(),
  };
}

function getBoxMaxSizeBytes(box) {
  if (Number.isInteger(box.max_file_size_bytes) && box.max_file_size_bytes > 0) return box.max_file_size_bytes;
  if (Number.isInteger(box.max_file_size_mb) && box.max_file_size_mb > 0) return box.max_file_size_mb * 1024 * 1024;
  return 0;
}

function toNonNegativeInt(value, fallback = 0) {
  if (value === undefined || value === null || value === '') return fallback;
  const parsed = Number.parseInt(value, 10);
  return Number.isInteger(parsed) && parsed >= 0 ? parsed : fallback;
}

function detectPreviewType(file) {
  const mime = (file.mime_type || '').toLowerCase();
  const ext = path.extname(file.original_name || '').toLowerCase();
  if (mime.startsWith('image/')) return 'image';
  if (mime.startsWith('video/')) return 'video';
  if (mime.startsWith('audio/')) return 'audio';
  if (mime === 'application/pdf' || ext === '.pdf') return 'pdf';
  if (mime.startsWith('text/') || ['.txt', '.md', '.csv', '.json', '.log'].includes(ext)) return 'text';
  return 'none';
}

async function canViewerAccessBox(viewerId, boxId) {
  const permission = await get('SELECT id FROM viewer_box_permissions WHERE viewer_id = ? AND box_id = ?', [viewerId, boxId]);
  return Boolean(permission);
}

async function resolveActor(req) {
  const admin = await getAdminFromRequest(req);
  if (admin) return admin;
  return getViewerFromRequest(req);
}


function getOrCreateVisitorKey(req, res) {
  const cookies = parseCookies(req);
  if (cookies.visitor_key) return cookies.visitor_key;
  const key = crypto.randomBytes(16).toString('hex');
  setCookie(res, 'visitor_key', key, 60 * 60 * 24 * 365);
  return key;
}

async function isBanned(subjectKey) {
  const row = await get('SELECT * FROM upload_bans WHERE subject_key = ? AND released_at IS NULL', [subjectKey]);
  return row || null;
}

async function recordViolation(subjectKey, reason) {
  await run('INSERT INTO upload_violations (subject_key, reason, created_at) VALUES (?, ?, ?)', [subjectKey, reason, nowIso()]);
  const recent = await get("SELECT COUNT(*) AS c FROM upload_violations WHERE subject_key = ? AND julianday(created_at) >= julianday('now', '-30 minutes')", [subjectKey]);
  if (recent && recent.c >= 5 && !(await isBanned(subjectKey))) {
    await run('INSERT INTO upload_bans (subject_key, reason, created_at, created_by) VALUES (?, ?, ?, ?)', [subjectKey, '自動BAN: 短時間に失敗が繰り返されたため', nowIso(), 'auto']);
  }
}

async function getActiveLoginBlock(subjectKey) {
  const row = await get('SELECT id, reason, expires_at FROM login_blocks WHERE subject_key = ?', [subjectKey]);
  if (!row) return null;
  if (new Date(row.expires_at).getTime() < Date.now()) {
    await run('DELETE FROM login_blocks WHERE id = ?', [row.id]);
    return null;
  }
  return row;
}

async function isLoginBlocked(subjectKeys) {
  for (const key of subjectKeys) {
    const block = await getActiveLoginBlock(key);
    if (block) return block;
  }
  return null;
}

async function recordLoginFailure(subjectKeys, reason) {
  for (const key of subjectKeys) {
    await run('INSERT INTO login_violations (subject_key, reason, created_at) VALUES (?, ?, ?)', [key, reason, nowIso()]);
    const recent = await get(
      `SELECT COUNT(*) AS c
       FROM login_violations
       WHERE subject_key = ? AND julianday(created_at) >= julianday('now', ?)` ,
      [key, `-${AUTH_FAILURE_WINDOW_MINUTES} minutes`],
    );
    if (recent && recent.c >= AUTH_FAILURE_LIMIT) {
      await run(
        `INSERT INTO login_blocks (subject_key, reason, created_at, expires_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(subject_key) DO UPDATE SET reason = excluded.reason, created_at = excluded.created_at, expires_at = excluded.expires_at`,
        [key, '短時間にログイン失敗が繰り返されました。', nowIso(), new Date(Date.now() + AUTH_BLOCK_MINUTES * 60 * 1000).toISOString()],
      );
    }
  }
}

async function clearLoginViolations(subjectKeys) {
  for (const key of subjectKeys) {
    await run('DELETE FROM login_violations WHERE subject_key = ?', [key]);
    await run('DELETE FROM login_blocks WHERE subject_key = ?', [key]);
  }
}

function makeLoginSubjectKeys(req, actorType, username = '') {
  const ipHash = hashKey(getClientIp(req) || 'unknown-ip');
  const normalized = normalizeUsername(username).toLowerCase();
  const keys = [`login-ip:${ipHash}`];
  if (normalized) keys.push(`login-${actorType}:${hashKey(normalized)}:${ipHash}`);
  return keys;
}

async function enforceUploadRateLimit(subjectKey, boxId) {
  const byBox = await get(
    `SELECT COUNT(*) AS c FROM upload_attempts
     WHERE subject_key = ? AND box_id = ? AND julianday(created_at) >= julianday('now', ?)`,
    [subjectKey, boxId, `-${UPLOAD_WINDOW_SHORT_MINUTES} minutes`],
  );
  if (byBox && byBox.c >= UPLOAD_ATTEMPT_LIMIT_SHORT) {
    return `短時間に操作が集中しています。${UPLOAD_WINDOW_SHORT_MINUTES}分ほど待ってから再試行してください。`;
  }
  const globalRecent = await get(
    `SELECT COUNT(*) AS c FROM upload_attempts
     WHERE subject_key = ? AND julianday(created_at) >= julianday('now', ?)`,
    [subjectKey, `-${UPLOAD_WINDOW_LONG_MINUTES} minutes`],
  );
  if (globalRecent && globalRecent.c >= UPLOAD_ATTEMPT_LIMIT_LONG) {
    return `アップロード試行回数が多すぎます。${UPLOAD_WINDOW_LONG_MINUTES}分以内に再試行してください。`;
  }
  return null;
}

async function recordUploadAttempt(subjectKey, boxId, wasSuccess) {
  await run('INSERT INTO upload_attempts (subject_key, box_id, was_success, created_at) VALUES (?, ?, ?, ?)', [subjectKey, boxId || null, wasSuccess ? 1 : 0, nowIso()]);
}

async function sendUploadPush(box, filesCount) {
  if (!hasPushConfig()) return;
  const targets = await all(
    `SELECT ns.id, ns.endpoint, ns.p256dh, ns.auth
     FROM notification_subscriptions ns
     INNER JOIN notification_box_settings nbs ON nbs.actor_type = ns.actor_type AND nbs.actor_id = ns.actor_id
     WHERE nbs.box_id = ? AND nbs.is_enabled = 1`,
    [box.id],
  );
  await Promise.all(targets.map(async (row) => {
    try {
      await webpush.sendNotification(
        { endpoint: row.endpoint, keys: { p256dh: row.p256dh, auth: row.auth } },
        JSON.stringify({ title: 'Uploader通知', body: `「${box.title}」に${filesCount}件アップロードされました`, url: `/admin/boxes/${box.id}/files` }),
      );
    } catch (_) {
      await run('DELETE FROM notification_subscriptions WHERE id = ?', [row.id]);
    }
  }));
}

async function trackEvent(eventType, actorRole = 'guest', boxId = null) {
  await run(
    'INSERT INTO analytics_events (event_type, box_id, actor_role, created_at) VALUES (?, ?, ?, ?)',
    [eventType, boxId, actorRole, nowIso()],
  );
}

function parseIds(input) {
  const values = Array.isArray(input) ? input : [input];
  return values
    .flatMap((value) => String(value || '').split(','))
    .map((value) => Number.parseInt(value, 10))
    .filter((value) => Number.isInteger(value) && value > 0);
}

async function postDiscordNotification(webhookUrl, boxTitle, files, uploaderName = '') {
  if (!webhookUrl) return;
  const content = `📦 募集ボックス「${boxTitle}」に ${files.length} 件のファイルがアップロードされました\n送信者: ${uploaderName || '未入力'}\n${files.map((f) => `- ${f.originalname} (${Math.round(f.size / 1024)} KB)`).join('\n')}`;
  try {
    await fetch(webhookUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ content }) });
  } catch (_) {
    // noop
  }
}

app.set('trust proxy', true);
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use((_, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});
app.use('/assets', express.static(path.join(__dirname, '..', 'public')));
app.use('/box-assets', express.static(HEADER_DIR));

const upload = multer({
  storage: multer.diskStorage({
    destination: (_, __, cb) => cb(null, UPLOAD_DIR),
    filename: (_, file, cb) => cb(null, `${Date.now()}-${crypto.randomBytes(6).toString('hex')}${path.extname(file.originalname).toLowerCase()}`),
  }),
});

const headerUpload = multer({
  storage: multer.diskStorage({
    destination: (_, __, cb) => cb(null, HEADER_DIR),
    filename: (_, file, cb) => cb(null, `${Date.now()}-${crypto.randomBytes(6).toString('hex')}${path.extname(file.originalname).toLowerCase()}`),
  }),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (_, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (['.png', '.jpg', '.jpeg', '.webp', '.gif'].includes(ext)) return cb(null, true);
    return cb(new Error('画像形式は png/jpg/jpeg/webp/gif のみ対応です。'));
  },
});

app.get('/healthz', (_, res) => res.json({ ok: true, now: nowIso() }));

app.get('/', async (req, res) => {
  const actor = await resolveActor(req);
  await trackEvent('page_home', actor ? actor.role : 'guest');
  const boxes = (await all('SELECT title, slug, description, is_active, expires_at, header_image_path FROM boxes ORDER BY id DESC')).map((b) => ({ ...b, is_expired: isBoxExpired(b) }));
  return res.send(views.homePage({ actor, boxes }));
});

app.get('/admin/register', async (req, res) => {
  const actor = await resolveActor(req);
  const count = await get('SELECT COUNT(*) AS c FROM admins');
  if (count.c > 0) {
    return res.status(403).send(views.errorPage({ title: '管理者登録不可', message: '管理者アカウントは初回作成の1件のみです。', actor }));
  }
  return res.send(views.adminRegisterPage({ actor }));
});

app.post('/admin/register', async (req, res) => {
  const { username = '', password = '' } = req.body;
  const cleanUser = normalizeUsername(username);
  if (!isValidUsername(cleanUser) || !isValidPassword(password)) return res.status(400).send(views.errorPage({ message: 'ユーザー名またはパスワードの形式が不正です。' }));
  const count = await get('SELECT COUNT(*) AS c FROM admins');
  const actor = await resolveActor(req);
  if (count.c > 0) return res.status(403).send(views.errorPage({ message: '管理者アカウントは追加できません。', actor }));
  const { salt, hash } = hashPassword(password);
  try {
    const result = await run('INSERT INTO admins (username, password_hash, password_salt, created_at) VALUES (?, ?, ?, ?)', [cleanUser, hash, salt, nowIso()]);
    setCookie(res, 'admin_session', await createSession('sessions', 'admin_id', result.lastID), 60 * 60 * 24 * 14);
    clearCookie(res, 'viewer_session');
    return redirect(res, '/admin');
  } catch (_) {
    return res.status(400).send(views.errorPage({ message: '同名ユーザーが存在します。', actor }));
  }
});

app.get('/admin/login', async (req, res) => {
  const admin = await getAdminFromRequest(req);
  if (admin) return redirect(res, '/admin');
  return res.send(views.adminLoginPage({ actor: await resolveActor(req) }));
});

app.post('/admin/login', async (req, res) => {
  const { username = '', password = '' } = req.body;
  const cleanUser = normalizeUsername(username);
  const subjectKeys = makeLoginSubjectKeys(req, 'admin', cleanUser);
  if (await isLoginBlocked(subjectKeys)) {
    await delayAuthFailureResponse();
    return res.status(429).send(views.errorPage({ title: 'ログイン制限', message: '短時間に試行が集中したため、少し時間を置いてから再度お試しください。' }));
  }
  if (!cleanUser || !isValidPassword(password)) {
    await recordLoginFailure(subjectKeys, '形式不正');
    await delayAuthFailureResponse();
    return res.status(401).send(views.errorPage({ title: 'ログイン失敗', message: '認証に失敗しました。' }));
  }
  const adminRow = await get('SELECT * FROM admins WHERE username = ?', [cleanUser]);
  if (!adminRow) {
    await recordLoginFailure(subjectKeys, 'ユーザー不一致');
    await delayAuthFailureResponse();
    return res.status(401).send(views.errorPage({ title: 'ログイン失敗', message: '認証に失敗しました。' }));
  }
  const attempted = hashPassword(password, adminRow.password_salt).hash;
  if (!safeCompare(attempted, adminRow.password_hash)) {
    await recordLoginFailure(subjectKeys, 'パスワード不一致');
    await delayAuthFailureResponse();
    return res.status(401).send(views.errorPage({ title: 'ログイン失敗', message: '認証に失敗しました。' }));
  }
  await clearLoginViolations(subjectKeys);
  setCookie(res, 'admin_session', await createSession('sessions', 'admin_id', adminRow.id), 60 * 60 * 24 * 14);
  clearCookie(res, 'viewer_session');
  return redirect(res, '/admin');
});

app.post('/admin/logout', requireAdmin(async (_, res, admin) => {
  await run('DELETE FROM sessions WHERE admin_id = ?', [admin.id]);
  clearCookie(res, 'admin_session');
  return redirect(res, '/');
}));

app.get('/viewer/login', async (req, res) => {
  const viewer = await getViewerFromRequest(req);
  if (viewer) return redirect(res, '/viewer');
  return res.send(views.viewerLoginPage({ actor: await resolveActor(req) }));
});

app.post('/viewer/login', async (req, res) => {
  const { username = '', password = '' } = req.body;
  const cleanUser = normalizeUsername(username);
  const subjectKeys = makeLoginSubjectKeys(req, 'viewer', cleanUser);
  if (await isLoginBlocked(subjectKeys)) {
    await delayAuthFailureResponse();
    return res.status(429).send(views.errorPage({ title: 'ログイン制限', message: '短時間に試行が集中したため、少し時間を置いてから再度お試しください。' }));
  }
  if (!cleanUser || !isValidPassword(password)) {
    await recordLoginFailure(subjectKeys, '形式不正');
    await delayAuthFailureResponse();
    return res.status(401).send(views.errorPage({ title: 'ログイン失敗', message: '認証に失敗しました。' }));
  }
  const viewerRow = await get('SELECT * FROM box_viewers WHERE username = ?', [cleanUser]);
  if (!viewerRow) {
    await recordLoginFailure(subjectKeys, 'ユーザー不一致');
    await delayAuthFailureResponse();
    return res.status(401).send(views.errorPage({ title: 'ログイン失敗', message: '認証に失敗しました。' }));
  }
  const attempted = hashPassword(password, viewerRow.password_salt).hash;
  if (!safeCompare(attempted, viewerRow.password_hash)) {
    await recordLoginFailure(subjectKeys, 'パスワード不一致');
    await delayAuthFailureResponse();
    return res.status(401).send(views.errorPage({ title: 'ログイン失敗', message: '認証に失敗しました。' }));
  }
  await clearLoginViolations(subjectKeys);
  setCookie(res, 'viewer_session', await createSession('viewer_sessions', 'viewer_id', viewerRow.id), 60 * 60 * 24 * 14);
  clearCookie(res, 'admin_session');
  return redirect(res, '/viewer');
});

app.post('/viewer/logout', async (req, res) => {
  const viewer = await getViewerFromRequest(req);
  if (viewer) await run('DELETE FROM viewer_sessions WHERE viewer_id = ?', [viewer.id]);
  clearCookie(res, 'viewer_session');
  return redirect(res, '/');
});

app.get('/viewer', async (req, res) => {
  const viewer = await getViewerFromRequest(req);
  if (!viewer) return redirect(res, '/viewer/login');
  const boxes = await all(
    `SELECT boxes.id, boxes.title, boxes.slug, boxes.description, boxes.is_active, boxes.expires_at
     FROM viewer_box_permissions
     INNER JOIN boxes ON boxes.id = viewer_box_permissions.box_id
     WHERE viewer_box_permissions.viewer_id = ?
     ORDER BY boxes.id DESC`,
    [viewer.id],
  );
  const rows = boxes.map((b) => ({ ...b, is_expired: isBoxExpired(b) }));
  const pushSettings = await all('SELECT box_id, is_enabled FROM notification_box_settings WHERE actor_type = ? AND actor_id = ?', ['viewer', viewer.id]);
  const pushMap = Object.fromEntries(pushSettings.map((r) => [String(r.box_id), r.is_enabled]));
  return res.send(views.viewerDashboardPage({ actor: viewer, boxes: rows, pushMap, vapidEnabled: hasPushConfig() }));
});

app.get('/admin', requireAdmin(async (_, res, admin) => {
  const boxes = await all('SELECT boxes.*, admins.username AS creator FROM boxes INNER JOIN admins ON admins.id = boxes.created_by_admin_id ORDER BY boxes.id DESC');
  const admins = await all('SELECT id, username, created_at FROM admins ORDER BY id');
  const viewers = await all(
    `SELECT box_viewers.id, box_viewers.username, box_viewers.created_at,
            GROUP_CONCAT(boxes.title, ' / ') AS allowed_boxes
     FROM box_viewers
     LEFT JOIN viewer_box_permissions ON viewer_box_permissions.viewer_id = box_viewers.id
     LEFT JOIN boxes ON boxes.id = viewer_box_permissions.box_id
     GROUP BY box_viewers.id
     ORDER BY box_viewers.id DESC`,
  );
  const pushSettings = await all('SELECT box_id, is_enabled FROM notification_box_settings WHERE actor_type = ? AND actor_id = ?', ['admin', admin.id]);
  const pushMap = Object.fromEntries(pushSettings.map((r) => [String(r.box_id), r.is_enabled]));
  const banRows = await all('SELECT id, subject_key, reason, created_at, created_by FROM upload_bans WHERE released_at IS NULL ORDER BY id DESC');
  const analyticsSummary = await all(`SELECT event_type, COUNT(*) AS total FROM analytics_events WHERE julianday(created_at) >= julianday('now', '-30 days') GROUP BY event_type ORDER BY total DESC`);
  const uploadsByDay = await all(`SELECT strftime('%Y-%m-%d', created_at) AS day, COUNT(*) AS total FROM analytics_events WHERE event_type = 'upload_success' AND julianday(created_at) >= julianday('now', '-14 days') GROUP BY day ORDER BY day DESC`);
  const boxPerformance = await all(`SELECT boxes.id, boxes.title, SUM(CASE WHEN analytics_events.event_type = 'page_box' THEN 1 ELSE 0 END) AS views, SUM(CASE WHEN analytics_events.event_type = 'upload_success' THEN 1 ELSE 0 END) AS uploads FROM boxes LEFT JOIN analytics_events ON analytics_events.box_id = boxes.id AND julianday(analytics_events.created_at) >= julianday('now', '-30 days') GROUP BY boxes.id ORDER BY uploads DESC, views DESC`);
  const vapidConfig = { publicKey: vapidPublicKey, privateKey: vapidPrivateKey, subject: vapidSubject };
  return res.send(views.adminDashboardPage({ actor: admin, boxes, admins, viewers, pushMap, vapidEnabled: hasPushConfig(), vapidConfig, bans: banRows, analyticsSummary, uploadsByDay, boxPerformance }));
}));

app.post('/admin/viewers/create', requireAdmin(async (req, res, admin) => {
  const { username = '', password = '', boxId = '' } = req.body;
  const cleanUser = normalizeUsername(username);
  const box = await get('SELECT id FROM boxes WHERE id = ?', [boxId]);
  if (!isValidUsername(cleanUser) || !isValidPassword(password) || !box) {
    return res.status(400).send(views.errorPage({ actor: admin, message: '閲覧アカウント作成の入力値が不正です。' }));
  }
  const { salt, hash } = hashPassword(password);
  try {
    const result = await run(
      'INSERT INTO box_viewers (username, password_hash, password_salt, created_at, created_by_admin_id) VALUES (?, ?, ?, ?, ?)',
      [cleanUser, hash, salt, nowIso(), admin.id],
    );
    await run('INSERT INTO viewer_box_permissions (viewer_id, box_id, created_at) VALUES (?, ?, ?)', [result.lastID, box.id, nowIso()]);
    return redirect(res, '/admin');
  } catch (_) {
    return res.status(400).send(views.errorPage({ actor: admin, message: '同名の閲覧アカウントが存在するか、権限登録に失敗しました。' }));
  }
}));

app.post('/admin/viewers/:id/assign', requireAdmin(async (req, res, admin) => {
  const viewer = await get('SELECT id FROM box_viewers WHERE id = ?', [req.params.id]);
  const box = await get('SELECT id FROM boxes WHERE id = ?', [req.body.boxId]);
  if (!viewer || !box) return res.status(400).send(views.errorPage({ actor: admin, message: '閲覧権限の付与対象が不正です。' }));
  await run('INSERT OR IGNORE INTO viewer_box_permissions (viewer_id, box_id, created_at) VALUES (?, ?, ?)', [viewer.id, box.id, nowIso()]);
  return redirect(res, '/admin');
}));

app.post('/admin/push-config', requireAdmin(async (req, res, admin) => {
  const publicKey = (req.body.vapidPublicKey || '').trim();
  const privateKey = (req.body.vapidPrivateKey || '').trim();
  const subject = (req.body.vapidSubject || '').trim() || 'mailto:admin@example.com';
  if ((publicKey && !privateKey) || (!publicKey && privateKey)) {
    return res.status(400).send(views.errorPage({ actor: admin, title: '入力エラー', message: 'VAPID公開鍵と秘密鍵はセットで入力してください。' }));
  }
  if (subject && !/^mailto:.+@.+\..+$/i.test(subject) && !/^https?:\/\/.+/i.test(subject)) {
    return res.status(400).send(views.errorPage({ actor: admin, title: '入力エラー', message: 'VAPID Subject は mailto: または http(s) URL を指定してください。' }));
  }

  vapidPublicKey = publicKey;
  vapidPrivateKey = privateKey;
  vapidSubject = subject;
  await setSetting('vapid_public_key', vapidPublicKey);
  await setSetting('vapid_private_key', vapidPrivateKey);
  await setSetting('vapid_subject', vapidSubject);
  configureWebPush();
  return redirect(res, '/admin');
}));


app.get('/push/vapid-public-key', async (req, res) => {
  const actor = await resolveActor(req);
  if (!actor) return res.status(401).json({ error: 'auth required' });
  if (!vapidPublicKey) return res.status(503).json({ error: 'push unavailable' });
  return res.json({ key: vapidPublicKey });
});

app.post('/push/subscribe', async (req, res) => {
  const actor = await resolveActor(req);
  if (!actor) return res.status(401).json({ ok: false });
  const sub = req.body && req.body.subscription;
  if (!sub || !sub.endpoint || !sub.keys || !sub.keys.p256dh || !sub.keys.auth) return res.status(400).json({ ok: false });
  await run(
    'INSERT OR REPLACE INTO notification_subscriptions (id, actor_type, actor_id, endpoint, p256dh, auth, created_at) VALUES ((SELECT id FROM notification_subscriptions WHERE actor_type = ? AND actor_id = ? AND endpoint = ?), ?, ?, ?, ?, ?, ?)',
    [actor.role, actor.id, sub.endpoint, actor.role, actor.id, sub.endpoint, sub.keys.p256dh, sub.keys.auth, nowIso()],
  );
  return res.json({ ok: true });
});

app.post('/push/boxes/:boxId/toggle', async (req, res) => {
  const actor = await resolveActor(req);
  if (!actor) return redirect(res, '/admin/login');
  const box = await get('SELECT id FROM boxes WHERE id = ?', [req.params.boxId]);
  if (!box) return res.status(404).send(views.errorPage({ actor, message: '募集ボックスが見つかりません。' }));
  if (actor.role === 'viewer' && !(await canViewerAccessBox(actor.id, box.id))) return res.status(403).send(views.errorPage({ actor, message: '権限がありません。' }));
  const current = await get('SELECT id, is_enabled FROM notification_box_settings WHERE actor_type = ? AND actor_id = ? AND box_id = ?', [actor.role, actor.id, box.id]);
  if (!current) {
    await run('INSERT INTO notification_box_settings (actor_type, actor_id, box_id, is_enabled, updated_at) VALUES (?, ?, ?, 1, ?)', [actor.role, actor.id, box.id, nowIso()]);
  } else {
    await run('UPDATE notification_box_settings SET is_enabled = ?, updated_at = ? WHERE id = ?', [current.is_enabled ? 0 : 1, nowIso(), current.id]);
  }
  return redirect(res, actor.role === 'admin' ? '/admin' : '/viewer');
});

app.post('/admin/bans/:id/release', requireAdmin(async (req, res, admin) => {
  const ban = await get('SELECT id FROM upload_bans WHERE id = ? AND released_at IS NULL', [req.params.id]);
  if (!ban) return res.status(404).send(views.errorPage({ actor: admin, message: 'BAN対象が見つかりません。' }));
  await run('UPDATE upload_bans SET released_at = ? WHERE id = ?', [nowIso(), ban.id]);
  return redirect(res, '/admin');
}));

function saveBoxHandler(mode) {
  return requireAdmin(async (req, res, admin) => {
    headerUpload.single('headerImage')(req, res, async (err) => {
      if (err) return res.status(400).send(views.errorPage({ actor: admin, message: err.message }));

      const input = normalizeBoxInput(req.body);
      if (!input.title || !Number.isInteger(input.maxFilesPerUpload) || input.maxFilesPerUpload < 1) {
        if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
        return res.status(400).send(views.errorPage({ actor: admin, message: '入力値が不正です。' }));
      }

      if (mode === 'create') {
        const baseSlug = uniqueSlug(input.title);
        let slug = baseSlug;
        let attempt = 1;
        while (await get('SELECT id FROM boxes WHERE slug = ?', [slug])) {
          slug = `${baseSlug}-${attempt}`;
          attempt += 1;
        }

        let passwordHash = null;
        let passwordSalt = null;
        if (input.boxPassword) ({ hash: passwordHash, salt: passwordSalt } = hashPassword(input.boxPassword));

        await run(
          `INSERT INTO boxes (title, slug, description, allowed_extensions, max_file_size_mb, max_file_size_bytes, max_files_per_upload, password_hash, password_salt, discord_webhook_url, is_active, created_by_admin_id, created_at, header_image_path, public_notice, success_message, require_uploader_name, max_total_files, expires_at, font_family, accent_color, custom_css, require_uploader_note, success_redirect_url)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            input.title,
            slug,
            input.description,
            input.extList.join(','),
            Math.floor(input.maxFileSizeBytes / (1024 * 1024)),
            input.maxFileSizeBytes,
            input.maxFilesPerUpload,
            passwordHash,
            passwordSalt,
            input.discordWebhookUrl,
            admin.id,
            nowIso(),
            req.file ? path.basename(req.file.path) : null,
            input.publicNotice,
            input.successMessage,
            input.requireUploaderName,
            input.maxTotalFiles,
            input.expiresAt ? new Date(input.expiresAt).toISOString() : null,
            input.fontFamily,
            input.accentColor,
            input.customCss,
            input.requireUploaderNote,
            input.successRedirectUrl,
          ],
        );
        return redirect(res, '/admin');
      }

      const box = await get('SELECT * FROM boxes WHERE id = ?', [req.params.id]);
      if (!box) return res.status(404).send(views.errorPage({ actor: admin, message: '募集ボックスが見つかりません。' }));

      let passwordHash = box.password_hash;
      let passwordSalt = box.password_salt;
      if (input.boxPassword) ({ hash: passwordHash, salt: passwordSalt } = hashPassword(input.boxPassword));

      let headerImagePath = box.header_image_path;
      if (req.body.removeHeaderImage && headerImagePath) {
        const oldPath = path.join(HEADER_DIR, headerImagePath);
        if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
        headerImagePath = null;
      }
      if (req.file) {
        if (headerImagePath) {
          const oldPath = path.join(HEADER_DIR, headerImagePath);
          if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
        }
        headerImagePath = path.basename(req.file.path);
      }

      await run(
        `UPDATE boxes SET title = ?, description = ?, allowed_extensions = ?, max_file_size_mb = ?, max_file_size_bytes = ?, max_files_per_upload = ?, password_hash = ?, password_salt = ?, discord_webhook_url = ?, header_image_path = ?, public_notice = ?, success_message = ?, require_uploader_name = ?, max_total_files = ?, expires_at = ?, font_family = ?, accent_color = ?, custom_css = ?, require_uploader_note = ?, success_redirect_url = ? WHERE id = ?`,
        [
          input.title,
          input.description,
          input.extList.join(','),
          Math.floor(input.maxFileSizeBytes / (1024 * 1024)),
          input.maxFileSizeBytes,
          input.maxFilesPerUpload,
          passwordHash,
          passwordSalt,
          input.discordWebhookUrl,
          headerImagePath,
          input.publicNotice,
          input.successMessage,
          input.requireUploaderName,
          input.maxTotalFiles,
          input.expiresAt ? new Date(input.expiresAt).toISOString() : null,
          input.fontFamily,
          input.accentColor,
          input.customCss,
          input.requireUploaderNote,
          input.successRedirectUrl,
          box.id,
        ],
      );
      return redirect(res, '/admin');
    });
  });
}

app.post('/admin/boxes/create', saveBoxHandler('create'));

app.get('/admin/boxes/:id/edit', requireAdmin(async (req, res, admin) => {
  const box = await get('SELECT * FROM boxes WHERE id = ?', [req.params.id]);
  if (!box) return res.status(404).send(views.errorPage({ actor: admin, title: 'Not Found', message: '募集ボックスが見つかりません。' }));
  return res.send(views.adminBoxEditPage({ actor: admin, box }));
}));

app.post('/admin/boxes/:id/edit', saveBoxHandler('edit'));

app.post('/admin/boxes/:id/toggle', requireAdmin(async (req, res, admin) => {
  const box = await get('SELECT id, is_active FROM boxes WHERE id = ?', [req.params.id]);
  if (!box) return res.status(404).send(views.errorPage({ actor: admin, title: 'Not Found', message: '募集ボックスが見つかりません。' }));
  await run('UPDATE boxes SET is_active = ? WHERE id = ?', [box.is_active ? 0 : 1, box.id]);
  return redirect(res, '/admin');
}));

app.get('/box/:slug', async (req, res) => {
  const actor = await resolveActor(req);
  const visitorKey = getOrCreateVisitorKey(req, res);
  const ban = await isBanned(visitorKey);
  if (ban) return res.status(403).send(views.errorPage({ actor, title: 'アップロード不可', message: `この端末からのアップロードは停止されています。理由: ${ban.reason}` }));
  const box = await get('SELECT * FROM boxes WHERE slug = ?', [req.params.slug]);
  if (!box || !box.is_active || isBoxExpired(box)) return res.status(404).send(views.errorPage({ actor, title: 'Not Found', message: '募集ボックスが存在しないか停止/期限切れです。' }));
  await trackEvent('page_box', actor ? actor.role : 'guest', box.id);
  const currentCount = await get('SELECT COUNT(*) AS c FROM uploaded_files WHERE box_id = ?', [box.id]);
  return res.send(views.boxPublicPage({ actor, box, currentCount: currentCount.c }));
});

app.post('/box/:slug/upload', (req, res, next) => {
  upload.array('files')(req, res, (err) => {
    if (!err) return next();
    if (err instanceof multer.MulterError) {
      return res.status(400).send(views.errorPage({ title: 'アップロード失敗', message: `アップロード処理エラー: ${err.message}` }));
    }
    return res.status(400).send(views.errorPage({ title: 'アップロード失敗', message: err.message || 'アップロード処理に失敗しました。' }));
  });
}, async (req, res) => {
  const actor = await resolveActor(req);
  const visitorKey = getOrCreateVisitorKey(req, res);
  const uploadSubjectKey = `upload:${hashKey(`${visitorKey}:${getClientIp(req) || 'unknown-ip'}`)}`;
  const ban = await isBanned(visitorKey);
  if (ban) return res.status(403).send(views.errorPage({ actor, title: 'アップロード不可', message: `この端末からのアップロードは停止されています。理由: ${ban.reason}` }));
  const box = await get('SELECT * FROM boxes WHERE slug = ?', [req.params.slug]);
  if (!box || !box.is_active || isBoxExpired(box)) return res.status(404).send(views.errorPage({ actor, title: 'Not Found', message: '募集ボックスが存在しないか停止/期限切れです。' }));
  const uploadLimitMessage = await enforceUploadRateLimit(uploadSubjectKey, box.id);
  if (uploadLimitMessage) {
    await recordViolation(visitorKey, '短時間多量アクセス');
    return res.status(429).send(views.errorPage({ actor, title: 'アップロード待機', message: uploadLimitMessage }));
  }
  await recordUploadAttempt(uploadSubjectKey, box.id, false);

  const files = req.files || [];
  const uploaderName = (req.body.uploaderName || '').trim();
  const uploaderNote = (req.body.uploaderNote || '').trim();
  const cleanup = () => files.forEach((file) => { if (fs.existsSync(file.path)) fs.unlinkSync(file.path); });

  if (!files.length) { await recordViolation(visitorKey, 'ファイル未選択'); return res.status(400).send(views.errorPage({ actor, title: 'アップロード失敗', message: 'ファイルがありません。' })); }
  if (box.require_uploader_name && !uploaderName) { cleanup(); return res.status(400).send(views.errorPage({ actor, title: 'アップロード失敗', message: '送信者名は必須です。' })); }
  if (box.require_uploader_note && !uploaderNote) { cleanup(); return res.status(400).send(views.errorPage({ actor, title: 'アップロード失敗', message: 'メモは必須です。' })); }
  if (files.length > box.max_files_per_upload) { cleanup(); await recordViolation(visitorKey, '回数上限超過'); return res.status(400).send(views.errorPage({ actor, title: 'アップロード失敗', message: `1回の上限(${box.max_files_per_upload})を超えています。` })); }

  const totalCount = await get('SELECT COUNT(*) AS c FROM uploaded_files WHERE box_id = ?', [box.id]);
  if (box.max_total_files && totalCount.c + files.length > box.max_total_files) {
    cleanup();
    return res.status(400).send(views.errorPage({ actor, title: 'アップロード失敗', message: `募集ボックスの総数上限(${box.max_total_files})を超えます。` }));
  }

  if (box.password_hash) {
    const provided = (req.body.boxPassword || '').trim();
    const attempted = hashPassword(provided, box.password_salt).hash;
    if (!provided || !safeCompare(attempted, box.password_hash)) {
      cleanup();
      await recordViolation(visitorKey, 'ボックスパスワード不一致');
      return res.status(403).send(views.errorPage({ actor, title: 'アップロード失敗', message: '募集ボックスパスワードが違います。' }));
    }
  }

  const allowed = new Set((box.allowed_extensions || '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean));
  const maxSizeBytes = getBoxMaxSizeBytes(box);
  for (const file of files) {
    const ext = path.extname(file.originalname).toLowerCase().replace(/^\./, '');
    if (allowed.size > 0 && !allowed.has(ext)) {
      cleanup();
      await recordViolation(visitorKey, `許可外拡張子: ${file.originalname}`);
      return res.status(400).send(views.errorPage({ actor, title: 'アップロード失敗', message: `許可されていない拡張子: ${file.originalname}` }));
    }
    if (maxSizeBytes && file.size > maxSizeBytes) {
      cleanup();
      await recordViolation(visitorKey, `サイズ超過: ${file.originalname}`);
      return res.status(400).send(views.errorPage({ actor, title: 'アップロード失敗', message: `サイズ超過: ${file.originalname}` }));
    }
  }

  try {
    for (const file of files) {
      await run(
        'INSERT INTO uploaded_files (box_id, uploader_name, uploader_note, original_name, stored_name, mime_type, size_bytes, uploader_ip, uploaded_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [box.id, uploaderName || null, uploaderNote || null, file.originalname, path.basename(file.path), file.mimetype, file.size, getClientIp(req), nowIso()],
      );
    }
    await recordUploadAttempt(uploadSubjectKey, box.id, true);
    await trackEvent('upload_success', actor ? actor.role : 'guest', box.id);
    await postDiscordNotification(box.discord_webhook_url, box.title, files, uploaderName);
    await sendUploadPush(box, files.length);
    return res.send(views.uploadDonePage({ actor, box, count: files.length }));
  } catch (err) {
    cleanup();
    return res.status(500).send(views.errorPage({ actor, title: 'アップロード失敗', message: '保存処理でエラーが発生しました。時間をおいて再試行してください。' }));
  }
});

async function getAuthorizedFile(req, fileId) {
  const actor = await resolveActor(req);
  if (!actor) return { actor: null, file: null, allowed: false };
  const file = await get('SELECT * FROM uploaded_files WHERE id = ?', [fileId]);
  if (!file) return { actor, file: null, allowed: false };
  if (actor.role === 'admin') return { actor, file, allowed: true };
  const allowed = await canViewerAccessBox(actor.id, file.box_id);
  return { actor, file, allowed };
}

app.get('/admin/boxes/:id/files', async (req, res) => {
  const actor = await resolveActor(req);
  if (!actor) return redirect(res, '/admin/login');

  const box = await get('SELECT * FROM boxes WHERE id = ?', [req.params.id]);
  if (!box) return res.status(404).send(views.errorPage({ actor, title: 'Not Found', message: '募集ボックスが見つかりません。' }));

  if (actor.role === 'viewer' && !(await canViewerAccessBox(actor.id, box.id))) {
    return res.status(403).send(views.errorPage({ actor, title: '権限エラー', message: 'この募集ボックスの閲覧権限がありません。' }));
  }

  const files = await all('SELECT id, uploader_name, uploader_note, original_name, stored_name, mime_type, size_bytes, uploader_ip, uploaded_at FROM uploaded_files WHERE box_id = ? ORDER BY id DESC', [box.id]);
  return res.send(views.filesPage({ actor, box, files }));
});


app.post('/files/bulk-download', async (req, res) => {
  const actor = await resolveActor(req);
  if (!actor) return redirect(res, '/admin/login');

  const box = await get('SELECT id, title FROM boxes WHERE id = ?', [req.body.boxId]);
  if (!box) return res.status(404).send(views.errorPage({ actor, message: '募集ボックスが見つかりません。' }));
  if (actor.role === 'viewer' && !(await canViewerAccessBox(actor.id, box.id))) {
    return res.status(403).send(views.errorPage({ actor, title: '権限エラー', message: 'この募集ボックスの閲覧権限がありません。' }));
  }

  const fileIds = parseIds(req.body.fileIds);
  if (fileIds.length === 0) {
    return res.status(400).send(views.errorPage({ actor, title: '入力エラー', message: 'ダウンロード対象を選択してください。' }));
  }

  const placeholders = fileIds.map(() => '?').join(',');
  const files = await all(
    `SELECT id, original_name, stored_name FROM uploaded_files WHERE box_id = ? AND id IN (${placeholders}) ORDER BY id DESC`,
    [box.id, ...fileIds],
  );
  if (files.length === 0) {
    return res.status(404).send(views.errorPage({ actor, title: 'Not Found', message: '対象ファイルが見つかりません。' }));
  }

  const safeTitle = uniqueSlug(box.title) || `box-${box.id}`;
  res.setHeader('Content-Type', 'application/zip');
  res.setHeader('Content-Disposition', `attachment; filename="${safeTitle}-files.zip"`);
  const archive = archiver('zip', { zlib: { level: 9 } });
  archive.on('error', () => {
    res.status(500).end();
  });
  archive.pipe(res);
  for (const file of files) {
    const fullPath = path.join(UPLOAD_DIR, path.basename(file.stored_name));
    if (!fs.existsSync(fullPath)) continue;
    archive.file(fullPath, { name: file.original_name });
  }
  archive.finalize();
});

app.post('/admin/files/bulk-delete', requireAdmin(async (req, res, admin) => {
  const box = await get('SELECT id FROM boxes WHERE id = ?', [req.body.boxId]);
  if (!box) return res.status(404).send(views.errorPage({ actor: admin, title: 'Not Found', message: '募集ボックスが見つかりません。' }));

  const fileIds = parseIds(req.body.fileIds);
  if (fileIds.length === 0) {
    return res.status(400).send(views.errorPage({ actor: admin, title: '入力エラー', message: '削除対象を選択してください。' }));
  }

  const placeholders = fileIds.map(() => '?').join(',');
  const files = await all(
    `SELECT id, stored_name FROM uploaded_files WHERE box_id = ? AND id IN (${placeholders})`,
    [box.id, ...fileIds],
  );
  for (const file of files) {
    const fullPath = path.join(UPLOAD_DIR, path.basename(file.stored_name));
    if (fs.existsSync(fullPath)) fs.unlinkSync(fullPath);
  }
  await run(`DELETE FROM uploaded_files WHERE box_id = ? AND id IN (${placeholders})`, [box.id, ...fileIds]);
  return redirect(res, `/admin/boxes/${box.id}/files`);
}));

app.get('/files/:id/download', async (req, res) => {
  const { actor, file, allowed } = await getAuthorizedFile(req, req.params.id);
  if (!actor) return redirect(res, '/admin/login');
  if (!file) return res.status(404).send(views.errorPage({ actor, title: 'Not Found', message: 'ファイルが見つかりません。' }));
  if (!allowed) return res.status(403).send(views.errorPage({ actor, title: '権限エラー', message: 'ダウンロード権限がありません。' }));

  const full = path.join(UPLOAD_DIR, path.basename(file.stored_name));
  if (!fs.existsSync(full)) return res.status(404).send(views.errorPage({ actor, title: 'Not Found', message: '実体ファイルが存在しません。' }));
  return res.download(full, file.original_name);
});

app.get('/files/:id/preview', async (req, res) => {
  const { actor, file, allowed } = await getAuthorizedFile(req, req.params.id);
  if (!actor) return redirect(res, '/admin/login');
  if (!file) return res.status(404).send(views.errorPage({ actor, title: 'Not Found', message: 'ファイルが見つかりません。' }));
  if (!allowed) return res.status(403).send(views.errorPage({ actor, title: '権限エラー', message: 'プレビュー権限がありません。' }));

  const full = path.join(UPLOAD_DIR, path.basename(file.stored_name));
  if (!fs.existsSync(full)) return res.status(404).send(views.errorPage({ actor, title: 'Not Found', message: '実体ファイルが存在しません。' }));

  const previewType = detectPreviewType(file);
  if (previewType === 'text') {
    const content = fs.readFileSync(full, 'utf8').slice(0, 200000);
    return res.send(views.previewPage({ actor, file, previewType, content }));
  }
  return res.send(views.previewPage({ actor, file, previewType }));
});

app.get('/files/:id/raw', async (req, res) => {
  const { actor, file, allowed } = await getAuthorizedFile(req, req.params.id);
  if (!actor) return redirect(res, '/admin/login');
  if (!file || !allowed) return res.status(403).send('Forbidden');
  const full = path.join(UPLOAD_DIR, path.basename(file.stored_name));
  if (!fs.existsSync(full)) return res.status(404).send('Not Found');
  if (file.mime_type) res.type(file.mime_type);
  return res.sendFile(full);
});


app.use(async (req, res) => {
  const actor = await resolveActor(req);
  res.status(404).send(views.errorPage({ actor, title: 'Not Found', message: 'ページが見つかりません。URLを確認してください。' }));
});

app.use(async (err, req, res, _next) => {
  const actor = await resolveActor(req);
  if (err instanceof multer.MulterError) {
    return res.status(400).send(views.errorPage({ actor, title: 'リクエストエラー', message: `アップロード処理エラー: ${err.message}` }));
  }
  return res.status(500).send(views.errorPage({ actor, title: 'サーバーエラー', message: '予期しないエラーが発生しました。' }));
});

initDb().then(async () => {
  await loadPushConfig();
  const adminCount = await get('SELECT COUNT(*) AS c FROM admins');
  app.listen(PORT, () => {
    console.log(`Uploader started on http://0.0.0.0:${PORT}`);
    if (adminCount.c === 0) console.log('最初に /admin/register から管理者を作成してください。');
  });
}).catch((err) => {
  console.error(err);
  process.exit(1);
});
