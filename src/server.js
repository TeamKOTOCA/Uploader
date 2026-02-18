const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const views = require('./views');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, '..', 'data');
const UPLOAD_DIR = path.join(__dirname, '..', 'uploads');
const HEADER_DIR = path.join(UPLOAD_DIR, 'headers');
const DB_PATH = path.join(DATA_DIR, 'uploader.db');

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });
fs.mkdirSync(HEADER_DIR, { recursive: true });

const db = new sqlite3.Database(DB_PATH);

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

  await ensureColumn('uploaded_files', 'uploader_name', 'TEXT');
  await ensureColumn('uploaded_files', 'uploader_note', 'TEXT');
}

function nowIso() {
  return new Date().toISOString();
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  return { salt, hash: crypto.pbkdf2Sync(password, salt, 120000, 64, 'sha512').toString('hex') };
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
  res.setHeader('Set-Cookie', `${name}=${encodeURIComponent(value)}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${maxAgeSeconds}`);
}

function clearCookie(res, name) {
  res.setHeader('Set-Cookie', `${name}=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0`);
}

async function createSession(adminId) {
  const token = crypto.randomBytes(32).toString('hex');
  await run('INSERT INTO sessions (token_hash, admin_id, created_at, expires_at) VALUES (?, ?, ?, ?)', [crypto.createHash('sha256').update(token).digest('hex'), adminId, nowIso(), new Date(Date.now() + (1000 * 60 * 60 * 24 * 14)).toISOString()]);
  return token;
}

async function getAdminFromRequest(req) {
  const token = parseCookies(req).admin_session;
  if (!token) return null;
  const session = await get(`SELECT sessions.id AS session_id, sessions.expires_at, admins.id, admins.username FROM sessions INNER JOIN admins ON admins.id = sessions.admin_id WHERE sessions.token_hash = ?`, [crypto.createHash('sha256').update(token).digest('hex')]);
  if (!session) return null;
  if (new Date(session.expires_at).getTime() < Date.now()) {
    await run('DELETE FROM sessions WHERE id = ?', [session.session_id]);
    return null;
  }
  return { id: session.id, username: session.username };
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

function parseTheme(value, fallback) {
  if (!value) return fallback;
  return value;
}

function normalizeHexColor(value, fallback = '#2563eb') {
  return /^#[0-9a-fA-F]{6}$/.test(value || '') ? value : fallback;
}

function normalizeFontFamily(value) {
  return ['system', 'sans', 'serif', 'mono'].includes(value) ? value : 'system';
}

function normalizeBoxInput(body) {
  const extList = (body.allowedExtensions || '').split(',').map((v) => v.trim().toLowerCase().replace(/^\./, '')).filter((v) => /^[a-z0-9]+$/.test(v));
  return {
    title: (body.title || '').trim(),
    description: (body.description || '').trim(),
    extList,
    maxFileSizeMb: Number.parseInt(body.maxFileSizeMb, 10),
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
    customCss: parseTheme((body.customCss || '').trim().slice(0, 1500), ''),
    successRedirectUrl: (body.successRedirectUrl || '').trim(),
  };
}

async function postDiscordNotification(webhookUrl, boxTitle, files, uploaderName = '') {
  if (!webhookUrl) return;
  const content = `📦 募集ボックス「${boxTitle}」に ${files.length} 件のファイルがアップロードされました\n送信者: ${uploaderName || '未入力'}\n${files.map((f) => `- ${f.originalname} (${Math.round(f.size / 1024)} KB)`).join('\n')}`;
  try {
    await fetch(webhookUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ content }) });
  } catch (_) {
    // notification failure should not block upload
  }
}

app.set('trust proxy', true);
app.use(express.urlencoded({ extended: false }));
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
  const admin = await getAdminFromRequest(req);
  const boxes = (await all('SELECT title, slug, description, is_active, expires_at, header_image_path FROM boxes ORDER BY id DESC')).map((b) => ({ ...b, is_expired: isBoxExpired(b) }));
  res.send(views.homePage({ admin, boxes }));
});

app.get('/admin/register', async (req, res) => {
  const admin = await getAdminFromRequest(req);
  const count = await get('SELECT COUNT(*) AS c FROM admins');
  if (count.c > 0 && !admin) return res.status(403).send(views.errorPage({ title: '管理者登録不可', message: '初回作成後はログイン済み管理者のみ追加できます。' }));
  return res.send(views.adminRegisterPage({ admin }));
});

app.post('/admin/register', async (req, res) => {
  const { username = '', password = '' } = req.body;
  const cleanUser = username.trim();
  if (!cleanUser || password.length < 8) return res.status(400).send(views.errorPage({ message: '入力が不正です。' }));
  const count = await get('SELECT COUNT(*) AS c FROM admins');
  const sessionAdmin = await getAdminFromRequest(req);
  if (count.c > 0 && !sessionAdmin) return res.status(403).send(views.errorPage({ message: '権限がありません。' }));
  const { salt, hash } = hashPassword(password);
  try {
    const result = await run('INSERT INTO admins (username, password_hash, password_salt, created_at) VALUES (?, ?, ?, ?)', [cleanUser, hash, salt, nowIso()]);
    setCookie(res, 'admin_session', await createSession(result.lastID), 60 * 60 * 24 * 14);
    return redirect(res, '/admin');
  } catch (_) {
    return res.status(400).send(views.errorPage({ message: '同名ユーザーが存在します。' }));
  }
});

app.get('/admin/login', async (req, res) => {
  if (await getAdminFromRequest(req)) return redirect(res, '/admin');
  return res.send(views.adminLoginPage());
});

app.post('/admin/login', async (req, res) => {
  const { username = '', password = '' } = req.body;
  const adminRow = await get('SELECT * FROM admins WHERE username = ?', [username.trim()]);
  if (!adminRow) return res.status(401).send(views.errorPage({ title: 'ログイン失敗', message: '認証に失敗しました。' }));
  const attempted = hashPassword(password, adminRow.password_salt).hash;
  if (!safeCompare(attempted, adminRow.password_hash)) return res.status(401).send(views.errorPage({ title: 'ログイン失敗', message: '認証に失敗しました。' }));
  setCookie(res, 'admin_session', await createSession(adminRow.id), 60 * 60 * 24 * 14);
  return redirect(res, '/admin');
});

app.post('/admin/logout', requireAdmin(async (_, res, admin) => {
  await run('DELETE FROM sessions WHERE admin_id = ?', [admin.id]);
  clearCookie(res, 'admin_session');
  return redirect(res, '/');
}));

app.get('/admin', requireAdmin(async (_, res, admin) => {
  const boxes = await all('SELECT boxes.*, admins.username AS creator FROM boxes INNER JOIN admins ON admins.id = boxes.created_by_admin_id ORDER BY boxes.id DESC');
  const admins = await all('SELECT id, username, created_at FROM admins ORDER BY id');
  return res.send(views.adminDashboardPage({ admin, boxes, admins }));
}));

function saveBoxHandler(mode) {
  return requireAdmin(async (req, res, admin) => {
    headerUpload.single('headerImage')(req, res, async (err) => {
      if (err) return res.status(400).send(views.errorPage({ admin, message: err.message }));

      const input = normalizeBoxInput(req.body);
      if (!input.title || input.extList.length === 0 || !Number.isInteger(input.maxFileSizeMb) || !Number.isInteger(input.maxFilesPerUpload)) {
        if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
        return res.status(400).send(views.errorPage({ admin, message: '入力値が不正です。' }));
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
          `INSERT INTO boxes (title, slug, description, allowed_extensions, max_file_size_mb, max_files_per_upload, password_hash, password_salt, discord_webhook_url, is_active, created_by_admin_id, created_at, header_image_path, public_notice, success_message, require_uploader_name, max_total_files, expires_at, font_family, accent_color, custom_css, require_uploader_note, success_redirect_url)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [input.title, slug, input.description, input.extList.join(','), input.maxFileSizeMb, input.maxFilesPerUpload, passwordHash, passwordSalt, input.discordWebhookUrl, admin.id, nowIso(), req.file ? path.basename(req.file.path) : null, input.publicNotice, input.successMessage, input.requireUploaderName, input.maxTotalFiles, input.expiresAt ? new Date(input.expiresAt).toISOString() : null, input.fontFamily, input.accentColor, input.customCss, input.requireUploaderNote, input.successRedirectUrl],
        );
        return redirect(res, '/admin');
      }

      const box = await get('SELECT * FROM boxes WHERE id = ?', [req.params.id]);
      if (!box) return res.status(404).send(views.errorPage({ admin, message: '募集ボックスが見つかりません。' }));

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
        `UPDATE boxes SET title = ?, description = ?, allowed_extensions = ?, max_file_size_mb = ?, max_files_per_upload = ?, password_hash = ?, password_salt = ?, discord_webhook_url = ?, header_image_path = ?, public_notice = ?, success_message = ?, require_uploader_name = ?, max_total_files = ?, expires_at = ?, font_family = ?, accent_color = ?, custom_css = ?, require_uploader_note = ?, success_redirect_url = ? WHERE id = ?`,
        [input.title, input.description, input.extList.join(','), input.maxFileSizeMb, input.maxFilesPerUpload, passwordHash, passwordSalt, input.discordWebhookUrl, headerImagePath, input.publicNotice, input.successMessage, input.requireUploaderName, input.maxTotalFiles, input.expiresAt ? new Date(input.expiresAt).toISOString() : null, input.fontFamily, input.accentColor, input.customCss, input.requireUploaderNote, input.successRedirectUrl, box.id],
      );
      return redirect(res, '/admin');
    });
  });
}

app.post('/admin/boxes/create', saveBoxHandler('create'));

app.get('/admin/boxes/:id/edit', requireAdmin(async (req, res, admin) => {
  const box = await get('SELECT * FROM boxes WHERE id = ?', [req.params.id]);
  if (!box) return res.status(404).send(views.errorPage({ admin, message: '募集ボックスが見つかりません。', title: 'Not Found' }));
  return res.send(views.adminBoxEditPage({ admin, box }));
}));

app.post('/admin/boxes/:id/edit', saveBoxHandler('edit'));

app.post('/admin/boxes/:id/toggle', requireAdmin(async (req, res) => {
  const box = await get('SELECT id, is_active FROM boxes WHERE id = ?', [req.params.id]);
  if (!box) return res.status(404).send(views.errorPage({ title: 'Not Found', message: '募集ボックスが見つかりません。' }));
  await run('UPDATE boxes SET is_active = ? WHERE id = ?', [box.is_active ? 0 : 1, box.id]);
  return redirect(res, '/admin');
}));

app.get('/box/:slug', async (req, res) => {
  const box = await get('SELECT * FROM boxes WHERE slug = ?', [req.params.slug]);
  if (!box || !box.is_active || isBoxExpired(box)) return res.status(404).send(views.errorPage({ title: 'Not Found', message: '募集ボックスが存在しないか停止/期限切れです。' }));
  const currentCount = await get('SELECT COUNT(*) AS c FROM uploaded_files WHERE box_id = ?', [box.id]);
  return res.send(views.boxPublicPage({ box, currentCount: currentCount.c }));
});

app.post('/box/:slug/upload', upload.array('files', 50), async (req, res) => {
  const box = await get('SELECT * FROM boxes WHERE slug = ?', [req.params.slug]);
  if (!box || !box.is_active || isBoxExpired(box)) return res.status(404).send(views.errorPage({ title: 'Not Found', message: '募集ボックスが存在しないか停止/期限切れです。' }));

  const files = req.files || [];
  const uploaderName = (req.body.uploaderName || '').trim();
  const uploaderNote = (req.body.uploaderNote || '').trim();
  const cleanup = () => files.forEach((file) => { if (fs.existsSync(file.path)) fs.unlinkSync(file.path); });

  if (!files.length) return res.status(400).send(views.errorPage({ title: 'アップロード失敗', message: 'ファイルがありません。' }));
  if (box.require_uploader_name && !uploaderName) { cleanup(); return res.status(400).send(views.errorPage({ title: 'アップロード失敗', message: '送信者名は必須です。' })); }
  if (box.require_uploader_note && !uploaderNote) { cleanup(); return res.status(400).send(views.errorPage({ title: 'アップロード失敗', message: 'メモは必須です。' })); }
  if (files.length > box.max_files_per_upload) { cleanup(); return res.status(400).send(views.errorPage({ title: 'アップロード失敗', message: `1回の上限(${box.max_files_per_upload})を超えています。` })); }

  const totalCount = await get('SELECT COUNT(*) AS c FROM uploaded_files WHERE box_id = ?', [box.id]);
  if (box.max_total_files && totalCount.c + files.length > box.max_total_files) { cleanup(); return res.status(400).send(views.errorPage({ title: 'アップロード失敗', message: `募集ボックスの総数上限(${box.max_total_files})を超えます。` })); }

  if (box.password_hash) {
    const provided = (req.body.boxPassword || '').trim();
    const attempted = hashPassword(provided, box.password_salt).hash;
    if (!provided || !safeCompare(attempted, box.password_hash)) { cleanup(); return res.status(403).send(views.errorPage({ title: 'アップロード失敗', message: '募集ボックスパスワードが違います。' })); }
  }

  const allowed = new Set(box.allowed_extensions.split(',').map((s) => s.trim().toLowerCase()));
  for (const file of files) {
    const ext = path.extname(file.originalname).toLowerCase().replace(/^\./, '');
    if (!allowed.has(ext)) { cleanup(); return res.status(400).send(views.errorPage({ title: 'アップロード失敗', message: `許可されていない拡張子: ${file.originalname}` })); }
    if (file.size > box.max_file_size_mb * 1024 * 1024) { cleanup(); return res.status(400).send(views.errorPage({ title: 'アップロード失敗', message: `サイズ超過: ${file.originalname}` })); }
  }

  for (const file of files) {
    await run(`INSERT INTO uploaded_files (box_id, uploader_name, uploader_note, original_name, stored_name, mime_type, size_bytes, uploader_ip, uploaded_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, [box.id, uploaderName || null, uploaderNote || null, file.originalname, path.basename(file.path), file.mimetype, file.size, getClientIp(req), nowIso()]);
  }

  await postDiscordNotification(box.discord_webhook_url, box.title, files, uploaderName);
  return res.send(views.uploadDonePage({ box, count: files.length }));
});

app.get('/admin/boxes/:id/files', requireAdmin(async (req, res, admin) => {
  const box = await get('SELECT * FROM boxes WHERE id = ?', [req.params.id]);
  if (!box) return res.status(404).send(views.errorPage({ title: 'Not Found', message: '募集ボックスが見つかりません。', admin }));
  const files = await all('SELECT id, uploader_name, uploader_note, original_name, stored_name, size_bytes, uploader_ip, uploaded_at FROM uploaded_files WHERE box_id = ? ORDER BY id DESC', [box.id]);
  return res.send(views.adminFilesPage({ admin, box, files }));
}));

app.get('/admin/files/:id/download', requireAdmin(async (req, res) => {
  const file = await get('SELECT * FROM uploaded_files WHERE id = ?', [req.params.id]);
  if (!file) return res.status(404).send(views.errorPage({ title: 'Not Found', message: 'ファイルが見つかりません。' }));
  const full = path.join(UPLOAD_DIR, file.stored_name);
  if (!fs.existsSync(full)) return res.status(404).send(views.errorPage({ title: 'Not Found', message: '実体ファイルが存在しません。' }));
  return res.download(full, file.original_name);
}));

initDb().then(async () => {
  const adminCount = await get('SELECT COUNT(*) AS c FROM admins');
  app.listen(PORT, () => {
    // eslint-disable-next-line no-console
    console.log(`Uploader started on http://0.0.0.0:${PORT}`);
    if (adminCount.c === 0) console.log('最初に /admin/register から管理者を作成してください。');
  });
}).catch((err) => {
  // eslint-disable-next-line no-console
  console.error(err);
  process.exit(1);
});
