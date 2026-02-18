const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

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
      if (err) {
        reject(err);
        return;
      }
      resolve(this);
    });
  });
}

function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) {
        reject(err);
        return;
      }
      resolve(row);
    });
  });
}

function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) {
        reject(err);
        return;
      }
      resolve(rows);
    });
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

  await ensureColumn('uploaded_files', 'uploader_name', 'TEXT');
  await ensureColumn('uploaded_files', 'uploader_note', 'TEXT');
}

function nowIso() {
  return new Date().toISOString();
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.pbkdf2Sync(password, salt, 120000, 64, 'sha512').toString('hex');
  return { salt, hash };
}

function safeCompare(a, b) {
  const aBuffer = Buffer.from(a, 'hex');
  const bBuffer = Buffer.from(b, 'hex');
  if (aBuffer.length !== bBuffer.length) {
    return false;
  }
  return crypto.timingSafeEqual(aBuffer, bBuffer);
}

function escapeHtml(value = '') {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function parseCookies(req) {
  const raw = req.headers.cookie || '';
  return raw.split(';').reduce((acc, item) => {
    const [key, ...rest] = item.trim().split('=');
    if (!key) {
      return acc;
    }
    acc[key] = decodeURIComponent(rest.join('='));
    return acc;
  }, {});
}

function setCookie(res, name, value, maxAgeSeconds) {
  res.setHeader('Set-Cookie', `${name}=${encodeURIComponent(value)}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${maxAgeSeconds}`);
}

function clearCookie(res, name) {
  res.setHeader('Set-Cookie', `${name}=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0`);
}

function renderActionBar(admin) {
  if (admin) {
    return `
    <div class="nav-actions">
      <span>ログイン中: <strong>${escapeHtml(admin.username)}</strong></span>
      <a class="btn secondary" href="/admin">管理画面</a>
      <form class="inline-form" method="post" action="/admin/logout"><button class="btn secondary" type="submit">ログアウト</button></form>
    </div>`;
  }
  return '<div class="nav-actions"><a class="btn secondary" href="/admin/login">管理者ログイン</a></div>';
}

function pageTemplate(title, body, admin = null) {
  return `<!doctype html>
<html lang="ja">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(title)}</title>
  <link rel="stylesheet" href="/assets/styles.css" />
</head>
<body>
  <header class="topbar">
    <div class="container topbar-inner">
      <div class="brand"><a href="/">Uploader</a></div>
      ${renderActionBar(admin)}
    </div>
  </header>
  <main class="container">
    ${body}
  </main>
</body>
</html>`;
}

function redirect(res, to) {
  res.status(302).set('Location', to).send();
}

function requireAdmin(handler) {
  return async (req, res) => {
    const admin = await getAdminFromRequest(req);
    if (!admin) {
      redirect(res, '/admin/login');
      return;
    }
    await handler(req, res, admin);
  };
}

function uniqueSlug(text) {
  return text
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '') || crypto.randomBytes(4).toString('hex');
}

async function postDiscordNotification(webhookUrl, boxTitle, files, uploaderName = '') {
  if (!webhookUrl) {
    return;
  }
  const content = `📦 募集ボックス「${boxTitle}」に ${files.length} 件のファイルがアップロードされました\n送信者: ${uploaderName || '未入力'}\n${files.map((f) => `- ${f.originalname} (${Math.round(f.size / 1024)} KB)`).join('\n')}`;
  try {
    await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content }),
    });
  } catch (_) {
    // noop
  }
}

function getClientIp(req) {
  return req.headers['cf-connecting-ip'] || req.ip || '';
}

function isBoxExpired(box) {
  if (!box.expires_at) {
    return false;
  }
  const expiresAtMs = new Date(box.expires_at).getTime();
  return Number.isFinite(expiresAtMs) && expiresAtMs < Date.now();
}

function normalizeBoxInput(body) {
  const cleanTitle = (body.title || '').trim();
  const parsedMaxMb = Number.parseInt(body.maxFileSizeMb, 10);
  const parsedMaxFiles = Number.parseInt(body.maxFilesPerUpload, 10);
  const parsedTotalFiles = body.maxTotalFiles ? Number.parseInt(body.maxTotalFiles, 10) : null;
  const extList = (body.allowedExtensions || '')
    .split(',')
    .map((v) => v.trim().toLowerCase().replace(/^\./, ''))
    .filter((v) => /^[a-z0-9]+$/.test(v));

  return {
    cleanTitle,
    description: (body.description || '').trim(),
    extList,
    parsedMaxMb,
    parsedMaxFiles,
    parsedTotalFiles,
    boxPassword: (body.boxPassword || '').trim(),
    discordWebhookUrl: (body.discordWebhookUrl || '').trim(),
    publicNotice: (body.publicNotice || '').trim(),
    successMessage: (body.successMessage || 'アップロードありがとうございました。').trim(),
    requireUploaderName: body.requireUploaderName ? 1 : 0,
    expiresAt: (body.expiresAt || '').trim(),
  };
}

async function createSession(adminId) {
  const token = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const createdAt = nowIso();
  const expiresAt = new Date(Date.now() + (1000 * 60 * 60 * 24 * 14)).toISOString();
  await run('INSERT INTO sessions (token_hash, admin_id, created_at, expires_at) VALUES (?, ?, ?, ?)', [tokenHash, adminId, createdAt, expiresAt]);
  return token;
}

async function getAdminFromRequest(req) {
  const cookies = parseCookies(req);
  const rawToken = cookies.admin_session;
  if (!rawToken) {
    return null;
  }

  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
  const session = await get(
    `SELECT sessions.id AS session_id, sessions.admin_id, sessions.expires_at, admins.username, admins.id
     FROM sessions
     INNER JOIN admins ON admins.id = sessions.admin_id
     WHERE sessions.token_hash = ?`,
    [tokenHash],
  );

  if (!session) {
    return null;
  }
  if (new Date(session.expires_at).getTime() < Date.now()) {
    await run('DELETE FROM sessions WHERE id = ?', [session.session_id]);
    return null;
  }

  return { id: session.id, username: session.username };
}

app.set('trust proxy', true);
app.use(express.urlencoded({ extended: false }));
app.use('/assets', express.static(path.join(__dirname, '..', 'public')));
app.use('/box-assets', express.static(HEADER_DIR));

const uploadStorage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, UPLOAD_DIR),
  filename: (_, file, cb) => {
    const unique = `${Date.now()}-${crypto.randomBytes(6).toString('hex')}`;
    cb(null, `${unique}${path.extname(file.originalname).toLowerCase()}`);
  },
});

const headerStorage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, HEADER_DIR),
  filename: (_, file, cb) => {
    const unique = `${Date.now()}-${crypto.randomBytes(6).toString('hex')}`;
    cb(null, `${unique}${path.extname(file.originalname).toLowerCase()}`);
  },
});

const upload = multer({ storage: uploadStorage });
const headerUpload = multer({
  storage: headerStorage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (_, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (['.png', '.jpg', '.jpeg', '.webp', '.gif'].includes(ext)) {
      cb(null, true);
      return;
    }
    cb(new Error('画像形式は png/jpg/jpeg/webp/gif のみ対応です。'));
  },
});

app.get('/healthz', (_, res) => {
  res.json({ ok: true, now: nowIso() });
});

app.get('/', async (req, res) => {
  const admin = await getAdminFromRequest(req);
  const boxes = await all('SELECT title, slug, description, is_active, expires_at, header_image_path FROM boxes ORDER BY id DESC');

  const boxHtml = boxes.map((box) => {
    const expired = isBoxExpired(box);
    return `
    <article class="box-item">
      ${box.header_image_path ? `<img class="box-thumb" src="/box-assets/${encodeURIComponent(box.header_image_path)}" alt="header" />` : ''}
      <h3>${escapeHtml(box.title)}</h3>
      <p class="muted">${escapeHtml(box.description || '説明なし')}</p>
      <p><span class="status-pill ${box.is_active && !expired ? '' : 'off'}">${box.is_active && !expired ? '公開中' : '停止/期限切れ'}</span></p>
      <a class="btn" href="/box/${encodeURIComponent(box.slug)}">アップロードページ</a>
    </article>
  `;
  }).join('');

  res.send(pageTemplate('トップ', `
    <section class="card">
      <h2>アップロード募集ボックス</h2>
      <p class="muted">Cloudflare Tunnel経由でも直接アクセスでも動作します。リンクを受け取った利用者は制限内で送信可能です。</p>
    </section>
    <section class="box-list">
      ${boxHtml || '<div class="card"><p>まだ募集ボックスがありません。</p></div>'}
    </section>
  `, admin));
});

app.get('/admin/register', async (req, res) => {
  const admin = await getAdminFromRequest(req);
  const count = await get('SELECT COUNT(*) AS c FROM admins');

  if (count.c > 0 && !admin) {
    res.status(403).send(pageTemplate('管理者登録不可', '<section class="card"><p class="notice-error">初回作成後はログイン済み管理者のみ追加できます。</p></section>'));
    return;
  }

  res.send(pageTemplate('管理者登録', `
    <section class="card">
      <h2>管理者登録</h2>
      <form method="post" action="/admin/register">
        <label>ユーザー名<input name="username" required minlength="3" maxlength="64" /></label>
        <label>パスワード<input type="password" name="password" required minlength="8" maxlength="128" /></label>
        <button class="btn" type="submit">作成</button>
      </form>
    </section>
  `, admin));
});

app.post('/admin/register', async (req, res) => {
  const { username = '', password = '' } = req.body;
  const cleanUser = username.trim();
  if (!cleanUser || password.length < 8) {
    res.status(400).send(pageTemplate('エラー', '<section class="card"><p class="notice-error">入力が不正です。</p></section>'));
    return;
  }

  const count = await get('SELECT COUNT(*) AS c FROM admins');
  const sessionAdmin = await getAdminFromRequest(req);
  if (count.c > 0 && !sessionAdmin) {
    res.status(403).send(pageTemplate('エラー', '<section class="card"><p class="notice-error">権限がありません。</p></section>'));
    return;
  }

  const { salt, hash } = hashPassword(password);
  try {
    const result = await run('INSERT INTO admins (username, password_hash, password_salt, created_at) VALUES (?, ?, ?, ?)', [cleanUser, hash, salt, nowIso()]);
    const token = await createSession(result.lastID);
    setCookie(res, 'admin_session', token, 60 * 60 * 24 * 14);
    redirect(res, '/admin');
  } catch (_) {
    res.status(400).send(pageTemplate('エラー', '<section class="card"><p class="notice-error">同名ユーザーが存在します。</p></section>'));
  }
});

app.get('/admin/login', async (req, res) => {
  const admin = await getAdminFromRequest(req);
  if (admin) {
    redirect(res, '/admin');
    return;
  }

  res.send(pageTemplate('管理者ログイン', `
    <section class="card">
      <h2>管理者ログイン</h2>
      <form method="post" action="/admin/login">
        <label>ユーザー名<input name="username" required /></label>
        <label>パスワード<input type="password" name="password" required /></label>
        <button class="btn" type="submit">ログイン</button>
      </form>
    </section>
  `));
});

app.post('/admin/login', async (req, res) => {
  const { username = '', password = '' } = req.body;
  const adminRow = await get('SELECT * FROM admins WHERE username = ?', [username.trim()]);
  if (!adminRow) {
    res.status(401).send(pageTemplate('ログイン失敗', '<section class="card"><p class="notice-error">認証に失敗しました。</p></section>'));
    return;
  }

  const attempted = hashPassword(password, adminRow.password_salt).hash;
  if (!safeCompare(attempted, adminRow.password_hash)) {
    res.status(401).send(pageTemplate('ログイン失敗', '<section class="card"><p class="notice-error">認証に失敗しました。</p></section>'));
    return;
  }

  const token = await createSession(adminRow.id);
  setCookie(res, 'admin_session', token, 60 * 60 * 24 * 14);
  redirect(res, '/admin');
});

app.post('/admin/logout', requireAdmin(async (_, res, admin) => {
  await run('DELETE FROM sessions WHERE admin_id = ?', [admin.id]);
  clearCookie(res, 'admin_session');
  redirect(res, '/');
}));

app.get('/admin', requireAdmin(async (req, res, admin) => {
  const boxes = await all(`SELECT boxes.*, admins.username AS creator FROM boxes INNER JOIN admins ON admins.id = boxes.created_by_admin_id ORDER BY boxes.id DESC`);
  const admins = await all('SELECT id, username, created_at FROM admins ORDER BY id');

  const boxRows = boxes.map((box) => `
    <tr>
      <td>${box.id}</td>
      <td>${escapeHtml(box.title)}</td>
      <td><a href="/box/${escapeHtml(box.slug)}">${escapeHtml(box.slug)}</a></td>
      <td>${escapeHtml(box.allowed_extensions)}</td>
      <td>${box.max_file_size_mb}MB / ${box.max_files_per_upload}件 / 総数${box.max_total_files || '無制限'}</td>
      <td>${box.password_hash ? 'あり' : 'なし'}</td>
      <td>${box.discord_webhook_url ? 'ON' : 'OFF'}</td>
      <td>${box.require_uploader_name ? '必須' : '任意'}</td>
      <td>${box.expires_at ? escapeHtml(box.expires_at) : 'なし'}</td>
      <td>${box.is_active ? '公開' : '停止'}</td>
      <td>${escapeHtml(box.creator)}</td>
      <td>
        <form class="inline-form" method="post" action="/admin/boxes/${box.id}/toggle"><button class="btn secondary" type="submit">${box.is_active ? '停止' : '再開'}</button></form>
        <a class="btn secondary" href="/admin/boxes/${box.id}/files">ファイル</a>
        <a class="btn secondary" href="/admin/boxes/${box.id}/edit">編集</a>
      </td>
    </tr>
  `).join('');

  const adminRows = admins.map((a) => `<tr><td>${a.id}</td><td>${escapeHtml(a.username)}</td><td>${escapeHtml(a.created_at)}</td></tr>`).join('');

  res.send(pageTemplate('管理画面', `
    <section class="grid two">
      <div class="card">
        <h2>募集ボックス作成</h2>
        <form method="post" action="/admin/boxes/create" enctype="multipart/form-data">
          <label>タイトル<input name="title" required maxlength="100" /></label>
          <label>説明<textarea name="description" rows="3" maxlength="500"></textarea></label>
          <label>ヘッダー画像（任意）<input type="file" name="headerImage" accept=".png,.jpg,.jpeg,.webp,.gif" /></label>
          <label>公開メッセージ（任意）<textarea name="publicNotice" rows="2" maxlength="300"></textarea></label>
          <label>完了メッセージ（任意）<input name="successMessage" maxlength="200" placeholder="アップロードありがとうございました。" /></label>
          <label>許可拡張子（例: png,jpg,pdf）<input name="allowedExtensions" required /></label>
          <label>最大ファイルサイズ(MB)<input type="number" name="maxFileSizeMb" min="1" max="500" value="20" required /></label>
          <label>最大ファイル数/回<input type="number" name="maxFilesPerUpload" min="1" max="50" value="5" required /></label>
          <label>最大総アップロード件数（任意）<input type="number" name="maxTotalFiles" min="1" max="100000" /></label>
          <label>受付期限（任意）<input type="datetime-local" name="expiresAt" /></label>
          <label><input type="checkbox" name="requireUploaderName" value="1" /> 送信者名を必須にする</label>
          <label>ボックスパスワード（任意）<input type="password" name="boxPassword" maxlength="128" /></label>
          <label>Discord Webhook URL（任意）<input name="discordWebhookUrl" maxlength="500" /></label>
          <button class="btn" type="submit">作成</button>
        </form>
      </div>
      <div class="card">
        <h2>管理者追加</h2>
        <p class="muted">初回作成後はログイン中管理者のみ作成できます。</p>
        <form method="post" action="/admin/register">
          <label>ユーザー名<input name="username" required minlength="3" maxlength="64" /></label>
          <label>パスワード<input type="password" name="password" required minlength="8" maxlength="128" /></label>
          <button class="btn" type="submit">追加</button>
        </form>
      </div>
    </section>

    <section class="card">
      <h2>募集ボックス一覧</h2>
      <div class="table-wrap">
        <table>
          <thead><tr><th>ID</th><th>タイトル</th><th>リンク</th><th>許可形式</th><th>制限</th><th>PW</th><th>Discord</th><th>送信者名</th><th>期限</th><th>状態</th><th>作成者</th><th>操作</th></tr></thead>
          <tbody>${boxRows || '<tr><td colspan="12">まだありません</td></tr>'}</tbody>
        </table>
      </div>
    </section>

    <section class="card">
      <h2>管理者一覧</h2>
      <div class="table-wrap">
        <table>
          <thead><tr><th>ID</th><th>ユーザー名</th><th>作成日時</th></tr></thead>
          <tbody>${adminRows}</tbody>
        </table>
      </div>
    </section>
  `, admin));
}));

app.post('/admin/boxes/create', requireAdmin(async (req, res, admin) => {
  headerUpload.single('headerImage')(req, res, async (err) => {
    if (err) {
      res.status(400).send(pageTemplate('エラー', `<section class="card"><p class="notice-error">${escapeHtml(err.message)}</p></section>`, admin));
      return;
    }

    const input = normalizeBoxInput(req.body);
    if (!input.cleanTitle || input.extList.length === 0 || !Number.isInteger(input.parsedMaxMb) || !Number.isInteger(input.parsedMaxFiles)) {
      if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
      res.status(400).send(pageTemplate('エラー', '<section class="card"><p class="notice-error">入力値が不正です。</p></section>', admin));
      return;
    }

    if (input.parsedTotalFiles && input.parsedTotalFiles < 1) {
      if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
      res.status(400).send(pageTemplate('エラー', '<section class="card"><p class="notice-error">最大総アップロード件数が不正です。</p></section>', admin));
      return;
    }

    const baseSlug = uniqueSlug(input.cleanTitle);
    let slug = baseSlug;
    let attempt = 1;
    while (await get('SELECT id FROM boxes WHERE slug = ?', [slug])) {
      slug = `${baseSlug}-${attempt}`;
      attempt += 1;
    }

    let passwordHash = null;
    let passwordSalt = null;
    if (input.boxPassword) {
      const result = hashPassword(input.boxPassword);
      passwordHash = result.hash;
      passwordSalt = result.salt;
    }

    const expiresAt = input.expiresAt ? new Date(input.expiresAt).toISOString() : null;

    await run(
      `INSERT INTO boxes (title, slug, description, allowed_extensions, max_file_size_mb, max_files_per_upload, password_hash, password_salt, discord_webhook_url, is_active, created_by_admin_id, created_at, header_image_path, public_notice, success_message, require_uploader_name, max_total_files, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [input.cleanTitle, slug, input.description, input.extList.join(','), input.parsedMaxMb, input.parsedMaxFiles, passwordHash, passwordSalt, input.discordWebhookUrl, admin.id, nowIso(), req.file ? path.basename(req.file.path) : null, input.publicNotice, input.successMessage, input.requireUploaderName, input.parsedTotalFiles, expiresAt],
    );

    redirect(res, '/admin');
  });
}));

app.get('/admin/boxes/:id/edit', requireAdmin(async (req, res, admin) => {
  const box = await get('SELECT * FROM boxes WHERE id = ?', [req.params.id]);
  if (!box) {
    res.status(404).send(pageTemplate('Not Found', '<section class="card"><p class="notice-error">募集ボックスが見つかりません。</p></section>', admin));
    return;
  }

  const expiresValue = box.expires_at ? new Date(box.expires_at).toISOString().slice(0, 16) : '';

  res.send(pageTemplate(`ボックス編集: ${box.title}`, `
    <section class="card">
      <h2>募集ボックス編集</h2>
      ${box.header_image_path ? `<img class="box-header" src="/box-assets/${escapeHtml(box.header_image_path)}" alt="header" />` : ''}
      <form method="post" action="/admin/boxes/${box.id}/edit" enctype="multipart/form-data">
        <label>タイトル<input name="title" required maxlength="100" value="${escapeHtml(box.title)}" /></label>
        <label>説明<textarea name="description" rows="3" maxlength="500">${escapeHtml(box.description || '')}</textarea></label>
        <label>ヘッダー画像（任意）<input type="file" name="headerImage" accept=".png,.jpg,.jpeg,.webp,.gif" /></label>
        <label><input type="checkbox" name="removeHeaderImage" value="1" /> 現在のヘッダー画像を削除する</label>
        <label>公開メッセージ（任意）<textarea name="publicNotice" rows="2" maxlength="300">${escapeHtml(box.public_notice || '')}</textarea></label>
        <label>完了メッセージ（任意）<input name="successMessage" maxlength="200" value="${escapeHtml(box.success_message || '')}" /></label>
        <label>許可拡張子（例: png,jpg,pdf）<input name="allowedExtensions" required value="${escapeHtml(box.allowed_extensions)}" /></label>
        <label>最大ファイルサイズ(MB)<input type="number" name="maxFileSizeMb" min="1" max="500" value="${box.max_file_size_mb}" required /></label>
        <label>最大ファイル数/回<input type="number" name="maxFilesPerUpload" min="1" max="50" value="${box.max_files_per_upload}" required /></label>
        <label>最大総アップロード件数（任意）<input type="number" name="maxTotalFiles" min="1" max="100000" value="${box.max_total_files || ''}" /></label>
        <label>受付期限（任意）<input type="datetime-local" name="expiresAt" value="${expiresValue}" /></label>
        <label><input type="checkbox" name="requireUploaderName" value="1" ${box.require_uploader_name ? 'checked' : ''} /> 送信者名を必須にする</label>
        <label>ボックスパスワード（変更時のみ入力）<input type="password" name="boxPassword" maxlength="128" /></label>
        <label>Discord Webhook URL（任意）<input name="discordWebhookUrl" maxlength="500" value="${escapeHtml(box.discord_webhook_url || '')}" /></label>
        <button class="btn" type="submit">更新</button>
      </form>
    </section>
  `, admin));
}));

app.post('/admin/boxes/:id/edit', requireAdmin(async (req, res, admin) => {
  headerUpload.single('headerImage')(req, res, async (err) => {
    if (err) {
      res.status(400).send(pageTemplate('エラー', `<section class="card"><p class="notice-error">${escapeHtml(err.message)}</p></section>`, admin));
      return;
    }

    const box = await get('SELECT * FROM boxes WHERE id = ?', [req.params.id]);
    if (!box) {
      if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
      res.status(404).send(pageTemplate('Not Found', '<section class="card"><p class="notice-error">募集ボックスが見つかりません。</p></section>', admin));
      return;
    }

    const input = normalizeBoxInput(req.body);
    if (!input.cleanTitle || input.extList.length === 0 || !Number.isInteger(input.parsedMaxMb) || !Number.isInteger(input.parsedMaxFiles)) {
      if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
      res.status(400).send(pageTemplate('エラー', '<section class="card"><p class="notice-error">入力値が不正です。</p></section>', admin));
      return;
    }

    let passwordHash = box.password_hash;
    let passwordSalt = box.password_salt;
    if (input.boxPassword) {
      const result = hashPassword(input.boxPassword);
      passwordHash = result.hash;
      passwordSalt = result.salt;
    }

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

    const expiresAt = input.expiresAt ? new Date(input.expiresAt).toISOString() : null;

    await run(
      `UPDATE boxes SET title = ?, description = ?, allowed_extensions = ?, max_file_size_mb = ?, max_files_per_upload = ?, password_hash = ?, password_salt = ?, discord_webhook_url = ?, header_image_path = ?, public_notice = ?, success_message = ?, require_uploader_name = ?, max_total_files = ?, expires_at = ? WHERE id = ?`,
      [input.cleanTitle, input.description, input.extList.join(','), input.parsedMaxMb, input.parsedMaxFiles, passwordHash, passwordSalt, input.discordWebhookUrl, headerImagePath, input.publicNotice, input.successMessage, input.requireUploaderName, input.parsedTotalFiles, expiresAt, box.id],
    );

    redirect(res, '/admin');
  });
}));

app.post('/admin/boxes/:id/toggle', requireAdmin(async (req, res) => {
  const box = await get('SELECT id, is_active FROM boxes WHERE id = ?', [req.params.id]);
  if (!box) {
    res.status(404).send(pageTemplate('Not Found', '<section class="card"><p class="notice-error">募集ボックスが見つかりません。</p></section>'));
    return;
  }
  await run('UPDATE boxes SET is_active = ? WHERE id = ?', [box.is_active ? 0 : 1, box.id]);
  redirect(res, '/admin');
}));

app.get('/box/:slug', async (req, res) => {
  const box = await get('SELECT * FROM boxes WHERE slug = ?', [req.params.slug]);
  if (!box || !box.is_active || isBoxExpired(box)) {
    res.status(404).send(pageTemplate('Not Found', '<section class="card"><p class="notice-error">募集ボックスが存在しないか停止/期限切れです。</p></section>'));
    return;
  }

  const currentCount = await get('SELECT COUNT(*) AS c FROM uploaded_files WHERE box_id = ?', [box.id]);
  const allowedExts = box.allowed_extensions.split(',').map((ext) => `.${ext}`).join(', ');

  res.send(pageTemplate(`アップロード: ${box.title}`, `
    <section class="card">
      ${box.header_image_path ? `<img class="box-header" src="/box-assets/${encodeURIComponent(box.header_image_path)}" alt="header" />` : ''}
      <h2>${escapeHtml(box.title)}</h2>
      <p class="muted">${escapeHtml(box.description || '説明なし')}</p>
      ${box.public_notice ? `<p class="notice-info">${escapeHtml(box.public_notice)}</p>` : ''}
      <p>許可形式: <span class="kbd">${escapeHtml(allowedExts)}</span> / 最大サイズ: <span class="kbd">${box.max_file_size_mb}MB</span> / 最大数: <span class="kbd">${box.max_files_per_upload}</span> / 現在件数: <span class="kbd">${currentCount.c}${box.max_total_files ? ` / ${box.max_total_files}` : ''}</span></p>
      <form method="post" action="/box/${encodeURIComponent(box.slug)}/upload" enctype="multipart/form-data">
        ${box.password_hash ? '<label>募集ボックスパスワード<input type="password" name="boxPassword" required /></label>' : ''}
        ${box.require_uploader_name ? '<label>送信者名<input name="uploaderName" maxlength="100" required /></label>' : '<label>送信者名（任意）<input name="uploaderName" maxlength="100" /></label>'}
        <label>メモ（任意）<textarea name="uploaderNote" rows="2" maxlength="200"></textarea></label>
        <label>ファイル<input type="file" name="files" multiple required /></label>
        <button class="btn" type="submit">アップロード</button>
      </form>
    </section>
  `));
});

app.post('/box/:slug/upload', upload.array('files', 50), async (req, res) => {
  const box = await get('SELECT * FROM boxes WHERE slug = ?', [req.params.slug]);
  if (!box || !box.is_active || isBoxExpired(box)) {
    res.status(404).send(pageTemplate('Not Found', '<section class="card"><p class="notice-error">募集ボックスが存在しないか停止/期限切れです。</p></section>'));
    return;
  }

  const files = req.files || [];
  const uploaderName = (req.body.uploaderName || '').trim();
  const uploaderNote = (req.body.uploaderNote || '').trim();
  if (files.length === 0) {
    res.status(400).send(pageTemplate('アップロード失敗', '<section class="card"><p class="notice-error">ファイルがありません。</p></section>'));
    return;
  }

  const cleanup = () => {
    files.forEach((file) => {
      if (fs.existsSync(file.path)) fs.unlinkSync(file.path);
    });
  };

  if (box.require_uploader_name && !uploaderName) {
    cleanup();
    res.status(400).send(pageTemplate('アップロード失敗', '<section class="card"><p class="notice-error">送信者名は必須です。</p></section>'));
    return;
  }

  if (files.length > box.max_files_per_upload) {
    cleanup();
    res.status(400).send(pageTemplate('アップロード失敗', `<section class="card"><p class="notice-error">1回の上限(${box.max_files_per_upload})を超えています。</p></section>`));
    return;
  }

  const totalCount = await get('SELECT COUNT(*) AS c FROM uploaded_files WHERE box_id = ?', [box.id]);
  if (box.max_total_files && totalCount.c + files.length > box.max_total_files) {
    cleanup();
    res.status(400).send(pageTemplate('アップロード失敗', `<section class="card"><p class="notice-error">募集ボックスの総数上限(${box.max_total_files})を超えます。</p></section>`));
    return;
  }

  if (box.password_hash) {
    const provided = (req.body.boxPassword || '').trim();
    const attempted = hashPassword(provided, box.password_salt).hash;
    if (!provided || !safeCompare(attempted, box.password_hash)) {
      cleanup();
      res.status(403).send(pageTemplate('アップロード失敗', '<section class="card"><p class="notice-error">募集ボックスパスワードが違います。</p></section>'));
      return;
    }
  }

  const allowed = new Set(box.allowed_extensions.split(',').map((s) => s.trim().toLowerCase()));
  for (const file of files) {
    const ext = path.extname(file.originalname).toLowerCase().replace(/^\./, '');
    if (!allowed.has(ext)) {
      cleanup();
      res.status(400).send(pageTemplate('アップロード失敗', `<section class="card"><p class="notice-error">許可されていない拡張子: ${escapeHtml(file.originalname)}</p></section>`));
      return;
    }
    if (file.size > box.max_file_size_mb * 1024 * 1024) {
      cleanup();
      res.status(400).send(pageTemplate('アップロード失敗', `<section class="card"><p class="notice-error">サイズ超過: ${escapeHtml(file.originalname)}</p></section>`));
      return;
    }
  }

  for (const file of files) {
    await run(
      `INSERT INTO uploaded_files (box_id, uploader_name, uploader_note, original_name, stored_name, mime_type, size_bytes, uploader_ip, uploaded_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [box.id, uploaderName || null, uploaderNote || null, file.originalname, path.basename(file.path), file.mimetype, file.size, getClientIp(req), nowIso()],
    );
  }

  await postDiscordNotification(box.discord_webhook_url, box.title, files, uploaderName);

  res.send(pageTemplate('アップロード完了', `
    <section class="card">
      <p class="notice-ok">${escapeHtml(box.success_message || 'アップロードありがとうございました。')}</p>
      <p class="muted">${files.length}件アップロードしました。</p>
      <a class="btn secondary" href="/box/${encodeURIComponent(box.slug)}">戻る</a>
    </section>
  `));
});

app.get('/admin/boxes/:id/files', requireAdmin(async (req, res, admin) => {
  const box = await get('SELECT * FROM boxes WHERE id = ?', [req.params.id]);
  if (!box) {
    res.status(404).send(pageTemplate('Not Found', '<section class="card"><p class="notice-error">募集ボックスが見つかりません。</p></section>', admin));
    return;
  }

  const files = await all('SELECT id, uploader_name, uploader_note, original_name, stored_name, size_bytes, uploader_ip, uploaded_at FROM uploaded_files WHERE box_id = ? ORDER BY id DESC', [box.id]);
  const rows = files.map((file) => `
    <tr>
      <td>${file.id}</td>
      <td>${escapeHtml(file.uploader_name || '-')}</td>
      <td>${escapeHtml(file.uploader_note || '-')}</td>
      <td>${escapeHtml(file.original_name)}</td>
      <td>${Math.round(file.size_bytes / 1024)} KB</td>
      <td>${escapeHtml(file.uploader_ip || '-')}</td>
      <td>${escapeHtml(file.uploaded_at)}</td>
      <td><a class="btn secondary" href="/admin/files/${file.id}/download">ダウンロード</a></td>
    </tr>
  `).join('');

  res.send(pageTemplate(`ファイル一覧: ${box.title}`, `
    <section class="card">
      <h2>${escapeHtml(box.title)} のアップロードファイル</h2>
      <p><a class="btn secondary" href="/admin">管理画面へ戻る</a></p>
      <div class="table-wrap">
        <table>
          <thead><tr><th>ID</th><th>送信者名</th><th>メモ</th><th>ファイル名</th><th>サイズ</th><th>IP</th><th>日時</th><th>操作</th></tr></thead>
          <tbody>${rows || '<tr><td colspan="8">まだアップロードなし</td></tr>'}</tbody>
        </table>
      </div>
    </section>
  `, admin));
}));

app.get('/admin/files/:id/download', requireAdmin(async (req, res) => {
  const file = await get('SELECT * FROM uploaded_files WHERE id = ?', [req.params.id]);
  if (!file) {
    res.status(404).send(pageTemplate('Not Found', '<section class="card"><p class="notice-error">ファイルが見つかりません。</p></section>'));
    return;
  }
  const full = path.join(UPLOAD_DIR, file.stored_name);
  if (!fs.existsSync(full)) {
    res.status(404).send(pageTemplate('Not Found', '<section class="card"><p class="notice-error">実体ファイルが存在しません。</p></section>'));
    return;
  }
  res.download(full, file.original_name);
}));

initDb().then(async () => {
  const adminCount = await get('SELECT COUNT(*) AS c FROM admins');
  app.listen(PORT, () => {
    // eslint-disable-next-line no-console
    console.log(`Uploader started on http://0.0.0.0:${PORT}`);
    if (adminCount.c === 0) {
      // eslint-disable-next-line no-console
      console.log('最初に /admin/register から管理者を作成してください。');
    }
  });
}).catch((err) => {
  // eslint-disable-next-line no-console
  console.error(err);
  process.exit(1);
});
