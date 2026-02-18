function escapeHtml(value = '') {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function layout({ title, body, admin = null, extraHead = '', extraScript = '' }) {
  const auth = admin
    ? `<div class="nav-actions"><span>ログイン中: <strong>${escapeHtml(admin.username)}</strong></span><a class="btn secondary" href="/admin">管理画面</a><form class="inline-form" method="post" action="/admin/logout"><button class="btn secondary" type="submit">ログアウト</button></form></div>`
    : '<div class="nav-actions"><a class="btn secondary" href="/admin/login">管理者ログイン</a></div>';

  return `<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>${escapeHtml(title)}</title>
<link rel="stylesheet" href="/assets/styles.css" />
${extraHead}
</head>
<body>
<header class="topbar"><div class="container topbar-inner"><div class="brand"><a href="/">Uploader</a></div>${auth}</div></header>
<main class="container">${body}</main>
<script src="/assets/app.js" defer></script>
${extraScript}
</body>
</html>`;
}

function infoCard(message) {
  return `<section class="card"><p>${escapeHtml(message)}</p></section>`;
}

function errorPage({ message, admin, title = 'エラー' }) {
  return layout({ title, admin, body: `<section class="card"><p class="notice-error">${escapeHtml(message)}</p></section>` });
}

function homePage({ admin, boxes }) {
  const boxHtml = boxes.map((box) => `
    <article class="box-item">
      ${box.header_image_path ? `<img class="box-thumb" src="/box-assets/${encodeURIComponent(box.header_image_path)}" alt="header" />` : ''}
      <h3>${escapeHtml(box.title)}</h3>
      <p class="muted">${escapeHtml(box.description || '説明なし')}</p>
      <p><span class="status-pill ${box.is_active && !box.is_expired ? '' : 'off'}">${box.is_active && !box.is_expired ? '公開中' : '停止/期限切れ'}</span></p>
      <a class="btn" href="/box/${encodeURIComponent(box.slug)}">アップロードページ</a>
    </article>
  `).join('');

  return layout({
    title: 'トップ',
    admin,
    body: `
      <section class="card">
        <h2>アップロード募集ボックス</h2>
        <p class="muted">カスタマイズ済みのボックス単位で、拡張子や容量などの制限を設定できます。</p>
      </section>
      <section class="box-list">${boxHtml || '<div class="card"><p>まだ募集ボックスがありません。</p></div>'}</section>
    `,
  });
}

function adminRegisterPage({ admin }) {
  return layout({
    title: '管理者登録',
    admin,
    body: `<section class="card"><h2>管理者登録</h2><form method="post" action="/admin/register"><label>ユーザー名<input name="username" required minlength="3" maxlength="64" /></label><label>パスワード<input type="password" name="password" required minlength="8" maxlength="128" /></label><button class="btn" type="submit">作成</button></form></section>`,
  });
}

function adminLoginPage() {
  return layout({
    title: '管理者ログイン',
    body: `<section class="card"><h2>管理者ログイン</h2><form method="post" action="/admin/login"><label>ユーザー名<input name="username" required /></label><label>パスワード<input type="password" name="password" required /></label><button class="btn" type="submit">ログイン</button></form></section>`,
  });
}

function boxFormFields(box = {}) {
  const expiresValue = box.expires_at ? new Date(box.expires_at).toISOString().slice(0, 16) : '';
  return `
    <label>タイトル<input name="title" required maxlength="100" value="${escapeHtml(box.title || '')}" /></label>
    <label>説明<textarea name="description" rows="3" maxlength="500">${escapeHtml(box.description || '')}</textarea></label>
    <label>ヘッダー画像（任意）<input type="file" name="headerImage" accept=".png,.jpg,.jpeg,.webp,.gif" /></label>
    ${box.id ? '<label><input type="checkbox" name="removeHeaderImage" value="1" /> 現在のヘッダー画像を削除する</label>' : ''}
    <label>公開メッセージ（任意）<textarea name="publicNotice" rows="2" maxlength="300">${escapeHtml(box.public_notice || '')}</textarea></label>
    <label>完了メッセージ（任意）<input name="successMessage" maxlength="200" value="${escapeHtml(box.success_message || '')}" placeholder="アップロードありがとうございました。" /></label>
    <label>フォント設定
      <select name="fontFamily">
        <option value="system" ${box.font_family === 'system' || !box.font_family ? 'selected' : ''}>System UI</option>
        <option value="sans" ${box.font_family === 'sans' ? 'selected' : ''}>Sans Serif</option>
        <option value="serif" ${box.font_family === 'serif' ? 'selected' : ''}>Serif</option>
        <option value="mono" ${box.font_family === 'mono' ? 'selected' : ''}>Monospace</option>
      </select>
    </label>
    <label>アクセントカラー（任意）<input type="color" name="accentColor" value="${escapeHtml(box.accent_color || '#2563eb')}" /></label>
    <label>追加CSS（任意・上級者向け）<textarea name="customCss" rows="4" maxlength="1500" placeholder="例: .card { border-radius: 16px; }">${escapeHtml(box.custom_css || '')}</textarea></label>
    <label>許可拡張子（例: png,jpg,pdf）<input name="allowedExtensions" required value="${escapeHtml(box.allowed_extensions || '')}" /></label>
    <label>最大ファイルサイズ(MB)<input type="number" name="maxFileSizeMb" min="1" max="500" value="${box.max_file_size_mb || 20}" required /></label>
    <label>最大ファイル数/回<input type="number" name="maxFilesPerUpload" min="1" max="50" value="${box.max_files_per_upload || 5}" required /></label>
    <label>最大総アップロード件数（任意）<input type="number" name="maxTotalFiles" min="1" max="100000" value="${box.max_total_files || ''}" /></label>
    <label>受付期限（任意）<input type="datetime-local" name="expiresAt" value="${expiresValue}" /></label>
    <label><input type="checkbox" name="requireUploaderName" value="1" ${box.require_uploader_name ? 'checked' : ''} /> 送信者名を必須にする</label>
    <label><input type="checkbox" name="requireUploaderNote" value="1" ${box.require_uploader_note ? 'checked' : ''} /> メモ入力を必須にする</label>
    <label>送信完了後のURL（任意）<input name="successRedirectUrl" maxlength="500" value="${escapeHtml(box.success_redirect_url || '')}" placeholder="https://example.com/thanks" /></label>
    <label>ボックスパスワード（変更時のみ入力）<input type="password" name="boxPassword" maxlength="128" /></label>
    <label>Discord Webhook URL（任意）<input name="discordWebhookUrl" maxlength="500" value="${escapeHtml(box.discord_webhook_url || '')}" /></label>
  `;
}

function adminDashboardPage({ admin, boxes, admins }) {
  const boxRows = boxes.map((box) => `
    <tr>
      <td>${box.id}</td>
      <td>${escapeHtml(box.title)}</td>
      <td><a href="/box/${escapeHtml(box.slug)}">${escapeHtml(box.slug)}</a></td>
      <td>${escapeHtml(box.allowed_extensions)}</td>
      <td>${box.max_file_size_mb}MB / ${box.max_files_per_upload}件 / 総数${box.max_total_files || '無制限'}</td>
      <td>${box.require_uploader_name ? '必須' : '任意'}</td>
      <td>${box.require_uploader_note ? '必須' : '任意'}</td>
      <td>${box.font_family || 'system'} / ${escapeHtml(box.accent_color || '#2563eb')}</td>
      <td>${box.expires_at ? escapeHtml(box.expires_at) : 'なし'}</td>
      <td>${box.is_active ? '公開' : '停止'}</td>
      <td>
        <button class="btn secondary js-copy" type="button" data-copy="/box/${escapeHtml(box.slug)}">リンクコピー</button>
        <form class="inline-form" method="post" action="/admin/boxes/${box.id}/toggle"><button class="btn secondary" type="submit">${box.is_active ? '停止' : '再開'}</button></form>
        <a class="btn secondary" href="/admin/boxes/${box.id}/files">ファイル</a>
        <a class="btn secondary" href="/admin/boxes/${box.id}/edit">編集</a>
      </td>
    </tr>
  `).join('');

  const adminRows = admins.map((a) => `<tr><td>${a.id}</td><td>${escapeHtml(a.username)}</td><td>${escapeHtml(a.created_at)}</td></tr>`).join('');

  return layout({
    title: '管理画面',
    admin,
    body: `
      <section class="grid two">
        <div class="card"><h2>募集ボックス作成</h2><form method="post" action="/admin/boxes/create" enctype="multipart/form-data">${boxFormFields()}<button class="btn" type="submit">作成</button></form></div>
        <div class="card"><h2>管理者追加</h2><p class="muted">初回作成後はログイン中管理者のみ作成できます。</p><form method="post" action="/admin/register"><label>ユーザー名<input name="username" required minlength="3" maxlength="64" /></label><label>パスワード<input type="password" name="password" required minlength="8" maxlength="128" /></label><button class="btn" type="submit">追加</button></form></div>
      </section>
      <section class="card"><h2>募集ボックス一覧</h2><div class="table-wrap"><table><thead><tr><th>ID</th><th>タイトル</th><th>リンク</th><th>許可形式</th><th>制限</th><th>送信者名</th><th>メモ</th><th>テーマ</th><th>期限</th><th>状態</th><th>操作</th></tr></thead><tbody>${boxRows || '<tr><td colspan="11">まだありません</td></tr>'}</tbody></table></div></section>
      <section class="card"><h2>管理者一覧</h2><div class="table-wrap"><table><thead><tr><th>ID</th><th>ユーザー名</th><th>作成日時</th></tr></thead><tbody>${adminRows}</tbody></table></div></section>
    `,
  });
}

function adminBoxEditPage({ admin, box }) {
  return layout({
    title: `ボックス編集: ${box.title}`,
    admin,
    body: `<section class="card"><h2>募集ボックス編集</h2>${box.header_image_path ? `<img class="box-header" src="/box-assets/${encodeURIComponent(box.header_image_path)}" alt="header" />` : ''}<form method="post" action="/admin/boxes/${box.id}/edit" enctype="multipart/form-data">${boxFormFields(box)}<button class="btn" type="submit">更新</button></form></section>`,
  });
}

function boxPublicPage({ box, currentCount }) {
  const fontMap = {
    system: 'system-ui, -apple-system, sans-serif',
    sans: 'Arial, Helvetica, sans-serif',
    serif: 'Georgia, "Times New Roman", serif',
    mono: 'ui-monospace, SFMono-Regular, Menlo, monospace',
  };
  const font = fontMap[box.font_family] || fontMap.system;
  const color = /^#[0-9a-fA-F]{6}$/.test(box.accent_color || '') ? box.accent_color : '#2563eb';
  const customCss = (box.custom_css || '').slice(0, 1500);
  const extraHead = `<style>:root{--primary:${color};--primary-hover:${color};} body{font-family:${font};} ${customCss}</style>`;

  return layout({
    title: `アップロード: ${box.title}`,
    extraHead,
    body: `<section class="card">${box.header_image_path ? `<img class="box-header" src="/box-assets/${encodeURIComponent(box.header_image_path)}" alt="header" />` : ''}<h2>${escapeHtml(box.title)}</h2><p class="muted">${escapeHtml(box.description || '説明なし')}</p>${box.public_notice ? `<p class="notice-info">${escapeHtml(box.public_notice)}</p>` : ''}<p>許可形式: <span class="kbd">${escapeHtml(box.allowed_extensions)}</span> / 最大サイズ: <span class="kbd">${box.max_file_size_mb}MB</span> / 最大数: <span class="kbd">${box.max_files_per_upload}</span> / 現在件数: <span class="kbd">${currentCount}${box.max_total_files ? ` / ${box.max_total_files}` : ''}</span></p><form method="post" action="/box/${encodeURIComponent(box.slug)}/upload" enctype="multipart/form-data">${box.password_hash ? '<label>募集ボックスパスワード<input type="password" name="boxPassword" required /></label>' : ''}${box.require_uploader_name ? '<label>送信者名<input name="uploaderName" maxlength="100" required /></label>' : '<label>送信者名（任意）<input name="uploaderName" maxlength="100" /></label>'}${box.require_uploader_note ? '<label>メモ<input name="uploaderNote" maxlength="200" required /></label>' : '<label>メモ（任意）<textarea name="uploaderNote" rows="2" maxlength="200"></textarea></label>'}<label>ファイル<input type="file" name="files" multiple required /></label><button class="btn" type="submit">アップロード</button></form></section>`,
  });
}

function uploadDonePage({ box, count }) {
  return layout({
    title: 'アップロード完了',
    body: `<section class="card"><p class="notice-ok">${escapeHtml(box.success_message || 'アップロードありがとうございました。')}</p><p class="muted">${count}件アップロードしました。</p>${box.success_redirect_url ? `<p><a class="btn" href="${escapeHtml(box.success_redirect_url)}">次へ進む</a></p>` : ''}<a class="btn secondary" href="/box/${encodeURIComponent(box.slug)}">戻る</a></section>`,
  });
}

function adminFilesPage({ admin, box, files }) {
  const rows = files.map((file) => `<tr><td>${file.id}</td><td>${escapeHtml(file.uploader_name || '-')}</td><td>${escapeHtml(file.uploader_note || '-')}</td><td>${escapeHtml(file.original_name)}</td><td>${Math.round(file.size_bytes / 1024)} KB</td><td>${escapeHtml(file.uploader_ip || '-')}</td><td>${escapeHtml(file.uploaded_at)}</td><td><a class="btn secondary" href="/admin/files/${file.id}/download">ダウンロード</a></td></tr>`).join('');
  return layout({
    title: `ファイル一覧: ${box.title}`,
    admin,
    body: `<section class="card"><h2>${escapeHtml(box.title)} のアップロードファイル</h2><p><a class="btn secondary" href="/admin">管理画面へ戻る</a></p><div class="table-wrap"><table><thead><tr><th>ID</th><th>送信者名</th><th>メモ</th><th>ファイル名</th><th>サイズ</th><th>IP</th><th>日時</th><th>操作</th></tr></thead><tbody>${rows || '<tr><td colspan="8">まだアップロードなし</td></tr>'}</tbody></table></div></section>`,
  });
}

module.exports = {
  escapeHtml,
  infoCard,
  errorPage,
  homePage,
  adminRegisterPage,
  adminLoginPage,
  adminDashboardPage,
  adminBoxEditPage,
  boxPublicPage,
  uploadDonePage,
  adminFilesPage,
};
