function escapeHtml(value = '') {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function renderActorNav(actor) {
  if (!actor) {
    return '<div class="nav-actions"><a class="btn secondary" href="/admin/login">管理者ログイン</a><a class="btn secondary" href="/viewer/login">閲覧アカウントログイン</a></div>';
  }
  if (actor.role === 'admin') {
    return `<div class="nav-actions"><span>管理者: <strong>${escapeHtml(actor.username)}</strong></span><a class="btn secondary" href="/admin">管理画面</a><form class="inline-form" method="post" action="/admin/logout"><button class="btn secondary" type="submit">ログアウト</button></form></div>`;
  }
  return `<div class="nav-actions"><span>閲覧者: <strong>${escapeHtml(actor.username)}</strong></span><a class="btn secondary" href="/viewer">閲覧ダッシュボード</a><form class="inline-form" method="post" action="/viewer/logout"><button class="btn secondary" type="submit">ログアウト</button></form></div>`;
}

function layout({ title, body, actor = null, extraHead = '' }) {
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
<header class="topbar"><div class="container topbar-inner"><div class="brand"><a href="/">Uploader</a></div>${renderActorNav(actor)}</div></header>
<main class="container">${body}</main>
<script src="/assets/app.js" defer></script>
</body>
</html>`;
}

function errorPage({ message, actor, title = 'エラー' }) {
  return layout({ title, actor, body: `<section class="card"><p class="notice-error">${escapeHtml(message)}</p></section>` });
}

function homePage({ actor, boxes }) {
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
    actor,
    body: `<section class="card"><h2>アップロード募集ボックス</h2><p class="muted">ボックス単位で制限やテーマを設定できます。</p></section><section class="box-list">${boxHtml || '<div class="card"><p>まだ募集ボックスがありません。</p></div>'}</section>`,
  });
}

function adminRegisterPage({ actor }) {
  return layout({ title: '管理者登録', actor, body: `<section class="card"><h2>管理者登録</h2><form method="post" action="/admin/register"><label>ユーザー名<input name="username" required minlength="3" maxlength="64" /></label><label>パスワード<input type="password" name="password" required minlength="8" maxlength="128" /></label><button class="btn" type="submit">作成</button></form></section>` });
}

function adminLoginPage({ actor }) {
  return layout({ title: '管理者ログイン', actor, body: `<section class="card"><h2>管理者ログイン</h2><form method="post" action="/admin/login"><label>ユーザー名<input name="username" required /></label><label>パスワード<input type="password" name="password" required /></label><button class="btn" type="submit">ログイン</button></form></section>` });
}

function viewerLoginPage({ actor }) {
  return layout({ title: '閲覧アカウントログイン', actor, body: `<section class="card"><h2>閲覧アカウントログイン</h2><p class="muted">募集ボックスの閲覧/ダウンロード専用アカウントです。</p><form method="post" action="/viewer/login"><label>ユーザー名<input name="username" required /></label><label>パスワード<input type="password" name="password" required /></label><button class="btn" type="submit">ログイン</button></form></section>` });
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
    <label>アクセントカラー<input type="color" name="accentColor" value="${escapeHtml(box.accent_color || '#2563eb')}" /></label>
    <label>追加CSS（任意）<textarea name="customCss" rows="4" maxlength="1500">${escapeHtml(box.custom_css || '')}</textarea></label>
    <label>許可拡張子（例: png,jpg,pdf）<input name="allowedExtensions" required value="${escapeHtml(box.allowed_extensions || '')}" /></label>
    <label>最大ファイルサイズ(MB)<input type="number" name="maxFileSizeMb" min="1" max="500" value="${box.max_file_size_mb || 20}" required /></label>
    <label>最大ファイル数/回<input type="number" name="maxFilesPerUpload" min="1" max="50" value="${box.max_files_per_upload || 5}" required /></label>
    <label>最大総アップロード件数（任意）<input type="number" name="maxTotalFiles" min="1" max="100000" value="${box.max_total_files || ''}" /></label>
    <label>受付期限（任意）<input type="datetime-local" name="expiresAt" value="${expiresValue}" /></label>
    <label><input type="checkbox" name="requireUploaderName" value="1" ${box.require_uploader_name ? 'checked' : ''} /> 送信者名を必須にする</label>
    <label><input type="checkbox" name="requireUploaderNote" value="1" ${box.require_uploader_note ? 'checked' : ''} /> メモ入力を必須にする</label>
    <label>送信完了後URL（任意）<input name="successRedirectUrl" maxlength="500" value="${escapeHtml(box.success_redirect_url || '')}" placeholder="https://example.com/thanks" /></label>
    <label>ボックスパスワード（変更時のみ入力）<input type="password" name="boxPassword" maxlength="128" /></label>
    <label>Discord Webhook URL（任意）<input name="discordWebhookUrl" maxlength="500" value="${escapeHtml(box.discord_webhook_url || '')}" /></label>
  `;
}

function adminDashboardPage({ actor, boxes, admins, viewers }) {
  const boxRows = boxes.map((box) => `
    <tr>
      <td>${box.id}</td><td>${escapeHtml(box.title)}</td><td><a href="/box/${escapeHtml(box.slug)}">${escapeHtml(box.slug)}</a></td>
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
  const viewerRows = viewers.map((v) => `<tr><td>${v.id}</td><td>${escapeHtml(v.username)}</td><td>${escapeHtml(v.allowed_boxes || '(未割当)')}</td><td>${escapeHtml(v.created_at)}</td><td><form method="post" action="/admin/viewers/${v.id}/assign"><div class="assign-row"><input type="number" name="boxId" min="1" required placeholder="box id"/><button class="btn secondary" type="submit">割当</button></div></form></td></tr>`).join('');

  return layout({
    title: '管理画面',
    actor,
    body: `
      <section class="grid two">
        <div class="card"><h2>募集ボックス作成</h2><form method="post" action="/admin/boxes/create" enctype="multipart/form-data">${boxFormFields()}<button class="btn" type="submit">作成</button></form></div>
        <div class="card"><h2>アカウント作成</h2><h3>管理者追加</h3><form method="post" action="/admin/register"><label>ユーザー名<input name="username" required minlength="3" maxlength="64" /></label><label>パスワード<input type="password" name="password" required minlength="8" maxlength="128" /></label><button class="btn" type="submit">管理者追加</button></form><hr/><h3>閲覧アカウント追加</h3><form method="post" action="/admin/viewers/create"><label>ユーザー名<input name="username" required minlength="3" maxlength="64" /></label><label>パスワード<input type="password" name="password" required minlength="8" maxlength="128" /></label><label>初期割当ボックスID<input type="number" name="boxId" min="1" required /></label><button class="btn" type="submit">閲覧アカウント追加</button></form></div>
      </section>
      <section class="card"><h2>募集ボックス一覧</h2><div class="table-wrap"><table><thead><tr><th>ID</th><th>タイトル</th><th>リンク</th><th>許可形式</th><th>制限</th><th>送信者名</th><th>メモ</th><th>テーマ</th><th>期限</th><th>状態</th><th>操作</th></tr></thead><tbody>${boxRows || '<tr><td colspan="11">まだありません</td></tr>'}</tbody></table></div></section>
      <section class="card"><h2>閲覧アカウント一覧</h2><div class="table-wrap"><table><thead><tr><th>ID</th><th>ユーザー名</th><th>閲覧可能ボックス</th><th>作成日時</th><th>追加割当</th></tr></thead><tbody>${viewerRows || '<tr><td colspan="5">まだありません</td></tr>'}</tbody></table></div></section>
      <section class="card"><h2>管理者一覧</h2><div class="table-wrap"><table><thead><tr><th>ID</th><th>ユーザー名</th><th>作成日時</th></tr></thead><tbody>${adminRows}</tbody></table></div></section>
    `,
  });
}

function adminBoxEditPage({ actor, box }) {
  return layout({ title: `ボックス編集: ${box.title}`, actor, body: `<section class="card"><h2>募集ボックス編集</h2>${box.header_image_path ? `<img class="box-header" src="/box-assets/${encodeURIComponent(box.header_image_path)}" alt="header" />` : ''}<form method="post" action="/admin/boxes/${box.id}/edit" enctype="multipart/form-data">${boxFormFields(box)}<button class="btn" type="submit">更新</button></form></section>` });
}

function viewerDashboardPage({ actor, boxes }) {
  const rows = boxes.map((box) => `<tr><td>${box.id}</td><td>${escapeHtml(box.title)}</td><td>${box.is_active && !box.is_expired ? '閲覧可能' : '停止/期限切れ'}</td><td><a class="btn secondary" href="/admin/boxes/${box.id}/files">ファイル一覧</a></td></tr>`).join('');
  return layout({ title: '閲覧ダッシュボード', actor, body: `<section class="card"><h2>閲覧可能な募集ボックス</h2><div class="table-wrap"><table><thead><tr><th>ID</th><th>タイトル</th><th>状態</th><th>操作</th></tr></thead><tbody>${rows || '<tr><td colspan="4">割り当てがありません</td></tr>'}</tbody></table></div></section>` });
}

function boxPublicPage({ actor, box, currentCount }) {
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
    actor,
    extraHead,
    body: `<section class="card">${box.header_image_path ? `<img class="box-header" src="/box-assets/${encodeURIComponent(box.header_image_path)}" alt="header" />` : ''}<h2>${escapeHtml(box.title)}</h2><p class="muted">${escapeHtml(box.description || '説明なし')}</p>${box.public_notice ? `<p class="notice-info">${escapeHtml(box.public_notice)}</p>` : ''}<p>許可形式: <span class="kbd">${escapeHtml(box.allowed_extensions)}</span> / 最大サイズ: <span class="kbd">${box.max_file_size_mb}MB</span> / 最大数: <span class="kbd">${box.max_files_per_upload}</span> / 現在件数: <span class="kbd">${currentCount}${box.max_total_files ? ` / ${box.max_total_files}` : ''}</span></p><form method="post" action="/box/${encodeURIComponent(box.slug)}/upload" enctype="multipart/form-data">${box.password_hash ? '<label>募集ボックスパスワード<input type="password" name="boxPassword" required /></label>' : ''}${box.require_uploader_name ? '<label>送信者名<input name="uploaderName" maxlength="100" required /></label>' : '<label>送信者名（任意）<input name="uploaderName" maxlength="100" /></label>'}${box.require_uploader_note ? '<label>メモ<input name="uploaderNote" maxlength="200" required /></label>' : '<label>メモ（任意）<textarea name="uploaderNote" rows="2" maxlength="200"></textarea></label>'}<label>ファイル<input type="file" name="files" multiple required /></label><button class="btn" type="submit">アップロード</button></form></section>`,
  });
}

function uploadDonePage({ actor, box, count }) {
  return layout({ title: 'アップロード完了', actor, body: `<section class="card"><p class="notice-ok">${escapeHtml(box.success_message || 'アップロードありがとうございました。')}</p><p class="muted">${count}件アップロードしました。</p>${box.success_redirect_url ? `<p><a class="btn" href="${escapeHtml(box.success_redirect_url)}">次へ進む</a></p>` : ''}<a class="btn secondary" href="/box/${encodeURIComponent(box.slug)}">戻る</a></section>` });
}

function filesPage({ actor, box, files }) {
  const rows = files.map((file) => `<tr><td>${file.id}</td><td>${escapeHtml(file.uploader_name || '-')}</td><td>${escapeHtml(file.uploader_note || '-')}</td><td>${escapeHtml(file.original_name)}</td><td>${Math.round(file.size_bytes / 1024)} KB</td><td>${escapeHtml(file.uploader_ip || '-')}</td><td>${escapeHtml(file.uploaded_at)}</td><td><a class="btn secondary" href="/files/${file.id}/preview">プレビュー</a><a class="btn secondary" href="/files/${file.id}/download">ダウンロード</a></td></tr>`).join('');
  return layout({ title: `ファイル一覧: ${box.title}`, actor, body: `<section class="card"><h2>${escapeHtml(box.title)} のアップロードファイル</h2><p><a class="btn secondary" href="${actor.role === 'admin' ? '/admin' : '/viewer'}">戻る</a></p><div class="table-wrap"><table><thead><tr><th>ID</th><th>送信者名</th><th>メモ</th><th>ファイル名</th><th>サイズ</th><th>IP</th><th>日時</th><th>操作</th></tr></thead><tbody>${rows || '<tr><td colspan="8">まだアップロードなし</td></tr>'}</tbody></table></div></section>` });
}

function previewPage({ actor, file, previewType, content = '' }) {
  let preview = '<p class="muted">このファイル形式はブラウザ内プレビューに対応していません。ダウンロードしてください。</p>';
  if (previewType === 'image') preview = `<img class="preview-media" src="/files/${file.id}/raw" alt="preview" />`;
  if (previewType === 'video') preview = `<video class="preview-media" src="/files/${file.id}/raw" controls></video>`;
  if (previewType === 'audio') preview = `<audio src="/files/${file.id}/raw" controls></audio>`;
  if (previewType === 'pdf') preview = `<iframe class="preview-frame" src="/files/${file.id}/raw"></iframe>`;
  if (previewType === 'text') preview = `<pre class="preview-text">${escapeHtml(content)}</pre>`;
  return layout({ title: `プレビュー: ${file.original_name}`, actor, body: `<section class="card"><h2>${escapeHtml(file.original_name)}</h2><p><a class="btn secondary" href="javascript:history.back()">戻る</a> <a class="btn secondary" href="/files/${file.id}/download">ダウンロード</a></p>${preview}</section>` });
}

module.exports = {
  escapeHtml,
  errorPage,
  homePage,
  adminRegisterPage,
  adminLoginPage,
  viewerLoginPage,
  adminDashboardPage,
  adminBoxEditPage,
  viewerDashboardPage,
  boxPublicPage,
  uploadDonePage,
  filesPage,
  previewPage,
};
