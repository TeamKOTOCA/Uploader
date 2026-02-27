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
    return '<div class="nav-actions"><a class="btn secondary" href="/login">ログイン</a></div>';
  }
  if (actor.role === 'admin') {
    return `<div class="nav-actions"><span>管理者: <strong>${escapeHtml(actor.username)}</strong></span><a class="btn secondary" href="/admin">管理画面</a><form class="inline-form" method="post" action="/admin/logout"><button class="btn secondary" type="submit">ログアウト</button></form></div>`;
  }
  return `<div class="nav-actions"><span>閲覧者: <strong>${escapeHtml(actor.username)}</strong></span><a class="btn secondary" href="/viewer">閲覧ダッシュボード</a><form class="inline-form" method="post" action="/viewer/logout"><button class="btn secondary" type="submit">ログアウト</button></form></div>`;
}


function buildOgpMeta(title) {
  const siteName = 'Uploader';
  const copy = '募集ボックスでファイルを送信';
  const siteUrl = (process.env.SITE_URL || '').trim().replace(/\/$/, '');
  const ogpImagePath = (process.env.OGP_IMAGE_PATH || '/assets/ogp.png').trim();
  const ogImage = /^https?:\/\//i.test(ogpImagePath)
    ? ogpImagePath
    : `${siteUrl}${ogpImagePath.startsWith('/') ? '' : '/'}${ogpImagePath}`;
  return [
    `<meta property="og:type" content="website" />`,
    `<meta property="og:site_name" content="${escapeHtml(siteName)}" />`,
    `<meta property="og:title" content="${escapeHtml(title)}" />`,
    `<meta property="og:description" content="${escapeHtml(copy)}" />`,
    `<meta property="og:image" content="${escapeHtml(ogImage)}" />`,
    `<meta name="twitter:card" content="summary_large_image" />`,
    `<meta name="twitter:title" content="${escapeHtml(title)}" />`,
    `<meta name="twitter:description" content="${escapeHtml(copy)}" />`,
    `<meta name="twitter:image" content="${escapeHtml(ogImage)}" />`,
    '<meta name="description" content="募集ボックスでファイルを送信" />',
  ].join('\n');
}

function layout({ title, body, actor = null, extraHead = '' }) {
  return `<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>${escapeHtml(title)}</title>
<link rel="stylesheet" href="/assets/styles.css" />
${buildOgpMeta(title)}
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
  return layout({ title, actor, body: `<section class="card"><h2>${escapeHtml(title)}</h2><p class="notice-error">${escapeHtml(message)}</p><p><a class="btn secondary" href="javascript:history.back()">前のページに戻る</a> <a class="btn secondary" href="/">トップへ</a></p></section>` });
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
  return layout({ title: '管理者登録', actor, body: `<section class="card"><h2>管理者登録（初回のみ）</h2><p class="muted">初回の管理者作成後は、管理画面から管理者アカウントを追加できます。</p><form method="post" action="/admin/register"><label>ユーザー名<input name="username" required minlength="3" maxlength="64" pattern="[a-zA-Z0-9_.-]{3,64}" /></label><label>パスワード<input type="password" name="password" required minlength="8" maxlength="128" /></label><button class="btn" type="submit">作成</button></form></section>` });
}

function adminLoginPage({ actor }) {
  return layout({ title: '管理者ログイン', actor, body: `<section class="card"><h2>管理者ログイン</h2><form method="post" action="/admin/login"><label>ユーザー名<input name="username" required minlength="3" maxlength="64" pattern="[a-zA-Z0-9_.-]{3,64}" /></label><label>パスワード<input type="password" name="password" required minlength="8" maxlength="128" /></label><button class="btn" type="submit">ログイン</button></form></section>` });
}

function loginChoicePage({ actor }) {
  return layout({
    title: 'ログイン',
    actor,
    body: `<section class="card"><h2>ログイン</h2><p class="muted">利用するアカウント種別を選択してください。</p><div class="grid two"><a class="btn" href="/admin/login">管理者としてログイン</a><a class="btn" href="/viewer/login">閲覧アカウントでログイン</a></div></section>`,
  });
}

function viewerLoginPage({ actor }) {
  return layout({ title: '閲覧アカウントログイン', actor, body: `<section class="card"><h2>閲覧アカウントログイン</h2><p class="muted">募集ボックスの閲覧/ダウンロード専用アカウントです。</p><form method="post" action="/viewer/login"><label>ユーザー名<input name="username" required minlength="3" maxlength="64" pattern="[a-zA-Z0-9_.-]{3,64}" /></label><label>パスワード<input type="password" name="password" required minlength="8" maxlength="128" /></label><button class="btn" type="submit">ログイン</button></form></section>` });
}



function formatFileSize(bytes) {
  const value = Number(bytes) || 0;
  if (!value) return '無制限';
  const units = [
    { unit: 'TB', size: 1024 ** 4 },
    { unit: 'GB', size: 1024 ** 3 },
    { unit: 'MB', size: 1024 ** 2 },
    { unit: 'KB', size: 1024 },
  ];
  const picked = units.find((item) => value >= item.size) || units[units.length - 1];
  const amount = value / picked.size;
  const rounded = amount >= 10 ? Math.round(amount * 10) / 10 : Math.round(amount * 100) / 100;
  return `${rounded}${picked.unit}`;
}

function splitSizeForInput(bytes) {
  const value = Number(bytes) || 0;
  if (!value) return { amount: 0, unit: 'MB' };
  const units = [
    { unit: 'TB', size: 1024 ** 4 },
    { unit: 'GB', size: 1024 ** 3 },
    { unit: 'MB', size: 1024 ** 2 },
    { unit: 'KB', size: 1024 },
  ];
  const picked = units.find((item) => value % item.size === 0) || units.find((item) => value >= item.size) || units[2];
  return { amount: Math.max(1, Math.round(value / picked.size)), unit: picked.unit };
}

function isImageFile(file) {
  const mime = String(file.mime_type || '').toLowerCase();
  const ext = String(file.original_name || '').toLowerCase();
  return mime.startsWith('image/') || /\.(png|jpe?g|gif|webp|bmp|svg)$/.test(ext);
}

function extensionOptions() {
  return ['png', 'jpg', 'jpeg', 'webp', 'gif', 'svg', 'pdf', 'txt', 'md', 'csv', 'json', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'zip', '7z', 'rar', 'mp3', 'wav', 'aac', 'flac', 'mp4', 'mov', 'mkv'];
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
    <label>許可拡張子（タグ入力 + 手動入力対応 / 空欄で全拡張子を許可）
      <input id="allowedExtensionsInput" name="allowedExtensions" value="${escapeHtml(box.allowed_extensions || '')}" />
    </label>
    <div class="ext-tools">
      <div class="ext-presets">
        <button class="btn secondary" type="button" data-ext-preset="png,jpg,jpeg,webp,gif,svg">画像ファイル</button>
        <button class="btn secondary" type="button" data-ext-preset="pdf,doc,docx,xls,xlsx,ppt,pptx,txt,md,csv">文書ファイル</button>
        <button class="btn secondary" type="button" data-ext-preset="mp3,wav,aac,flac,ogg">音声ファイル</button>
        <button class="btn secondary" type="button" data-ext-preset="mp4,mov,mkv,webm">動画ファイル</button>
        <button class="btn secondary" type="button" data-ext-preset="zip,7z,rar,tar,gz">圧縮ファイル</button>
      </div>
      <div class="assign-row">
        <input id="extCandidate" list="extSuggestions" placeholder="例: pdf" />
        <datalist id="extSuggestions">${extensionOptions().map((ext) => `<option value="${ext}">`).join('')}</datalist>
        <button class="btn secondary" type="button" data-add-extension>追加</button>
      </div>
      <p class="muted">下の候補をクリックして追加できます。最終的にはカンマ区切りとして保存されます。</p>
      <div id="selectedExtensions" class="tag-list" aria-live="polite"></div>
    </div>
    <label>最大ファイルサイズ（0または空で無制限）
      ${(() => {
        const { amount, unit } = splitSizeForInput(box.max_file_size_bytes || ((box.max_file_size_mb || 0) * 1024 * 1024));
        return `<div class="inline-size"><input type="number" name="maxFileSizeValue" min="0" max="1048576" value="${amount}" /><select name="maxFileSizeUnit"><option value="KB" ${unit === 'KB' ? 'selected' : ''}>KB</option><option value="MB" ${unit === 'MB' ? 'selected' : ''}>MB</option><option value="GB" ${unit === 'GB' ? 'selected' : ''}>GB</option><option value="TB" ${unit === 'TB' ? 'selected' : ''}>TB</option></select></div>`;
      })()}
    </label>
    <label>最大ファイル数/回<input type="number" name="maxFilesPerUpload" min="1" max="1000" value="${box.max_files_per_upload || 20}" required /></label>
    <label>最大総アップロード件数（任意）<input type="number" name="maxTotalFiles" min="1" max="100000" value="${box.max_total_files || ''}" /></label>
    <label>受付期限（任意）<input type="datetime-local" name="expiresAt" value="${expiresValue}" /></label>
    <label><input type="checkbox" name="requireUploaderName" value="1" ${box.require_uploader_name ? 'checked' : ''} /> 送信者名を必須にする</label>
    <label><input type="checkbox" name="requireUploaderNote" value="1" ${box.require_uploader_note ? 'checked' : ''} /> メモ入力を必須にする</label>
    <label><input type="checkbox" name="isPrivate" value="1" ${box.is_private ? 'checked' : ''} /> 非公開ボックス（トップページに表示しない / 権限ユーザーのみアクセス可）</label>
    <label>送信完了後URL（任意）<input name="successRedirectUrl" maxlength="500" value="${escapeHtml(box.success_redirect_url || '')}" placeholder="https://example.com/thanks" /></label>
    <label>ボックスパスワード（変更時のみ入力）<input type="password" name="boxPassword" maxlength="128" /></label>
    <label>Discord Webhook URL（任意）<input name="discordWebhookUrl" maxlength="500" value="${escapeHtml(box.discord_webhook_url || '')}" /></label>
  `;
}

function adminDashboardPage({ actor, boxes, admins, viewers, pushMap = {}, vapidEnabled = false, vapidConfig = {}, bans = [], analyticsSummary = [], uploadsByDay = [], boxPerformance = [] }) {
  const boxRows = boxes.map((box) => `
    <tr>
      <td>${box.id}</td><td>${escapeHtml(box.title)}</td><td><a href="/box/${escapeHtml(box.slug)}">${escapeHtml(box.slug)}</a></td>
      <td>${escapeHtml(box.allowed_extensions || 'すべて許可')}</td>
      <td>${formatFileSize(box.max_file_size_bytes || ((box.max_file_size_mb || 0) * 1024 * 1024))} / ${box.max_files_per_upload}件 / 総数${box.max_total_files || '無制限'}</td>
      <td>${box.is_active ? (box.is_private ? '非公開' : '公開') : '停止'}</td>
      <td>
        <form class="inline-form" method="post" action="/push/boxes/${box.id}/toggle"><button class="btn secondary" type="submit">${pushMap[String(box.id)] ? 'Push ON' : 'Push OFF'}</button></form>
        <button class="btn secondary js-copy" type="button" data-copy="/box/${escapeHtml(box.slug)}">リンクコピー</button>
        <form class="inline-form" method="post" action="/admin/boxes/${box.id}/toggle"><button class="btn secondary" type="submit">${box.is_active ? '停止' : '再開'}</button></form>
        <a class="btn secondary" href="/admin/boxes/${box.id}/files">ファイル</a>
        <a class="btn secondary" href="/admin/boxes/${box.id}/edit">編集</a>
        <form class="inline-form" method="post" action="/admin/boxes/${box.id}/delete" onsubmit="return confirm('このボックスとアップロード済みファイルを削除します。よろしいですか？');"><button class="btn secondary" type="submit">削除</button></form>
      </td>
    </tr>
  `).join('');

  const adminRows = admins.map((a) => `<tr><td>${a.id}</td><td>${escapeHtml(a.username)}</td><td>${escapeHtml(a.created_at)}</td></tr>`).join('');
  const viewerRows = viewers.map((v) => `<tr><td>${v.id}</td><td>${escapeHtml(v.username)}</td><td>${escapeHtml(v.allowed_boxes || '(未割当)')}</td><td>${escapeHtml(v.created_at)}</td><td><form method="post" action="/admin/viewers/${v.id}/assign"><div class="assign-row"><input type="number" name="boxId" min="1" required placeholder="box id"/><button class="btn secondary" type="submit">割当</button></div></form><form method="post" action="/admin/viewers/${v.id}/delete" onsubmit="return confirm('閲覧アカウントを削除します。よろしいですか？');"><button class="btn secondary danger" type="submit">削除</button></form></td></tr>`).join('');
  const banRows = bans.map((b) => `<tr><td>${b.id}</td><td>${escapeHtml(b.subject_key)}</td><td>${escapeHtml(b.reason)}</td><td>${escapeHtml(b.created_by)}</td><td>${escapeHtml(b.created_at)}</td><td><form method="post" action="/admin/bans/${b.id}/release"><button class="btn secondary" type="submit">解除</button></form></td></tr>`).join('');

  return layout({
    title: '管理画面',
    actor,
    body: `
      <section class="tabs" data-tabs>
        <div class="tab-buttons">
          <button class="btn secondary" type="button" data-tab-target="tab-boxes">募集ボックス</button>
          <button class="btn secondary" type="button" data-tab-target="tab-create">作成</button>
          <button class="btn secondary" type="button" data-tab-target="tab-accounts">アカウント</button>
          <button class="btn secondary" type="button" data-tab-target="tab-push">通知設定</button>
          <button class="btn secondary" type="button" data-tab-target="tab-analytics">アクセス解析</button>
          <button class="btn secondary" type="button" data-tab-target="tab-ban">BAN管理</button>
          <button class="btn secondary" type="button" data-tab-target="tab-environment">環境バックアップ</button>
        </div>
        <div class="tab-panel" data-tab-panel="tab-boxes"><section class="card"><h2>募集ボックス一覧</h2><div class="table-wrap"><table><thead><tr><th>ID</th><th>タイトル</th><th>リンク</th><th>許可形式</th><th>制限</th><th>状態</th><th>操作</th></tr></thead><tbody>${boxRows || '<tr><td colspan="7">まだありません</td></tr>'}</tbody></table></div></section></div>
        <div class="tab-panel" data-tab-panel="tab-create"><section class="grid two"><div class="card"><h2>募集ボックス作成</h2><form method="post" action="/admin/boxes/create" enctype="multipart/form-data">${boxFormFields()}<button class="btn" type="submit">作成</button></form></div></section></div>
        <div class="tab-panel" data-tab-panel="tab-accounts"><section class="grid two"><div class="card"><h2>アカウント作成</h2><h3>管理者アカウント追加</h3><form method="post" action="/admin/admins/create"><label>ユーザー名<input name="username" required minlength="3" maxlength="64" pattern="[a-zA-Z0-9_.-]{3,64}" /></label><label>パスワード<input type="password" name="password" required minlength="8" maxlength="128" /></label><button class="btn" type="submit">管理者アカウント追加</button></form><h3>閲覧アカウント追加</h3><form method="post" action="/admin/viewers/create"><label>ユーザー名<input name="username" required minlength="3" maxlength="64" pattern="[a-zA-Z0-9_.-]{3,64}" /></label><label>パスワード<input type="password" name="password" required minlength="8" maxlength="128" /></label><label>初期割当ボックスID<input type="number" name="boxId" min="1" required /></label><button class="btn" type="submit">閲覧アカウント追加</button></form><p><a class="btn secondary" href="/admin/account">自分のアカウント設定</a></p></div><div class="card"><h2>閲覧アカウント一覧</h2><div class="table-wrap"><table><thead><tr><th>ID</th><th>ユーザー名</th><th>閲覧可能ボックス</th><th>作成日時</th><th>操作</th></tr></thead><tbody>${viewerRows || '<tr><td colspan="5">まだありません</td></tr>'}</tbody></table></div></div></section><section class="card"><h2>管理者一覧</h2><div class="table-wrap"><table><thead><tr><th>ID</th><th>ユーザー名</th><th>作成日時</th></tr></thead><tbody>${adminRows}</tbody></table></div></section></div>
        <div class="tab-panel" data-tab-panel="tab-push"><section class="grid two"><div class="card"><h2>通知設定</h2>${vapidEnabled ? '<button type="button" class="btn" id="enablePushBtn">このブラウザでPush通知を有効化</button><p class="muted">有効化後、各ボックスの Push ON/OFF を切り替えできます。</p>' : '<p class="notice-info">Push通知は未設定です。下のVAPID設定を保存してください。</p>'}</div><div class="card"><h2>VAPID Key設定</h2><form method="post" action="/admin/push-config"><label>VAPID Subject<input name="vapidSubject" maxlength="300" placeholder="mailto:admin@example.com" value="${escapeHtml(vapidConfig.subject || 'mailto:admin@example.com')}" /></label><label>VAPID Public Key<input name="vapidPublicKey" maxlength="300" value="${escapeHtml(vapidConfig.publicKey || '')}" /></label><label>VAPID Private Key<input name="vapidPrivateKey" maxlength="300" value="${escapeHtml(vapidConfig.privateKey || '')}" /></label><p class="muted">無効化したい場合は公開鍵・秘密鍵を両方空欄にして保存してください。</p><button class="btn" type="submit">VAPID設定を保存</button></form></div></section></div>
        <div class="tab-panel" data-tab-panel="tab-analytics"><section class="grid two"><div class="card"><h2>イベント集計 (30日)</h2><div class="table-wrap"><table><thead><tr><th>イベント</th><th>件数</th></tr></thead><tbody>${analyticsSummary.map((row) => `<tr><td>${escapeHtml(row.event_type)}</td><td>${row.total}</td></tr>`).join('') || '<tr><td colspan="2">データなし</td></tr>'}</tbody></table></div></div><div class="card"><h2>日別アップロード (14日)</h2><div class="table-wrap"><table><thead><tr><th>日付</th><th>件数</th></tr></thead><tbody>${uploadsByDay.map((row) => `<tr><td>${escapeHtml(row.day)}</td><td>${row.total}</td></tr>`).join('') || '<tr><td colspan="2">データなし</td></tr>'}</tbody></table></div></div></section><section class="card"><h2>ボックス別パフォーマンス (30日)</h2><div class="table-wrap"><table><thead><tr><th>ID</th><th>タイトル</th><th>閲覧数</th><th>アップロード成功</th><th>CVR</th></tr></thead><tbody>${boxPerformance.map((row) => `<tr><td>${row.id}</td><td>${escapeHtml(row.title)}</td><td>${row.views || 0}</td><td>${row.uploads || 0}</td><td>${row.views ? `${Math.round((row.uploads / row.views) * 1000) / 10}%` : '-'}</td></tr>`).join('') || '<tr><td colspan="5">データなし</td></tr>'}</tbody></table></div></section></div>
        <div class="tab-panel" data-tab-panel="tab-ban"><section class="card"><h2>BAN管理</h2><p class="muted">IP単体BANは行わず、端末識別キー単位で自動BANされます。</p><div class="table-wrap"><table><thead><tr><th>ID</th><th>識別キー</th><th>理由</th><th>実行者</th><th>日時</th><th>操作</th></tr></thead><tbody>${banRows || '<tr><td colspan="6">現在BANはありません</td></tr>'}</tbody></table></div></section></div>
        <div class="tab-panel" data-tab-panel="tab-environment"><section class="grid two"><div class="card"><h2>環境バックアップ (ZIP)</h2><p class="muted">データベースとアップロードファイルをまとめてZIPで保存します。</p><p><a class="btn" href="/admin/environment/download">環境全体をZIPダウンロード</a></p></div><div class="card"><h2>環境復元 (ZIP)</h2><p class="notice-info">復元すると現在のデータベース/アップロードファイルが置き換わります。</p><form method="post" action="/admin/environment/restore" enctype="multipart/form-data" onsubmit="return confirm('環境を復元すると現在のデータは上書きされます。よろしいですか？');"><label>復元用ZIP<input type="file" name="backupZip" accept=".zip,application/zip" required /></label><button class="btn secondary" type="submit">ZIPから復元する</button></form></div></section></div>
      </section>
    `,
  });
}

function adminBoxEditPage({ actor, box }) {
  return layout({ title: `ボックス編集: ${box.title}`, actor, body: `<section class="card"><h2>募集ボックス編集</h2>${box.header_image_path ? `<img class="box-header" src="/box-assets/${encodeURIComponent(box.header_image_path)}" alt="header" />` : ''}<form method="post" action="/admin/boxes/${box.id}/edit" enctype="multipart/form-data">${boxFormFields(box)}<button class="btn" type="submit">更新</button></form><form method="post" action="/admin/boxes/${box.id}/delete" onsubmit="return confirm('このボックスとアップロード済みファイルを削除します。よろしいですか？');"><button class="btn secondary" type="submit">このボックスを削除</button></form></section>` });
}

function viewerDashboardPage({ actor, boxes, pushMap = {}, vapidEnabled = false }) {
  const rows = boxes.map((box) => `<tr><td>${box.id}</td><td>${escapeHtml(box.title)}</td><td>${box.is_active && !box.is_expired ? '閲覧可能' : '停止/期限切れ'}</td><td><form class="inline-form" method="post" action="/push/boxes/${box.id}/toggle"><button class="btn secondary" type="submit">${pushMap[String(box.id)] ? 'Push ON' : 'Push OFF'}</button></form></td><td><a class="btn secondary" href="/admin/boxes/${box.id}/files">ファイル一覧</a></td></tr>`).join('');
  return layout({ title: '閲覧ダッシュボード', actor, body: `<section class="tabs" data-tabs><div class="tab-buttons"><button class="btn secondary" type="button" data-tab-target="tab-viewer-boxes">募集ボックス</button><button class="btn secondary" type="button" data-tab-target="tab-viewer-push">通知設定</button></div><div class="tab-panel" data-tab-panel="tab-viewer-boxes"><section class="card"><h2>閲覧可能な募集ボックス</h2><p><a class="btn secondary" href="/viewer/account">アカウント設定</a></p><div class="table-wrap"><table><thead><tr><th>ID</th><th>タイトル</th><th>状態</th><th>通知</th><th>操作</th></tr></thead><tbody>${rows || '<tr><td colspan="5">割り当てがありません</td></tr>'}</tbody></table></div></section></div><div class="tab-panel" data-tab-panel="tab-viewer-push"><section class="card"><h2>通知設定</h2>${vapidEnabled ? '<button type="button" class="btn" id="enablePushBtn">このブラウザでPush通知を有効化</button>' : '<p class="notice-info">Push通知は未設定です。管理者へ問い合わせてください。</p>'}</section></div></section>` });
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
    body: `<section class="card">${box.header_image_path ? `<img class="box-header" src="/box-assets/${encodeURIComponent(box.header_image_path)}" alt="header" />` : ''}<h2>${escapeHtml(box.title)}</h2><p class="muted">${escapeHtml(box.description || '説明なし')}</p>${box.public_notice ? `<p class="notice-info">${escapeHtml(box.public_notice)}</p>` : ''}<p>許可形式: <span class="kbd">${escapeHtml(box.allowed_extensions || 'すべて許可')}</span> / 最大サイズ: <span class="kbd">${formatFileSize(box.max_file_size_bytes || ((box.max_file_size_mb || 0) * 1024 * 1024))}</span></p><form id="uploadForm" method="post" action="/box/${encodeURIComponent(box.slug)}/upload" enctype="multipart/form-data">${box.password_hash ? '<label>募集ボックスパスワード<input type="password" name="boxPassword" required /></label>' : ''}${box.require_uploader_name ? '<label>送信者名<input name="uploaderName" maxlength="100" required /></label>' : '<label>送信者名（任意）<input name="uploaderName" maxlength="100" /></label>'}${box.require_uploader_note ? '<label>メモ<input name="uploaderNote" maxlength="200" required /></label>' : '<label>メモ（任意）<textarea name="uploaderNote" rows="2" maxlength="200"></textarea></label>'}<label>ファイル<input id="uploadFilesInput" type="file" name="files" multiple required /></label><div id="uploadDropzone" class="upload-dropzone" tabindex="0">ここにファイルをドラッグ&ドロップ</div><ul id="selectedUploadFiles" class="file-list" aria-live="polite"></ul><div id="uploadBusyNotice" class="upload-busy" hidden>アップロード中です。ページを閉じずにお待ちください…</div><div class="upload-progress-wrap"><progress id="uploadProgress" max="100" value="0"></progress><span id="uploadProgressText" class="muted">待機中</span></div><button id="uploadSubmitButton" class="btn" type="submit">アップロード</button></form></section>`,
  });
}

function accountPage({ actor }) {
  const isAdmin = actor.role === 'admin';
  const action = isAdmin ? '/admin/account/password' : '/viewer/account/password';
  const heading = isAdmin ? '管理者アカウント設定' : '閲覧アカウント設定';
  return layout({ title: heading, actor, body: `<section class="card" data-auto-push-prompt="1"><h2>${heading}</h2><p class="muted">ログイン中ユーザー: ${escapeHtml(actor.username)}</p><button type="button" class="btn secondary" id="enablePushBtn">このブラウザでPush通知を有効化</button><p class="muted">ページ表示時に通知有効化を確認します。</p><h3>パスワード変更</h3><form method="post" action="${action}"><label>現在のパスワード<input type="password" name="currentPassword" required minlength="8" maxlength="128" /></label><label>新しいパスワード<input type="password" name="newPassword" required minlength="8" maxlength="128" /></label><button class="btn" type="submit">変更する</button></form><p><a class="btn secondary" href="${isAdmin ? '/admin' : '/viewer'}">戻る</a></p></section>` });
}

function uploadDonePage({ actor, box, count }) {
  return layout({ title: 'アップロード完了', actor, body: `<section class="card"><p class="notice-ok">${escapeHtml(box.success_message || 'アップロードありがとうございました。')}</p><p class="muted">${count}件アップロードしました。</p>${box.success_redirect_url ? `<p><a class="btn" href="${escapeHtml(box.success_redirect_url)}">次へ進む</a></p>` : ''}<a class="btn secondary" href="/box/${encodeURIComponent(box.slug)}">戻る</a></section>` });
}

function filesPage({ actor, box, files }) {
  const rows = files.map((file) => `<tr><td><input class="bulk-file-id" type="checkbox" name="fileIds" value="${file.id}" /></td><td>${file.id}</td><td>${isImageFile(file) ? `<img class="file-thumb" src="/files/${file.id}/raw" alt="thumb-${file.id}" loading="lazy" />` : '<span class="file-thumb-placeholder">-</span>'}</td><td>${escapeHtml(file.uploader_name || '-')}</td><td>${escapeHtml(file.uploader_note || '-')}</td><td>${escapeHtml(file.original_name)}</td><td>${Math.round(file.size_bytes / 1024)} KB</td><td>${escapeHtml(file.uploader_ip || '-')}</td><td>${escapeHtml(file.uploaded_at)}</td><td><a class="btn secondary" href="/files/${file.id}/preview">プレビュー</a><a class="btn secondary" href="/files/${file.id}/download">ダウンロード</a></td></tr>`).join('');
  const deleteForm = actor.role === 'admin' ? `<form id="bulkDeleteForm" method="post" action="/admin/files/bulk-delete"><input type="hidden" name="boxId" value="${box.id}" /><input type="hidden" name="fileIds" id="bulkDeleteIds" /><button class="btn secondary" type="submit">選択ファイルを削除</button></form>` : '';
  return layout({ title: `ファイル一覧: ${box.title}`, actor, body: `<section class="card"><h2>${escapeHtml(box.title)} のアップロードファイル</h2><p><a class="btn secondary" href="${actor.role === 'admin' ? '/admin' : '/viewer'}">戻る</a></p><div class="bulk-actions"><button class="btn secondary" type="button" id="bulkSelectAll">すべて選択/解除</button><form id="bulkDownloadForm" method="post" action="/files/bulk-download"><input type="hidden" name="boxId" value="${box.id}" /><input type="hidden" name="fileIds" id="bulkDownloadIds" /><button class="btn secondary" type="submit">選択をZIPダウンロード</button></form>${deleteForm}</div><label>絞り込み<input id="fileFilterInput" placeholder="ファイル名 / 送信者名で検索" /></label><div class="table-wrap"><table id="filesTable"><thead><tr><th>選択</th><th>ID</th><th>サムネイル</th><th>送信者名</th><th>メモ</th><th>ファイル名</th><th>サイズ</th><th>IP</th><th>日時</th><th>操作</th></tr></thead><tbody>${rows || '<tr><td colspan="10">まだアップロードなし</td></tr>'}</tbody></table></div></section>` });
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
  loginChoicePage,
  viewerLoginPage,
  adminDashboardPage,
  adminBoxEditPage,
  viewerDashboardPage,
  accountPage,
  boxPublicPage,
  uploadDonePage,
  filesPage,
  previewPage,
};
