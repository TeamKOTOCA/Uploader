# 開発者向けガイド

## 1. 構成
- `src/server.js`: ルーティング、認証、DB、アップロード処理
- `src/views.js`: HTMLレンダリング（server.js から分離）
- `public/styles.css`: 白/黄/黒ベースのフラットUIスタイル
- `public/app.js`: 管理UI補助（リンクコピー）
- `uploads/headers`: ボックスヘッダー画像

## 2. 認証/権限
- 管理者アカウント: フル管理（ボックス作成・編集・停止、管理者/閲覧者作成、閲覧権限付与）
- 閲覧アカウント: ボックス単位で `viewer_box_permissions` に基づく閲覧/ダウンロード/プレビューのみ

### 関連テーブル
- `admins`, `sessions`
- `box_viewers`, `viewer_sessions`, `viewer_box_permissions`

## 3. 拡張されたボックス項目
- `header_image_path`
- `public_notice`
- `success_message`
- `success_redirect_url`
- `font_family`
- `accent_color`
- `custom_css`
- `require_uploader_name`
- `require_uploader_note`
- `max_total_files`
- `expires_at`

既存DBは `PRAGMA table_info` + `ALTER TABLE` で自動拡張されます。

## 4. プレビュー機能
`/files/:id/preview` で以下をブラウザ表示:
- 画像 / 動画 / 音声 / PDF / テキスト
- それ以外はダウンロード案内

## 5. ローカル起動
```bash
npm install
npm start
```

## 6. Docker
```bash
docker compose up -d --build
```

## 7. Cloudflare Tunnel 併用
1. Zero TrustでTunnel作成
2. token取得
3. `.env` に `TUNNEL_TOKEN=...`
4. `docker compose --profile cloudflare up -d --build`

## 8. 運用メモ
- `app.set('trust proxy', true)` 有効
- IPは `cf-connecting-ip` 優先
- `/healthz` で死活監視可能


## 9. 大容量ファイル対応
- ボックスの `max_file_size_mb` は `NULL/0` を無制限として扱います。
- 2GB前後のファイルを扱う場合は、リバースプロキシやトンネル側のアップロード制限値も調整してください。


## 10. Push通知
- `notification_subscriptions`: ブラウザ購読情報
- `notification_box_settings`: アカウント×ボックスの通知ON/OFF
- `VAPID_PUBLIC_KEY` / `VAPID_PRIVATE_KEY` が設定されるとWeb Push送信が有効になります。

## 11. 自動BAN
- `upload_violations` に失敗イベントを記録し、短時間の失敗連続で `upload_bans` に自動登録します。
- BAN対象はIPではなく `visitor_key` Cookie による端末識別キーです。
- 管理画面の BAN管理タブから理由確認と解除が可能です。
