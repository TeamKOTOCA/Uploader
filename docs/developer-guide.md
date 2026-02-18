# 開発者向けガイド

## 1. 構成
- `src/server.js`: ルーティング、認証、DB、アップロード処理
- `src/views.js`: HTMLレンダリング（server.js から分離）
- `public/styles.css`: モダンUIスタイル
- `public/app.js`: 管理UI補助（リンクコピー）
- `uploads/headers`: ボックスヘッダー画像

## 2. 拡張されたボックス項目
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

## 3. ローカル起動
```bash
npm install
npm start
```

## 4. Docker
```bash
docker compose up -d --build
```

## 5. Cloudflare Tunnel 併用
1. Zero TrustでTunnel作成
2. token取得
3. `.env` に `TUNNEL_TOKEN=...`
4. `docker compose --profile cloudflare up -d --build`

## 6. 運用メモ
- `app.set('trust proxy', true)` 有効
- IPは `cf-connecting-ip` 優先
- `/healthz` で死活監視可能
