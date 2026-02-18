# Uploader (Self-hosted OSS)

募集ボックス方式のアップロードサイトです。管理者がボックスを作成し、リンクを知っている利用者が制限付きでファイルを送信できます。

## 主要機能
- 複数管理者アカウント
- 募集ボックスごとの詳細カスタマイズ
  - ヘッダー画像
  - フォント設定（system/sans/serif/mono）
  - アクセントカラー
  - 追加CSS（上級者向け）
  - 公開メッセージ / 完了メッセージ / 完了後URL
  - 許可拡張子、ファイルサイズ、回数制限、総数制限、受付期限
  - 送信者名必須 / メモ必須
- Discord Webhook 通知
- 管理者向けファイル一覧・ダウンロード
- Docker / LXC / Cloudflare Tunnel 運用対応
- `/healthz` ヘルスチェック

## 起動
```bash
npm install
npm start
```

## Docker（通常）
```bash
docker compose up -d --build
```

## Docker + Cloudflare Tunnel
`.env` に `TUNNEL_TOKEN=...` を設定し、以下を実行します。
```bash
docker compose --profile cloudflare up -d --build
```

## 画面構成（実装）
- ルーティング/業務ロジック: `src/server.js`
- HTMLテンプレート: `src/views.js`
- スタイル: `public/styles.css`
- 補助JS: `public/app.js`

## ドキュメント
- 利用者向け: `docs/user-guide.md`
- 開発者向け: `docs/developer-guide.md`
