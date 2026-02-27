# Uploader (Self-hosted OSS)

募集ボックス方式のアップロードサイトです。管理者がボックスを作成し、リンクを知っている利用者が制限付きでファイルを送信できます。

## 主要機能
- 複数管理者アカウント（追加作成対応）
- 募集ボックスごとの詳細カスタマイズ
  - ヘッダー画像
  - フォント設定（system/sans/serif/mono）
  - アクセントカラー
  - 追加CSS（上級者向け）
  - 公開メッセージ / 完了メッセージ / 完了後URL
  - 許可拡張子、ファイルサイズ（0/空で無制限）、回数制限、総数制限、受付期限
  - 送信者名必須 / メモ必須
- 閲覧専用アカウント
  - ボックス単位で閲覧/ダウンロード権限を付与
  - 管理権限なし
- 管理者・閲覧者向けファイル一覧
- 拡張子入力支援（プリセット一括入力 + 候補付きタグ追加 + 手動入力）
- アップロード画面での選択ファイル一覧表示
- ファイルプレビュー（画像/動画/音声/PDF/テキスト）
- Discord Webhook 通知
- Push通知（管理者/閲覧者が各ボックス単位で ON/OFF）
- 自動BAN（端末識別キー単位、管理画面で理由確認/解除）
- Docker / LXC / Cloudflare Tunnel 運用対応
- `/healthz` ヘルスチェック
- 管理画面から環境全体（DB + uploads）のZIPバックアップ/復元

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


## 大容量アップロード運用メモ
- アプリ側はボックスの「最大ファイルサイズ」を 0 または空欄にすると無制限扱いです。
- 2GB級のアップロード時は、Cloudflare/Nginx/Traefik など前段プロキシのボディサイズ制限も合わせて緩和してください。


## Push通知の有効化
- VAPID鍵は初回起動時に自動生成されます（管理画面で後から変更可能）。
- `VAPID_PUBLIC_KEY` / `VAPID_PRIVATE_KEY` / `VAPID_SUBJECT` を環境変数で指定した場合は、その値が優先されます。
- ログイン後の管理画面/閲覧画面で「このブラウザでPush通知を有効化」を押し、各ボックスで Push ON にすると通知対象になります。


## OGP設定
- OGPのキャッチコピーは `募集ボックスでファイルを送信` です。
- OGP画像は `OGP_IMAGE_PATH` で指定できます（デフォルト: `/assets/ogp.png`）。
- 絶対URLの画像を使う場合は `OGP_IMAGE_PATH=https://...` を指定してください。
- 相対パス指定時の絶対URL化には `SITE_URL` を使用します（例: `https://uploader.example.com`）。
