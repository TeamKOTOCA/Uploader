# Uploader (Self-hosted OSS)

管理者が募集ボックスを作成し、リンクを知っている利用者が制限付きでファイルを送信できる Node.js 製アップロードサイトです。

## 主な機能
- 複数管理者アカウント
- 募集ボックスごとの制限
  - 許可拡張子（複数）
  - 1ファイル最大サイズ
  - 1回アップロード最大ファイル数
  - 最大総アップロード件数（任意）
  - 受付期限（任意）
  - 送信者名必須化（任意）
  - 任意パスワード
  - 任意 Discord Webhook 通知
  - 停止 / 再開
  - ヘッダー画像設定
  - 公開メッセージ / 完了メッセージ
- 管理者向けアップロードファイル一覧・ダウンロード（送信者名/メモ/IP付き）
- Docker / LXC でセルフホストしやすい構成
- Cloudflare Tunnel 経由アクセス対応（直接アクセスも可）

## クイックスタート（ローカル）
```bash
npm install
npm start
```

- トップ: `http://localhost:3000/`
- 初回管理者作成: `http://localhost:3000/admin/register`
- ヘルスチェック: `http://localhost:3000/healthz`

## Docker で起動（通常）
```bash
docker compose up -d --build
```

## Docker + Cloudflare Tunnel で起動
`.env` などで `TUNNEL_TOKEN` を指定し、Cloudflare プロファイルを有効化します。

```bash
docker compose --profile cloudflare up -d --build
```

## ドキュメント
- 利用者向け: `docs/user-guide.md`
- 開発者向け: `docs/developer-guide.md`

## ライセンス
利用時はご自身の運用ポリシーに合わせて `LICENSE` を追加してください。
