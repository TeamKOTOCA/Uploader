# Uploader (Self-hosted OSS)

管理者が募集ボックスを作成し、リンクを知っている利用者が制限付きでファイルを送信できる Node.js 製アップロードサイトです。

## 特徴
- 複数管理者アカウント
- 募集ボックスごとの制限
  - 許可拡張子（複数）
  - 1ファイル最大サイズ
  - 1回アップロード最大ファイル数
  - 任意パスワード
  - 任意 Discord Webhook 通知
  - 停止 / 再開
- 管理者向けアップロードファイル一覧・ダウンロード
- Docker / LXC でセルフホストしやすい最小構成

## クイックスタート（ローカル）
```bash
npm install
npm start
```

- トップ: `http://localhost:3000/`
- 初回管理者作成: `http://localhost:3000/admin/register`

## Docker で起動
```bash
docker compose up -d --build
```

## ドキュメント
- 利用者向け: `docs/user-guide.md`
- 開発者向け: `docs/developer-guide.md`

## ライセンス
利用時はご自身の運用ポリシーに合わせて `LICENSE` を追加してください。
