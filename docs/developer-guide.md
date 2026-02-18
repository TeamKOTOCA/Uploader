# 開発者向けガイド

## 1. 構成
- `src/server.js`: メインアプリケーション（ルーティング・DB初期化・認証・アップロード処理）
- `public/styles.css`: UI スタイル
- `data/`: SQLite DB 格納先（実行時生成）
- `uploads/`: アップロードファイル格納先（実行時生成）
- `uploads/headers`: 募集ボックスのヘッダー画像格納先

## 2. ローカル起動
```bash
npm install
npm start
```

## 3. Docker 起動（通常）
```bash
docker compose up -d --build
```

## 4. Docker + Cloudflare Tunnel
1. Cloudflare Zero Trust で Tunnel を作成し token を取得
2. `.env` に `TUNNEL_TOKEN=...` を設定
3. 以下で起動

```bash
docker compose --profile cloudflare up -d --build
```

- 直接アクセス（`:3000`）と Tunnel 経由アクセスを併用可能です。
- アプリは `app.set('trust proxy', true)` と `cf-connecting-ip` 優先でIP記録します。

## 5. LXC でのセルフホスト例
1. Ubuntu LXC コンテナを作成
2. Node.js 22 を導入
3. 本リポジトリを配置
4. `npm install --omit=dev`
5. `PORT=3000 node src/server.js`
6. nginx/caddy などでリバースプロキシ + HTTPS を構成

## 6. セキュリティ設計メモ
- 管理者パスワードは PBKDF2(SHA-512) でハッシュ化
- セッションはランダムトークンの SHA-256 をDB保存し、Cookieには生トークン保持
- ボックスごとの拡張子/サイズ/件数/総数/期限/送信者名必須を制御
- ヘルスチェックは `/healthz`

## 7. 改善候補
- CSRF 対策トークン
- 監査ログ
- S3 など外部ストレージ対応
- 管理者権限ロール分離
