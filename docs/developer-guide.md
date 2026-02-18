# 開発者向けガイド

## 1. 構成
- `src/server.js`: メインアプリケーション（ルーティング・DB初期化・認証・アップロード処理）
- `public/styles.css`: UI スタイル
- `data/`: SQLite DB 格納先（実行時生成）
- `uploads/`: アップロードファイル格納先（実行時生成）

## 2. ローカル起動
```bash
npm install
npm start
```

## 3. Docker 起動
```bash
docker compose up -d --build
```

## 4. LXC でのセルフホスト例
1. Ubuntu LXC コンテナを作成
2. Node.js 22 を導入
3. 本リポジトリを配置
4. `npm install --omit=dev`
5. `PORT=3000 node src/server.js`
6. nginx/caddy などでリバースプロキシ + HTTPS を構成

## 5. セキュリティ設計メモ
- 管理者パスワードは PBKDF2(SHA-512) でハッシュ化
- セッションはランダムトークンの SHA-256 をDB保存し、Cookieには生トークン保持
- ボックスごとの拡張子/サイズ/件数制御を実施

## 6. 改善候補
- CSRF 対策トークン
- 監査ログ
- S3 など外部ストレージ対応
- 管理者権限ロール分離
