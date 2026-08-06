# cloudarmor-mcp

[English](README.md) | 日本語

[Google Cloud Armor](https://cloud.google.com/armor) の WAF ログを点検する MCP サーバーです。ルール別の遮断集計・自リージョン発の誤検知チェック・preview（ドライラン）ルールのレビューを、Cloud Logging から直接読み取ります。

毎日の「WAF は健全か？」の点検のために作りました。`daily_brief` を1回呼べば、*何をブロックしたか・ブロックすべきでない相手をブロックしていないか・preview ルールは昇格できる状態か* が一度に分かります。

ドキュメント: <https://shigechika.github.io/cloudarmor-mcp/>

## ツール

| ツール | 用途 |
|---|---|
| `daily_brief` | 朝の点検用サマリー1コール。ルール別 enforce 遮断・自リージョン発の誤検知レンズ・preview 遮断 |
| `enforce_denies` | ルール優先度別の enforce 遮断件数 |
| `home_region_denies` | 送信元 IP が自リージョンに属する enforce 遮断。known-normal に指定していないルールでの遮断は誤検知の候補 |
| `preview_denies` | preview（ドライラン）遮断件数。静かな preview ルールは enforce への昇格候補 |
| `health_check` | バージョン・設定の有無・Cloud Logging への最小プローブ |

全ツールが読み取り専用です。件数には上限（既定 2000 件/クエリ）があり、上限に達した結果は正確な合計ではなく `>= N (capped)` と表示されます。

## セットアップ

### 1. 最小権限のサービスアカウント

**`roles/logging.viewer` のみ**を付与したサービスアカウントを作成し、鍵を発行します。人間のアカウントと違い、サービスアカウントは組織の再認証ポリシーの対象外なので、無人実行の点検が知らないうちに失効することがありません。

```bash
gcloud iam service-accounts create waf-log-viewer --project=YOUR_PROJECT
gcloud projects add-iam-policy-binding YOUR_PROJECT \
  --member=serviceAccount:waf-log-viewer@YOUR_PROJECT.iam.gserviceaccount.com \
  --role=roles/logging.viewer
gcloud iam service-accounts keys create key.json \
  --iam-account=waf-log-viewer@YOUR_PROJECT.iam.gserviceaccount.com
```

### 2. インストール

```bash
pip install cloudarmor-mcp
# または
uv tool install cloudarmor-mcp
```

### 3. 環境変数

| 変数 | 必須 | 意味 |
|---|---|---|
| `CLOUDARMOR_PROJECT` | ○ | ロードバランサのログが入る GCP プロジェクト ID |
| `GOOGLE_APPLICATION_CREDENTIALS` | ○ | サービスアカウント鍵ファイルのパス |
| `CLOUDARMOR_BACKEND_SERVICES` | | 絞り込むバックエンドサービス名（カンマ区切り。既定は全て） |
| `CLOUDARMOR_HOME_REGION` | | 自組織のトラフィックとみなす ISO リージョンコード（例 `JP`）。誤検知レンズが有効になる |
| `CLOUDARMOR_RULES_INI` | | ルール INI のパス（ラベルと known-normal 優先度。下記） |
| `CLOUDARMOR_MAX_ENTRIES` | | 1クエリあたりの取得上限（既定 2000） |

### 4. ルール INI（任意）

自組織のルール番号をプロンプトから追い出し、レポートに人間が読める名前を付けられます。

```ini
[rules]
101 = 自リージョン外からの深いパス巡回をブロック
500 = AutoDiscover 探索のブロック
1002 = OWASP LFI 対策

[home]
; 自リージョン発でもこの優先度での遮断は想定内（誤検知ではない）
known_normal_priorities = 500, 600
```

### 5. Claude Code

```bash
claude mcp add cloudarmor -- cloudarmor-mcp
```

サーバーの env に上記の環境変数を設定してください。

## CLI

```bash
cloudarmor-mcp --version   # バージョン表示
cloudarmor-mcp --check     # 設定と API 疎通の確認（healthy なら exit 0）
cloudarmor-mcp --brief     # daily_brief を標準出力へ（cron / スモークテスト用）
```

## レポートの読み方

- **ルール別 enforce 遮断** — 平常時の遮断量です。内訳の急な変化は確認する価値があります。
- **自リージョン発の遮断** — 自国・自地域から来て遮断されたリクエストです。正規の利用者や正規クローラーの遮断はここに現れます。ローカル発のスキャナーも同じく現れるため、`known_normal_priorities`（例: AutoDiscover 遮断）に挙げたルールは suspicious 一覧から自動的に除かれます。
- **preview 遮断** — ドライラン中のルールです。自リージョン発の遮断が出ない状態が続く preview ルールは、enforce への昇格候補です。

## ライセンス

MIT
