# セットアップ

## 1. 最小権限のサービスアカウント

**`roles/logging.viewer` のみ**を付与したサービスアカウントを作成し、鍵を発行します。

```bash
gcloud iam service-accounts create waf-log-viewer --project=YOUR_PROJECT
gcloud projects add-iam-policy-binding YOUR_PROJECT \
  --member=serviceAccount:waf-log-viewer@YOUR_PROJECT.iam.gserviceaccount.com \
  --role=roles/logging.viewer
gcloud iam service-accounts keys create key.json \
  --iam-account=waf-log-viewer@YOUR_PROJECT.iam.gserviceaccount.com
```

!!! tip "人間のアカウントを使わない理由"
    多くの組織では人間の Google アカウントに再認証ポリシーが設定されています。
    リフレッシュトークン自体は有効なまま、アクセストークンの取得時に1日程度の
    間隔で対話的な本人確認を求められる、という挙動です。人間のアカウントで
    バックグラウンドの点検を回すと、予測できないタイミングで
    `Reauthentication failed` で止まり、しかもポリシーではなく障害のように
    見えます。サービスアカウントはこのポリシーの対象外なので、本サーバーは
    サービスアカウント前提で作られています。

鍵ファイルはパーミッション `600` にし、バージョン管理には入れないでください。

## 2. インストール

```bash
pip install cloudarmor-mcp
# または
uv tool install cloudarmor-mcp
```

## 3. 環境変数

| 変数 | 必須 | 意味 |
|---|---|---|
| `CLOUDARMOR_PROJECT` | ○ | ロードバランサのログが入る GCP プロジェクト ID |
| `GOOGLE_APPLICATION_CREDENTIALS` | ○ | サービスアカウント鍵ファイルのパス |
| `CLOUDARMOR_BACKEND_SERVICES` | | 絞り込むバックエンドサービス名（カンマ区切り。既定は全て） |
| `CLOUDARMOR_HOME_REGION` | | 自組織のトラフィックとみなす ISO リージョンコード（例 `JP`）。誤検知レンズが有効になる |
| `CLOUDARMOR_RULES_INI` | | ルール INI のパス（下記） |
| `CLOUDARMOR_MAX_ENTRIES` | | 1クエリあたりの取得上限（既定 2000） |

バックエンドサービス名は次で調べられます。

```bash
gcloud compute backend-services list --project=YOUR_PROJECT --format='value(name)'
```

`CLOUDARMOR_BACKEND_SERVICES` を未設定にするとプロジェクト内の全バックエンドが
対象になります。ロードバランサが1つなら正しい設定ですが、複数ある環境では
ノイズになります。

## 4. ルール INI（任意）

ログ上のルール優先度はただの数字です。この設定で名前を付け、自リージョン発の
遮断のうちどれが想定内かを指定します。

```ini
[rules]
101 = 自リージョン外からの深いパス巡回をブロック
500 = AutoDiscover 探索のブロック
1002 = OWASP LFI 対策

[home]
; 自リージョン発でもこの優先度での遮断は想定内（誤検知ではない）
known_normal_priorities = 500, 600
```

どちらのセクションも任意です。`[rules]` が無ければ優先度は数字のまま表示され、
`[home]` が無ければ自リージョン発の遮断はすべて suspicious として列挙されます。

!!! note "優先度は整数の文字列として照合されます"
    Cloud Logging はルール優先度を JSON の数値で返すため、実際には `101.0` の
    形で届きます。サーバー側で整数値の float を `101` に戻してから照合するので、
    INI には `101.0` ではなく `101` と素直に書いてください。

## 5. MCP クライアントへの登録

### Claude Code（プラグイン）

このリポジトリはプラグイン 1 個のマーケットプレイスも兼ねています。

```
/plugin marketplace add shigechika/cloudarmor-mcp
/plugin install cloudarmor-mcp@cloudarmor-mcp
```

プラグインは `uvx cloudarmor-mcp` を起動し、上記の環境変数と同じものを読みます。
Claude Code を起動する前に export しておいてください。`GOOGLE_APPLICATION_CREDENTIALS`
は依然として自分のマシン上に存在するサービスアカウント鍵ファイルを指す必要があります —
このファイルはプラグインが用意したり取得したりできないので、プラグインの設定だけでは
本サーバーを完全には構成できません。

プラグインは `uvx` を起動するため、Claude Code を実行するプロセスの `PATH` に
`uvx` が通っている必要があります。ログインシェルなら通常問題ありませんが、
GUI から起動した場合は通っていないことがあります。プラグインが起動しない場合は
[uv](https://docs.astral.sh/uv/) をシステム全体にインストールしてください。

### Claude Code（手動）

```bash
claude mcp add cloudarmor -- cloudarmor-mcp
```

サーバーの環境に上記の環境変数を設定します。定期実行に組み込む前に、設定・
認証情報・API アクセスまで一気通貫で確認しておきます。

```bash
cloudarmor-mcp --check   # exit 0 かつ "healthy — cloudarmor-mcp <version> project=<id>"
```
