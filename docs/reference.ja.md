# リファレンス

## ツール

全ツールが読み取り専用です。`health_check` を除き、いずれも `since_hours`
（float・既定 26）を受け取ります。

### `daily_brief(since_hours=26)`

朝の点検サマリーを1コールで返します。ルール別 enforce 遮断・自リージョン発の
誤検知レンズ（`CLOUDARMOR_HOME_REGION` 設定時のみ）・preview 遮断。クエリに失敗した
セクションは `query failed — <理由>` としてその場に表示され、他のセクションは
そのまま実行されます。

### `enforce_denies(since_hours=26)`

enforce 遮断をルール優先度別に集計し、多い順に返します。

### `preview_denies(since_hours=26)`

同じ内容を preview（ドライラン）モードのルールについて返します。

### `home_region_denies(since_hours=26)`

送信元 IP が `CLOUDARMOR_HOME_REGION` に属する enforce 遮断を返します。
`known_normal_priorities` の優先度は件数として集約・抑制し、それ以外は送信元 IP と
リクエスト URL 付きで列挙します（最大40行、超過分は件数表示）。自リージョンが
未設定の場合はエラーではなく、その旨の文を返します。

### `health_check()`

キー構成が常に一定の dict を返します。監視側でキーの有無を分岐する必要がありません。

| キー | 意味 |
|---|---|
| `status` | `healthy`（設定＋プローブ成功）／`degraded`（設定は OK・プローブ失敗）／`error`（設定が使えない） |
| `service` | 常に `cloudarmor-mcp` |
| `version` | パッケージのバージョン |
| `project` | 解決されたプロジェクト ID、または `null` |
| `backend_services` | 解決されたフィルタ一覧 |
| `home_region` | 解決されたリージョンコード、または `null` |
| `rules_ini` | 中身のあるルール INI を読み込めた場合に `true` |
| `probe` | `ok`、または失敗理由 |

## 環境変数

| 変数 | 必須 | 既定 | 意味 |
|---|---|---|---|
| `CLOUDARMOR_PROJECT` | ○ | — | ロードバランサのログが入る GCP プロジェクト ID |
| `GOOGLE_APPLICATION_CREDENTIALS` | ○ | — | サービスアカウント鍵のパス（`roles/logging.viewer`） |
| `CLOUDARMOR_BACKEND_SERVICES` | | 全て | バックエンドサービス名（カンマ区切り） |
| `CLOUDARMOR_HOME_REGION` | | 無効 | 誤検知レンズで使う ISO リージョンコード |
| `CLOUDARMOR_RULES_INI` | | なし | ルールのラベルと known-normal 優先度 |
| `CLOUDARMOR_MAX_ENTRIES` | | 2000 | 1クエリあたりの取得件数。解釈できない値は既定にフォールバック |

## CLI

```bash
cloudarmor-mcp            # stdio で MCP サーバーとして起動
cloudarmor-mcp --version  # バージョンを表示して終了
cloudarmor-mcp --check    # 設定と API アクセスを確認
cloudarmor-mcp --brief    # daily_brief を標準出力へ
```

終了コード:

| コマンド | 0 | 1 | 2 |
|---|---|---|---|
| `--check` | healthy | `CLOUDARMOR_PROJECT` 未設定 | degraded（プローブ失敗） |
| `--brief` | 全セクションを描画 | いずれかのセクションのクエリが失敗 | — |

`--brief` は cron やスモークテストに向いた形です。終了コードが非ゼロかどうかで
「WAF が静かだった」のか「ログを読めなかった」のかを区別できます。テキストの
レポートだけでは区別がつきません。

## ログフィルタ

参考までに、サーバーが組み立てる Cloud Logging フィルタは次の形です。

```text
resource.type="http_load_balancer"
jsonPayload.enforcedSecurityPolicy.outcome="DENY"
[jsonPayload.securityPolicyRequestData.remoteIpInfo.regionCode="JP"]
[resource.labels.backend_service_name="..." | =("a" OR "b")]
timestamp >= "<RFC3339 UTC>"
```

preview のクエリでは outcome の行が
`jsonPayload.previewSecurityPolicy.configuredAction="DENY"` に置き換わります。
エントリは新しい順に取得します。
