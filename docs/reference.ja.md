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
cloudarmor-mcp deny-export --date YYYY-MM-DD [--tz ZONE] [--kind both|enforced|preview] [--max-entries N] [--backend a,b]
                          # 1 日分の DENY エントリーを JSON で（README 参照）
cloudarmor-mcp traffic-export --date YYYY-MM-DD [--tz ZONE] [--sample RATE] [--max-entries N] [--backend a,b]
                          # 1 日分の全リクエストを間引いて JSON で（README 参照）
```

終了コード:

| コマンド | 0 | 1 | 2 |
|---|---|---|---|
| `--check` | healthy | `CLOUDARMOR_PROJECT` 未設定 | degraded（プローブ失敗） |
| `--brief` | 全セクションを描画 | いずれかのセクションのクエリが失敗 | — |
| `deny-export` | 書き出した | Cloud Logging のクエリが失敗（標準出力に途中までの文書が残ることがある）、または読み手が標準出力を閉じた | 使い方・設定の誤り。`CLOUDARMOR_PROJECT` 未設定、クライアントを作れない（認証情報）、まだ終わっていない日を含む |
| `traffic-export` | 書き出した | `deny-export` と同じ | `deny-export` と同じ。範囲外の `--sample`（0.000001〜1 の外）も含む |

`--brief` は cron やスモークテストに向いた形です。終了コードが非ゼロかどうかで
「WAF が静かだった」のか「ログを読めなかった」のかを区別できます。テキストの
レポートだけでは区別がつきません。

### `traffic-export` の文書

形とレコードの項目は `deny-export` と同じで、違いは次のとおりです。

| 項目 | 意味 |
|---|---|
| `schema` | `cloudarmor-mcp/traffic-export/1` |
| `sample` | `sample(insertId, ...)` に渡した割合。`kind` の代わりに入る |
| `entries[]` | 間引いて残った、ロードバランサーの全リクエスト（許可・拒否・キャッシュからの応答） |
| `entries[].cache_hit` | CDN のキャッシュから返したとき `true`（`deny-export` のレコードにも入るが、実際には常に `false`） |
| `entries[].enforced` | バックエンドのセキュリティポリシーが評価しなかったとき（CDN のキャッシュ命中など）`null`。そのとき `region` と `asn` も `null`。キャッシュ命中かどうかは `cache_hit` で見分ける |
| `capped` | `deny-export` と同じ。`true` のときは古い順に読んだ 1 日の前半だけなので、`1 / sample` 倍しない |

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

`traffic-export` は outcome の行を持たず、1 日の範囲（`timestamp >=` と `timestamp <`）の後ろに
`sample(insertId, RATE)` を付けます（RATE が 1 のときは付けません）。エントリは古い順に取得します。
