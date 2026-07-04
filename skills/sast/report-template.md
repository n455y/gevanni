# セキュリティ診断レポート

> **対象**: {{TARGET_NAME}}
> **スコープ**: {{SCOPE}}
> **診断日**: {{DATE}}
> **診断方式**: ホワイトボックス静的解析 (Dynamic Workflow fan-out)
> **適用観点数**: {{POV_COUNT}} / 診断ユニット数: {{UNIT_COUNT}}

---

## 1. エグゼクティブサマリ

- 診断ユニット数: **{{UNIT_COUNT}}**
- 適用観点数: **{{POV_COUNT}}**
- 発見合計: **{{TOTAL}} 件**
  - Critical: **{{C}}** / High: **{{H}}** / Medium: **{{M}}** / Low: **{{L}}** / Info: **{{I}}**

### 重大な所見 (Critical / High)

{{CRITICAL_HIGH_SUMMARY:- 重大な所見はありません。}}

### 制限事項・対象外
{{SCOPE_NOTES}}
- 本レポートは静的解析に基づく「可能性」の提示であり、動的検証を含まない。
- 以下の観点/領域は事前フィルタで対象外とした: {{EXCLUDED_PERSPECTIVES}}

---

## 2. リスク一覧表

深刻度順 → 信頼度順でソート。

| # | 深刻度 | 観点ID | ルート / 場所 | タイトル | 信頼度 |
|---|--------|--------|---------------|----------|--------|
{{RISK_TABLE_ROWS}}

---

## 3. 観点別詳細

{{#SEVERITY_GROUP:Critical}}
### Critical

#### [{{POV_ID}}] {{TITLE}}
- **場所**: `{{LOCATION}}`
- **信頼度**: {{CONFIDENCE}}
- **参照**: {{REFS}}
- **エビデンス**:
{{EVIDENCE}}
- **対策**:
{{REMEDIATION}}
{{/SEVERITY_GROUP}}

{{#SEVERITY_GROUP:High}}
### High
... (同構造)
{{/SEVERITY_GROUP}}

{{#SEVERITY_GROUP:Medium}}
### Medium
... (同構造)
{{/SEVERITY_GROUP}}

{{#SEVERITY_GROUP:Low}}
### Low
... (同構造)
{{/SEVERITY_GROUP}}

{{#SEVERITY_GROUP:Info}}
### Info
... (同構造)
{{/SEVERITY_GROUP}}

---

## 4. 補足

- 本レポートは**静的解析(SAST的)**に基づく。動的診断(実リクエスト検証)は `gevanni` スキャナーで別途実施することを推奨。
- フレームワークの保護(パラメータ化クエリ、自動エスケープ、型付き入力等)が確認できた箇所は原則として非対象とした。ただし設定漏れ・例外パスには注意。
- 信頼度 `low` または深刻度 `Info` の項目は FP の可能性がある。動的検証で裏取りを推奨。
- 対象コードの変更がある場合は再診断が必要。
