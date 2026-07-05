// plugin-template.ts — カスタムシグネチャプラグインの参照テンプレート
//
// scan スキルのギャップ分析で生成されるプラグインは、このテンプレートの構造に従う。
// 実際のプラグイン生成時は、検出すべき脆弱性クラスに応じて
// payload, 検出パターン, groups がカスタマイズされる。
//
// 配置先: <cwd>/.gevanni/plugins/autoload/custom-<vuln-type>.ts
//
// autoload ディレクトリ内の .ts/.js ファイルは discoverPluginFiles() によって
// 自動検出されるため、config.json への手動追加は不要。
//
// インポートパスは gevanni の src/ からの相対パス。
// カスタムプラグインは .gevanni/plugins/autoload/ に置かれ、
// gevanni のビルドイン plugin-loader が動的インポートするため
// これらの相対インポートが解決される。

import { SignatureGroupId } from "../../types/branded.ts";
import type { Exchange } from "../../types/models.ts";
import { BuiltinMutationType, BuiltinPayload } from "../../types/models.ts";
import type { RunAuditContext } from "../../commands/run-audit.ts";
import { MutationFilteredSignaturePlugin } from "../signature/mutation-filtered.ts";

// ── 検出パターン定義 ──────────────────────────────────────────────
// 脆弱性クラスごとに適切な正規表現またはレスポンス判定ロジックを定義する。
// 例: SQL エラーメッセージ、コマンド実行結果、XSS ペイロード反射 など

const DETECTION_PATTERNS: RegExp[] = [
  // ここに脆弱性を示すレスポンスパターンを追加
  /example error pattern/i,
];

export default class CustomPlugin extends MutationFilteredSignaturePlugin {
  // ── プラグイン識別子 ────────────────────────────────────────────
  // 命名規則: signature:custom-<kebab-case-vuln-type>
  // 例: signature:custom-sqli-error, signature:custom-xss-reflected
  readonly name = "signature:custom-example";

  // ── シグネチャグループ ──────────────────────────────────────────
  // SignatureGroupId は型安全なグループ識別子。
  // 使用可能な値は gevanni のグループ定義に依存。
  // 一般的なもの: sqli, xss, cmdi, path-traversal, ssti, xxe, ldap,
  //              nosqli, crlf, xpath, ssi, prototype-pollution
  protected readonly groups = [SignatureGroupId("custom")];

  // ── 適用するミューテーションタイプ ──────────────────────────────
  // BuiltinMutationType:
  //   AppendValue  - 既存の値の末尾にペイロードを追加 (最も一般的)
  //   ReplaceValue - 値をペイロードで完全置換
  //   InsertValue  - 値の先頭にペイロードを挿入
  protected readonly mutationTypes = [BuiltinMutationType.AppendValue] as const;

  // ── 監査実行 ────────────────────────────────────────────────────
  // context から parameter (テスト対象パラメータ) と
  // replay (リクエスト再実行関数) を受け取り、
  // ペイロードを送信してレスポンスを分析する。
  //
  // 戻り値: Finding { vulnerable: boolean, evidence, request, response }
  protected async runAudit({ parameter, replay }: RunAuditContext) {
    // 1. ペイロード生成
    const payload = BuiltinPayload.String("<payload>");

    // 2. ミューテーション作成 & リクエスト再実行
    const result = await replay([
      parameter.createMutation(payload, BuiltinMutationType.AppendValue),
    ]);

    // 3. 全 Exchange を収集（リダイレクトチェーン含む）
    const allExchanges: Exchange[] = result.allExchanges;

    // 4. レスポンス分析 — 脆弱性を示すパターンを検出
    const matches = allExchanges.filter((ex) =>
      DETECTION_PATTERNS.some((p) =>
        p.test(ex.response.body?.toString() ?? "")
      )
    );

    // 5. 判定結果を返す
    return {
      vulnerable: matches.length > 0,
      evidence: {
        judgmentId: "custom-detection",
        exchanges: allExchanges,
        evidenceExchanges: matches,
      },
      request: result.exchange.request,
      response: result.exchange.response,
    };
  }
}

// ── 実装パターン一覧 ──────────────────────────────────────────────
//
// 【パターン A】エラーメッセージベース検出
//   脆弱性の発生時に特徴的なエラーメッセージがレスポンスに含まれる場合。
//   例: SQL エラー, スタックトレース, LDAP エラー
//   → DETECTION_PATTERNS を定義してレスポンスボディを正規表現マッチ
//
// 【パターン B】ペイロード反射検出
//   送信したペイロードがレスポンスにそのまま現れる場合。
//   例: Reflected XSS, SSTI の数式評価結果
//   → payload 文字列がレスポンスに含まれるかチェック
//   → const reflected = allExchanges.filter(ex => ex.response.body?.includes(payload))
//
// 【パターン C】Diff ベース検出
//   安全な入力と危険な入力のレスポンス差分から検出する場合。
//   例: Boolean-based SQLi, NoSQL boolean
//   → safePayload と unsafePayload の2回の replay 結果を比較
//   → this.compareDiff(safeResult.exchange, unsafeResult.exchange, scenario.diffStrategy)
//
// 【パターン D】ヘッダ分析
//   レスポンスヘッダに脆弱性の痕跡が現れる場合。
//   例: CRLF インジェクション、HTTP ヘッダインジェクション
//   → ex.response.headers を分析
//
// 【パターン E】ステータスコード分析
//   特定のステータスコードが脆弱性を示す場合。
//   例: 500 エラーの詳細メッセージ、403 バイパス
//   → ex.response.status をチェック

// ── コンストラクタオプション (オプショナル) ──────────────────────
//
// プラグインが設定可能なオプションを受け取る場合:
//
// export default class CustomPlugin extends MutationFilteredSignaturePlugin {
//   readonly name = "signature:custom-example";
//   protected readonly groups = [SignatureGroupId("custom")];
//   protected readonly mutationTypes = [BuiltinMutationType.AppendValue] as const;
//   private opts: { threshold?: number; extraPatterns?: string[] };
//
//   constructor(options?: { threshold?: number; extraPatterns?: string[] }) {
//     super();
//     this.opts = options ?? {};
//   }
//
//   protected async runAudit(context: RunAuditContext) {
//     const threshold = this.opts.threshold ?? 0.5;
//     // ...
//   }
// }
//
// コンストラクタオプションを使用する場合、config.json に明示的に
// プラグインを列挙し、{ file, options } 形式で指定する（autoload の自動検出では
// オプションを渡せないため）:
// {
//   "file": "./.gevanni/plugins/autoload/custom-example.ts",
//   "options": { "threshold": 0.8, "extraPatterns": ["custom error"] }
// }
