// sast Dynamic Workflow テンプレート
//
// 役割: 「診断ユニット × 観点」の直積でサブエージェントを fan-out し、
//       構造化 FINDINGS を集約して返す。
//
// フィルタリング戦略:
//   事前のタグフィルタは行わない。全観点を全ユニットで実行する。
//   各エージェントが実際のコードを読み、観点の precondition を
//   満たすかどうかを判断する。満たさなければ findings: []。
//   前提条件を満たさなければ findings: [] を返す。
//   規模超過時は観点をバッチ分割し逐次実行する（切り捨てなし、No-silent-caps）。
//
// 呼び方(メインエージェント):
//   Workflow({
//     scriptPath: "<絶対パス>/.claude/skills/sast/workflow-template.js",
//     args: { units, perspectives }
//   })
//   - units:        Array<{ id, method, route, desc, files, deps? }>
//   - perspectives: Array<{ id, name, precondition, focus, signals, fpNote, refs }>
//                   precondition: 前提条件（1文、絶対に必要な条件のみ）。
//                   focus: 詳細なチェック内容。signals: 参考ヒント。
//
// 戻り値: { summary, units, findings }
//   - summary: { unitsAssessed, perspectivesApplied, totalFindings, bySeverity }
//   - units:   Array<{ unit, route, findings }>  (ユニットごとの発見)
//   - findings: 全発見のフラット配列
//
// 注意: Workflow スクリプト内では Date.now/Math.random/new Date は使えない。
//       タイムスタンプ等はメインエージェント側で付与すること。

export const meta = {
  name: 'sast',
  description: 'White-box security assessment: fan out (diagnostic unit × perspective) and merge findings',
  phases: [
    { title: '診断', detail: 'unit × perspective の直積を並列診断' },
    { title: '統合', detail: 'findings を集約して返却' },
  ],
}

const FINDINGS_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        properties: {
          povId: { type: 'string', description: '観点ID。入力の perspective.id をそのまま返す' },
          severity: { type: 'string', enum: ['Critical', 'High', 'Medium', 'Low', 'Info'] },
          confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
          title: { type: 'string', description: '発見の短いタイトル' },
          location: { type: 'string', description: 'file:line または "METHOD path"' },
          evidence: { type: 'string', description: '該当コード断片 + なぜ問題か(1-2文)' },
          remediation: { type: 'string', description: '具体的な修正(コード例/設定名)' },
          refs: { type: 'string', description: 'ASVS/WSTG/CS 参照。観点の refs を引き継ぐ' },
        },
        required: ['povId', 'severity', 'confidence', 'title', 'location', 'evidence', 'remediation', 'refs'],
      },
    },
  },
  required: ['findings'],
}

const SOURCE_ROOT = '/workspace'

const ASSESS_PROMPT = (unit, pov) => `あなたはセキュリティ診断エージェント。以下の「1つの診断ユニット」を「1つの観点」でのみ審査する。他の観点には踏み込まない。

## 診断ユニット
- ID: ${unit.id}
- ルート/メソッド: ${unit.method} ${unit.route}
- 説明: ${unit.desc || unit.code || '(no description)'}
- ソースファイル（このファイルを Read で実際に読むこと）: ${(unit.files || []).map(f => SOURCE_ROOT + '/' + f).join(', ')}

## 観点
- ID: ${pov.id}
- 名前: ${pov.name}
- 前提条件（このコードに適用可能か？大雑把に判断せよ）: ${pov.precondition || pov.focus}
- チェック内容: ${pov.focus}
- 検出のヒント（参考。これに限定されない）: ${pov.signals}
- False-Positive 注意: ${pov.fpNote}
- 参照: ${pov.refs}

## 指示
1. **前提条件チェック**: まず上記のソースファイルを Read し、「前提条件」に照らして、この観点がこのコードに適用可能かを**意味的に**判断せよ。大雑把でよい。例えば「SQLクエリを構築している」が前提条件なら、コードがDBを使っていれば満たす。コードが前提条件を全く満たさないと判断した場合は findings: [] を返して終了。
2. **詳細診断**: 前提条件を満たす場合、「チェック内容」に沿ってコードを精査し、脆弱性の有無を判定せよ。
3. evidence には実際のコード箇所（file:line）と該当コード断片を含め、なぜ問題かを1-2文で書く。
4. FP を避ける: フレームワークの保護(パラメータ化クエリ、自動エスケープ、型付き入力等)が確実に効いている場合は問題としない。判断に迷う場合は confidence を下げる。
5. severity は悪用可能性と影響で判定する。実証不能・推測なら Info または findings:[]。
6. remediation は具体的に(コード例や設定名)。
7. refs には観点の refs を引き継ぐ。`

// ── 観点バッチ分割 ──────────────────────────────────────────────────
// 事前スキップは行わない。全観点を全ユニットで実行する。
// 各エージェントが Preconditions を満たすかコードを読んで判断する。
// units × perspectives が上限(1000)を超える場合、観点をバッチ分割し
// 逐次実行する。バッチサイズ = floor(1000 / units.length)。
// 切り捨ては行わない（No-silent-caps）。
const splitPerspectives = (perspectives, unitsLen) => {
  const HARD_AGENT_CAP = 1000
  const maxPerBatch = Math.max(1, Math.floor(HARD_AGENT_CAP / unitsLen))
  if (perspectives.length <= maxPerBatch) {
    return [{ perspectives, batchNum: 1, totalBatches: 1 }]
  }
  const batches = []
  for (let i = 0; i < perspectives.length; i += maxPerBatch) {
    batches.push({
      perspectives: perspectives.slice(i, i + maxPerBatch),
      batchNum: Math.floor(i / maxPerBatch) + 1,
      totalBatches: Math.ceil(perspectives.length / maxPerBatch),
    })
  }
  return batches
}

phase('診断')

const units = (args && args.units) || []
const perspectives = (args && args.perspectives) || []

if (!units.length || !perspectives.length) {
  throw new Error(
    'args.units と args.perspectives が必要です。メインエージェントが手順1(ユニット分割)と手順2(観点カタログ読込+事前フィルタ)を済ませてから Workflow を起動してください。'
  )
}

const batches = splitPerspectives(perspectives, units.length)
const totalAgents = units.length * perspectives.length
if (batches.length > 1) {
  log(`規模超過: ${units.length}ユニット × ${perspectives.length}観点 = ${totalAgents} > 上限1000。${batches.length}バッチに分割して逐次実行します（バッチサイズ: ${batches[0].perspectives.length}観点/バッチ）`)
}
log(`ユニット ${units.length} × 観点 ${perspectives.length} = 最大 ${totalAgents} エージェント (concurrency 16${batches.length > 1 ? `, ${batches.length}バッチ逐次` : ''})`)

// バッチを逐次実行し、ユニット単位で所見を蓄積
const unitFindingsMap = Object.fromEntries(
  units.map((u) => [u.id, { unit: u.id, route: `${u.method} ${u.route}`, findings: [] }])
)

for (const batch of batches) {
  if (batches.length > 1) {
    log(`バッチ ${batch.batchNum}/${batch.totalBatches}: 観点 ${batch.perspectives[0].id}〜${batch.perspectives[batch.perspectives.length - 1].id} (${batch.perspectives.length}件) を診断中...`)
  }

  const batchResults = await pipeline(
    units,
    // stage1: バッチ内の全観点を全ユニットで実行。エージェント自身がコードを読んで前提条件をチェックする
    (unit) => parallel(
      batch.perspectives.map((pov) => () =>
        agent(ASSESS_PROMPT(unit, pov), {
          label: `${unit.id}:${pov.id}`,
          phase: '診断',
          schema: FINDINGS_SCHEMA,
        })
          .then((r) => (r && Array.isArray(r.findings) ? r.findings : []))
          .catch(() => []) // 1観点の失敗で全体は止めない
      )
    ),
    // stage2: ユニット単位でマージ
    (findingsPerPov, unit) => {
      const all = findingsPerPov.flat()
      log(`${unit.id} (${unit.method} ${unit.route}): ${all.length} 件`)
      return { unit: unit.id, route: `${unit.method} ${unit.route}`, findings: all }
    }
  )

  // バッチ結果をユニット別に蓄積
  for (const r of batchResults) {
    unitFindingsMap[r.unit].findings.push(...r.findings)
  }
}

phase('統合')

const results = Object.values(unitFindingsMap)
const allFindings = results.flatMap((r) => r.findings)
const bySeverity = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 }
for (const f of allFindings) bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1

log(
  `統合完了: 計 ${allFindings.length} 件 — Critical=${bySeverity.Critical} High=${bySeverity.High} Medium=${bySeverity.Medium} Low=${bySeverity.Low} Info=${bySeverity.Info}` +
    (batches.length > 1 ? ` (${batches.length}バッチ逐次実行)` : '')
)

return {
  summary: {
    unitsAssessed: units.length,
    perspectivesApplied: perspectives.length,
    perspectivesDropped: 0,
    totalFindings: allFindings.length,
    bySeverity,
  },
  units: results,
  findings: allFindings,
}
