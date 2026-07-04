// sast Dynamic Workflow テンプレート
//
// 役割: 「診断ユニット × 観点」の直積でサブエージェントを fan-out し、
//       構造化 FINDINGS を集約して返す。
//
// 呼び方(メインエージェント):
//   Workflow({
//     scriptPath: "<絶対パス>/.claude/skills/sast/workflow-template.js",
//     args: { units, perspectives }
//   })
//   - units:        手順1の出力. Array<{ id, method, route, code, deps? }>
//   - perspectives: 手順2の出力(事前フィルタ済み). Array<{ id, name, focus, signals, fpNote, refs }>
//                    優先度順(Critical寄りを先)に並べること。規模超過時に優先度で間引く。
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

const ASSESS_PROMPT = (unit, pov) => `あなたはセキュリティ診断エージェント。以下の「1つの診断ユニット」を「1つの観点」でのみ審査する。他の観点には踏み込まない。

## 診断ユニット
- ID: ${unit.id}
- ルート/メソッド: ${unit.method} ${unit.route}
- コード:
\`\`\`
${unit.code}
\`\`\`
- 依存先(参照のみ、深追いしない): ${(unit.deps || []).join(', ') || '(なし)'}

## 観点
- ID: ${pov.id}
- 名前: ${pov.name}
- チェック内容: ${pov.focus}
- 静的解析シグナル: ${pov.signals}
- False-Positive 注意: ${pov.fpNote}
- 参照: ${pov.refs}

## 指示
1. この観点に関連する問題「のみ」を報告する。該当しなければ findings: [] を返す。
2. evidence には実際のコード箇所と該当断文を含め、なぜ問題かを1-2文で書く。
3. FP を避ける: フレームワークの保護(パラメータ化クエリ、自動エスケープ、型付き入力、ルーターのバリデーション等)が効いている場合は問題としない。判断に迷う場合は confidence を下げる。
4. severity は悪用可能性と影響で判定する。実証不能・推測なら Info または findings:[]。
5. remediation は具体的に(コード例や設定名)。
6. refs には観点の refs を引き継ぐ。`

// 規模の安全弁。units × perspectives が上限を超える場合、優先度順に並んだ
// perspectives を先頭から残す(No-silent-caps: log で明示)。
const capPerspectives = (perspectives, unitsLen) => {
  const HARD_AGENT_CAP = 1000
  const estimated = unitsLen * perspectives.length
  if (estimated <= HARD_AGENT_CAP) return { perspectives, dropped: 0 }
  const keep = Math.max(1, Math.floor(HARD_AGENT_CAP / unitsLen))
  const dropped = perspectives.length - keep
  log(`規模超過: ユニット×観点=${estimated} > 上限${HARD_AGENT_CAP}。観点を ${perspectives.length} → ${keep} に優先度で間引く(優先度順前提)。`)
  return { perspectives: perspectives.slice(0, keep), dropped }
}

phase('診断')

const units = (args && args.units) || []
const perspectives = (args && args.perspectives) || []

if (!units.length || !perspectives.length) {
  throw new Error(
    'args.units と args.perspectives が必要です。メインエージェントが手順1(ユニット分割)と手順2(観点カタログ読込+事前フィルタ)を済ませてから Workflow を起動してください。'
  )
}

log(`ユニット ${units.length} × 観点 ${perspectives.length} = 最大 ${units.length * perspectives.length} エージェント (concurrency 16)`)
const { perspectives: povs, dropped } = capPerspectives(perspectives, units.length)

const results = await pipeline(
  units,
  // stage1: 1ユニットを全観点で並列診断
  (unit) =>
    parallel(
      povs.map((pov) => () =>
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

phase('統合')

const allFindings = results.flatMap((r) => r.findings)
const bySeverity = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 }
for (const f of allFindings) bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1

log(
  `統合完了: 計 ${allFindings.length} 件 — Critical=${bySeverity.Critical} High=${bySeverity.High} Medium=${bySeverity.Medium} Low=${bySeverity.Low} Info=${bySeverity.Info}` +
    (dropped ? ` (規模超過で観点 ${dropped} 件を間引き)` : '')
)

return {
  summary: {
    unitsAssessed: units.length,
    perspectivesApplied: povs.length,
    perspectivesDropped: dropped,
    totalFindings: allFindings.length,
    bySeverity,
  },
  units: results,
  findings: allFindings,
}
