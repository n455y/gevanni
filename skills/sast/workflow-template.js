// sast Dynamic Workflow template
//
// Purpose: Fan out sub-agents across the cartesian product of "assessment units × perspectives"
//          and aggregate structured FINDINGS.
//
// Filtering strategy:
//   No pre-filtering by tags. Every perspective runs against every unit.
//   Each agent reads the actual code and checks whether the perspective's
//   precondition is satisfied. If not, returns findings: [].
//   If scale exceeds the limit, perspectives are split into batches and run
//   sequentially (nothing is silently dropped — No-silent-caps).
//
// Usage (from the main agent):
//   Workflow({
//     scriptPath: "<absolute-path>/.claude/skills/sast/workflow-template.js",
//     args: { units, perspectives, mode, sourceFiles }
//   })
//   - units:        Array<{ id, method, route, desc, files, deps? }>
//                   Required in standard mode. Not used in fast mode.
//   - perspectives: Array<{ id, name, precondition, focus, signals, fpNote, refs }>
//                   precondition: minimum requirement (1 sentence, strictly necessary).
//                   focus: detailed checks. signals: hints for reference.
//   - mode:         'standard' (default) | 'fast'.
//                   standard: fan out across units × perspectives (precision-first).
//                   fast: one agent per perspective scanning the whole source
//                         (faster/cheaper, lower precision, more FPs).
//   - sourceFiles:  Array<relative-path> (fast mode only, optional).
//                   Target source files to scan. If omitted in fast mode, each
//                   agent self-discovers files under SOURCE_ROOT (excluding EXCLUDE_GLOBS).
//
// Returns: { summary, units, findings }
//   - summary: { unitsAssessed, perspectivesApplied, perspectivesDropped,
//                totalFindings, bySeverity, mode, scannedFiles? }
//       standard: unitsAssessed = units.length, scannedFiles omitted.
//       fast:     unitsAssessed = null, scannedFiles = sourceFiles.length.
//                 units collapses to a single pseudo-unit "WHOLE".
//   - units:   Array<{ unit, route, findings }>  (findings per unit)
//   - findings: flat array of all findings
//
// Note: Date.now/Math.random/new Date are not available inside Workflow scripts.
//       Add timestamps etc. on the main agent side.

export const meta = {
  name: 'sast',
  description: 'White-box security assessment: fan out (assessment unit × perspective) and merge findings',
  phases: [
    { title: 'Assess', detail: 'Parallel assessment across unit × perspective' },
    { title: 'Merge', detail: 'Aggregate and return findings' },
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
          povId: { type: 'string', description: 'Perspective ID. Pass through the input perspective.id as-is.' },
          severity: { type: 'string', enum: ['Critical', 'High', 'Medium', 'Low', 'Info'] },
          confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
          title: { type: 'string', description: 'Short title of the finding' },
          location: { type: 'string', description: 'file:line (required). If attributable to an endpoint, also set unitId/route.' },
          unitId: { type: 'string', description: 'Assessment unit ID (e.g. "U03"). Standard mode: always set. Fast mode: best-effort — set only when the finding can be attributed to a known endpoint; otherwise omit.' },
          route: { type: 'string', description: '"METHOD path" of the relevant endpoint. Same optional semantics as unitId.' },
          evidence: { type: 'string', description: 'Relevant code snippet + why it is a problem (1-2 sentences)' },
          remediation: { type: 'string', description: 'Concrete fix (code example / config name)' },
          refs: { type: 'string', description: 'ASVS/WSTG/CS references. Inherit from the perspective refs.' },
        },
        required: ['povId', 'severity', 'confidence', 'title', 'location', 'evidence', 'remediation', 'refs'],
      },
    },
  },
  required: ['findings'],
}

const SOURCE_ROOT = '/workspace'

// Directories/files to skip when scanning the whole source in fast mode.
const EXCLUDE_GLOBS = 'node_modules, .git, dist, build, .next, vendor, target, __pycache__, *.min.js, *.map, package-lock.json, yarn.lock, .terraform, coverage'

// Perspective + Instructions block shared by both modes.
const PERSPECTIVE_BLOCK = (pov) => `## Perspective
- ID: ${pov.id}
- Name: ${pov.name}
- Precondition (is this applicable to the code? Judge loosely): ${pov.precondition || pov.focus}
- What to check: ${pov.focus}
- Detection hints (for reference, not exhaustive): ${pov.signals}
- False-positive note: ${pov.fpNote}
- References: ${pov.refs}`

const INSTRUCTIONS_BLOCK = (readInstruction, attributionInstruction) => `## Instructions
1. **Precondition check**: First, ${readInstruction} and determine **semantically** whether this perspective applies to the code, based on the "Precondition". Be loose. For example, if the precondition is "code constructs SQL queries" and the code uses a database, it is satisfied. If the code clearly does not satisfy the precondition at all, return findings: [] and stop.
2. **Detailed assessment**: If the precondition is met, inspect the code against "What to check" and determine whether vulnerabilities exist.
3. In evidence, include the actual code location (file:line), the relevant code snippet, and why it is a problem in 1-2 sentences.
4. Avoid false positives: if framework protections (parameterized queries, auto-escaping, typed inputs, etc.) are reliably in place, do not flag it. Lower confidence when uncertain.
5. Judge severity by exploitability and impact. If unverifiable or speculative, use Info or findings: [].
6. Make remediation concrete (code examples or config names).
7. Inherit the perspective's refs into the refs field.
8. **Attribution**: ${attributionInstruction}`

const ASSESS_PROMPT = (unit, pov) => `You are a security assessment agent. Assess the following single "assessment unit" using only the single "perspective" below. Do not expand into other perspectives.

## Assessment Unit
- ID: ${unit.id}
- Route/Method: ${unit.method} ${unit.route}
- Description: ${unit.desc || unit.code || '(no description)'}
- Source files (read these files using the Read tool): ${(unit.files || []).map(f => SOURCE_ROOT + '/' + f).join(', ')}

${PERSPECTIVE_BLOCK(pov)}

${INSTRUCTIONS_BLOCK(
  'read the source files above',
  'This finding belongs to the assessment unit above — the main agent will attach unitId/route automatically; you do not need to set them.'
)}`

// Fast-mode prompt: one agent = one perspective, scanning the whole source.
const ASSESS_PROMPT_FAST = (pov, sourceFiles) => {
  const fileList = Array.isArray(sourceFiles) && sourceFiles.length
    ? sourceFiles.map(f => SOURCE_ROOT + '/' + f).join('\n  - ')
    : null
  const sourceBlock = fileList
    ? `## Source files to scan (read the relevant parts with the Read tool)
  - ${fileList}
  - Skip any path matching: ${EXCLUDE_GLOBS}`
    : `## Source to scan
  - Recursively read/glob files under ${SOURCE_ROOT} using the Read/Glob/Grep tools and scan the whole source for this perspective.
  - Skip any path matching: ${EXCLUDE_GLOBS}.`

  return `You are a security assessment agent running in **fast mode**. Scan the **whole source code** below using only the single "perspective" provided. Do not expand into other perspectives. Read only the relevant parts of each file (no need to read every file in full); after the precondition check, focus on files whose content matches this perspective's signals.

${sourceBlock}

${PERSPECTIVE_BLOCK(pov)}

${INSTRUCTIONS_BLOCK(
  'scan the source code above',
  'When a finding can be attributed to a known endpoint, set unitId (e.g. "U03") and route ("METHOD path") to the most strongly related endpoint. If attribution is ambiguous or unknown, omit unitId/route and rely on location (file:line) only — do not fabricate attribution.'
)}`
}

// ── Perspective batch splitting ──────────────────────────────────────────
// No pre-skipping. All perspectives run against all units.
// Each agent reads the code and decides whether the Preconditions are met.
// If units × perspectives exceeds the limit (1000), perspectives are split
// into batches and run sequentially. Batch size = floor(1000 / units.length).
// Nothing is silently dropped (No-silent-caps).
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

phase('Assess')

const mode = (args && args.mode === 'fast') ? 'fast' : 'standard'
const units = (args && args.units) || []
const perspectives = (args && args.perspectives) || []

if (!perspectives.length) {
  throw new Error(
    'args.perspectives is required. The main agent must complete step 2 (perspective catalog load + pre-filter) before launching the Workflow.'
  )
}
if (mode === 'standard' && !units.length) {
  throw new Error(
    'args.units is required in standard mode. The main agent must complete step 1 (unit splitting) before launching the Workflow. (Use args.mode: "fast" to skip unit splitting.)'
  )
}

// ── Fast mode: one agent per perspective, scanning the whole source ───────
// No batch splitting: perspectives (max 133) never exceed the 1000 agent cap.
if (mode === 'fast') {
  const sourceFiles = (args && Array.isArray(args.sourceFiles)) ? args.sourceFiles : null
  log(`Fast mode: ${perspectives.length} perspectives × whole-source scan = max ${perspectives.length} agents (concurrency 16, no batching needed)${sourceFiles ? `, ${sourceFiles.length} source files provided` : ', agent self-discovery of source files'}`)

  const fastRaw = await parallel(
    perspectives.map((pov) => () =>
      agent(ASSESS_PROMPT_FAST(pov, sourceFiles), {
        label: pov.id,
        phase: 'Assess',
        schema: FINDINGS_SCHEMA,
      })
        .then((r) => (r && Array.isArray(r.findings) ? r.findings : []))
        .catch(() => []) // don't abort the whole run for one perspective failure
    )
  )
  const fastFindings = fastRaw.flat()

  phase('Merge')

  const bySeverity = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 }
  for (const f of fastFindings) bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1

  log(`Merge complete: ${fastFindings.length} total — Critical=${bySeverity.Critical} High=${bySeverity.High} Medium=${bySeverity.Medium} Low=${bySeverity.Low} Info=${bySeverity.Info}`)

  return {
    summary: {
      unitsAssessed: null,
      perspectivesApplied: perspectives.length,
      perspectivesDropped: 0,
      totalFindings: fastFindings.length,
      bySeverity,
      mode: 'fast',
      scannedFiles: sourceFiles ? sourceFiles.length : null,
    },
    units: [{ unit: 'WHOLE', route: '(whole source)', findings: fastFindings }],
    findings: fastFindings,
  }
}

const batches = splitPerspectives(perspectives, units.length)
const totalAgents = units.length * perspectives.length
if (batches.length > 1) {
  log(`Scale exceeded: ${units.length} units × ${perspectives.length} perspectives = ${totalAgents} > limit 1000. Splitting into ${batches.length} batches for sequential execution (batch size: ${batches[0].perspectives.length} perspectives/batch)`)
}
log(`Units ${units.length} × perspectives ${perspectives.length} = max ${totalAgents} agents (concurrency 16${batches.length > 1 ? `, ${batches.length} sequential batches` : ''})`)

// Run batches sequentially, accumulating findings per unit
const unitFindingsMap = Object.fromEntries(
  units.map((u) => [u.id, { unit: u.id, route: `${u.method} ${u.route}`, findings: [] }])
)

for (const batch of batches) {
  if (batches.length > 1) {
    log(`Batch ${batch.batchNum}/${batch.totalBatches}: assessing perspectives ${batch.perspectives[0].id}–${batch.perspectives[batch.perspectives.length - 1].id} (${batch.perspectives.length} items)...`)
  }

  const batchResults = await pipeline(
    units,
    // stage1: run all perspectives in the batch against each unit. Agents self-check preconditions by reading the code.
    (unit) => parallel(
      batch.perspectives.map((pov) => () =>
        agent(ASSESS_PROMPT(unit, pov), {
          label: `${unit.id}:${pov.id}`,
          phase: 'Assess',
          schema: FINDINGS_SCHEMA,
        })
          .then((r) => (r && Array.isArray(r.findings) ? r.findings : []))
          .catch(() => []) // don't abort the whole run for one perspective failure
      )
    ),
    // stage2: merge per unit — attach unitId/route to every finding (schema allows them as optional)
    (findingsPerPov, unit) => {
      const all = findingsPerPov.flat()
      const route = `${unit.method} ${unit.route}`
      for (const f of all) {
        f.unitId = unit.id
        f.route = route
      }
      log(`${unit.id} (${unit.method} ${unit.route}): ${all.length} findings`)
      return { unit: unit.id, route, findings: all }
    }
  )

  // Accumulate batch results per unit
  for (const r of batchResults) {
    unitFindingsMap[r.unit].findings.push(...r.findings)
  }
}

phase('Merge')

const results = Object.values(unitFindingsMap)
const allFindings = results.flatMap((r) => r.findings)
const bySeverity = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 }
for (const f of allFindings) bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1

log(
  `Merge complete: ${allFindings.length} total — Critical=${bySeverity.Critical} High=${bySeverity.High} Medium=${bySeverity.Medium} Low=${bySeverity.Low} Info=${bySeverity.Info}` +
    (batches.length > 1 ? ` (${batches.length} sequential batches)` : '')
)

return {
  summary: {
    unitsAssessed: units.length,
    perspectivesApplied: perspectives.length,
    perspectivesDropped: 0,
    totalFindings: allFindings.length,
    bySeverity,
    mode: 'standard',
  },
  units: results,
  findings: allFindings,
}
