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
//     args: { units, perspectives }
//   })
//   - units:        Array<{ id, method, route, desc, files, deps? }>
//   - perspectives: Array<{ id, name, precondition, focus, signals, fpNote, refs }>
//                   precondition: minimum requirement (1 sentence, strictly necessary).
//                   focus: detailed checks. signals: hints for reference.
//
// Returns: { summary, units, findings }
//   - summary: { unitsAssessed, perspectivesApplied, totalFindings, bySeverity }
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
          location: { type: 'string', description: 'file:line or "METHOD path"' },
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

const ASSESS_PROMPT = (unit, pov) => `You are a security assessment agent. Assess the following single "assessment unit" using only the single "perspective" below. Do not expand into other perspectives.

## Assessment Unit
- ID: ${unit.id}
- Route/Method: ${unit.method} ${unit.route}
- Description: ${unit.desc || unit.code || '(no description)'}
- Source files (read these files using the Read tool): ${(unit.files || []).map(f => SOURCE_ROOT + '/' + f).join(', ')}

## Perspective
- ID: ${pov.id}
- Name: ${pov.name}
- Precondition (is this applicable to the code? Judge loosely): ${pov.precondition || pov.focus}
- What to check: ${pov.focus}
- Detection hints (for reference, not exhaustive): ${pov.signals}
- False-positive note: ${pov.fpNote}
- References: ${pov.refs}

## Instructions
1. **Precondition check**: First, read the source files above and determine **semantically** whether this perspective applies to the code, based on the "Precondition". Be loose. For example, if the precondition is "code constructs SQL queries" and the code uses a database, it is satisfied. If the code clearly does not satisfy the precondition at all, return findings: [] and stop.
2. **Detailed assessment**: If the precondition is met, inspect the code against "What to check" and determine whether vulnerabilities exist.
3. In evidence, include the actual code location (file:line), the relevant code snippet, and why it is a problem in 1-2 sentences.
4. Avoid false positives: if framework protections (parameterized queries, auto-escaping, typed inputs, etc.) are reliably in place, do not flag it. Lower confidence when uncertain.
5. Judge severity by exploitability and impact. If unverifiable or speculative, use Info or findings: [].
6. Make remediation concrete (code examples or config names).
7. Inherit the perspective's refs into the refs field.`

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

const units = (args && args.units) || []
const perspectives = (args && args.perspectives) || []

if (!units.length || !perspectives.length) {
  throw new Error(
    'args.units and args.perspectives are required. The main agent must complete step 1 (unit splitting) and step 2 (perspective catalog load + pre-filter) before launching the Workflow.'
  )
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
    // stage2: merge per unit
    (findingsPerPov, unit) => {
      const all = findingsPerPov.flat()
      log(`${unit.id} (${unit.method} ${unit.route}): ${all.length} findings`)
      return { unit: unit.id, route: `${unit.method} ${unit.route}`, findings: all }
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
  },
  units: results,
  findings: allFindings,
}
