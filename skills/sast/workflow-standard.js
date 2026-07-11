// sast standard-mode Dynamic Workflow template
//
// Purpose: Pair-driven fan-out. Receives a list of (unit × perspective) pairs
//          pre-built by the main agent (after README-area exclusion), and runs
//          one sub-agent per pair. The prompt places the PERSPECTIVE block first
//          and the UNIT block second, then sorts pairs by povId so that adjacent
//          agents share the same perspective prefix → prompt-cache friendly.
//
//          No precondition self-check inside agents (README-area exclusion is
//          already done by the main agent's dedicated sub-agent in Step 2).
//
//          This template handles <= 1000 pairs. If pairs.length > 1000, the
//          main agent splits pairs into chunks and invokes this Workflow
//          multiple times sequentially (workflow self-recursion is limited to
//          1 level, so splitting MUST happen on the main-agent side).
//
// Usage:
//   Workflow({
//     scriptPath: "<absolute-path>/skills/sast/workflow-standard.js",
//     args: { pairs, units, perspectives }
//   })
//   - pairs:        Array<{ unitId, povId }>  (after README-area exclusion)
//   - units:        Array<{ id, method, route, desc, files, deps? }>
//   - perspectives: Array<{ id, name, precondition, focus, signals, fpNote, refs }>
//
// Returns: { summary, units, findings }

export const meta = {
  name: 'sast-standard',
  description: 'Pair-driven standard scan: one agent per (unit × perspective) pair',
  phases: [
    { title: 'Assess', detail: 'One agent per unit×perspective pair (perspective-first prompt)' },
    { title: 'Merge', detail: 'Aggregate findings per unit and return' },
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
          location: { type: 'string', description: 'file:line (required).' },
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

const PERSPECTIVE_BLOCK = (pov) => `## Perspective
- ID: ${pov.id}
- Name: ${pov.name}
- Precondition (reference info on what this perspective assumes): ${pov.precondition || pov.focus}
- What to check: ${pov.focus}
- Detection hints (for reference, not exhaustive): ${pov.signals}
- False-positive note: ${pov.fpNote}
- References: ${pov.refs}`

const UNIT_BLOCK = (unit) => `## Assessment Unit
- ID: ${unit.id}
- Route/Method: ${unit.method} ${unit.route}
- Description: ${unit.desc || unit.code || '(no description)'}
- Source files (read these files using the Read tool): ${(unit.files || []).map(f => SOURCE_ROOT + '/' + f).join(', ')}
- Deps (for context): ${(unit.deps || []).map(f => SOURCE_ROOT + '/' + f).join(', ') || '(none)'}`

const INSTRUCTIONS_BLOCK = `## Instructions
1. Inspect the code in the Assessment Unit against the perspective's "What to check" and determine whether vulnerabilities exist.
2. In evidence, include the actual code location (file:line), the relevant code snippet, and why it is a problem in 1-2 sentences.
3. Avoid false positives: if framework protections (parameterized queries, auto-escaping, typed inputs, etc.) are reliably in place, do not flag it. Lower confidence when uncertain.
4. Judge severity by exploitability and impact. If unverifiable or speculative, use Info or findings: [].
5. Make remediation concrete (code examples or config names).
6. Inherit the perspective's Refs into the refs field.`

const ASSESS_PROMPT = (unit, pov) => `You are a security assessment agent. Assess the unit below using only the single perspective provided. Do not expand into other perspectives.

${PERSPECTIVE_BLOCK(pov)}

${UNIT_BLOCK(unit)}

${INSTRUCTIONS_BLOCK}`

phase('Assess')

const pairs = (args && args.pairs) || []
const units = (args && args.units) || []
const perspectives = (args && args.perspectives) || []

if (!pairs.length) {
  throw new Error(
    'args.pairs is required (Step 2 output: unit×perspective pair list after README-area exclusion).'
  )
}
if (!units.length) {
  throw new Error('args.units is required in standard mode (Step 1 output: unit splitting).')
}
if (!perspectives.length) {
  throw new Error(
    'args.perspectives is required. The main agent must complete step 2 (perspective catalog) before launching the Workflow.'
  )
}

// Build lookup maps for resolving unit/perspective objects by id.
const unitById = Object.fromEntries(units.map((u) => [u.id, u]))
const povById = Object.fromEntries(perspectives.map((p) => [p.id, p]))

// Validate every pair resolves; collect (but do not silently drop) unresolved pairs.
const unresolved = pairs.filter(({ unitId, povId }) => !unitById[unitId] || !povById[povId])
if (unresolved.length) {
  throw new Error(
    `Unresolved pairs (unitId/povId not found in units/perspectives): ${unresolved.length}. First few: ${JSON.stringify(unresolved.slice(0, 3))}`
  )
}

// Sort pairs by povId (then unitId) so adjacent agents share the same perspective
// prefix → prompt-cache friendly. localeCompare gives a stable ordering.
const sortedPairs = pairs.slice().sort((a, b) => {
  const c = String(a.povId).localeCompare(String(b.povId))
  return c !== 0 ? c : String(a.unitId).localeCompare(String(b.unitId))
})

log(`Standard mode: ${sortedPairs.length} unit×perspective pairs = ${sortedPairs.length} agents (concurrency 16). Sorted by povId for cache efficiency.`)

const rawFindings = await parallel(
  sortedPairs.map(({ unitId, povId }) => () => {
    const unit = unitById[unitId]
    const pov = povById[povId]
    return agent(ASSESS_PROMPT(unit, pov), {
      label: `${povId}:${unitId}`,
      phase: 'Assess',
      schema: FINDINGS_SCHEMA,
    })
      .then((r) => (r && Array.isArray(r.findings) ? r.findings : []))
      .catch(() => [])
  })
)

phase('Merge')

// Flatten, attach unitId/route to every finding, aggregate per unit.
const unitFindingsMap = Object.fromEntries(
  units.map((u) => [u.id, { unit: u.id, route: `${u.method} ${u.route}`, findings: [] }])
)

const allFindings = []
for (const findingsForPair of rawFindings) {
  for (const f of findingsForPair) {
    allFindings.push(f)
  }
}

// Attach attribution. povId already set by the agent; we attach unitId/route via a
// pair→unit map. Because findings come back per-pair (same order as sortedPairs),
// we iterate in parallel rather than map by povId (a unit may have multiple pairs).
for (let i = 0; i < sortedPairs.length; i++) {
  const { unitId } = sortedPairs[i]
  const route = unitFindingsMap[unitId] ? unitFindingsMap[unitId].route : ''
  for (const f of rawFindings[i]) {
    f.unitId = unitId
    f.route = route
    if (unitFindingsMap[unitId]) unitFindingsMap[unitId].findings.push(f)
  }
}

const bySeverity = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 }
for (const f of allFindings) bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1

log(`Merge complete: ${allFindings.length} total — Critical=${bySeverity.Critical} High=${bySeverity.High} Medium=${bySeverity.Medium} Low=${bySeverity.Low} Info=${bySeverity.Info}`)

return {
  summary: {
    unitsAssessed: units.length,
    perspectivesApplied: perspectives.length,
    perspectivesDropped: 0,
    totalFindings: allFindings.length,
    bySeverity,
    mode: 'standard',
  },
  units: Object.values(unitFindingsMap),
  findings: allFindings,
}
