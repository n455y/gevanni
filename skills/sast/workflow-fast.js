// sast fast-mode Dynamic Workflow template
//
// Purpose: One agent per perspective, each scanning the whole source.
//          Fast/cheap, lower precision, more FPs. Perspectives max 133 < 1000,
//          so no batch splitting is needed.
//
// Usage:
//   Workflow({
//     scriptPath: "<absolute-path>/skills/sast/workflow-fast.js",
//     args: { perspectives, sourceFiles }
//   })
//   - perspectives: Array<{ id, name, precondition, focus, signals, fpNote, refs }>
//   - sourceFiles:  Array<relative-path> (optional). If omitted, each agent
//                   self-discovers files under SOURCE_ROOT (excluding EXCLUDE_GLOBS).
//
// Returns: { summary, units, findings }

export const meta = {
  name: 'sast-fast',
  description: 'Fast white-box scan: one agent per perspective over the whole source',
  phases: [
    { title: 'Assess', detail: 'One agent per perspective scanning whole source' },
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
          unitId: { type: 'string', description: 'Assessment unit ID (e.g. "U03"). Best-effort: set only when the finding can be attributed to a known endpoint; otherwise omit.' },
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

const PERSPECTIVE_BLOCK = (pov) => `## Perspective
- ID: ${pov.id}
- Name: ${pov.name}
- Precondition (reference info on what this perspective assumes): ${pov.precondition || pov.focus}
- What to check: ${pov.focus}
- Detection hints (for reference, not exhaustive): ${pov.signals}
- False-positive note: ${pov.fpNote}
- References: ${pov.refs}`

const INSTRUCTIONS_BLOCK = (readInstruction, attributionInstruction) => `## Instructions
1. Inspect the code against "What to check" and determine whether vulnerabilities exist.
2. In evidence, include the actual code location (file:line), the relevant code snippet, and why it is a problem in 1-2 sentences.
3. Avoid false positives: if framework protections (parameterized queries, auto-escaping, typed inputs, etc.) are reliably in place, do not flag it. Lower confidence when uncertain.
4. Judge severity by exploitability and impact. If unverifiable or speculative, use Info or findings: [].
5. Make remediation concrete (code examples or config names).
6. Inherit the perspective's Refs into the refs field.
7. **Attribution**: ${attributionInstruction}`

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

  return `You are a security assessment agent running in **fast mode**. Scan the **whole source code** below using only the single "perspective" provided. Do not expand into other perspectives. Read only the relevant parts of each file (no need to read every file in full); focus on files whose content matches this perspective's signals.

${sourceBlock}

${PERSPECTIVE_BLOCK(pov)}

${INSTRUCTIONS_BLOCK(
  'scan the source code above',
  'When a finding can be attributed to a known endpoint, set unitId (e.g. "U03") and route ("METHOD path") to the most strongly related endpoint. If attribution is ambiguous or unknown, omit unitId/route and rely on location (file:line) only — do not fabricate attribution.'
)}`
}

phase('Assess')

const perspectives = (args && args.perspectives) || []
if (!perspectives.length) {
  throw new Error(
    'args.perspectives is required. The main agent must complete step 2 (perspective catalog load + pre-filter) before launching the Workflow.'
  )
}

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
      .catch(() => [])
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
