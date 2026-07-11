# Security Assessment Report

> **Target**: {{TARGET_NAME}}
> **Scope**: {{SCOPE}}
> **Date**: {{DATE}}
> **Mode**: {{MODE}} (standard: unit × perspective | fast: whole-source per perspective)
> **Method**: White-box static analysis (Dynamic Workflow fan-out)
> **Perspectives applied**: {{POV_COUNT}} / Assessment units: {{UNIT_COUNT_OR_WHOLE}}

---

## 1. Executive Summary

- Assessment units: **{{UNIT_COUNT_OR_WHOLE}}**
- Perspectives applied: **{{POV_COUNT}}**
- Total findings: **{{TOTAL}}**
  - Critical: **{{C}}** / High: **{{H}}** / Medium: **{{M}}** / Low: **{{L}}** / Info: **{{I}}**

{{MODE_NOTE}}

### Critical / High Findings

{{CRITICAL_HIGH_SUMMARY:- No critical or high findings.}}

### Limitations & Out of Scope
{{SCOPE_NOTES}}
- This report presents "potential issues" based on static analysis; it does not include dynamic verification.
- The following perspectives/areas were excluded by pre-filtering: {{EXCLUDED_PERSPECTIVES}}

---

## 2. Risk Table

Sorted by severity → confidence.

| # | Severity | Perspective ID | Location (and route) | Title | Confidence |
|---|----------|----------------|----------------------|-------|-------------|
{{RISK_TABLE_ROWS}}

---

## 3. Details by Perspective

{{#SEVERITY_GROUP:Critical}}
### Critical

#### [{{POV_ID}}] {{TITLE}}
- **Location**: `{{LOCATION}}`
- **Confidence**: {{CONFIDENCE}}
- **References**: {{REFS}}
- **Evidence**:
{{EVIDENCE}}
- **Remediation**:
{{REMEDIATION}}
{{/SEVERITY_GROUP}}

{{#SEVERITY_GROUP:High}}
### High
... (same structure)
{{/SEVERITY_GROUP}}

{{#SEVERITY_GROUP:Medium}}
### Medium
... (same structure)
{{/SEVERITY_GROUP}}

{{#SEVERITY_GROUP:Low}}
### Low
... (same structure)
{{/SEVERITY_GROUP}}

{{#SEVERITY_GROUP:Info}}
### Info
... (same structure)
{{/SEVERITY_GROUP}}

---

## 4. Notes

- This report is based on **static analysis (SAST)**. Dynamic testing (live request verification) should be performed separately using the `gevanni` scanner.
- Areas where framework protections (parameterized queries, auto-escaping, typed inputs, etc.) were confirmed are generally excluded. However, be aware of configuration gaps and exceptional code paths.
- Items with `low` confidence or `Info` severity may be false positives. Dynamic verification is recommended.
- A re-assessment is required if the target code changes.
