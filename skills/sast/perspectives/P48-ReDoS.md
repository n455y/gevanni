---
id: P48
name: ReDoS
refs: ASVS V5.3.x / WSTG-INPV-08 / CS: Regular Expression Denial of Service
---

# P48 — ReDoS

## Preconditions

The code evaluates regular expressions.


## Overview
Regular Expression Denial of Service (ReDoS) is a denial-of-service vector in which a crafted input forces a regex engine into **catastrophic backtracking** — exponential or polynomial time relative to input length. The root cause is a "evil pattern": a regex containing overlapping quantifiers (e.g. `(a+)+`, `(a*)*`) or nested quantifiers with ambiguous alternatives (`(a|a)*`, `(\d|\w)+`) where the engine cannot decide greedily how to partition a string and ends up exploring an exponential number of paths. Most production regex engines (PCRE, JavaScript V8/SpiderMonkey, Python `re`, Java `java.util.regex`, Ruby Oniguruma, Go `regexp` RE2-derived, PHP PCRE) are backtracking engines — and all but Go's are vulnerable. A single 28-character malicious input can hang a worker thread for minutes or hours, draining CPU and exhausting the event loop / thread pool until the service is unavailable.

## What to check
- Does any regex applied to **request-controlled input** contain overlapping/nested quantifiers — `(a+)+`, `(a*)*`, `(a|a)*`, `(.+.+)+`, `([a-zA-Z]+)*`, `(\s|\w)*$`?
- Are quantifiers (`*`, `+`, `{n,m}`) applied to **alternations with overlapping character classes** (e.g. `(\w|\d)+`, `(\d|\w)*`) — these collapse to catastrophic backtracking on non-matching tails?
- Is a regex constructed from **user-supplied input** — `new RegExp(req.body.pattern)`, `re.compile(request.POST['pattern'])`, `Pattern.compile(userInput)` — letting an attacker choose the pattern itself?
- Is there an outer quantifier wrapping a group that already has a quantifier (`(...+)+`, `(...*)+`) — the classic ReDoS shape?
- Are there nested unbounded quantifiers separated by optional or ambiguous content (`.+x.+y` style) where a non-match forces backtracking?
- Is the **input length unbounded** (no pre-truncation) before the regex is evaluated? Long inputs amplify any backtracking.
- Does the regex engine in use backtrack at all? (Go `regexp`, Rust `regex`, and the `re2` bindings are linear-time and **not** vulnerable to catastrophic backtracking — they reject ambiguous patterns instead.)
- Is a timeout/watchdog set on the match (PCRE2 `MATCH_LIMIT`, Java no native timeout, Python no native timeout before 3.11 `re` has none — 3.12+ adds no built-in; rely on `regex` module or signal-based cancellation)?

## Static signals
Overlapping/nested quantifiers in static patterns:
- JS/TS: `/^(a+)+$/`, `/^(a*)*$/`, `/^(a|a)*$/`, `new RegExp('^(x+x+)+y')`
- Python: `re.compile(r'^(\d+)+$')`, `re.match(r'^(a+)+$', s)`
- Java: `Pattern.compile("^(a+)+$")`, `pattern.matcher(input).matches()`
- Go: `regexp.MustCompile(\`^([a-zA-Z]+)*$\`)` — Go's RE2 will **reject** this at compile time (good); its presence signals a developer misunderstanding that may recur in other languages.
- Ruby: `/^(a+)+$/`, `Regexp.new('^(a+)+$')`
- PHP: `preg_match('/^(a+)+$/', $input)`, `preg_match_all` on unbounded input

User-supplied pattern construction:
- `new RegExp(req.body.pattern)` / `new RegExp(req.query.r, 'g')` (Node, browser)
- `re.compile(request.POST['pattern'])` / `re.compile(form.pattern.data)` (Python/Flask/Django)
- `Pattern.compile(userInput)` (Java/Spring)
- `preg_match('/'.$userPattern.'/', $s)` (PHP — also injection into the pattern)
- `Regexp.new(params[:pattern])` (Ruby/Rails)
- `regexp.Compile(r.FormValue("pattern"))` (Go)

Quantifiers over alternations with overlapping classes:
- `(\w|\d)+`, `(\d+|\w+)*`, `([0-9]+|[a-z]+)*$`, `(a|ab)*`
- `^(a+)+$` family — the textbook exponential pattern

Missing input length caps before matching:
- `re.match(pattern, request.headers['x-custom'])` with no `len()` guard
- `pattern.matcher(req.body.longField).matches()` with no truncation

## False positives
- The regex engine is linear-time / non-backtracking: Go `regexp`, Rust `regex`, Node `re2` package, Google RE2 bindings — catastrophic backtracking cannot occur; the engine returns an error on patterns it cannot evaluate in linear time instead.
- The pattern was vetted as "safe" by `safe-regex` / `static-module` / `rxxr2` analysis and the audit is enforced (e.g. CI lint, runtime check) — confirm the check actually covers this pattern.
- Input is **strictly validated and length-capped** before the match (e.g. UUID, integer, max 50 chars allow-listed charset) — a bounded input cannot drive exponential backtracking; downgrade to Medium/Info.
- The pattern has no quantifiers, or only fixed quantifiers (`{3}`, `?`), or anchors with non-overlapping alternatives — linear by construction.
- The regex matches a trusted, server-generated string (not request data).
- Java/.NET compiled `Pattern` reused across requests is a performance good-practice; do not flag mere `Pattern.compile` of a *constant* safe pattern.

## Attack scenario
1. Attacker identifies an endpoint that validates input with a backtracking regex, e.g. a signup form checking email format with `/^([a-zA-Z0-9._%+-]+)*@example\.com$/`.
2. Attacker crafts a payload tailored to the overlapping quantifier: a long run of valid characters **without** the terminator — e.g. `aaaaaa...(50 a's)...!` (no `@`).
3. The regex engine tries to partition the 50 `a`s among `([a-zA-Z0-9._%+-]+)*` in exponentially many ways, each failing at the `@`, causing ~2^50 backtrack steps.
4. A single request pins a worker thread / event loop tick for seconds to minutes; a few hundred concurrent requests exhaust the process pool, CPU hits 100%, and legitimate users time out.
5. If the pattern itself is user-supplied (`new RegExp(req.body.pattern)`), the attacker supplies an evil pattern with a benign-looking input — same outcome, no need to study the application's regexes.

## Impact
- **Availability**: primary impact — CPU exhaustion, thread/event-loop starvation, request timeouts, and full service unavailability. Often achievable with a single small request repeated at low volume.
- **Confidentiality**: indirect — timeouts and crashes may leak stack traces, expose debug info, or trigger fallback code paths that bypass normal controls.
- **Integrity**: indirect — race conditions during overload, partial writes, or fail-open error handlers may corrupt state.
- Severity scales with the exponent: a truly exponential pattern (e.g. `(a+)+`) on unbounded input is **Critical** (single-request DoS); polynomial patterns or length-capped inputs are Medium; a linear-time engine reduces it to Informational.

## Remediation
Replace evil patterns with linear equivalents and bound the input; prefer a non-backtracking engine where available:
```ts
// VULNERABLE — overlapping quantifier on request input (catastrophic backtracking)
app.post('/validate', (req, res) => {
  const re = /^(a+)+$/;                 // evil: (a+)+
  if (!re.test(req.body.value)) return res.status(400).end();
  res.status(200).end();
});

// VULNERABLE — user-supplied pattern
const re = new RegExp(req.body.pattern);
```
```ts
// SAFE — linear pattern, length cap, and non-backtracking engine
import RE2 from 're2';                  // linear-time, rejects evil patterns
app.post('/validate', (req, res) => {
  const value = String(req.body.value).slice(0, 64);   // bound input length
  const re = new RE2(/^a+$/);           // no nested quantifier
  if (!re.test(value)) return res.status(400).end();
  res.status(200).end();
});
```
Defense-in-depth: cap input length *before* matching, lint patterns with `safe-regex`/`hyperscan`/`rxxr2` in CI, set a match timeout where the engine supports one (PCRE2 `MATCH_LIMIT`, Java `java.util.regex` has none — wrap in a future with timeout), and prefer a linear engine (Go `regexp`, Rust `regex`, `re2`) for any regex that touches untrusted input.

## References
- OWASP ASVS V5.3.x — Input validation and output encoding requirements
- OWASP WSTG-INPV-08 — Testing for Regular Expression Denial of Service
- OWASP Cheat Sheet: Regular Expression Denial of Service
