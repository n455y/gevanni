---
id: P9
name: UserEnumeration
refs: ASVS V2.1.x, V2.5.x / WSTG-ATHN-03, WSTG-ATHN-10 / CS: Authentication, User Privacy Protection
---

# P9 — User Enumeration

## Preconditions

The code handles user login or registration.


## Overview
User enumeration leaks whether a given identifier (username, email, account ID) exists in the system, typically through **differential responses** during authentication, registration, or password reset. The differences can be explicit (distinct messages or HTTP status codes: "user not found" vs "wrong password") or implicit — response timing, redirect behavior, error codes, page titles, or even whether a rate-limit or lockout triggers. The root cause is asymmetric code paths: the application takes an early exit or skips work (notably password-hash verification) when the account is absent, so an attacker can distinguish "no such user" from "bad password" with a single request. The resulting account list fuels credential stuffing, targeted phishing, and privacy disclosure (membership disclosure of an email address).

## What to check
- On login failure, are the **message, HTTP status code, and response body identical** whether the user exists or not? `404 user not found` vs `401 invalid credentials` is a textbook leak.
- Does the handler return early when the user is missing, skipping password-hash verification and thereby producing a measurably **shorter response time** for non-existent accounts?
- During **registration / sign-up**, does the app immediately reject a duplicate email/username ("this email is already registered") instead of using a generic "check your email to confirm" flow?
- During **password reset / account recovery**, does the page reveal "no account found for this address" vs "a reset link has been sent"? Does the reset email *always* send (or appear to) regardless of existence?
- Are distinct **error codes, redirect targets, or response headers** (e.g. `Location`, different `Set-Cookie`) emitted for known vs unknown users?
- Does a lockout / rate-limit message fire only after N failures for a *real* account, revealing existence through lockout status?
- Do change-password or 2FA enrollment endpoints confirm existence ("user does not exist") on identifier lookup?
- On success vs failure, do **timing, CPU cost, or log lines** differ? Compare wall-clock across a known-good vs fabricated username.
- Are user IDs, profile URLs, or avatars **guessable/enumerable** (sequential `/user/1023`, `/u/42`)? See related IDOR perspectives.
- Does the API return structured error objects (`{"error":"username_not_found"}`) that a script can read even when the human-facing text is identical?

## Static signals
Differential return on user existence (login):
- Node/Express: `if (!user) return res.status(404).send('user not found');` vs `if (!await bcrypt.compare(...)) return res.status(401).send('wrong password');`
- Python (Django/Flask/FastAPI): `raise Http404('user not found')`, `abort(404)`, `return jsonify({'error':'no such user'}), 404`, `if user is None: return 'No account with that email', 404`
- Java (Spring): `throw new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found");`, `return new ResponseEntity<>("invalid username", HttpStatus.NOT_FOUND);`
- Go: `http.Error(w, "user not found", http.StatusNotFound)`, `if user == (User{}) { ... StatusNotFound }`
- PHP (Laravel): `return response()->json(['error'=>'user not found'], 404);`, `abort(404, 'user not found');`
- Ruby (Rails): `render plain: 'user not found', status: :not_found`, `head 404`

Early return / skipping hash verification (timing oracle):
- `if (!user) { return fail(); } const ok = await bcrypt.compare(password, user.hash);` — no dummy hash compare when absent
- Python: `if user is None: return False` then `bcrypt.checkpw(...)` only in the positive branch
- Java/Spring Security custom `UserDetailsService`: `throw new UsernameNotFoundException(name)` before any password check

Registration disclosure:
- `if (await User.findOne({email})) return res.status(409).send('email already registered');`
- Django: `form.add_error('email', 'A user with that email already exists.')` (the built-in default!)
- Rails `validates :email, uniqueness: true` surfacing the model error verbatim to the client

Reset/recovery disclosure:
- `if (!user) return res.send('No account found with that email address');`
- `if (!user) { res.redirect('/reset/not-found'); }`
- Login: `login.error = 'username does not exist'` vs `'password incorrect'`

Structured error keys:
- `{"error_code":"USER_NOT_FOUND"}`, `{"field":"username","message":"..."}`, `{"errors":[{"detail":"not found"}]}` (JSON:API)

## False positives
- A **single generic message** ("invalid username or password") is returned for both missing-user and wrong-password, AND the code path always performs a constant-time hash comparison against a dummy hash (or otherwise equalizes work). This is the correct pattern — skip it.
- Endpoints intended to be public directories (intentional member search, public profile listing) where disclosure is by design — note as accepted business risk, not a defect.
- Lockout that triggers equally on fake and real usernames (rate-limit keyed only on IP/credential pair, not on account existence).
- Timing differences under ~1ms that are below realistic network jitter and not from skipped hash work.
- Self-service "is this username taken?" checks that are a deliberate part of the registration UX (acceptable if rate-limited and privacy-neutral; flag if they reveal email/account existence rather than handle availability).

## Attack scenario
1. Attacker compiles a target list (a leaked corporate email roster, a guessed pattern `first.last@victim.com`, or a purchased list).
2. For each candidate the attacker sends a login request with any password and records the response — message text, status code, elapsed time, and any headers.
3. Real accounts respond with "invalid credentials" after a full bcrypt/argon2 verification (~100–300ms); fabricated accounts return "user not found" in a few ms (or a 404, or a distinct error key). Even if text is identical, the **timing gap** sorts the list.
4. The attacker now has a confirmed, valid account list and launches **credential stuffing** with leaked password dumps (e.g. from a breach) — only for known-good accounts, dodging lockout noise.
5. With a confirmed-existence list the attacker also enables targeted phishing ("Your account `j.doe@victim.com` needs a password reset") and, where the reset endpoint also enumerates, silently verifies membership of an address.

## Impact
- **Confidentiality**: disclosure of who is a registered user/member (membership inference); on registration flows, confirmation that a specific email is enrolled — a privacy leak (GDPR/PII relevance).
- **Integrity**: enables credential stuffing and account takeover of weak-password accounts; amplifies phishing success.
- **Availability**: lockout-based enumeration can trigger account lockouts (denial for the legitimate user).
- Severity scales with the value of the account list: a consumer forum is Low/Medium; a banking, healthcare, or internal SSO directory where existence is sensitive is Medium/High. Enumeration + a credential-stuffing toolchain can achieve mass account takeover.

## Remediation
Use one message for every failure cause and equalize the work, including a constant-cost dummy operation when the user does not exist:
```ts
// VULNERABLE — existence leaks via status code + skipped hash work
const user = await User.findByEmail(email);
if (!user) return res.status(404).send('user not found');
if (!await bcrypt.compare(password, user.hash)) return res.status(401).send('wrong password');

// SAFE — identical response; always perform a hash compare to normalize timing
const GENERIC = 'invalid email or password';
const user = await User.findByEmail(email);
const hash = user?.hash ?? DUMMY_BCRYPT_HASH;   // precomputed valid hash
const ok = await bcrypt.compare(password, hash) && !!user;
if (!ok) return res.status(401).send(GENERIC);  // same code, same body, every time

// Registration & reset: never confirm existence —
// return "if an account exists, a confirmation/reset link has been emailed"
// and send (or simulate sending) the email for unknown users too.
```
For registration and password reset, prefer a generic "check your inbox" acknowledgement over a duplicate/not-found error, and rate-limit by IP to blunt brute-force enumeration. Add per-IP rate limiting and CAPTCHA as defense-in-depth — they cap how fast an attacker can probe, but the message/timing fix is the real control.

## References
- OWASP ASVS V2.1.x, V2.5.x — Authentication error messaging and password reset anti-enumeration
- OWASP WSTG-ATHN-03 (Testing for Weak Lock Out), WSTG-ATHN-10 (Testing for Browser Cache / response differences) — authentication response analysis
- OWASP Cheat Sheets: Authentication, User Privacy Protection
