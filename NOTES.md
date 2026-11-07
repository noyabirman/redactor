# Decision notes

Raw notes, one line per decision. They will be moved into README.md and this file deleted.

## General
- **README follows the order of the brief's README section,** so reviewers can check each requirement easily.
- **Python, not Go.** Go is new to me; the brief allows another language if stated in the README.
- **Recursion, not an explicit stack.** Shorter and easier to read; the ~1000-level limit is handled with a `too_deep` placeholder.
- **Read input as bytes, line by line.** Invalid UTF-8 can't crash the decoder, and memory is O(longest line), not O(file). Time is O(input size x number of rules).

- **Sub-millisecond answer: prefer moving redaction off the request path** (async queue) before optimizing it; if inline, compiled language, one-pass matching, no re-serialize, hard budget.

## Rules file
- **Rules are loaded and checked before reading any input (fail closed).** Missing file, bad YAML, unknown action/scope/validator or a broken regex -> exit code 2 and nothing on stdout. Traffic is never passed through unredacted.
- **`yaml.safe_load`, not `yaml.load`.** It only builds plain types, so a malicious rules file can't create Python objects.
- **Regexes are compiled once at load time.** Faster, and a broken regex is caught before any output.
- **Fixed the `jwt` pattern (the "known issue").** JWTs use base64url (`-` and `_`), but the pattern only allowed base64 (`+`, `/`, `=`). JWTs with `-`/`_` were missed (input lines 11, 16) or cut in the middle, leaking the end of the signature (`****_adQssw5c`, line 15). Added `-` and `_`, kept `+/=`. JWTs in `Authorization` headers were masked anyway by the `auth-headers` key rule, which is likely why only tokens in bodies and free text were reported.
- **Card pattern allows one space or dash between digits** (`4111 1111 1111 1111`, `5555-5555-5555-4444`). Luhn still filters random numbers.
- **The `settings` block in rules.yaml is not read yet.** `****`, keep 4 and `*` are constants in the code (same values). To do.

## Service mode
- **Python's built-in `http.server` (`ThreadingHTTPServer`), no web framework.** No new dependencies and full control over streaming; not as production-hardened as a real framework.
- **If the rules can't be loaded, the server doesn't start** (exit 2, same as the CLI). There is never a moment where traffic could pass through unredacted; Kubernetes sees the pod fail.
- **`GET /healthz` returns 200 `ok` while the server runs.** Since it can't run without valid rules, "running" means "rules loaded". Used for both liveness and readiness.
- **`/redact` reads and answers one line at a time** with the same `process_line` as the CLI, so both modes give identical output.
- **The response status (200) is sent before the body is read,** so a bad line can't change it later; bad lines get the usual placeholder.

## Bad lines
- **A line that can't be parsed becomes a placeholder:** `{"_redactor_error":"invalid_json","line":20}`. Printing it as-is could leak data (line 20 has a truncated JWT, line 50 an email); dropping it silently hides the problem. The line number lets you find it in the original file. (Input lines 20, 21, 50.)
- **Blank lines are skipped** (lines 19, 22), as is usual for NDJSON.
- **stderr gets only the line number and a reason, never content.** For unexpected errors only the exception type is printed, because the message could contain the value.
- **JSON nested too deeply** (Python's recursion limit, ~1000 levels) -> placeholder `too_deep` instead of a crash.
- **Safety net:** any unexpected error in redaction -> placeholder `internal_error`; the run continues.
- **Counts are added per line only if the line succeeds,** so a failed line doesn't leave partial counts.
- **Valid JSON that isn't an object** (`42`, `["a@b.com"]`, lines 23-24) is still redacted, not rejected.

## Output format
- **Output is re-serialized JSON.** Same values, possibly different text: `10.50` -> `10.5`, `1e3` -> `1000.0`, non-ASCII as `\uXXXX` (always valid ASCII, encoding can't fail).
- **Duplicate keys: the last one wins** (Python's json). The earlier value is dropped, not leaked (line 25).

## Key rules
- **`exact` names are case-insensitive** (HTTP headers are): `authorization`, `AUTHORIZATION` (lines 2, 14).
- **Scope:** `headers` = request and response headers, `body` = request and response bodies, other top-level fields (`ts`, `path`, ...) only get `scope: any` rules.
- **The first matching rule wins.**
- **A rule on a list or object applies to every value inside** (`Set-Cookie: [..]` -> `["****","****"]`, line 31). `null` stays `null`.
- **Numbers are redacted too and become strings** (`"card_number": 4111111111111111` -> `"************1111"`, line 28).

## Actions
- **`partial` on 4 characters or fewer masks everything**, otherwise a short value (e.g. a CVV) would stay fully visible.
- **`hash` output is `sha256:<hex>`.** The prefix lets a second run recognise it and leave it alone (idempotency), and shows the algorithm.
- **Limitation: unsalted hash.** Someone can hash a list of known emails and compare. HMAC with a secret key would fix that.

## Value rules
- **Applied to every string, in every scope; only the matched part is replaced.**
- **Only strings are scanned, not numbers** (as the brief says). A card stored as a number under an unknown key name is not found.
- **Limitation (Luhn):** about 10% of random numbers pass Luhn, so some long IDs (13-19 digits) will be redacted. That errs on the safe side, on purpose.
- **Limitation (card pattern):** a card followed by more digits (`4111 1111 1111 1111 123`) is matched as one 19-digit number, fails Luhn, and stays visible. Only one separator between digits.
- **Note:** in Python `\d` also matches non-Latin digits (e.g. Arabic-Indic). Harmless.

## String bodies
- **The type is detected from the content, not the Content-Type header,** so a wrong or missing header can't skip redaction.
- **JSON inside a string** (lines 1, 10, 11) is parsed, fully redacted (key rules too) and written back as a string, keeping the field's type.
- **Form-encoded** (line 8) is decoded first (`%40` -> `@`), key rules on names, value rules on values. Unchanged pairs are kept exactly as they were.
- **Anything else** (plain text, HTML, binary-looking, lines 9, 17, 31, 42) gets value rules only.
- **Query string in `path` is redacted like a form body** (`?token=...&email=gina%40...`). Query parameters are request data, so `scope: body` rules apply to them. Before this fix the token and the URL-encoded email leaked.
- **Limitations:** only `body` fields get this treatment; `password: hunter2` inside free text isn't caught; base64 with `=` padding looks like a form (harmless, nothing changes).
