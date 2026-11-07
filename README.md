# API Traffic Log Redactor

Reads API traffic logs (NDJSON, one HTTP transaction per line), redacts sensitive data according to `rules.yaml`, and writes the same NDJSON to stdout.

**Language: Python 3.12.** 
Go is completely new to me, and the brief allows another language in that case, so I chose Python.
The only dependencies are `pyyaml` (rules file) and `pytest` (tests).

## 1. Build, run and test

### Setup
```sh
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### CLI
```sh
python redactor.py --rules rules.yaml input.ndjson > redacted.ndjson
cat input.ndjson | python redactor.py          # reads stdin if no file is given
```
- `--rules` defaults to `rules.yaml` in the current directory.
- Redacted NDJSON goes to **stdout**. Warnings and the per-rule summary go to **stderr**.
- Exit code `0` on success, `2` if the rules file can't be loaded (nothing is written to stdout).

### Tests
```sh
pytest            # or: python -m pytest -v
```
The tests use the real `rules.yaml`, so a mistake in the rules file makes them fail too.

### Service mode
In process.........

## 2. Design decisions and trade-offs

### Streaming
The input is read **line by line, as bytes**, and each line is written out before the
next one is read. Nothing else is kept between lines except the per-rule counters.
- **Memory:** O(longest line), not O(file size).
- **Time:** O(input size x number of rules). Every value is visited once and checked against each rule.
- Reading bytes (not text) means invalid UTF-8 can't crash the reader; each line is decoded on its own.

### Recursion
`redact_value` walks the parsed JSON recursively: for a dict it checks every key
against the key rules, for a list every item, and for a string it applies the value rules.
- Recursion follows the shape of the data, so the code stays short and easy to read.
- Trade-off: Python stops at about 1000 levels. Deeper JSON gets a `too_deep` placeholder
  instead of a crash. An explicit stack would remove the limit, but real API payloads are not that deep.
- New dicts and lists are built instead of changing the old ones (removing keys while looping is an error).

### Rule matching
- Rules are **checked and compiled once**, before any input is read. A broken regex stops the program.
- **Key rules** match the key name: `exact` lists are case-insensitive (HTTP headers are), `regex` uses `search`.
  `scope` limits a rule to headers, bodies, or both. The first matching rule wins.
- **Value rules** run on every string, wherever it is; only the matched part is replaced.
  The `luhn` validator keeps random 16-digit numbers (order IDs, timestamps) from being redacted.
- **String bodies** are checked by content, not by `Content-Type`: JSON inside a string gets full
  redaction, form-encoded data is URL-decoded first, anything else gets value rules.
- **Idempotent:** `****` and `****1111` don't match any rule again, and hashes carry a `sha256:` prefix
  so a second run leaves them alone.

### Failure handling: fail closed
The rule everywhere: **if we're not sure a value is safe, it doesn't go out.**
- **Rules can't be loaded** -> exit code 2, nothing on stdout.
- **A line can't be parsed** (bad JSON, bad UTF-8, too deep) -> a placeholder instead of the line:
  `{"_redactor_error":"invalid_json","line":20}`. Printing the line as-is could leak data
  (e.g. a truncated JWT the pattern no longer matches); dropping it would hide the problem.
  The line number points to the original line.
- **Unexpected error** in redaction -> placeholder `internal_error`, and the run continues.
- **stderr** only ever gets line numbers, reasons and error types, never content.

## 3. The JWT report

**What I found.** The `jwt` pattern in the provided `rules.yaml` only allowed base64 characters:
```
eyJ[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]*
```
But JWTs use **base64url** (RFC 7515), where the special characters are `-` and `_`, not `+` and `/`.
So any JWT containing `-` or `_` was handled wrongly, in two ways:
- **Missed completely** when `-`/`_` is in the header or payload: `access_token` in a response body
  (input line 11) and a token inside a log message (line 16) came out in full.
- **Cut in the middle** when `_` is in the signature: the regex stopped at the `_`, so the output was
  `****_adQssw5c`, leaking the end of the signature (line 15, `id_token` and `note`). This is the worse
  case, because the field looks redacted.

JWTs in `Authorization` headers were masked anyway by the `auth-headers` key rule, which is probably
why the problem was only noticed in production samples with tokens in bodies and free text.

**What I did.** Added `-` and `_` to all three parts of the pattern, and kept `+/=` in case a
non-standard token uses plain base64:
```
eyJ[A-Za-z0-9_+/=-]+\.[A-Za-z0-9_+/=-]+\.[A-Za-z0-9_+/=-]*
```
**How I checked.** I wrote the tests first and they failed on the old pattern
(`'****_adQssw5c' == '****'`). They pass with the new one. On `input.ndjson` the `jwt` count went
from 2 to 4, and the output contains no `eyJ` at all.
