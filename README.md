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
pip install -r requirements-dev.txt   # pyyaml + pytest (requirements.txt has only pyyaml)
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
```sh
python redactor.py --serve --addr :8080 --rules rules.yaml
curl --data-binary @input.ndjson localhost:8080/redact     # redacted NDJSON back
curl localhost:8080/healthz                                 # "ok"
```
- `POST /redact`: NDJSON in, redacted NDJSON out. The body is read, redacted and written
  back **one line at a time**, never held in memory as a whole. Needs a `Content-Length`.
- `GET /healthz`: `200 ok` while the server runs. The server **doesn't start** if the rules
  can't be loaded (exit code 2), so "running" also means "rules loaded". It is used for both
  the Kubernetes readiness and liveness probes.

### Docker
```sh
docker build -t redactor .
docker run --rm -p 8080:8080 redactor                                     # service mode
docker run --rm -i redactor --rules /etc/redactor/rules.yaml < input.ndjson  # CLI
```

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

## 4. Deployment files

**[`Dockerfile`](Dockerfile)**
- `python:3.12.7-slim-bookworm`, pinned to an exact version so builds are repeatable. Small and
  familiar, with a shell for debugging (distroless would be smaller but harder to debug).
- Dependencies are installed before the code is copied, so a code change doesn't reinstall them.
- Only `pyyaml` goes into the image (`pytest` is in `requirements-dev.txt`).
- Runs as a non-root user (uid 10001). Service mode by default; other arguments run the CLI.

**[`k8s/redactor.yaml`](k8s/redactor.yaml)**: three objects, kept minimal on purpose.
- **ConfigMap** with the rules, mounted at `/etc/redactor/rules.yaml`, so rules change without a
  new image. It's a copy of `rules.yaml`, and a test fails if the two differ.
- **Deployment** with 2 replicas (one can restart without downtime), readiness and liveness probes
  on `/healthz`, CPU/memory requests and limits, and a locked-down container: non-root, read-only
  filesystem, no privilege escalation, all Linux capabilities dropped.
- **Service**: a stable address (`http://redactor`) inside the cluster.

If the ConfigMap has broken rules, new pods exit and never become ready, while the old pods keep
running with the old rules. So a bad rules change can't let traffic through unredacted.

To try it locally with [kind](https://kind.sigs.k8s.io):
```sh
kind create cluster
docker build -t redactor . && kind load docker-image redactor
kubectl apply -f k8s/redactor.yaml
kubectl port-forward service/redactor 8080:80
```
The image is `redactor:latest` so this works without a registry. In production it would come from
a registry with a fixed version tag. I built and ran the image with Docker, but didn't run the
manifest on a real cluster.

## 5. Known limitations and what I'd do with more time

| Limitation | With more time |
|---|---|
| `hash` is plain SHA-256, so known values (e.g. a list of emails) can be hashed and compared. | HMAC-SHA-256 with a secret key from a Kubernetes Secret. |
| About 10% of random numbers pass Luhn, so some 13-19 digit IDs get redacted. This errs on the safe side, on purpose. | Also require a known card prefix (BIN range), or a card-like key or word nearby. |
| A card followed by more digits (`4111 1111 1111 1111 123`) is matched as one number, fails Luhn and stays visible. Only one space or dash between digits. | When a match fails Luhn, also try the shorter matches inside it. |
| Value rules only scan strings. A card stored as a JSON number under an unknown key name is not found. | Also scan integers of 13-19 digits. |
| `password: hunter2` inside free text is not caught (key rules need a key/value structure). | Value rules for `name: value` / `name=value` patterns of secret key names. |
| JSON and form detection only applies to `body` fields and the query string, not to other strings. | Try it on every string that starts with `{` or `[`, measuring the cost. |
| The `settings` block in `rules.yaml` is not read; `****`, keep 4 and `*` are constants with the same values. | Read them in `load_rules`. |
| A single very long line is loaded into memory as a whole. | A maximum line size; longer lines get a placeholder. |
| Output is re-serialized: `10.50` -> `10.5`, non-ASCII as `\uXXXX`, duplicate keys keep the last value. Same data, different text. | Rewrite only the matched spans of the original text. |
| JSON deeper than ~1000 levels gets a placeholder (recursion limit). | An explicit stack instead of recursion. |
| One line at a time, one CPU core. | A worker pool that keeps the output order (bonus in the brief). |
| The service needs `Content-Length`; chunked uploads get `411`. The 411 is sent without reading the body, so a client that is still sending may see a connection reset instead. | Read chunked bodies line by line too. |
| Rules are read only at startup. After changing the ConfigMap: `kubectl rollout restart deployment/redactor`. | Hot reload of the rules file (bonus in the brief). |
| The service doesn't log per-request redaction counts, and there are no metrics. | Prometheus metrics per rule (bonus in the brief). |

## 6. Inline on live traffic with a sub-millisecond budget

I would first move redaction off the request path if at all possible: copy the traffic to a queue
and redact it asynchronously, so a slow line can never delay a user. If it really must be inline,
I'd change four things. **Language:** a compiled language like Go, with no interpreter overhead.
**One pass instead of many:** today every string is scanned once per value rule; I'd combine all
patterns into a single automaton (RE2 sets or Hyperscan) and check key names with one hash lookup.
**No full parse and re-serialize:** a streaming tokenizer that copies the original bytes and only
rewrites the matched spans, with no allocations per request. **A hard budget:** cap the body size
that gets scanned and skip known binary content types, and decide up front what happens when the
budget runs out (for a security product, drop or mask the body rather than pass it through).
Then measure p99 latency on realistic traffic, not the average.
