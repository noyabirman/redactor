# Take-Home Assignment: API Traffic Log Redactor

Thanks for your interest in the internship! This assignment mirrors a small slice
of what our team does: we collect API traffic logs, **redact sensitive data**, and
store them so they can be used for threat detection.

## Ground rules

- **Time box:** submit within **72 hours** of receiving this. We expect roughly
  **5-7 focused hours** of work. We don't expect perfection. We care about
  good judgment and clear communication about the trade-offs you made.
- **AI tools are allowed and expected** (Copilot, ChatGPT, Claude, etc.). That's how we work too.
  However, in the interview you'll be asked to explain and defend every part of
  your submission and make a small live change to it. Only submit what you understand.
- **Language:** Go is strongly preferred (it's our main language). If Go is
  completely new to you, you may use another language. Tell us in the README.
- All sample data is synthetic. Please don't add real personal data or real secrets to your repo.

## Priorities

The scope is intentionally slightly larger than comfortable. If you run short on
time, prioritize in this order:

1. Correct, streaming redaction with tests
2. A clear README
3. Deployment files
4. Bonuses

An honestly documented "not done" beats a claimed-but-broken feature.

## What to build

### 1. A CLI redaction tool

```
redactor [--rules rules.yaml] [input-file]      # reads stdin if no file is given
```

- **Input:** NDJSON. One HTTP transaction per line (see `input.ndjson`).
- **Output:** the same NDJSON on stdout, with sensitive data redacted.
- **Summary:** when finished, print counts of redactions per rule to **stderr**.

Each line looks like this:

```json
{"ts":"...","method":"POST","path":"/v1/users",
 "headers":{"Authorization":"Bearer ...","X-Api-Key":"..."},
 "body":{"user":{"email":"a@b.com"},"note":"card 4111 1111 1111 1111 on file"},
 "response":{"status":200,"headers":{},"body":"{\"token\":\"...\"}"}}
```

`body` can be a JSON object, array, string, number, `null`, or text that isn't JSON at all
(form-encoded, plain text, even binary-looking data).

### 2. Config-driven rules

Rules live in a YAML file (`rules.yaml`, provided), not in code. There are two kinds:

| Kind | Matches on | Example |
|---|---|---|
| `key_rules` | The **name** of a JSON key or HTTP header | any key called `password` |
| `value_rules` | The **content** of a string, whatever the key is called | anything that looks like an email |

Rules support these actions:

| Action | Behavior |
|---|---|
| `mask` | Replace with `****` |
| `partial` | Keep only the last 4 characters of the matched value, mask the rest |
| `hash` | Replace with the SHA-256 of the value |
| `remove` | For key rules, drop the key. For value rules, delete the matched text. |

A value rule may name a `validator` (currently only `luhn`). The match counts only if the validator accepts it.

You can change the config format if you have a good reason. Document it if you do.

### 3. Behavior we expect

- **Detect at minimum:** emails, JWTs, credit card numbers (Luhn-validated, so a random
  16-digit number isn't redacted), and credentials in headers.
- **Recursive:** redact anywhere in nested objects and arrays.
- **Embedded values:** redact sensitive values inside free-text strings, and inside
  non-JSON bodies (form-encoded, plain text).
- **Robust:** never crash on malformed lines, bad JSON, or binary-looking data. Degrade gracefully and
  report the problem. **Never write the offending sensitive data to stderr or logs.**
  Decide what to emit for a line you can't safely process, and explain the choice.
- **Idempotent:** running the tool on its own output gives identical output.
- **Streaming:** it must handle inputs far larger than memory. State your memory and time complexity.
- **Tests:** unit tests for the redaction engine, covering the edge cases you think matter.

### 4. Service mode (minimal)

```
redactor --serve --addr :8080 --rules /etc/redactor/rules.yaml
```

- `POST /redact`: the request body is NDJSON, the response is redacted NDJSON. Stream it. Don't buffer the whole body.
- A health endpoint (your choice of path and semantics, and explain it in the README).
- If the rules can't be loaded, the service must **not** pass traffic through unredacted.

### 5. Deployment files

Include the files you'd use to deploy this as a service in Kubernetes: a **Dockerfile**
and a **Kubernetes manifest (or manifests)** of your choice. We won't prescribe what
they contain. Use your best judgment and add a short README note on the choices you made and why.

- You don't need a running cluster. **No Kubernetes experience is assumed.**
- We'll discuss these files in the interview, so only include things you can explain.
- Helpful starting points if this is new: Docker's "Get started" guide, the Kubernetes "Basics" tutorial.
  [`kind`](https://kind.sigs.k8s.io) runs a throwaway local cluster if you want to try it.

### 6. Git

Submit a git repository with your **real commit history** (please don't squash).
We'll read your commits the way a teammate would when reviewing your work, so
structure them however you think makes your changes easiest to understand.

### 7. Known issue reported by users

> Users reported that the provided `rules.yaml` misses some JWTs seen in production
> samples. Please investigate.

## README (required)

Replace the template `README.md` with your own. It must contain:

1. How to build, run, and test (CLI and service mode)
2. Design decisions and trade-offs (why this approach to recursion, streaming, rule matching, and failure handling)
3. What you found about the JWT report and what you did about it
4. Notes on your deployment files: what you chose and why
5. Known limitations and what you'd do differently with more time
6. One paragraph: *"If this had to run inline on live production traffic with a sub-millisecond budget per request, what would you change?"*

## Optional bonuses (only after everything above)

- Concurrency (worker pool) with preserved output order and correctness guarantees
- Prometheus-style metrics
- Hot-reload of the rules file
- Anything else you think makes it better. Tell us why.

## Submission

- A public git repo link, or a zip that includes the `.git` directory
- Make sure the commit history is intact
- Reply to the email with any assumptions you made and anything you'd like us to know

Good luck, and have fun with it!
