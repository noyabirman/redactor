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
