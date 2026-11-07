"""API traffic log redactor.

Step 3: load the rules file, parse each NDJSON line, and replace lines that
can't be parsed with a safe placeholder record.
"""

import argparse
import hashlib
import json
import sys

import yaml

VALID_ACTIONS = {"mask", "partial", "hash", "remove"}


class RulesError(Exception):
    """The rules file is missing or invalid."""


def load_rules(path):
    """Read the rules YAML file and check its basic structure.

    Raises RulesError if anything is wrong, so the caller can refuse to run.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            # safe_load only builds plain types (dict, list, str, ...),
            # never arbitrary Python objects.
            rules = yaml.safe_load(f)
    except OSError as e:
        raise RulesError(f"cannot read rules file {path}: {e.strerror}")
    except yaml.YAMLError as e:
        raise RulesError(f"rules file {path} is not valid YAML: {e}")

    if not isinstance(rules, dict):
        raise RulesError(f"rules file {path} must contain a YAML mapping at the top level")

    for section in ("key_rules", "value_rules"):
        section_rules = rules.get(section, [])
        if not isinstance(section_rules, list):
            raise RulesError(f"'{section}' must be a list")
        for rule in section_rules:
            if not isinstance(rule, dict) or "name" not in rule:
                raise RulesError(f"every rule in '{section}' needs a 'name'")
            if rule.get("action") not in VALID_ACTIONS:
                raise RulesError(
                    f"rule '{rule['name']}' has invalid action {rule.get('action')!r}"
                )

    return rules


MASK = "****"
KEEP_LAST = 4
FILL = "*"
HASH_PREFIX = "sha256:"


def apply_action(action, value):
    """Return the new value after applying the action.

    'remove' is not handled here: it deletes the key itself, so the code
    that walks over the dict takes care of it.
    """
    # Values can also be numbers (e.g. "card_number": 4111111111111111).
    text = str(value)

    if action == "mask":
        return MASK

    elif action == "partial":
        # Too short to keep 4 characters without revealing the whole value:
        # mask all of it.
        if len(text) <= KEEP_LAST:
            return FILL * len(text)
        return FILL * (len(text) - KEEP_LAST) + text[-KEEP_LAST:]

    elif action == "hash":
        # Already hashed (we are running on our own output): leave it alone,
        # so running the tool twice gives the same result.
        if text.startswith(HASH_PREFIX):
            return text
        return HASH_PREFIX + hashlib.sha256(text.encode("utf-8")).hexdigest()

    raise ValueError(f"apply_action does not handle action {action!r}")


def process_line(raw, line_no):
    """Turn one raw input line (bytes) into one output line (bytes).

    Returns (output, error):
      - a normal line:     (redacted JSON line, None)
      - a blank line:      (None, None)          -> nothing is written
      - a line we can't parse: (placeholder line, short reason)

    We never return the original bytes of a bad line, because it may contain
    sensitive data we couldn't find (for example, a truncated JWT).
    """
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return placeholder(line_no, "invalid_utf8"), "invalid UTF-8"

    if not text.strip():
        return None, None

    try:
        record = json.loads(text)
    except json.JSONDecodeError:
        return placeholder(line_no, "invalid_json"), "invalid JSON"

    # Redaction will happen here in a later step.

    return to_json_line(record), None


def placeholder(line_no, reason):
    """The line we emit instead of a line we couldn't safely process."""
    return to_json_line({"_redactor_error": reason, "line": line_no})


def to_json_line(value):
    # ensure_ascii=True escapes every non-ASCII character (é -> é), so the
    # output is always valid ASCII and encoding it can never fail.
    # separators=(",", ":") gives compact output with no extra spaces.
    return (json.dumps(value, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")


def main():
    parser = argparse.ArgumentParser(description="Redact sensitive data from NDJSON logs.")
    parser.add_argument("--rules", default="rules.yaml", help="rules YAML file (default: rules.yaml)")
    parser.add_argument("input_file", nargs="?", help="NDJSON file to read (default: stdin)")
    args = parser.parse_args()

    # Load the rules BEFORE reading any input. If they can't be loaded,
    # stop here: we must never pass traffic through unredacted.
    try:
        rules = load_rules(args.rules)
    except RulesError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(2)

    # Work with bytes, not text, so binary-looking or invalid UTF-8 lines never crash us.
    if args.input_file:
        source = open(args.input_file, "rb")
    else:
        source = sys.stdin.buffer

    output = sys.stdout.buffer

    bad_lines = 0

    # Iterating over a file reads one line at a time, so memory use stays small
    # no matter how big the input is.
    with source:
        for line_no, raw in enumerate(source, start=1):
            out, error = process_line(raw, line_no)
            if error:
                bad_lines += 1
                # Only the line number and reason go to stderr, never the content.
                print(f"warning: line {line_no}: {error}, replaced with placeholder", file=sys.stderr)
            if out is not None:
                output.write(out)

    if bad_lines:
        print(f"{bad_lines} line(s) could not be processed", file=sys.stderr)


if __name__ == "__main__":
    main()
