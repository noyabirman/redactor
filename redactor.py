"""API traffic log redactor.

Reads NDJSON (one HTTP transaction per line), redacts sensitive data according
to a rules file, and writes NDJSON. Lines that can't be parsed are replaced
with a safe placeholder record.
"""

import argparse
import hashlib
import json
import re
import sys
from collections import Counter

import yaml

VALID_ACTIONS = {"mask", "partial", "hash", "remove"}
VALID_SCOPES = {"headers", "body", "any"}


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
            if section == "key_rules":
                prepare_key_rule(rule)

    return rules


def prepare_key_rule(rule):
    """Check a key rule and add fields that make matching fast.

    Adds rule["_exact"] (a set of lowercase names) and/or rule["_regex"]
    (a compiled regex). The leading underscore marks fields we added,
    as opposed to fields that came from the YAML file.
    """
    name = rule["name"]
    match = rule.get("match")
    if not isinstance(match, dict):
        raise RulesError(f"key rule '{name}' needs a 'match' with 'exact' or 'regex'")

    if "exact" not in match and "regex" not in match:
        raise RulesError(f"key rule '{name}' needs a 'match' with 'exact' or 'regex'")

    if "exact" in match:
        names = match["exact"]
        if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
            raise RulesError(f"key rule '{name}': 'exact' must be a list of names")
        # Lowercase, because HTTP header names are case-insensitive
        # ("Authorization" and "authorization" are the same header).
        rule["_exact"] = {n.lower() for n in names}

    if "regex" in match:
        try:
            # Compile once here, not on every key: faster, and a broken regex
            # stops the program before any line is written.
            rule["_regex"] = re.compile(match["regex"])
        except (re.error, TypeError) as e:
            raise RulesError(f"key rule '{name}' has an invalid regex: {e}")

    scope = rule.get("scope", "any")
    if scope not in VALID_SCOPES:
        raise RulesError(f"key rule '{name}' has invalid scope {scope!r}")
    rule["scope"] = scope


def key_matches(rule, key):
    """True if the key name matches this key rule."""
    if "_exact" in rule and key.lower() in rule["_exact"]:
        return True
    if "_regex" in rule and rule["_regex"].search(key):
        return True
    return False


def find_key_rule(rules, key, scope):
    """Return the first key rule that applies to this key in this scope, or None.

    The first matching rule in the file wins.
    """
    for rule in rules.get("key_rules", []):
        if rule["scope"] in ("any", scope) and key_matches(rule, key):
            return rule
    return None


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


def apply_to_leaves(action, value):
    """Apply an action to a value that may be a dict or a list.

    Example: "password": ["a", "b"]  ->  "password": ["****", "****"].
    null stays null: there is nothing to hide, and keeping it is idempotent.
    """
    if isinstance(value, dict):
        return {k: apply_to_leaves(action, v) for k, v in value.items()}
    if isinstance(value, list):
        return [apply_to_leaves(action, v) for v in value]
    if value is None:
        return None
    return apply_action(action, value)


def redact_value(value, scope, rules, counts):
    """Redact a JSON value of any type, at any depth.

    scope is "headers", "body" or "other" (fields like ts, method, path),
    so each key rule only applies where its 'scope' says.
    counts is a Counter: how many times each rule was applied.
    """
    if isinstance(value, dict):
        result = {}
        # We build a new dict instead of changing the old one, because
        # deleting keys from a dict while looping over it is an error.
        for key, item in value.items():
            rule = find_key_rule(rules, key, scope)
            if rule is None:
                # No rule for this key: look deeper inside its value.
                result[key] = redact_value(item, scope, rules, counts)
            elif rule["action"] == "remove":
                counts[rule["name"]] += 1
                # Don't copy the key into result: it is dropped.
            else:
                counts[rule["name"]] += 1
                result[key] = apply_to_leaves(rule["action"], item)
        return result

    if isinstance(value, list):
        return [redact_value(item, scope, rules, counts) for item in value]

    # A string, number, true/false or null. value_rules will be applied here
    # in the next step.
    return value


def redact_record(record, rules, counts):
    """Redact one parsed line, using the right scope for each part of it."""
    if not isinstance(record, dict):
        # A line like 42 or ["a@b.com"]: still valid JSON, still redacted.
        return redact_value(record, "other", rules, counts)

    result = {}
    for key, item in record.items():
        if key == "headers":
            result[key] = redact_value(item, "headers", rules, counts)
        elif key == "body":
            result[key] = redact_value(item, "body", rules, counts)
        elif key == "response" and isinstance(item, dict):
            # The response has its own headers and body.
            result[key] = redact_record(item, rules, counts)
        else:
            # Other top-level fields (ts, method, path, status, ...):
            # only rules with scope "any" apply here.
            result.update(redact_value({key: item}, "other", rules, counts))
    return result


def process_line(raw, line_no, rules, counts):
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

    record = redact_record(record, rules, counts)

    return to_json_line(record), None


def placeholder(line_no, reason):
    """The line we emit instead of a line we couldn't safely process."""
    return to_json_line({"_redactor_error": reason, "line": line_no})


def to_json_line(value):
    # ensure_ascii=True writes every non-ASCII character (Hebrew, emoji, ...)
    # as a backslash-u escape, so the output is always valid ASCII and
    # encoding it can never fail.
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
    counts = Counter()

    # Iterating over a file reads one line at a time, so memory use stays small
    # no matter how big the input is.
    with source:
        for line_no, raw in enumerate(source, start=1):
            out, error = process_line(raw, line_no, rules, counts)
            if error:
                bad_lines += 1
                # Only the line number and reason go to stderr, never the content.
                print(f"warning: line {line_no}: {error}, replaced with placeholder", file=sys.stderr)
            if out is not None:
                output.write(out)

    print_summary(rules, counts, bad_lines)


def print_summary(rules, counts, bad_lines):
    """Print redaction counts per rule to stderr (only names and numbers)."""
    print("redactions per rule:", file=sys.stderr)
    for section in ("key_rules", "value_rules"):
        for rule in rules.get(section, []):
            # Rules with 0 are printed too: "this rule never fired" is useful to know.
            print(f"  {rule['name']}: {counts[rule['name']]}", file=sys.stderr)
    if bad_lines:
        print(f"{bad_lines} line(s) could not be processed", file=sys.stderr)


if __name__ == "__main__":
    main()
