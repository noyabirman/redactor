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
from urllib.parse import quote_plus, unquote_plus

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
            else:
                prepare_value_rule(rule)

    return rules


VALIDATORS = {"luhn"}


def prepare_value_rule(rule):
    """Check a value rule and compile its pattern into rule["_regex"]."""
    name = rule["name"]
    pattern = rule.get("pattern")
    if not isinstance(pattern, str) or not pattern:
        raise RulesError(f"value rule '{name}' needs a 'pattern'")
    try:
        rule["_regex"] = re.compile(pattern)
    except re.error as e:
        raise RulesError(f"value rule '{name}' has an invalid pattern: {e}")

    validator = rule.get("validator")
    if validator is not None and validator not in VALIDATORS:
        raise RulesError(f"value rule '{name}' has unknown validator {validator!r}")


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


def luhn_valid(text):
    """True if the digits in text pass the Luhn checksum (used by card numbers).

    Spaces and dashes are ignored, so "4111 1111 1111 1111" works too.
    From the right: double every second digit (subtract 9 if the result is
    over 9), add everything up, and the total must end in 0.
    """
    digits = [int(c) for c in text if c in "0123456789"]
    if len(digits) < 13:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def apply_value_rules(text, rules, counts):
    """Redact every part of a string that matches a value rule.

    Only the matched part changes: "mail a@b.com now" -> "mail sha256:... now".
    """
    for rule in rules.get("value_rules", []):

        def replace(match):
            found = match.group(0)
            if rule.get("validator") == "luhn" and not luhn_valid(found):
                return found  # looks like a card number but isn't one: keep it
            counts[rule["name"]] += 1
            if rule["action"] == "remove":
                return ""
            return apply_action(rule["action"], found)

        # sub() calls replace() for every match and puts its result in place.
        text = rule["_regex"].sub(replace, text)
    return text


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

    if isinstance(value, str):
        # value_rules have no scope: they apply to every string, wherever it is.
        return apply_value_rules(value, rules, counts)

    # A number, true/false or null: nothing to search in.
    return value


# name=value pairs joined by "&", with no spaces, e.g. "email=a%40b.com&password=x".
FORM_RE = re.compile(r"[^=&\s]+=[^&\s]*(?:&[^=&\s]+=[^&\s]*)*")


def redact_body(body, rules, counts):
    """Redact a request or response body.

    A body can be JSON (already parsed), or a string. A string body can hold
    JSON, form-encoded data, or plain text, and each is handled differently.
    We look at the content itself and not at the Content-Type header, so a
    wrong or missing header can't make us skip redaction.
    """
    if not isinstance(body, str):
        return redact_value(body, "body", rules, counts)

    # 1. JSON inside a string, e.g. "{\"token\":\"abc\"}".
    if body.lstrip().startswith(("{", "[")):
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, (dict, list)):
            redacted = redact_value(parsed, "body", rules, counts)
            # Give it back as a string, so the field keeps its original type.
            return json.dumps(redacted, ensure_ascii=True, separators=(",", ":"))

    # 2. Form-encoded, e.g. "email=a%40b.com&password=x".
    if FORM_RE.fullmatch(body):
        return redact_form(body, rules, counts)

    # 3. Anything else (plain text, HTML, binary-looking data): value rules only.
    return apply_value_rules(body, rules, counts)


def redact_form(body, rules, counts):
    """Redact a form-encoded body: key rules on names, value rules on values."""
    result = []
    for pair in body.split("&"):
        raw_name, _, raw_value = pair.partition("=")
        # Decode first: "bob%40example.com" must become "bob@example.com"
        # or the email pattern won't see it.
        name = unquote_plus(raw_name)
        value = unquote_plus(raw_value)

        rule = find_key_rule(rules, name, "body")
        if rule is not None:
            counts[rule["name"]] += 1
            if rule["action"] == "remove":
                continue
            new_value = apply_action(rule["action"], value)
        else:
            new_value = apply_value_rules(value, rules, counts)

        if new_value == value:
            # Nothing to hide: keep the pair exactly as it was.
            result.append(pair)
        else:
            # Encode again. "*" and ":" stay readable ("****", "sha256:...").
            result.append(raw_name + "=" + quote_plus(new_value, safe="*:"))
    return "&".join(result)


def redact_path(path, rules, counts):
    """Redact a request path, including its query string.

    "/v1/reset?token=abc&email=gina%40example.com" -> the query part is
    handled like a form body, so key rules (token) and URL-decoding work.
    """
    base, question_mark, query = path.partition("?")
    base = apply_value_rules(base, rules, counts)
    if question_mark and FORM_RE.fullmatch(query):
        return base + "?" + redact_form(query, rules, counts)
    return base + question_mark + apply_value_rules(query, rules, counts)


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
            result[key] = redact_body(item, rules, counts)
        elif key == "path" and isinstance(item, str):
            result[key] = redact_path(item, rules, counts)
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
    except RecursionError:
        return placeholder(line_no, "too_deep"), "JSON nested too deeply"

    # Count into a separate Counter and add it to the totals only if the
    # whole line succeeds, so a failed line doesn't leave half its counts behind.
    line_counts = Counter()
    try:
        output = to_json_line(redact_record(record, rules, line_counts))
    except RecursionError:
        # Our redaction is recursive; Python stops at about 1000 levels.
        return placeholder(line_no, "too_deep"), "JSON nested too deeply"
    except Exception as e:
        # Safety net: a bug in our code must not crash the whole run or let
        # the line through unredacted. Only the error TYPE is reported,
        # because the message could contain the data.
        return placeholder(line_no, "internal_error"), f"internal error ({type(e).__name__})"

    counts.update(line_counts)
    return output, None


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
