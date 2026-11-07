"""API traffic log redactor.

Step 2: load the rules file, then pass NDJSON lines through unchanged.
"""

import argparse
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

    # Iterating over a file reads one line at a time, so memory use stays small
    # no matter how big the input is.
    with source:
        for line in source:
            output.write(line)


if __name__ == "__main__":
    main()
