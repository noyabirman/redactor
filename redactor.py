"""API traffic log redactor.

Step 1: read NDJSON line by line (from a file or stdin) and print each line unchanged.
"""

import argparse
import sys


def main():
    parser = argparse.ArgumentParser(description="Redact sensitive data from NDJSON logs.")
    parser.add_argument("input_file", nargs="?", help="NDJSON file to read (default: stdin)")
    args = parser.parse_args()

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
