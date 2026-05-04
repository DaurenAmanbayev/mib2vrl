"""
Subprocess entry point for isolated, timeout-killable MIB parsing.

Run as: python -m mib2vrl._parse_single <path>

Prints a JSON array of serialised MibModule dicts to stdout.
Any parse errors are raised as exceptions (non-zero exit → parent logs them).
"""

import dataclasses
import json
import sys

from mib2vrl.parser.mib_parser import parse_file


def main() -> None:
    path = sys.argv[1]
    try:
        content = open(path, encoding="utf-8").read()
    except UnicodeDecodeError:
        content = open(path, encoding="latin-1").read()

    modules = parse_file(content, source_file=path)
    print(json.dumps([dataclasses.asdict(m) for m in modules]))


if __name__ == "__main__":
    main()
