#!/usr/bin/env python3
"""Run one complete unmodified 926-case body domain at an explicit shared path."""
from pathlib import Path
import argparse
import json
from qualify_files import execute, REFERENCE

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = execute(args.binary.absolute(), REFERENCE, args.fixture.absolute(), args.output.absolute(), large=True)
    print(json.dumps(result, sort_keys=True))
