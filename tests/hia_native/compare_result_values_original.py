# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Compile one locked reference project and replay one complete result domain."""
from pathlib import Path
import argparse
import json
import os
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from result_value_registry import COUNTS, DOMAINS, encoded, regular, require, sha
from hia_native_result_qualification import inspect_native_outputs, inspect_original_domain
from hia_native_result_reference import replay_domain


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repo", "build", "native", "output", "rustc", "cargo"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--domain", choices=DOMAINS, required=True)
    args = parser.parse_args()
    require(os.getpgrp() == os.getpid(), "original result wrapper requires an outer-owned isolated process group")
    root = args.repo.resolve(strict=True)
    native = args.native.resolve(strict=True)
    before = inspect_native_outputs(root, args.build, native)
    result = replay_domain(root, args.output, native, args.domain, args.rustc.absolute(), args.cargo.absolute())
    checked = inspect_original_domain(root, args.output, native, args.domain,
        rustc=args.rustc.absolute(), cargo=args.cargo.absolute())
    require(checked["result"] == result and inspect_native_outputs(root, args.build, native) == before,
        "native evidence changed while executing original comparison")
    print(json.dumps(dict(schema="hepta.result-values.original-summary.v1", status="PASS", domain=args.domain,
        cases=sum(COUNTS[args.domain].values()), actual_original_processes=len(COUNTS[args.domain]),
        actual_native_entries_added=0, complete_bytes_equal=True,
        result_sha256=sha(regular(args.output / args.domain / "result.json")),
        shared_build_sha256=sha(regular(args.output / "build/result.json")))))


if __name__ == "__main__":
    main()
