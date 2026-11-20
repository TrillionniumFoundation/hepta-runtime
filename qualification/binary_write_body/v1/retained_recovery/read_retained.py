#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Read original captures through the repaired DATA reader; never run applications."""
from pathlib import Path
import argparse
import base64
import hashlib
import json
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SOURCE_MANIFEST = "5a4adda7189b444d5451381e815eaf7defdc4db0e42b77b222c9c630e8f3eb57"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--case", type=int, required=True)
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    work = args.work.resolve(strict=True)
    sys.path[:0] = [str(HERE), str(source / "scripts")]
    from evidence_common import decode, encoded, pin, require, source_evidence
    from read_capture import verify
    from readonly import guarded

    require(pin(source / "SOURCE_MANIFEST.json")["sha256"] == SOURCE_MANIFEST,
            "retained original source manifest changed")
    original_identity = source_evidence(source)
    runtime_path = work / "runtime"
    runtime = decode((runtime_path / "RUNTIME.json").read_bytes())
    require(runtime["status"] == "SOURCE_AND_RUNTIME_ONLY_PASS"
            and runtime["source"] == original_identity
            and runtime["python_version"] == [3, 12, 3]
            and runtime["signal_profile"] == {"13": 1, "25": 1}
            and runtime["original_write_application_calls"] == 0
            and runtime["native_write_application_calls"] == 0,
            "fixed retained original runtime input")
    require({p.name for p in runtime_path.iterdir()}
            == {"RUNTIME.json"} | {r["copy"] for r in runtime["modules"].values()},
            "complete retained runtime module set")
    for row in runtime["modules"].values():
        require(pin(runtime_path / row["copy"])
                == {k: row[k] for k in ("bytes", "sha256")},
                "complete retained runtime module bytes")
    result = guarded(
        lambda: verify(source, work / "cases" / str(args.case), args.case, runtime),
        roots=[source, runtime_path, work / "cases" / str(args.case), HERE],
    )
    result["recovery_reader"] = {
        name: pin(HERE / name)
        for name in ("read_retained.py", "read_capture.py", "kernel_binding.py",
                     "read_write_journal.py", "base64_3123.py")
    }
    result["original_source_identity"] = original_identity
    result["new_original_application_calls"] = 0
    result["new_native_application_calls"] = 0
    result["new_compiler_calls"] = 0
    print(encoded(result).decode(), end="")


if __name__ == "__main__":
    main()
