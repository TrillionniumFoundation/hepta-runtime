# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Execute original large-domain limits and descriptor-mutation controls."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess
import time

from qualify_rea_zip_differential import classic
from rea_zip_native_transport import ZipModule, request


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", type=Path, required=True)
    ap.add_argument("--manifest", type=Path, required=True)
    ap.add_argument("--oracle", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    out = args.output
    out.mkdir(mode=0o700, exist_ok=False)
    (out / "qualification-source.py").write_bytes(Path(__file__).read_bytes())
    module = ZipModule(args.manifest, args.source)
    rows = []
    started = time.monotonic()
    try:
        for label, count, name_bytes in [
            ("full-50000-entry-domain", 50000, 8),
            ("count-50001-refusal", 50001, 8),
            ("retained-budget-below", 50000, 143),
            ("retained-budget-above", 50000, 144),
        ]:
            entries = [{"name": (f"{index:08}" + "x" * (name_bytes - 8)).encode()}
                       for index in range(count)]
            data = classic(entries)
            path = out / (label + ".zip")
            path.write_bytes(data)
            path.chmod(0o400)
            pin = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            del entries, data
            case = {"path": str(path), "filter": "all", "offset": 0, "limit": 1}
            reference = subprocess.run([str(args.oracle)], input=json.dumps(case) + "\n",
                text=True, capture_output=True, timeout=120)
            (out / (label + ".reference.stdout")).write_text(reference.stdout)
            (out / (label + ".reference.stderr")).write_text(reference.stderr)
            assert reference.returncode == 0
            expected = json.loads(reference.stdout)
            fd = os.open(path, os.O_RDONLY)
            tick = time.monotonic()
            try:
                with (out / (label + ".events.jsonl")).open("x") as stream:
                    wire = request(fd, limit=1)
                    stream.write(json.dumps({"event": "input", "bytes_hex": wire.hex()}) + "\n")
                    actual = module.invoke(wire, fd, stream)
            finally:
                os.close(fd)
            received = ({"ok": True, "value": json.loads(actual["payload"])}
                        if actual["status"] == 0 else {"ok": False, "error": actual["payload"]})
            row = {"label": label, "fixture": pin, "reference": expected, "native": received,
                "equal": expected == received, "native_calls": actual["native_calls"],
                "native_effects": actual["effects"], "seconds": time.monotonic() - tick}
            rows.append(row)
            (out / "progress.json").write_text(json.dumps(rows, sort_keys=True, indent=2) + "\n")
            print(json.dumps({k: row[k] for k in ["label", "equal", "native_calls", "native_effects", "seconds"]}), flush=True)
            assert row["equal"]

        seed = (args.source / "tests/fixtures/rea_artifact_sample.zip").read_bytes()
        changed = out / "changed-during-read.zip"
        changed.write_bytes(seed)
        changed.chmod(0o600)
        fd = os.open(changed, os.O_RDONLY)
        mutations = []
        try:
            def mutate(effect, _):
                if effect[2] == 2:
                    before = os.stat(changed)
                    os.utime(changed, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000))
                    after = os.stat(changed)
                    mutations.append({"before_mtime_ns": before.st_mtime_ns,
                        "after_mtime_ns": after.st_mtime_ns})
            with (out / "changed-during-read.events.jsonl").open("x") as stream:
                wire = request(fd)
                stream.write(json.dumps({"event": "input", "bytes_hex": wire.hex()}) + "\n")
                actual = module.invoke(wire, fd, stream, before_effect=mutate)
            assert actual["status"] == 1 and actual["payload"] == "REA inspection denied: admitted artifact changed during read"
            assert len(mutations) == 1 and mutations[0]["before_mtime_ns"] != mutations[0]["after_mtime_ns"]
            rows.append({"label": "real-descriptor-mutation", "native": actual,
                "mutations": mutations, "expected_original_ensure_unchanged_error": True})
        finally:
            os.close(fd)
        report = {"status": "PASS", "limit_comparisons": 4, "descriptor_mutation_controls": 1,
            "seconds": time.monotonic() - started, "rows": rows, "full_public_route_qualified": False}
        (out / "terminal.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
        print(json.dumps({k: v for k, v in report.items() if k != "rows"}), flush=True)
    finally:
        module.close()


if __name__ == "__main__":
    main()
