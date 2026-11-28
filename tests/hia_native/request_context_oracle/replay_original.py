"""Replay actual Rust observations through the selected native HIA owner.

This runner never calculates hint deduplication or scope results. Its expected
bytes are complete observations produced by the separately compiled original
RequestContext on the pinned Tokio runtime. Private framing is transport only.
"""
from __future__ import annotations
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import sys
import time


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def replay(original: Path, manifest: Path, loader_root: Path, output: Path) -> dict:
    sys.path.insert(0, str(loader_root / "scripts"))
    from hia_native_loader import NativeModule

    output.mkdir(parents=True, exist_ok=False)
    module = NativeModule(manifest, manifest_sha256=sha(manifest))
    counts = {"traces": 0, "calls": 0, "expected_bytes": 0, "matched_bytes": 0}
    started = time.monotonic()
    try:
        with gzip.open(output / "native-output.jsonl.gz", "wt", encoding="utf-8") as stream:
            for line in original.read_text().splitlines():
                row = json.loads(line)
                if row["schema"] != "hepta.runtime.request-context.original-trace.v1":
                    continue
                counts["traces"] += 1
                session = module.session(workspace_capacity=1 << 21, output_capacity=1 << 20)
                try:
                    for step in row["steps"]:
                        wire = bytes.fromhex(step["input_hex"])
                        expected = bytes.fromhex(step["output_hex"])
                        actual = session.invoke(wire)
                        stream.write(json.dumps({"trace": row["id"], "index": step["index"],
                            "operation": step["operation"], "input_hex": wire.hex(),
                            "output_hex": actual.hex()}, separators=(",", ":")) + "\n")
                        stream.flush()
                        counts["calls"] += 1
                        counts["expected_bytes"] += len(expected)
                        if actual != expected:
                            raise AssertionError({"trace": row["id"], "step": step,
                                "observed_hex": actual.hex()})
                        counts["matched_bytes"] += len(actual)
                finally:
                    session.close()
    finally:
        module.close()
    report = {"schema": "hepta.runtime.request-context.original-native-differential.v1",
        "ok": True, **counts, "seconds": time.monotonic() - started,
        "original_sha256": sha(original), "manifest_sha256": sha(manifest),
        "native_output_archive_sha256": sha(output / "native-output.jsonl.gz"),
        "expected_semantics": "compiled byte-identical original RequestContext with actual Tokio scopes",
        "peek_scope": "test-only clone observation; not an original public accessor",
        "cache_alias_scope": "private identifiers observing actual Arc<ViewCache> identities",
        "native_scheduler_executed": False, "production_cutover_qualified": False,
        "resource_scope": "finite exercised cases fit explicit native workspace/output extents"}
    (output / "RESULT.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--original", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--loader-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(replay(args.original, args.manifest, args.loader_root, args.output), sort_keys=True))
