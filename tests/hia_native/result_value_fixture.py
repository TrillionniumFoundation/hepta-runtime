# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Read complete, pinned original observations without executing an oracle.

These are native-test inputs, not fresh Rust evidence. The separate original
recipe recompiles the locked reference and replays every retained request.
"""
from pathlib import Path
import gzip
import hashlib
import json

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "result_value_fixtures"
COUNTS = {"binary32": {"main": 541693}, "typed": {"probes": 2, "cases": 5249},
          "request": {"probes": 44, "cases": 1926}}


def pack(path, raw):
    """Retain complete raw bytes in deterministic, bounded gzip storage."""
    encoded = gzip.compress(raw, compresslevel=6, mtime=0)
    Path(path).write_bytes(encoded)
    return dict(bytes=len(raw), sha256=SHA(raw), compressed_bytes=len(encoded),
                compressed_sha256=SHA(encoded))


def retained(domain, name, wire, output):
    manifest_raw = (FIXTURES / "manifest.json").read_bytes()
    manifest = json.loads(manifest_raw)
    assert manifest["schema"] == "hepta.result-values.retained-original-fixtures.v1"
    assert manifest["fresh_original_execution"] is False
    assert {key: {n: row["cases"] for n, row in value.items()}
            for key, value in manifest["domains"].items()} == COUNTS
    row = manifest["domains"][domain][name]
    assert row["file"] == domain + "-" + name + ".jsonl.gz"
    assert (len(wire), SHA(wire)) == (row["request_bytes"], row["request_sha256"]), (
        "native case generator differs from the complete actual-original input", domain, name)
    compressed = (FIXTURES / row["file"]).read_bytes()
    assert (len(compressed), SHA(compressed)) == (row["compressed_bytes"], row["sha256"])
    stdout = gzip.decompress(compressed)
    assert (len(stdout), SHA(stdout)) == (row["raw_bytes"], row["raw_sha256"])
    assert stdout.count(b"\n") == row["cases"]
    output = Path(output)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    inputs = pack(output / "requests.bin.gz", wire)
    observed = pack(output / "retained.stdout.gz", stdout)
    receipt = dict(schema="hepta.result-values.retained-input.v1", domain=domain, name=name,
        cases=row["cases"], observation_kind="retained-original-fixture", actual_original_executions=0,
        original_observation_job=row["actual_original_job"], fixture_manifest_sha256=SHA(manifest_raw),
        fixture_sha256=row["sha256"], input=inputs, stdout=observed)
    (output / "receipt.json").write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
    return stdout, receipt
