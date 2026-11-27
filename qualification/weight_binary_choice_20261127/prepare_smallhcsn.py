#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Bind sealed SmallHCSN data to actual prior native candidate receipts; no new forward."""

import argparse
import json
import re
import struct
from pathlib import Path

from verify_report import data_sha256, f32_bytes, require, sha


def choice_data(candidate):
    objective = candidate["objective"]
    require(objective["kind"] == "BinaryChoiceContrast" and objective["query_count"] == 80 and objective["input_rows"] == 160, "requires the complete 80-query sealed train task")
    rows = objective["linear_rows"]
    require(len(rows) == 160 and all(len(row) == 20 for row in rows), "requires actual 160 by 20 features")
    feature_bytes = b"".join(f32_bytes(value) for row in rows for value in row)
    require(feature_bytes.hex() == objective["linear_rows_f32_bytes_hex"] and sha(feature_bytes) == objective["linear_rows_f32_sha256"], "feature JSON differs from sealed F32 bytes")
    baseline_pairs = objective["baseline_candidate_scores"]
    require(len(baseline_pairs) == 80 and all(len(pair) == 2 for pair in baseline_pairs), "requires complete per-choice baselines")
    baseline = [value for pair in baseline_pairs for value in pair]
    baseline_bytes = b"".join(f32_bytes(value) for value in baseline)
    require(baseline_bytes.hex() == objective["baseline_f32_bytes_hex"] and sha(baseline_bytes) == objective["baseline_f32_sha256"], "baseline JSON differs from sealed F32 bytes")
    require(objective["pairing"] == [[2 * i, 2 * i + 1] for i in range(80)], "sealed query-major pairing differs")
    require(objective["absolute_query_margin_targets"] == [2 * label - 1 for label in objective["labels"]], "sealed +/-1 targets differ from labels")
    require(len(objective["labels"]) == 80 and all(type(label) is int and label in (0, 1) for label in objective["labels"]), "invalid binary labels")
    bindings = candidate["bindings"]
    seed = candidate["seed"]
    identity_context = bytes.fromhex(bindings["producer_cache_sha256"]) + struct.pack("<Q", seed)
    def identity(domain, index):
        return sha(domain + identity_context + struct.pack("<Q", index))
    data = {
        "producer": {
            "parent_checkpoint_sha256": candidate["parent_artifact_sha256"],
            "producer_code_sha256": bindings["producer_sha256"],
            "producer_cache_sha256": bindings["producer_cache_sha256"],
            "physical_source_sha256": bindings["physical_source_sha256"],
            "evaluation_protocol_sha256": bindings["new_protocol_sha256"],
        },
        "rows": rows,
        "row_ids": [identity(b"hepta.smallhcsn.train-row.v1\0", index) for index in range(160)],
        "baseline": baseline,
        "pairs": [{"query_id": identity(b"hepta.smallhcsn.train-query.v1\0", index), "choice0_row": 2 * index, "choice1_row": 2 * index + 1, "margin_target": target} for index, target in enumerate(objective["absolute_query_margin_targets"])],
    }
    return data, data_sha256(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-requests", type=Path, required=True)
    parser.add_argument("--receipt-map", type=Path, help="JSON mapping seed to actual f32_roundtrip stdout JSON path")
    parser.add_argument("--model-root", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--check-source-only", action="store_true")
    args = parser.parse_args()
    for path in (args.native_requests, args.receipt_map, args.model_root, args.out):
        require(path is None or path.is_absolute(), "all paths must be explicit and absolute")
    source_manifest_path = args.native_requests / "manifest.json"
    source_manifest_bytes = source_manifest_path.read_bytes()
    source_manifest = json.loads(source_manifest_bytes)
    expected = {row["seed"]: row for row in source_manifest["cases"]}
    require(set(expected) == {47, 83, 137}, "sealed source manifest seeds differ")
    require(args.check_source_only or args.receipt_map is not None, "receipt-bound generation requires --receipt-map")
    receipt_map = {} if args.check_source_only else json.loads(args.receipt_map.read_bytes())
    if not args.check_source_only:
        require(args.model_root is not None and args.out is not None, "receipt-bound generation requires model root and new output directory")
        require(set(receipt_map) == {"47", "83", "137"}, "requires all three actual candidate receipts")
    results = []
    pending = []
    for seed in (47, 83, 137):
        source_path = args.native_requests / f"candidate_{seed}.json"
        source_bytes = source_path.read_bytes()
        require(sha(source_bytes) == expected[seed]["sha256"], "sealed source file differs from manifest")
        candidate = json.loads(source_bytes)
        require(candidate["seed"] == seed and candidate["weight_shape"] == [2, 20], "wrong actual model profile")
        data, commitment = choice_data(candidate)
        record = {"seed": seed, "source_request_sha256": sha(source_bytes), "data_sha256": commitment, "rows": 160, "queries": 80, "new_model_forwards": 0}
        if not args.check_source_only:
            receipt_path = Path(receipt_map[str(seed)])
            require(receipt_path.is_absolute(), "receipt path must be absolute")
            receipt_bytes = receipt_path.read_bytes()
            roundtrip = json.loads(receipt_bytes)
            require(roundtrip["schema"] == "hepta.weight.source-bound-f32-research-roundtrip.v1", "wrong native engineering receipt")
            receipt = roundtrip["evaluation"]["guard"]["candidate"]
            require(receipt["source_sha256"] == candidate["parent_artifact_sha256"] and receipt["sha256"] == candidate["local_precompiled_candidate_sha256"], "native candidate is not the sealed inward candidate")
            require(re.fullmatch(r"wa1_[0-9a-f]{64}", receipt["artifact_id"]) is not None, "invalid canonical F32 artifact ID")
            require(receipt["source_modified"] is False and receipt["production_eligible"] is False, "unexpected native artifact scope")
            require(roundtrip["restored"]["restored_complete_bytes_and_stored_bias_reauthenticated"] is True, "prior engineering roundtrip lacks restored source verification")
            bias_sha = sha(bytes.fromhex(candidate["bias_f32_bytes_hex"]))
            request = {"kind": "binary_choice_contrast", "params": {
                "parent": {"input": {"kind": "path", "path": str(args.model_root / Path(candidate["parent_artifact"]).name)}, "complete_sha256": candidate["parent_artifact_sha256"], "weight_payload_sha256": sha(bytes.fromhex(candidate["old_weight_f32_bytes_hex"])), "bias_payload_sha256": bias_sha},
                "candidate": {"input": {"kind": "artifact", "artifact_id": receipt["artifact_id"]}, "complete_sha256": candidate["local_precompiled_candidate_sha256"], "weight_payload_sha256": candidate["new_weight_f32_sha256"], "bias_payload_sha256": bias_sha},
                "weight_tensor": candidate["weight_tensor"], "bias_tensor": candidate["bias_tensor"], "data": data, "expected_data_sha256": commitment,
            }}
            output = json.dumps(request, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"
            require(len(output) <= 1024 * 1024, "native contrast request exceeds its byte cap")
            name = f"seed{seed}_binary_choice_contrast.json"
            pending.append((name, output))
            record.update(request_file=name, request_sha256=sha(output), bytes=len(output), candidate_artifact_id=receipt["artifact_id"], native_roundtrip_sha256=sha(receipt_bytes))
        results.append(record)
    manifest = {"schema": "hepta.smallhcsn.native-binary-choice-inputs.v1", "source_manifest_sha256": sha(source_manifest_bytes), "preparer_sha256": sha(Path(__file__).read_bytes()), "reference_sha256": sha(Path(__file__).with_name("verify_report.py").read_bytes()), "cases": results, "new_model_forwards": 0, "new_parameter_fits": 0, "new_candidate_selection": False, "full_model_executed": False, "production_eligible": False}
    if not args.check_source_only:
        args.out.mkdir(parents=True, exist_ok=False)
        for name, output in pending:
            (args.out / name).write_bytes(output)
        (args.out / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    print(json.dumps(manifest, sort_keys=True, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
