#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Independent bit-level task aggregation of actual native output; no model forward."""

import argparse
import hashlib
import json
import math
import struct
from pathlib import Path


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def f32(value):
    value = struct.unpack("<f", struct.pack("<f", value))[0]
    require(math.isfinite(value), "nonfinite F32 value")
    return value


def f32_bytes(value):
    return struct.pack("<f", f32(value))


def from_bits(value):
    require(type(value) is int and 0 <= value < 2**32, "invalid unsigned F32 bits")
    return f32(struct.unpack("<f", struct.pack("<I", value))[0])


def bits(value):
    return struct.unpack("<I", f32_bytes(value))[0]


def valid_hash(value):
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def data_sha256(data):
    rows = data["rows"]
    require(2 <= len(rows) <= 4096 and len(rows) % 2 == 0, "incomplete paired rows")
    columns = len(rows[0])
    require(1 <= columns <= 4096, "invalid columns")
    require(all(len(row) == columns for row in rows), "ragged rows")
    require(len(data["row_ids"]) == len(rows), "row identity length differs")
    require(len(set(data["row_ids"])) == len(rows), "duplicate row identity")
    require(len(data["baseline"]) == len(rows), "baseline length differs")
    require(len(data["pairs"]) * 2 == len(rows), "pair count differs")
    require(len({pair["query_id"] for pair in data["pairs"]}) == len(data["pairs"]), "duplicate query identity")
    require(len(rows) * columns * 4 <= 16_777_216, "combined MAC budget exceeded")
    require(len(rows) * 7 <= 16_384, "combined output and aggregation budget exceeded")
    h = hashlib.sha256(b"hepta.weight.binary-choice-data.v1\0")
    for field in ("parent_checkpoint_sha256", "producer_code_sha256", "producer_cache_sha256", "physical_source_sha256", "evaluation_protocol_sha256"):
        value = data["producer"][field]
        require(valid_hash(value), f"invalid producer hash: {field}")
        h.update(value.encode("ascii"))
    h.update(struct.pack("<QQ", len(rows), columns))
    for row, identity, baseline in zip(rows, data["row_ids"], data["baseline"]):
        require(valid_hash(identity), "invalid row identity")
        h.update(identity.encode("ascii"))
        for value in row:
            h.update(f32_bytes(value))
        h.update(f32_bytes(baseline))
    h.update(struct.pack("<Q", len(data["pairs"])))
    for index, pair in enumerate(data["pairs"]):
        require(valid_hash(pair["query_id"]), "invalid query identity")
        require(type(pair["choice0_row"]) is int and pair["choice0_row"] == 2 * index, "wrong choice0 pairing")
        require(type(pair["choice1_row"]) is int and pair["choice1_row"] == 2 * index + 1, "wrong choice1 pairing")
        require(type(pair["margin_target"]) is int and pair["margin_target"] in (-1, 1), "invalid margin target")
        h.update(pair["query_id"].encode("ascii"))
        h.update(struct.pack("<QQb", pair["choice0_row"], pair["choice1_row"], pair["margin_target"]))
    return h.hexdigest()


def aggregate(raw_bits, data):
    require(len(raw_bits) == len(data["rows"]), "raw head length differs")
    scores = []
    for row, baseline in zip(raw_bits, data["baseline"]):
        require(len(row) == 2, "raw head width differs")
        contrast = f32(from_bits(row[1]) - from_bits(row[0]))
        scores.append(f32(f32(baseline) + contrast))
    margins = []
    squared_error = 0.0
    correct = 0
    for pair in data["pairs"]:
        margin = f32(scores[pair["choice1_row"]] - scores[pair["choice0_row"]])
        error = float(margin) - pair["margin_target"]
        squared_error += error * error
        margins.append(bits(margin))
        correct += (margin > 0.0) == (pair["margin_target"] == 1)
    return {"query_margin_bits": margins, "mean_squared_margin_error": squared_error / len(margins), "correct_queries": correct, "accuracy": correct / len(margins)}


def verify(request, report):
    require(request["kind"] == "binary_choice_contrast", "wrong request kind")
    params = request["params"]
    data = params["data"]
    commitment = data_sha256(data)
    require(commitment == params["expected_data_sha256"] == report["data_sha256"], "data commitment differs")
    require(data["producer"] == report["producer"], "producer declarations differ")
    require(data["producer"]["parent_checkpoint_sha256"] == params["parent"]["complete_sha256"], "feature parent differs")
    require(report["schema"] == "hepta.weight.binary-choice-contrast.v1", "wrong report schema")
    require(report["full_model_executed"] is False and report["feature_provenance_verified"] is False and report["production_eligible"] is False, "scope claims changed")
    require(report["complete_sources_authenticated"] is True and report["physical_and_bias_bytes_unchanged"] is True, "missing native source authentication")
    require(report["operation_deadline_seconds"] == 60 and report["batch_row_limit"] == 64, "original deadline or batch limit changed")
    require(math.isfinite(report["seconds_elapsed"]) and 0 <= report["seconds_elapsed"] <= 60, "native evaluation exceeded its deadline")
    rows, columns = len(data["rows"]), len(data["rows"][0])
    expected_work = {"rows": rows, "queries": rows // 2, "columns": columns, "combined_linear_macs": rows * columns * 4, "combined_linear_output_values": rows * 4, "combined_aggregate_values": rows * 3, "combined_output_and_aggregate_values": rows * 7}
    require(report["work"] == expected_work, "combined work differs")
    independent = {}
    for model in ("parent", "candidate"):
        result, binding = report[model], params[model]
        for field, expected_field in (("complete_sha256", "complete_sha256"), ("weight_payload_sha256", "weight_payload_sha256"), ("bias_payload_sha256", "bias_payload_sha256")):
            require(result["source"][field] == binding[expected_field], f"{model} source binding differs")
        require(result["source"]["complete_source_hash_passes"] == 1, "capture pass accounting differs")
        expected = aggregate(result["raw_head_bits"], data)
        for field, value in expected.items():
            require(result[field] == value, f"{model} native {field} differs from independent F32 aggregation")
        chunks = list(range(0, rows, 64))
        require(len(result["batches"]) == len(chunks), "batch count differs")
        for start, batch in zip(chunks, result["batches"]):
            count = min(64, rows - start)
            require(batch["start_row"] == start and batch["row_count"] == count, "batch row range differs")
            require(batch["macs"] == count * columns * 2 and batch["output_values"] == count * 2, "batch work differs")
            require(batch["source_sha256"] == binding["complete_sha256"] and batch["captured_weight_payload_sha256"] == binding["weight_payload_sha256"], "batch source commitment differs")
            payload = b"".join(struct.pack("<II", *row) for row in result["raw_head_bits"][start:start + count])
            require(batch["raw_output_bits_sha256"] == sha(payload), "batch raw outputs differ")
        independent[model] = {key: value for key, value in expected.items() if key != "query_margin_bits"}
    for field in ("source_size_bytes", "weight_offset", "weight_length", "protected_bytes_sha256", "bias_payload_sha256"):
        require(report["parent"]["source"][field] == report["candidate"]["source"][field], "protected model identity differs")
    require(report["mean_squared_error_reduction"] == independent["parent"]["mean_squared_margin_error"] - independent["candidate"]["mean_squared_margin_error"], "MSE change differs")
    require(report["accuracy_change"] == independent["candidate"]["accuracy"] - independent["parent"]["accuracy"], "accuracy change differs")
    return {"schema": "hepta.weight.binary-choice-independent-report-check.v1", "pass": True, "data_sha256": commitment, "parent": independent["parent"], "candidate": independent["candidate"], "native_output_aggregation_only": True, "new_model_forwards": 0, "full_model_executed": False, "production_eligible": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("request", type=Path)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    request_bytes, report_bytes = args.request.read_bytes(), args.report.read_bytes()
    result = verify(json.loads(request_bytes), json.loads(report_bytes))
    result.update(request_file_sha256=sha(request_bytes), report_file_sha256=sha(report_bytes), verifier_sha256=sha(Path(__file__).read_bytes()))
    print(json.dumps(result, sort_keys=True, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
