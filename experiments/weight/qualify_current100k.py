#!/usr/bin/env python3
"""Read pinned input-only rows and qualify one disposable Current100k CPU session.

The comparison tolerance is fixed here before any model output is observed.
This checks engineering parity, cache behavior and reversible head edits. It
does not read outcomes, establish model quality, or change a frozen experiment.
Source files are read-only; a new output directory retains immutable receipts.
"""
import argparse
import hashlib
import os
from pathlib import Path
import resource
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "workers" / "weight"))

from weight_runtime.artifacts import atomic_create, file_sha256
from weight_runtime.current100k import CONTRACT, FEATURE_WIDTH, SCALE_USD, validate_rows
from weight_runtime.errors import WeightError, canonical, checksum, digest, integer, loads, need
from weight_runtime.patches import tensor_sha256
from weight_runtime.session import Session


SCHEMA = "hepta.weight.current100k-engineering-qualification.v1"
FEATURE_ATOL = 2e-6
FEATURE_RTOL = 2e-5
HEAD_DELTA_SCALED = 0.01
USD_DELTA_ATOL = 2e-6
USD_DELTA_RTOL = 2e-5
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_FEATURE_BYTES = 64 * 1024 * 1024


def pinned_bytes(path, expected, maximum):
    checksum(expected)
    source = Path(path).resolve(strict=True)
    need(source.is_file(), "INVALID_PATH", "Pinned input must be a file")
    with source.open("rb") as stream:
        content = stream.read(maximum + 1)
    need(len(content) <= maximum, "INPUT_LIMIT", "Pinned input exceeds its byte limit", path=str(source))
    need(hashlib.sha256(content).hexdigest() == expected,
         "IDENTITY_MISMATCH", "Pinned input SHA256 differs", path=str(source))
    return source, content


def reference_features(content, indices, row_count):
    import torch
    from safetensors.torch import load
    need(isinstance(indices, (list, tuple)) and len(indices) == row_count
         and len(set(indices)) == len(indices), "INVALID_REFERENCE", "Reference indices must match ordered input rows")
    for index in indices:
        integer(index, "reference_index", 0, 100000)
    # Inspect only the tensor directory before decoding payload values. A file
    # containing labels is not admitted or loaded as an outcome-bearing dataset.
    need(len(content) >= 8, "INVALID_REFERENCE", "Truncated safetensors input")
    header_bytes = int.from_bytes(content[:8], "little")
    need(2 <= header_bytes <= 1024 * 1024 and 8 + header_bytes <= len(content),
         "INVALID_REFERENCE", "Reference tensor directory exceeds its bounds")
    header = loads(content[8:8 + header_bytes])
    need(isinstance(header, dict) and set(header) == {"features"},
         "INVALID_REFERENCE", "Reference must contain only the features tensor, without labels or metadata")
    tensors = load(content)
    features = tensors["features"]
    need(features.dtype == torch.float32 and features.ndim == 2 and features.shape[1] == FEATURE_WIDTH
         and features.shape[0] > max(indices) and bool(torch.isfinite(features).all()),
         "INVALID_REFERENCE", "Expected a finite FP32 reference matrix [rows,768]")
    selected = features[list(indices)].clone()
    return selected, {"full_shape": list(features.shape), "dtype": str(features.dtype),
                      "selected_indices": list(indices), "selected_tensor_sha256": tensor_sha256(selected)}


def comparison(actual, reference, atol, rtol):
    import torch
    need(actual.shape == reference.shape and actual.dtype == reference.dtype == torch.float32,
         "REFERENCE_SHAPE", "Actual and reference FP32 shapes differ")
    delta = (actual.double() - reference.double()).abs()
    reference_abs = reference.double().abs()
    allowed = atol + rtol * reference_abs
    nonzero = reference_abs > 0
    return {"atol": atol, "rtol": rtol, "max_abs": float(delta.max()),
            "max_relative_nonzero_reference": float((delta[nonzero] / reference_abs[nonzero]).max())
                if bool(nonzero.any()) else None,
            "elements_outside_tolerance": int((delta > allowed).sum()),
            "bitwise_equal": tensor_sha256(actual) == tensor_sha256(reference),
            "passed": bool((delta <= allowed).all())}


def exercise(session, opened, rows, reference, timings, observations):
    """Exercise an already-open actual provider once, without reopening its base."""
    import torch
    need(opened["model"]["provider"] == "current100k_value"
         and opened["model"]["task_kind"] == "regression",
         "TASK_SEMANTICS", "Qualification requires Current100k USD regression")
    need(opened["model"]["task_contract"] == CONTRACT,
         "IDENTITY_MISMATCH", "Opened Current100k contract differs")
    n = len(rows)
    results = {}

    def call(name, operation, params):
        wall, cpu = time.monotonic(), time.process_time()
        try:
            result = session.dispatch(operation, params)
            observations.append({"name": name, "operation": operation, "result": result})
            return result
        finally:
            timings[name] = {"wall_seconds": time.monotonic() - wall,
                             "cpu_seconds": time.process_time() - cpu}

    def output(result):
        values = session.store.load_tensors(result["outputs"]["artifact_id"])
        need(set(values) == {"features", "value_scaled", "value_usd"},
             "TASK_SEMANTICS", "Unexpected Current100k output tensors")
        return values

    parent = call("parent", "probe", {"inputs": {"rows": rows}})
    before = output(parent)
    results["reference_feature_parity"] = comparison(before["features"], reference, FEATURE_ATOL, FEATURE_RTOL)
    results["reference_feature_parity"]["actual_tensor_sha256"] = tensor_sha256(before["features"])
    results["parent_input"] = parent["input"]
    results["parent_computation"] = parent["computation"]
    # Keep all diagnostics when reference parity fails; later checks still
    # inspect only frozen inputs and model state, never labels or rewards.
    need(parent["input"]["input_id"] == digest(rows)
         and [r["row_sha256"] for r in parent["input"]["rows"]] == [digest(row) for row in rows],
         "INPUT_IDENTITY", "Provider did not preserve frozen row identities")
    for name in ("value_scaled", "value_usd"):
        need(tuple(before[name].shape) == (n,), "REFERENCE_SHAPE", "Current100k scalar output shape changed")
    need(torch.equal(before["value_usd"], before["value_scaled"] * SCALE_USD),
         "OUTPUT_SCALE", "Raw USD scaling differs")
    parent_weight = session.provider.get_tensor("value.weight")
    parent_bias = session.provider.get_tensor("value.bias")
    parent_hashes = {"value.weight": tensor_sha256(parent_weight), "value.bias": tensor_sha256(parent_bias)}
    patch = call("head_patch", "patch", {
        "expected_model_id": opened["model_id"], "operations": [{
            "tensor": "value.bias", "operation": "add", "indices": [0],
            "value": HEAD_DELTA_SCALED, "expected_tensor_sha256": parent_hashes["value.bias"]}]})
    serialized = session.store.load_tensors(patch["parameters"]["artifact_id"])
    need(set(serialized) == {"value.bias"}, "PATCH_SCOPE", "Qualification changed more than the bias")
    realized_usd_delta = float((serialized["value.bias"].double() - parent_bias.double())[0]) * SCALE_USD
    need(realized_usd_delta != 0, "PATCH_NO_EFFECT", "Bias delta vanished in actual FP32 storage")
    patched = call("patched", "probe", {"inputs": {"rows": rows}, "patch_id": patch["patch"]["artifact_id"]})
    changed = output(patched)
    measured_usd_delta = changed["value_usd"] - before["value_usd"]
    wanted_delta = torch.full_like(measured_usd_delta, realized_usd_delta)
    results["head_patch"] = {"requested_delta_scaled": HEAD_DELTA_SCALED,
                             "realized_delta_usd": realized_usd_delta,
                             "actual_delta_usd": measured_usd_delta.tolist(),
                             "effect": comparison(measured_usd_delta, wanted_delta, USD_DELTA_ATOL, USD_DELTA_RTOL),
                             "features_unchanged": torch.equal(before["features"], changed["features"]),
                             "computation": patched["computation"], "patch": patch}
    restored = call("restored_uncached", "probe", {"inputs": {"rows": rows}, "bypass_feature_cache": True})
    after = output(restored)
    final_hashes = {name: tensor_sha256(session.provider.get_tensor(name)) for name in parent_hashes}
    results["restoration"] = {
        "parent_parameter_hashes": parent_hashes, "final_parameter_hashes": final_hashes,
        "same_parameters": final_hashes == parent_hashes,
        "same_output_artifact_bytes": restored["outputs"]["sha256"] == parent["outputs"]["sha256"],
        "same_features": torch.equal(before["features"], after["features"]),
        "same_usd_values": torch.equal(before["value_usd"], after["value_usd"]),
        "computation": restored["computation"],
    }
    same_input = all(result["input"] == parent["input"] for result in (patched, restored))
    results["encoded_input_identity_preserved"] = same_input
    computational_checks = {
        "logical_rows_counted_each_time": all(r["computation"]["logical_forward_examples"] == n
                                              for r in (parent, patched, restored)),
        "head_patch_reused_all_features": patched["computation"]["feature_cache_hits"] == n
            and patched["computation"]["encoder_forward_examples"] == 0,
        "restoration_recomputed_every_row": restored["computation"]["encoder_forward_examples"] == n
            and restored["computation"]["feature_cache_hits"] == 0
            and restored["computation"]["feature_cache_bypass_reason"] == "explicit_recomputation",
        "logical_forward_budget": session.forward_examples == 3 * n,
        "one_patch_candidate": session.patch_candidates == 1,
    }
    results["computation_checks"] = computational_checks
    results["counts"] = {"logical_forward_examples": session.forward_examples,
                         "patch_candidates": session.patch_candidates,
                         "encoder_forward_examples": sum(r["computation"]["encoder_forward_examples"]
                                                         for r in (parent, patched, restored)),
                         "feature_cache_hits": sum(r["computation"]["feature_cache_hits"]
                                                   for r in (parent, patched, restored)),
                         "model_forward_seconds": sum(r["model_forward_seconds"] for r in (parent, patched, restored)),
                         "backward_steps": 0, "optimizer_calls": 0}
    results["passed"] = bool(results["reference_feature_parity"]["passed"]
                              and results["head_patch"]["effect"]["passed"]
                              and results["head_patch"]["features_unchanged"] and same_input
                              and all(computational_checks.values())
                              and all(results["restoration"][key] for key in
                                      ("same_parameters", "same_output_artifact_bytes", "same_features", "same_usd_values")))
    return results


def run(model_config, model_config_sha256, input_rows, input_rows_sha256,
        reference_path, reference_sha256, reference_indices, output_dir, cpu_threads=2,
        *, session_factory=Session):
    """One immutable run; an existing directory is never replayed or overwritten."""
    started, cpu_started = time.monotonic(), time.process_time()
    integer(cpu_threads, "cpu_threads", 1, 8)
    config_path, config_bytes = pinned_bytes(model_config, model_config_sha256, MAX_JSON_BYTES)
    rows_path, row_bytes = pinned_bytes(input_rows, input_rows_sha256, MAX_JSON_BYTES)
    reference_source, reference_bytes = pinned_bytes(reference_path, reference_sha256, MAX_FEATURE_BYTES)
    config, rows = loads(config_bytes), validate_rows(loads(row_bytes))
    need(isinstance(config, dict) and all(key in config for key in ("source_dir", "base_dir", "head_path", "head_sha256")),
         "INVALID_MODEL", "Expected a Current100k model configuration")
    # Three logical passes must fit the existing worker's hard 160-example cap.
    need(3 * len(rows) <= 160, "EXPERIMENT_BUDGET", "Qualification supports at most 53 frozen rows")
    reference, reference_info = reference_features(reference_bytes, reference_indices, len(rows))
    del reference_bytes
    head_path = Path(config["head_path"]).resolve(strict=True)
    source_pins = {str(config_path): model_config_sha256, str(rows_path): input_rows_sha256,
                   str(reference_source): reference_sha256, str(head_path): checksum(config["head_sha256"])}
    need(file_sha256(head_path) == config["head_sha256"], "IDENTITY_MISMATCH", "Original head hash differs before load")
    root = Path(output_dir).absolute()
    need(not root.exists() and not root.is_symlink(), "OUTPUT_EXISTS", "Use a new qualification directory; no automatic replay")
    root.mkdir(parents=True, mode=0o700, exist_ok=False)
    roots = sorted({str(Path(config["source_dir"]).resolve(strict=True)),
                    str(Path(config["base_dir"]).resolve(strict=True)), str(head_path.parent)})
    open_spec = {"provider": "current100k_value", "model": config, "input_roots": roots,
                 "output_root": str(root / "artifacts"), "cpu_threads": cpu_threads,
                 "limits": {"max_forward_examples": 3 * len(rows), "max_patch_candidates": 1}}
    declared = {"schema": SCHEMA, "script_sha256": file_sha256(__file__),
                "source_pins": source_pins, "reference": reference_info, "rows": len(rows),
                "input_rows_digest": digest(rows), "cpu_threads_requested": cpu_threads,
                "feature_atol": FEATURE_ATOL, "feature_rtol": FEATURE_RTOL,
                "head_delta_scaled": HEAD_DELTA_SCALED,
                "usd_delta_atol": USD_DELTA_ATOL, "usd_delta_rtol": USD_DELTA_RTOL,
                "open_spec_sha256": digest(open_spec), "task_contract_sha256": digest(CONTRACT),
                "engineering_parity_only": True, "labels_read": False,
                "production_eligible": False, "quality_improvement_claim": False}
    atomic_create(root / "started.json", canonical(declared) + b"\n")
    session, opened, details, failure, closed = None, None, None, None, None
    observations, timings = [], {}
    try:
        session = session_factory("current100k-qualification")
        wall, cpu = time.monotonic(), time.process_time()
        try:
            opened = session.open(open_spec)
        finally:
            timings["load"] = {"wall_seconds": time.monotonic() - wall,
                               "cpu_seconds": time.process_time() - cpu}
        details = exercise(session, opened, rows, reference, timings, observations)
    except Exception as exc:
        failure = exc.as_dict() if isinstance(exc, WeightError) else {
            "code": "QUALIFICATION_ERROR", "message": str(exc)[:2048], "exception_type": type(exc).__name__}
    finally:
        if session is not None:
            wall, cpu = time.monotonic(), time.process_time()
            try:
                closed = session.close({})
            except Exception as exc:
                failure = {"code": "CLOSE_FAILED", "message": str(exc)[:2048], "prior_failure": failure}
            timings["close"] = {"wall_seconds": time.monotonic() - wall,
                                "cpu_seconds": time.process_time() - cpu}
    final_hashes = {}
    for path, expected in source_pins.items():
        try:
            final_hashes[path] = file_sha256(path)
        except OSError:
            final_hashes[path] = None
    sources_unchanged = final_hashes == source_pins
    passed = failure is None and details is not None and details["passed"] and sources_unchanged and closed["closed"]
    receipt = {**declared, "status": "PASS_ENGINEERING_PARITY" if passed else "FAIL_ENGINEERING_PARITY",
               "passed": bool(passed), "opened": opened, "checks": details, "failure": failure,
               "source_hashes_after": final_hashes, "source_files_unchanged": sources_unchanged,
               "session_open_calls": 1, "close": closed, "observations": observations,
               "timings": timings, "total_wall_seconds": time.monotonic() - started,
               "total_cpu_seconds": time.process_time() - cpu_started,
               "peak_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * (1 if sys.platform == "darwin" else 1024),
               "limitations": [
                   "Frozen reference indices are caller-declared and must be matched to original row receipts",
                   "CPU thread/library differences may change floating-point bytes; the tolerance was fixed before execution",
                   "No outcomes were loaded; parity and reversible edits do not establish predictive quality or financial returns",
                   "This exercises the resident Session provider, not the MCP transport or production model-selection path",
                   "A failed or interrupted directory is retained and cannot be automatically replayed",
               ]}
    receipt["receipt_sha256"] = digest(receipt)
    atomic_create(root / "qualification.json", canonical(receipt) + b"\n")
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("model-config", "model-config-sha256", "input-rows", "input-rows-sha256",
                 "reference-features", "reference-features-sha256", "output-dir"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--reference-indices", required=True, type=int, nargs="+")
    parser.add_argument("--cpu-threads", type=int, default=2)
    args = parser.parse_args()
    os.environ.update(HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1", TOKENIZERS_PARALLELISM="false", USE_TF="0")
    os.umask(0o077)
    try:
        result = run(args.model_config, args.model_config_sha256, args.input_rows, args.input_rows_sha256,
                     args.reference_features, args.reference_features_sha256, args.reference_indices,
                     args.output_dir, args.cpu_threads)
    except (WeightError, OSError, ValueError) as exc:
        error = exc.as_dict() if isinstance(exc, WeightError) else {"code": type(exc).__name__, "message": str(exc)}
        print(canonical({"ok": False, "error": error, "engineering_parity_only": True}).decode())
        return 1
    print(canonical({"ok": result["passed"], "status": result["status"],
                     "receipt": str(Path(args.output_dir).absolute() / "qualification.json"),
                     "receipt_sha256": result["receipt_sha256"], "checks": result["checks"],
                     "total_wall_seconds": result["total_wall_seconds"], "failure": result["failure"]}).decode())
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
