"""Prepare pinned, previously viewed Current100k inputs without an encoder.

Label times are conservative accounting-as-of upper bounds, never invented
settlement timestamps. The original pinned accounting implementation verifies
the complete final executions, commissions and terminal state at each cutoff.
"""
from __future__ import annotations
import argparse
from decimal import Decimal
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time
import types

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "workers" / "weight"))
from weight_runtime.artifacts import atomic_create
from weight_runtime.current100k import feature_text as current100k_feature_text, validate_head
from weight_runtime.errors import WeightError, canonical, checksum, digest, integer, loads, need

SCHEMA = "hepta.weight.current100k.signal-input-request.v1"
TIME_BASIS = "VERIFIED_ORIGINAL_ACCOUNTING_ASOF_UPPER_BOUND"
PIN_NAMES = ("dataset", "features", "labels", "head", "layer_binding", "layer_report",
             "period", "oms_capture", "accounting_module", "signal_module")
NUMERIC_EXECUTION_FIELDS = ("quantity", "price", "cumulative_quantity", "commission")
IDENTITY_EXECUTION_FIELDS = ("execution_id", "command_id", "order_id", "side", "commission_currency")


def source_digest(value):
    # Preserve the original trader canonicalization explicitly.
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def read_pin(pin, maximum=64 * 1024 * 1024):
    need(isinstance(pin, dict) and set(pin) == {"path", "sha256"}, "INPUT_PIN", "Exact path/hash pin required")
    checksum(pin["sha256"], "input sha256")
    path = Path(pin["path"])
    need(path.is_absolute(), "INPUT_PIN", "Input path must be absolute")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_size <= maximum, "INPUT_LIMIT", "Bounded regular input required")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(maximum + 1)
        after = os.fstat(fd)
        signature = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(len(raw) <= maximum and signature(before) == signature(after), "INPUT_CHANGED", "Input changed during capture")
    finally:
        os.close(fd)
    need(hashlib.sha256(raw).hexdigest() == pin["sha256"], "INPUT_CHANGED", "Input SHA256 differs", path=str(path))
    return raw


def load_module(raw, path, role):
    """Execute the exact captured source bytes, not a second mutable-file read."""
    name = "_current100k_signal_" + role + "_" + hashlib.sha256(raw).hexdigest()
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    try:
        exec(compile(raw, str(path), "exec"), module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def validate_request(request):
    keys = {"schema", "information_cutoff_ms", "oms_captured_at_ms", "expected_rows",
            "split_indices", "layer_rows", *PIN_NAMES}
    need(isinstance(request, dict) and set(request) == keys and request["schema"] == SCHEMA,
         "INPUT_REQUEST", "Exact pinned signal-input request required")
    n = integer(request["expected_rows"], "expected_rows", 6, 4096)
    cutoff = integer(request["information_cutoff_ms"], "information_cutoff_ms", 1)
    need(integer(request["oms_captured_at_ms"], "oms_captured_at_ms", 1) >= cutoff,
         "INPUT_REQUEST", "Capture must cover the historical information cutoff")
    splits = request["split_indices"]
    need(isinstance(splits, list) and len(splits) == 2 and all(type(i) is int for i in splits)
         and 0 < splits[0] < splits[1] < n, "INPUT_REQUEST", "Two fixed zero-based split indices required")
    entries = request["layer_rows"]
    need(isinstance(entries, list) and len(entries) == n and
         all(isinstance(e, dict) and set(e) == {"index", "receipt", "tensors"}
             and type(e["index"]) is int and e["index"] == i for i, e in enumerate(entries)),
         "INPUT_REQUEST", "Every original layer row must be pinned in original order")


def validate_rows(dataset, period_sha):
    need(dataset.get("schema") == "heptatrader.current100k-value-dataset.v1"
         and dataset.get("period_sha256") == period_sha, "INPUT_LINEAGE", "Original dataset/period mismatch")
    rows, ids = dataset["rows"], set()
    previous = 0
    for row in rows:
        need(row.get("schema") == "heptatrader.current100k-value-row.v1"
             and row.get("row_id") == source_digest({k: v for k, v in row.items() if k != "row_id"})
             and row["row_id"] not in ids, "INPUT_LINEAGE", "Original row identity/order changed")
        ids.add(row["row_id"])
        start = integer(row["input_started_at_ms"], "input_started_at_ms", 1)
        need(start >= previous and row["period_sha256"] == period_sha,
             "INPUT_LINEAGE", "Original rows must retain chronological order and period")
        previous = start
        need(hashlib.sha256(row["feature_text"].encode()).hexdigest() == row["feature_text_sha256"],
             "INPUT_LINEAGE", "Original feature text changed")
        reward, item, binding = row["reward"], row["source_request"], row["source_binding"]
        original = item["request"]
        need(reward.get("reward_id") == row["reward_id"] == source_digest(
                 {k: v for k, v in reward.items() if k != "reward_id"})
             and all(reward.get(k) is True for k in ("learning_eligible", "exact_input_bound", "fees_complete", "settlement_complete"))
             and not reward.get("unsettled_commands") and not reward.get("learning_exclusion_reasons"),
             "INPUT_LINEAGE", "Original complete reward required")
        need(source_digest(original) == row["input_id"] == item["request_sha256"] == binding["request_sha256"] == reward["input_id"]
             and original["request_id"] == row["request_id"] == binding["request_id"] == reward["input_attribution"]["request_id"]
             and original["started_at_ms"] == start == binding["request_started_at_ms"]
             and binding["command"]["command_id"] == row["open_command_id"] == reward["open_command_id"]
             and binding["command"]["side"] == row["action"]
             and original["instrument"] == reward["instrument"] == "EUR.USD"
             and reward["currency"] == "USD" and original["model_id"] == reward["behavior_model_id"],
             "INPUT_LINEAGE", "Original request/reward/command binding changed")
        need(row["feature_text"] == current100k_feature_text(original, row["action"]),
             "INPUT_LINEAGE", "Feature text does not match the original flat request and Current100k action template")
        need(item["producer_manifest_sha256"] == binding["producer_manifest_sha256"] ==
             reward["input_attribution"]["producer_manifest_sha256"] == dataset["producer_manifest_sha256"],
             "INPUT_LINEAGE", "Producer identity changed")
        executions = reward["executions"]
        need(executions and len({e["execution_id"] for e in executions}) == len(executions)
             and set(reward["execution_ids"]) == {e["execution_id"] for e in executions}
             and set(reward["command_ids"]) == {e["command_id"] for e in executions},
             "INPUT_LINEAGE", "Original reward execution population changed")
        position = cash = fees = Decimal(0)
        for execution in executions:
            numbers = {k: Decimal(str(execution[k])) for k in NUMERIC_EXECUTION_FIELDS}
            need(all(v.is_finite() for v in numbers.values()) and numbers["quantity"] > 0 and numbers["price"] > 0
                 and execution["commission_currency"] == "USD" and execution["side"] in ("BUY", "SELL"),
                 "INPUT_LINEAGE", "Invalid original execution economics")
            signed = numbers["quantity"] * (1 if execution["side"] == "BUY" else -1)
            position += signed
            cash -= signed * numbers["price"]
            fees += numbers["commission"]
        need(position == 0 and cash == Decimal(reward["realized_gross_usd"])
             and fees == Decimal(reward["actual_commissions_usd"]) == Decimal(row["actual_commissions_usd"])
             and cash - fees == Decimal(reward["realized_net_usd"]) == Decimal(row["net_usd"]),
             "INPUT_LINEAGE", "Original reward economic recomputation failed")
    return rows


def reward_matches(row, ledger, as_of_ms):
    if row["input_started_at_ms"] > as_of_ms:
        return "INPUT_NOT_YET_AVAILABLE"
    expected = {e["execution_id"]: e for e in row["reward"]["executions"]}
    commands = set(row["reward"]["command_ids"])
    if commands & set(ledger["settlement_pending_command_ids"]):
        return "ORIGINAL_COMMAND_SETTLEMENT_PENDING"
    if set(expected) & (set(ledger["fee_missing_execution_ids"]) | set(ledger["fee_conflicting_execution_ids"])):
        return "ORIGINAL_EXECUTION_FEE_UNAVAILABLE"
    actual = [e for e in ledger["executions"] if e["command_id"] in commands]
    if len(actual) != len(expected) or {e["execution_id"] for e in actual} != set(expected):
        return "ORIGINAL_EXECUTION_POPULATION_UNAVAILABLE_OR_CHANGED"
    for observed in actual:
        reference = expected[observed["execution_id"]]
        if any(observed.get(k) != reference.get(k) for k in IDENTITY_EXECUTION_FIELDS):
            return "ORIGINAL_EXECUTION_IDENTITY_CHANGED"
        if any(observed.get(k) is None or Decimal(str(observed[k])) != Decimal(str(reference[k]))
               for k in NUMERIC_EXECUTION_FIELDS):
            return "ORIGINAL_EXECUTION_ECONOMICS_UNAVAILABLE_OR_CHANGED"
    return None


def label_proofs(rows, events, period, accounting, checkpoints, capture_ms, *, retained_attempts=None):
    """Keep the source event-cutoff semantics, including malformed future clocks."""
    proofs = [] if retained_attempts is None else retained_attempts
    for as_of in checkpoints:
        attempt = {"as_of_ms": as_of, "basis": "ORIGINAL_OMS_EVENT_TS_MS",
                   "status": "REPLAY_STARTED"}
        # Publish progress into the caller's retained list before starting work;
        # an interrupted later replay must not erase earlier completed evidence.
        proofs.append(attempt)
        try:
            # Match resident_rewards.current(event_cutoff_ms=...). Malformed records
            # and timestamps beyond the observed capture are not silently filtered.
            retained = [e for e in events if not (type(e.get("ts_ms")) is int and as_of < e["ts_ms"] <= capture_ms)]
            attempt.update(retained_events=len(retained), excluded_events=len(events) - len(retained))
            ledger = accounting.replay(retained, period, "EUR.USD", as_of)
            reasons = [reward_matches(row, ledger, as_of) for row in rows]
            attempt.update(status="REPLAY_COMPLETED", row_reasons=reasons,
                           verified_rows=sum(reason is None for reason in reasons))
        except Exception as exc:
            attempt.update(status="REPLAY_FAILED", error_type=type(exc).__name__, error=str(exc)[:1000],
                           row_reasons=["ORIGINAL_ACCOUNTING_REPLAY_FAILED"] * len(rows), verified_rows=0)
        except BaseException as exc:
            attempt.update(status="REPLAY_INTERRUPTED", error_type=type(exc).__name__, error=str(exc)[:1000],
                           row_reasons=["ORIGINAL_ACCOUNTING_REPLAY_INTERRUPTED"] * len(rows),
                           verified_rows=0, partial_work_unknown=True)
            raise
    return proofs


def prepare(request, output_root, *, request_pin=None):
    """Create one new input pack; failure receipts cannot be overwritten."""
    import torch
    from safetensors.torch import load, save
    validate_request(request)
    request = loads(canonical(request))
    root = Path(output_root)
    root.mkdir(parents=True, exist_ok=False, mode=0o700)
    started, cpu_started = time.monotonic(), time.process_time()
    pins, progress = [], {"layer_rows_checked": 0, "accounting_replays": []}

    def read(pin, maximum=64 * 1024 * 1024):
        raw = read_pin(pin, maximum)
        pins.append(pin)
        return raw

    try:
        atomic_create(root / "request.json", canonical(request) + b"\n")
        if request_pin is not None:
            need(loads(read(request_pin, 4 * 1024 * 1024)) == request,
                 "INPUT_CHANGED", "Pinned request differs from admitted request")
        raw = {name: read(request[name], 128 * 1024 * 1024 if name == "oms_capture" else
                         32 * 1024 * 1024 if name == "dataset" else 16 * 1024 * 1024)
               for name in PIN_NAMES}
        dataset = loads(raw["dataset"])
        rows = validate_rows(dataset, request["period"]["sha256"])
        n = request["expected_rows"]
        need(len(rows) == n, "INPUT_LINEAGE", "Original row count changed")
        cutoff = request["information_cutoff_ms"]
        starts = [row["input_started_at_ms"] for row in rows]
        boundaries = [starts[i] for i in request["split_indices"]]
        end = max(starts) + 1
        need(boundaries[0] < boundaries[1] < end <= cutoff,
             "INPUT_LINEAGE", "Fixed score intervals must precede the development cutoff")
        folds = [{"fit_before_ms": first, "score_start_ms": first, "score_end_ms": last, "embargo_ms": 0}
                 for first, last in zip(boundaries, [boundaries[1], end])]
        source_features, label_file = load(raw["features"]), load(raw["labels"])
        need(set(source_features) == {"features"} and set(label_file) == {"labels_usd"},
             "INPUT_LINEAGE", "Expected original feature and label tensor files")
        mean, labels = source_features["features"], label_file["labels_usd"]
        need(mean.dtype == torch.float32 and mean.shape == (n, 768) and bool(torch.isfinite(mean).all())
             and bool(torch.allclose(mean.norm(dim=1), torch.ones(n), atol=1e-5, rtol=1e-5)),
             "INPUT_LINEAGE", "Original normalized FP32 feature matrix required")
        expected_labels = torch.tensor([float(row["net_usd"]) for row in rows], dtype=torch.float32)
        need(labels.dtype == torch.float32 and labels.shape == (n,) and bool(torch.isfinite(expected_labels).all())
             and torch.equal(labels, expected_labels), "INPUT_LINEAGE", "Original FP32 net_usd labels differ")
        validate_head(load(raw["head"]))
        binding, report = loads(raw["layer_binding"]), loads(raw["layer_report"])
        expected_probes = [{"index": i, "variant": "original", "text_sha256": row["feature_text_sha256"]}
                           for i, row in enumerate(rows)]
        need(binding.get("schema") == "heptatrader.layer-diagnosis-binding.v1"
             and binding.get("scope") == "KNOWN_DEVELOPMENT_INPUTS"
             and binding.get("dataset_sha256") == request["dataset"]["sha256"]
             and binding.get("feature_cache_sha256") == request["features"]["sha256"]
             and binding.get("selected_indices") == list(range(n)) and binding.get("probes") == expected_probes
             and binding.get("dtype") == "float32" and binding.get("device") == "cpu"
             and binding.get("weights_modified") is False and binding.get("fit_performed") is False,
             "INPUT_LINEAGE", "Original all-row layer binding differs")
        need(report.get("schema") == "heptatrader.current100k-layer-diagnosis.v1"
             and report.get("binding_sha256") == request["layer_binding"]["sha256"]
             and report.get("original_rows") == n == report.get("requested_probes") == report.get("completed_probes")
             and report.get("skipped_probes") == [] and report.get("weights_modified") is False
             and report.get("historical_labels_already_viewed") is True
             and report["layer_geometry"][-1]["index"] == 23 and report["layer_geometry"][-1]["stage"] == "final_norm",
             "INPUT_LINEAGE", "Complete original final-layer diagnosis required")
        signal = load_module(raw["signal_module"], request["signal_module"]["path"], "structured")
        action, grouped, structured, parity = [], [], [], []
        for i, (row, entry) in enumerate(zip(rows, request["layer_rows"])):
            receipt = loads(read(entry["receipt"]))
            need(receipt.get("index") == i and receipt.get("variant") == "original" and receipt.get("supported") is True
                 and receipt.get("row_id") == row["row_id"] and receipt.get("text_sha256") == row["feature_text_sha256"]
                 and receipt.get("hidden_state_count") == 24 and receipt["layers"][-1]["index"] == 23
                 and receipt["layers"][-1]["stage"] == "final_norm", "INPUT_LINEAGE", "Layer receipt/input identity mismatch")
            tensors = load(read(entry["tensors"], 16 * 1024 * 1024))
            selected = {name: tensors["normalized." + name + ".23"] for name in ("all", "action", "quotes", "template")}
            for vector in selected.values():
                need(vector.dtype == torch.float32 and vector.shape == (768,) and bool(torch.isfinite(vector).all())
                     and abs(float(vector.norm()) - 1.) <= 2e-5, "INPUT_LINEAGE", "Final-layer normalized vectors required")
            error = float((selected["all"] - mean[i]).abs().max())
            need(error <= 2e-6, "MEAN_CACHE_PARITY", "Layer mean differs from original frozen features", index=i, error=error)
            balance = (selected["quotes"] + selected["template"] + selected["action"]) / 3.
            need(float(balance.norm()) > 1e-12, "GROUPED_DEGENERATE", "Balanced grouped vector is zero")
            grouped.append(torch.nn.functional.normalize(balance, dim=0))
            action.append(selected["action"])
            structured.append(signal.structured_features(row["feature_text"], row["action"], row["input_started_at_ms"]))
            parity.append(error)
            progress["layer_rows_checked"] += 1
        accounting = load_module(raw["accounting_module"], request["accounting_module"]["path"], "accounting")
        period = loads(raw["period"])
        accounting.validate_period(period)
        need(Decimal(str(period["instruments"]["EUR.USD"]["opening_quantity"])) == 0,
             "INPUT_LINEAGE", "Original accounting period must start flat")
        oms = raw["oms_capture"]
        need(not oms or oms.endswith(b"\n"), "OMS_CAPTURE", "Uncommitted OMS tail is not an input prefix")
        events = [loads(line) for line in oms.splitlines()]
        need(all(isinstance(event, dict) for event in events), "OMS_CAPTURE", "Original OMS object records required")
        checkpoints = [value - 1 for value in boundaries] + [cutoff]
        proofs = label_proofs(rows, events, period, accounting, checkpoints, request["oms_captured_at_ms"],
                             retained_attempts=progress["accounting_replays"])
        atomic_create(root / "label-availability.json", canonical({"label_time_basis": TIME_BASIS,
            "accounting_module_sha256": request["accounting_module"]["sha256"],
            "oms_capture_sha256": request["oms_capture"]["sha256"], "checkpoints": proofs}) + b"\n")
        need(all(reason is None for reason in proofs[-1]["row_reasons"]),
             "LABEL_AVAILABILITY_UNPROVEN", "Final original accounting does not prove every frozen reward")
        metadata = [{"row_id": row["row_id"], "request_id": row["request_id"],
                     "input_started_at_ms": row["input_started_at_ms"], "label_time_basis": TIME_BASIS,
                     "label_available_by_ms": next(p["as_of_ms"] for p in proofs if p["row_reasons"][i] is None)}
                    for i, row in enumerate(rows)]
        tensors = {"masked_mean": mean, "action": torch.stack(action), "grouped": torch.stack(grouped),
                   "structured": torch.stack(structured)}
        blobs = {"features": save(tensors), "labels": raw["labels"], "head": raw["head"],
                 "rows": canonical(metadata) + b"\n"}
        artifacts = {}
        for key, blob in blobs.items():
            path = root / (key + (".json" if key == "rows" else ".safetensors"))
            atomic_create(path, blob)
            artifacts[key] = {"path": str(path.resolve()), "sha256": hashlib.sha256(blob).hexdigest()}
        checks = []
        for pin in pins:
            try:
                read_pin(pin, 128 * 1024 * 1024)
                checks.append({**pin, "passed": True})
            except Exception as exc:
                checks.append({**pin, "passed": False, "error": str(exc)[:500]})
        atomic_create(root / "source-integrity.json", canonical({"passed": all(x["passed"] for x in checks), "checks": checks}) + b"\n")
        need(all(x["passed"] for x in checks), "INPUT_CHANGED", "An input changed before final publication")
        result = {"schema": "hepta.weight.current100k.signal-inputs-ready.v1", "request_sha256": digest(request),
                  "partition": "previously_viewed_development", "rows": n, "artifacts": artifacts,
                  "information_cutoff_ms": cutoff, "split_indices": request["split_indices"], "folds": folds,
                  "label_time_basis": TIME_BASIS, "exact_settlement_times_claimed": False,
                  "available_before_fit_counts": [sum(m["input_started_at_ms"] < t and m["label_available_by_ms"] < t
                                                       for m in metadata) for t in boundaries],
                  "max_mean_cache_error": max(parity), "source_integrity_passed": True,
                  "grouped_recipe": "L2_NORMALIZE((normalized.quotes.23+normalized.template.23+normalized.action.23)/3)",
                  "cost": {"wall_seconds": time.monotonic() - started, "process_cpu_seconds": time.process_time() - cpu_started,
                           "accounting_replay_calls": len(proofs), "encoder_forward_examples": 0,
                           "original_encoding_seconds": None, "end_to_end_cost_complete": False},
                  "prospective_evidence": False, "trade_authority": False}
        atomic_create(root / "ready.json", canonical(result) + b"\n")
        return result
    except BaseException as exc:
        error = exc.as_dict() if isinstance(exc, WeightError) else {"code": type(exc).__name__, "message": str(exc)[:1000]}
        failure = {"error": error, "progress": progress,
            "status": "failed" if isinstance(exc, Exception) else "interrupted",
            "retained_progress_is_lower_bound": True,
            "request_sha256": digest(request), "wall_seconds": time.monotonic() - started,
            "process_cpu_seconds": time.process_time() - cpu_started,
            "automatic_replay_allowed": False, "ready": False}
        try:
            atomic_create(root / "failure.json", canonical(failure) + b"\n")
        except BaseException as retention_error:
            if hasattr(exc, "add_note"):
                exc.add_note("Failure receipt could not be retained: " + str(retention_error)[:512])
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--request-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    request_pin = {"path": str(args.request.resolve()), "sha256": args.request_sha256}
    request = loads(read_pin(request_pin, 4 * 1024 * 1024))
    import torch
    torch.set_num_threads(1)
    result = prepare(request, args.output, request_pin=request_pin)
    print(canonical({"ready": str(args.output / "ready.json"), "rows": result["rows"],
                     "available_before_fit_counts": result["available_before_fit_counts"],
                     "prospective_evidence": False}).decode())


if __name__ == "__main__":
    main()

