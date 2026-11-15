#!/usr/bin/env python3
"""Run one pinned development mechanism plan in a disposable resident worker.

The configuration's output_root must be OUT/artifacts. Existing completed results
can be read back, but an interrupted or failed experiment is never rerun in place.
No source checkpoint, production profile or trading process is changed.
"""
import argparse
import os
from pathlib import Path
import resource
import sys
import threading

for _key in ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS"):
    os.environ.setdefault(_key, "2")
os.environ.update(HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1", TOKENIZERS_PARALLELISM="false", USE_TF="0")
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "workers" / "weight"))

from weight_runtime.artifacts import atomic_create, file_sha256
from weight_runtime.errors import WeightError, canonical, digest, integer, loads, need
from weight_runtime.mechanism import ExperimentPlan, required_limits, run_experiment
from weight_runtime.transport import Deadline, Dispatcher, memory_watch, package_identity


def run(config_path, config_sha256, plan_path, plan_sha256, out):
    for path, expected in ((config_path, config_sha256), (plan_path, plan_sha256)):
        need(Path(path).stat().st_size <= 1048576, "INPUT_LIMIT", "Configuration/plan exceeds 1 MiB")
        need(file_sha256(path) == expected, "IDENTITY_MISMATCH", "Pinned input file differs", path=str(path))
    config = loads(Path(config_path).read_bytes())
    plan_document = loads(Path(plan_path).read_bytes())
    plan = ExperimentPlan.parse(plan_document)
    root = Path(out).resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    need(config.get("output_root") == str(root / "artifacts"), "PATH_DENIED", "Config output_root must be OUT/artifacts")
    # Lower the existing worker counters to the complete predeclared design. No
    # request may acquire additional candidate/forward budget while the run lives.
    effective_limits = dict(config.get("limits", {}))
    for name, amount in required_limits(plan).items():
        need(effective_limits.get(name, amount) >= amount, "EXPERIMENT_BUDGET", "Configured limit cannot fit this plan", field=name)
        effective_limits[name] = amount
    config["limits"] = effective_limits
    identity = {"config_sha256": config_sha256, "plan_sha256": plan_sha256,
                "script_sha256": file_sha256(__file__), "effective_open_spec_sha256": digest(config),
                "worker": package_identity(Path(__file__).resolve().parents[2] / "workers" / "weight" / "worker.py")}
    summary_path = root / "summary.json"
    if summary_path.exists():
        previous = loads(summary_path.read_bytes())
        need(previous.get("identity") == identity, "IDENTITY_MISMATCH", "Completed experiment has another identity")
        return previous
    need(not (root / "started.json").exists() and not (root / "artifacts").exists(),
         "UNKNOWN_OPERATION_STATE", "An incomplete experiment already owns this directory; inspect its receipts")
    atomic_create(root / "plan.json", canonical(plan_document) + b"\n")
    atomic_create(root / "started.json", canonical({"identity": identity,
                  "planned_forward_examples": plan.forward_examples,
                  "planned_patch_candidates": plan.candidate_count}) + b"\n")
    dispatcher = Dispatcher(plan.experiment_id)
    receipts = []
    stop = threading.Event()
    memory = integer(config.get("max_memory_bytes", 4294967296), "max_memory_bytes", 134217728, 137438953472)
    threading.Thread(target=memory_watch, args=(memory, stop), daemon=True).start()

    def call(operation, params):
        request = {"id": "mechanism-%05d" % len(receipts), "op": operation, "params": params}
        timeout = integer(params.get("timeout_ms", plan.budget.max_request_ms), "timeout_ms", 1, 600000)
        with Deadline(timeout):
            response = dispatcher.handle(request)
        receipts.append({"request": request, "response": response})
        if not response["ok"]:
            error = response["error"]
            raise WeightError(error["code"], error["message"], error.get("details"))
        return response["result"]

    result = None
    failure = None
    opened = None
    try:
        opened = call("open", config)
        result = run_experiment(call, opened, plan)
    except Exception as exc:
        failure = exc.as_dict() if isinstance(exc, WeightError) else {
            "code": "EXPERIMENT_FAILED", "message": str(exc)[:2048], "exception_type": type(exc).__name__}
        raise
    finally:
        try:
            if opened is not None:
                closed = call("close", {"timeout_ms": 5000})
                if result is not None:
                    result["close"] = closed
        finally:
            stop.set()
            atomic_create(root / "receipts.json", canonical(receipts) + b"\n")
            if failure is not None:
                atomic_create(root / "failure.json", canonical({"identity": identity, "error": failure,
                              "completed": False, "automatic_replay_allowed": False}) + b"\n")
    result.update(identity=identity, load_seconds=opened["load_seconds"],
                  peak_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * (1 if sys.platform == "darwin" else 1024))
    atomic_create(summary_path, canonical(result) + b"\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("config", "config-sha256", "plan", "plan-sha256", "out"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    try:
        result = run(args.config, args.config_sha256, args.plan, args.plan_sha256, args.out)
    except (WeightError, OSError, ValueError) as exc:
        error = exc.as_dict() if isinstance(exc, WeightError) else {"code": "EXPERIMENT_FAILED", "message": str(exc)}
        print(canonical({"ok": False, "error": error}).decode())
        return 1
    print(canonical({"ok": True, "status": result["status"], "experiment_id": result["experiment_id"],
                     "cost": result["cost"], "production_eligible": False,
                     "summary_sha256": file_sha256(Path(args.out).resolve() / "summary.json")}).decode())
    return 0


if __name__ == "__main__":
    sys.exit(main())
