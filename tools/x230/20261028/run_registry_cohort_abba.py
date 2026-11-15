#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Compare two explicitly pinned runtime binaries using repeated cold reuse waves.

This is a new, direct ABBA experiment. It does not reinterpret the older A62
reports or attest a build/qualification from a supplied source map. Every MCP
request reuses one of six original launched jobs; the local SSH wrapper always
exits before exec. No new request key, remote command or production write is used.
"""
import argparse
import gzip
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import signal
import sys
import threading
import time
import types


HERE = Path(__file__).absolute().parent
HELPERS = {
    "run_reuse_throughput.py": "e0ba8cd46b9f88844bf0dadafcfc605b5c05cd0b734f7f3cb5ca5fb04603de5a",
    "run_native_validation.py": "309afefe719d63e52377930db5d997b3ac3c244873fbb83055e9950b956903f6",
    "x230_observation_benchmark.py": "0c4a06ed1613039d703bb575a8440c9030eac2dc51fcc2c96e96fc90a609da3e",
    "pinned_native_protocol.py": "2a88c03591908b1054b492d2d717027cb180d176c78eed4de280d7a6a193e956",
    "pinned_resource_sampler.py": "a9554e63416504428439a6cf3fe1f5b8ede090c2ef856bda3f1add413d06d40a",
}
CONCURRENCY = (1, 4, 8)
GROUPS = ("cold_initial", "cold_steady", "cold_all", "warm")


def need(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def load_helpers():
    modules = {}
    for filename, expected in HELPERS.items():
        path = HERE / filename
        need(sha(path) == expected, "reviewed helper differs: " + filename)
        spec = importlib.util.spec_from_file_location("cohort_" + path.stem, path)
        need(spec is not None and spec.loader is not None, "cannot load helper: " + filename)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        need(sha(path) == expected, "helper changed during import: " + filename)
        modules[path.stem] = module
    return modules


def load_variant(p, native, args, label, output):
    binary = p.direct(getattr(args, label))
    source = p.direct(getattr(args, label + "_source"))
    manifest = p.direct(getattr(args, label + "_source_manifest"))
    binary_receipt = p.receipt(binary)
    manifest_receipt, raw = p.receipt(manifest, contents=True)
    need(binary_receipt["sha256"] == getattr(args, label + "_sha256")
         and os.access(binary, os.X_OK), label + " binary SHA/executable differs")
    need(manifest_receipt["sha256"] == getattr(args, label + "_source_manifest_sha256"),
         label + " source manifest SHA differs")
    expected = json.loads(raw)
    need(isinstance(expected, dict) and expected
         and all(isinstance(k, str) and isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v)
                 for k, v in expected.items()), label + " requires a flat compiler-input path-to-SHA map")
    actual = native.candidate_sources(p, source)
    need(actual == expected, label + " current compiler-input source differs from its supplied map")
    need(not output.is_relative_to(source), "evidence directory cannot modify either source snapshot")
    p.create(output / (label + "-source-manifest.input.json"), raw)
    return {"label": label, "source": str(source), "source_files": len(actual),
            "source_map": actual, "source_manifest": manifest_receipt, "binary": binary_receipt,
            "qualification_claim": False,
            "source_binary_binding_scope": "explicit supplied identities; build provenance must be checked separately"}


def verify_variant(p, native, variant):
    p.check_manifest({row["path"]: row for row in (variant["binary"], variant["source_manifest"])})
    need(native.candidate_sources(p, Path(variant["source"])) == variant["source_map"],
         variant["label"] + " compiler inputs changed during experiment")


def require_distinct_binaries(bundles):
    need(bundles["A"]["binary"]["sha256"] != bundles["B"]["binary"]["sha256"],
         "baseline and candidate have the same binary SHA256")


def logged_resources(base):
    """Extend the retained sampler without modifying it or its 100 ms cadence.

    update_peak receives the actual current field value before applying max().
    Capture those values to preserve every sample, including missing fields and
    samples crossing a phase boundary. The original error log and identity checks
    remain owned by the parent sampler.
    """
    class LoggedResources(base.Resources):
        def __init__(self, pid, error_path, **kwargs):
            self.sample_path = Path(error_path).with_name("resource-samples.jsonl")
            self.sample_stream = self.sample_path.open("xb")
            self.sample_hash = hashlib.sha256()
            self.sample_rows = 0
            self.sample_error = None
            self.sample_finalized = False
            self.current_phase = "startup"
            self.current_values = {}
            try:
                super().__init__(pid, error_path, **kwargs)
            except BaseException:
                self.sample_stream.close()
                raise

        def update_peak(self, name, value):
            self.current_values[name] = value
            super().update_peak(name, value)

        def sample_once(self):
            started = time.monotonic()
            first_phase = self.current_phase
            first_error = self.error_count
            self.current_values = {}
            super().sample_once()
            with self.lock:
                row = {"sequence": self.sample_rows, "start_monotonic": started,
                       "end_monotonic": time.monotonic(), "phase_start": first_phase,
                       "phase_end": self.current_phase, "fields": dict(self.current_values),
                       "controller_cpu_seconds": self.seen.get((self.pid, self.birth)),
                       "error_count": self.error_count, "sample_errors": self.error_count - first_error,
                       "root_identity_lost": self.root_identity_lost}
            raw = (json.dumps(row, sort_keys=True) + "\n").encode()
            try:
                need(self.sample_stream.write(raw) == len(raw), "incomplete resource sample write")
                self.sample_stream.flush()
                self.sample_hash.update(raw)
                self.sample_rows += 1
            except Exception as error:
                self.sample_error = type(error).__name__ + ": " + str(error)
                raise

        def snapshot(self):
            result = super().snapshot()
            result["raw_samples"] = {"path": str(self.sample_path), "rows": self.sample_rows,
                "sha256": self.sample_hash.hexdigest(), "finalized": self.sample_finalized,
                "error": self.sample_error,
                "scope": "every sampler pass; fields and process tree are non-atomic observations"}
            return result

        def finalize_log(self):
            # The original sampler calls this in its worker's run-finally.
            # A blocked flush/fsync must not make the bounded stop() caller
            # become a filesystem-I/O owner after its join deadline.
            try:
                super().finalize_log()
            finally:
                try:
                    if not self.sample_finalized:
                        self.sample_stream.flush()
                        os.fsync(self.sample_stream.fileno())
                        self.sample_stream.close()
                        self.sample_finalized = True
                except (OSError, ValueError) as error:
                    self.sample_error = type(error).__name__ + ": " + str(error)

        def stop(self, join_timeout=5):
            result = super().stop(join_timeout)
            return {**self.snapshot(), "sampler_thread_stopped": result["sampler_thread_stopped"]}
    return types.SimpleNamespace(Resources=LoggedResources)


def planned_round(number, arm, waves, warm_calls):
    cells = []
    for concurrency in CONCURRENCY:
        for wave in range(waves):
            for category, count in (("cold_initial" if wave == 0 else "cold_steady", 6),
                                    ("warm", warm_calls)):
                name = f"C{concurrency}-wave-{wave:02d}-{category}"
                cells.append({"phase": name, "category": category, "concurrency": concurrency,
                              "wave": wave, "planned_calls": count, "completed": False})
    return {"round": number, "arm": arm, "phases": cells, "started": False, "passed": False}


def make_fixture(p, bench, reuse, directory, config, jobs, synthetic_records):
    state = directory / "state"
    registry = state / "jobs"
    registry.mkdir(mode=0o700, parents=True)
    os.chmod(state, 0o700)
    expected = {}
    for job in jobs:
        path = registry / (job["id"] + ".json")
        p.create(path, job["raw"])
        expected[path.name] = job["sha256"]
    for index in range(synthetic_records):
        identity = f"benchmark-unqueried-history-{index:05d}"
        record = dict(jobs[0]["record"], id=identity, host="main", ssh_target="never-connect.invalid",
            unit="hepta-runtime-job-" + identity, remote_job_dir="/__hepta_never_execute__/jobs/" + identity,
            executable="/__hepta_never_execute__", args=[], cwd=None, env_keys=[], request_digest="0" * 64,
            request_fingerprint=0, idempotency_key="local-unqueried-history-" + str(index), created_unix_ms=index)
        raw = bench.canonical(record)
        path = registry / (identity + ".json")
        with path.open("xb") as stream:
            stream.write(raw)
        expected[path.name] = bench.digest(raw)
    p.create(directory / "jobs-input-sha256.json", p.canonical(expected))
    config_path = directory / "runtime.json"
    p.create(config_path, p.canonical(dict(config, state_dir=str(state), controller_workspace_roots=[])))
    wrapper_dir = directory / "bin"
    wrapper_dir.mkdir(mode=0o700)
    wrapper = wrapper_dir / "ssh"
    p.create(wrapper, reuse.DENY_SSH.encode())
    wrapper.chmod(0o700)
    denial = directory / "denied-ssh.jsonl"
    p.create(denial, b"")
    return registry, expected, config_path, wrapper, denial


def verify_registry(registry, expected):
    actual = {path.name: sha(path) for path in registry.glob("*.json")}
    need(actual == expected, "original/synthetic receipts changed or another job was allocated")


def summarize_rows(rows, seconds):
    executed = [row for row in rows if row.get("executed")]
    values = sorted(row["elapsed_ms"] for row in executed)
    successes = sum(row.get("okay") is True for row in rows)
    return {"recorded_calls": len(rows), "executed": len(executed), "successes": successes,
            "failed_executed": sum(row.get("okay") is not True for row in executed),
            "seconds": seconds, "successful_calls_per_second": successes / seconds if seconds else None,
            **{f"p{q}_ms": values[math.ceil(len(values) * q / 100) - 1] if values else None
               for q in (50, 95, 99)}, "max_ms": max(values) if values else None,
            "percentile_method": "nearest-rank over every executed attempt, including failed attempts"}


def summarize_resources(rounds, selected):
    maxima, coverage = {}, {}
    stable = boundaries = errors = journals = 0
    for row in rounds:
        if not row.get("directory"):
            continue
        path = Path(row["directory"]) / "resource-samples.jsonl"
        if not path.exists():
            continue
        journals += 1
        with path.open(encoding="utf-8") as stream:
            for line in stream:
                sample = json.loads(line)
                first, last = sample["phase_start"], sample["phase_end"]
                if first != last:
                    boundaries += int(first in selected or last in selected)
                    continue
                if first not in selected:
                    continue
                stable += 1
                errors += sample["sample_errors"]
                for key, value in sample["fields"].items():
                    if value is not None:
                        maxima[key] = max(maxima.get(key, value), value)
                        coverage[key] = coverage.get(key, 0) + 1
    return {"journals": journals, "samples_wholly_within_phase": stable,
            "boundary_samples_excluded_from_phase_peaks": boundaries,
            "sample_errors_wholly_within_phase": errors, "maximum_observed_fields": maxima,
            "readable_samples_per_field": coverage,
            "scope": "non-atomic 100ms observations within selected phases; missing fields remain unknown"}


def summarize(report):
    """Recompute metrics from the original journals, never from selected successes."""
    result = {}
    for arm in ("A", "B"):
        result[arm] = {}
        for concurrency in CONCURRENCY:
            by_group = {}
            for group in GROUPS:
                wanted = lambda cell: cell["concurrency"] == concurrency and (
                    cell["category"] == group or group == "cold_all" and cell["category"].startswith("cold_"))
                cells, calls, pings = [], [], []
                original_rows_complete = True
                for row in report["rounds"]:
                    if row["arm"] != arm:
                        continue
                    chosen = {cell["phase"]: cell for cell in row["phases"] if wanted(cell)}
                    cells.extend(chosen.values())
                    if not row.get("events") or not Path(row["events"]).exists():
                        original_rows_complete = False
                        continue
                    indices = {name: [] for name in chosen}
                    with gzip.open(row["events"], "rt", encoding="utf-8") as stream:
                        for line in stream:
                            event = json.loads(line)
                            if event.get("phase") in chosen:
                                target = pings if event.get("kind") == "ping" else calls
                                target.append({key: event.get(key) for key in ("executed", "okay", "elapsed_ms")})
                                if event.get("kind") != "ping":
                                    indices[event["phase"]].append(event.get("index"))
                    original_rows_complete = original_rows_complete and all(
                        sorted(indices[name]) == list(range(cell["planned_calls"]))
                        for name, cell in chosen.items())
                seconds = sum(cell.get("result", {}).get("seconds", 0) for cell in cells)
                metrics = summarize_rows(calls, seconds)
                cpu = sum(cell.get("result", {}).get("controller_cpu_seconds", 0) for cell in cells)
                planned = sum(cell["planned_calls"] for cell in cells)
                time_complete = all(cell["completed"] for cell in cells)
                complete = (time_complete and original_rows_complete and len(calls) == planned
                            and all(cell.get("result", {}).get("passed") is True for cell in cells))
                if not time_complete:
                    metrics["successful_calls_per_second"] = None
                ping_metrics = summarize_rows(pings, seconds)
                if not time_complete:
                    ping_metrics["successful_calls_per_second"] = None
                metrics.update(planned_calls=planned, unrecorded_calls=planned - len(calls),
                    planned_phases=len(cells), completed_phases=sum(cell["completed"] for cell in cells),
                    complete=complete, measured_time_complete=time_complete,
                    original_phase_indices_complete=original_rows_complete,
                    controller_cpu_seconds=cpu,
                    controller_cpu_ms_per_success=1000 * cpu / metrics["successes"]
                        if time_complete and metrics["successes"] else None,
                    ping=ping_metrics)
                by_group[group] = metrics
                metrics["resources"] = summarize_resources(
                    [row for row in report["rounds"] if row["arm"] == arm],
                    {cell["phase"] for cell in cells})
            result[arm][str(concurrency)] = by_group
    comparison = {}
    fields = ("successful_calls_per_second", "controller_cpu_ms_per_success", "p50_ms", "p95_ms", "p99_ms")
    for concurrency in CONCURRENCY:
        comparison[str(concurrency)] = {}
        for group in GROUPS:
            first, second = result["A"][str(concurrency)][group], result["B"][str(concurrency)][group]
            eligible = report["passed"] and first["complete"] and second["complete"]
            comparison[str(concurrency)][group] = {"comparison_eligible": eligible,
                "candidate_over_baseline": {field: second[field] / first[field]
                    if eligible and first[field] not in (None, 0) and second[field] is not None else None
                    for field in fields},
                "ping_p99_ratio": second["ping"]["p99_ms"] / first["ping"]["p99_ms"]
                    if eligible and first["ping"]["p99_ms"] not in (None, 0)
                    and second["ping"]["p99_ms"] is not None else None}
    return {"per_arm": result, "comparison": comparison}


def invalidate_comparisons(summary):
    """A later global evidence failure invalidates every previously built ratio."""
    for concurrency in summary.get("comparison", {}).values():
        for group in concurrency.values():
            group["comparison_eligible"] = False
            group["candidate_over_baseline"] = {key: None for key in group["candidate_over_baseline"]}
            group["ping_p99_ratio"] = None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for label in ("baseline", "candidate"):
        parser.add_argument("--" + label, type=Path, required=True, help="direct runtime binary path")
        parser.add_argument("--" + label + "-sha256", required=True)
        parser.add_argument("--" + label + "-source", type=Path, required=True)
        parser.add_argument("--" + label + "-source-manifest", type=Path, required=True)
        parser.add_argument("--" + label + "-source-manifest-sha256", required=True)
    parser.add_argument("--recovery-report", type=Path, required=True)
    parser.add_argument("--recovery-report-sha256", required=True)
    parser.add_argument("--out", type=Path, required=True, help="new evidence directory, parent must exist")
    parser.add_argument("--waves", type=int, choices=range(8, 33), default=8)
    parser.add_argument("--warm-calls", type=int, choices=(48, 96), default=48)
    parser.add_argument("--synthetic-records", type=int, choices=(0, 6000), default=6000)
    args = parser.parse_args(argv)
    sys.dont_write_bytecode = True
    os.umask(0o077)
    modules = load_helpers()
    p, native, reuse, bench, sampler = (modules[name] for name in (
        "pinned_native_protocol", "run_native_validation", "run_reuse_throughput",
        "x230_observation_benchmark", "pinned_resource_sampler"))
    args.out = p.direct(args.out, exists=False)
    args.out.mkdir(mode=0o700)
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    report = {"schema": "hepta-registry-cohort-abba/v1", "passed": False, "started_utc": p.utc(),
        "order": "ABBA", "waves_per_concurrency_per_round": args.waves, "cold_calls_per_wave": 6,
        "warm_calls_per_wave": args.warm_calls, "synthetic_records": args.synthetic_records,
        "scope": "direct binary ABBA: stdio MCP + original-key lookup + audit + locally denied SSH status",
        "cold_definition": "new non-JSON directory marker invalidates positive hits before each six-original wave; known ownership and OS page cache remain",
        "cold_initial_definition": "first invalidated wave of each concurrency within each controller round",
        "cold_steady_definition": "later invalidated waves of that concurrency in the same controller",
        "observer_cost": "20ms ping; original 100ms resource sampling plus one raw sample write per pass; gzip events",
        "resource_limits": "non-atomic samples may miss processes/fields; observation errors remain separately visible",
        "not_covered": ["new-key launch throughput", "remote status throughput", "network bandwidth", "production tail SLA"],
        "qualification_claim": False, "automatic_retries": 0, "new_keys_submitted": 0,
        "real_ssh_execs": None, "remote_effects": None, "tokio_workers": 2,
        "rounds": [planned_round(index, arm, args.waves, args.warm_calls) for index, arm in enumerate("ABBA")]}
    active = load_samples = None
    try:
        need(sys.platform == "linux" and hasattr(os, "pidfd_open"), "Linux pidfd/wait4 required")
        bundles = {arm: load_variant(p, native, args, label, args.out)
                   for arm, label in (("A", "baseline"), ("B", "candidate"))}
        require_distinct_binaries(bundles)
        report["variants"] = bundles
        helpers = [Path(__file__).absolute(), *(HERE / name for name in HELPERS)]
        report["helpers"] = {str(path): p.receipt(p.direct(path)) for path in helpers}
        config, jobs, pinned = reuse.load_originals(p, bench, args.recovery_report,
            args.recovery_report_sha256, args.out)
        report.update(original_inputs=pinned,
                      originals=[{key: job[key] for key in ("host", "id", "sha256")} for job in jobs])
        Controller = reuse.make_controller(bench, logged_resources(sampler))
        p.save(args.out / "report.json", report)
        for row in report["rounds"]:
            load, gate = native.load_gate(p)
            row.update(load_before=load, load_gate=gate)
            need(gate["clear"], "busy build/service or incomplete load sample; no retry")
            p.check_manifest(pinned)
            p.check_manifest(report["helpers"])
            for bundle in bundles.values():
                verify_variant(p, native, bundle)
            directory = args.out / f"round-{row['round']}-{row['arm']}"
            directory.mkdir(mode=0o700)
            row.update(directory=str(directory), started=True)
            registry, expected, config_path, wrapper, denial = make_fixture(
                p, bench, reuse, directory, config, jobs, args.synthetic_records)
            row.update(wrapper_sha256=sha(wrapper), synthetic_history_is_not_original_job_evidence=True)
            load_samples = native.LoadSamples(p, directory / "load-samples.jsonl")
            load_samples.start()
            active = Controller(bundles[row["arm"]]["binary"]["path"], config_path, directory, wrapper, denial)
            row["startup"] = active.startup
            row["events"] = str(directory / "events.jsonl.gz")
            with gzip.open(row["events"], "wt", encoding="utf-8", compresslevel=1) as events:
                log_lock = threading.Lock()
                for cell in row["phases"]:
                    if cell["category"].startswith("cold_"):
                        marker = registry / f"invalidation-C{cell['concurrency']}-wave-{cell['wave']:02d}.marker"
                        p.create(marker, b"not a durable job record\n")
                        cell["invalidation"] = p.receipt(marker)
                    active.resources.current_phase = cell["phase"]
                    cell["start_monotonic"] = time.monotonic()
                    result = reuse.phase(active, bench, jobs, cell["concurrency"], cell["planned_calls"],
                        cell["phase"], events, log_lock)
                    cell.update(result=result, completed=True, end_monotonic=time.monotonic())
                    active.resources.current_phase = "between-phases"
                    p.save(args.out / "report.json", report)
                    print(json.dumps({"round": row["round"], "arm": row["arm"], "phase": cell["phase"],
                        "successes": result["successes"], "seconds": result["seconds"]}), flush=True)
                    need(result["passed"], "reuse/ping contract failed; remaining calls are not retried")
            active.resources.current_phase = "shutdown"
            row["shutdown"] = active.close()
            active = None
            row["load_samples"] = load_samples.finish()
            load_samples = None
            row["events_receipt"] = p.receipt(Path(row["events"]))
            attempts = [json.loads(line) for line in denial.read_text().splitlines()]
            expected_calls = sum(cell["planned_calls"] for cell in row["phases"])
            row["blocked_status_attempts"] = len(attempts)
            need(len(attempts) == expected_calls and all(item.get("denied_before_exec") is True for item in attempts),
                 "denied-status receipt count/content differs; no unexpected SSH attempt is admissible")
            need(sha(wrapper) == row["wrapper_sha256"], "deny SSH wrapper changed")
            verify_registry(registry, expected)
            close = row["shutdown"]
            resource = close["resources"]
            need(close["exit_code"] == 0 and not close["shutdown_signals"] and close["reader_stopped"]
                 and close["reader_error"] is None and close["unmatched_responses"] == 0
                 and not close["observed_descendant_survivors"], "controller cleanup differs")
            need(resource["sampler_thread_stopped"] and resource["error_log_complete"]
                 and resource["raw_samples"]["finalized"] and resource["raw_samples"]["error"] is None,
                 "resource evidence was not completely retained")
            need(sha(resource["raw_samples"]["path"]) == resource["raw_samples"]["sha256"],
                 "raw resource sample digest differs")
            need(row["load_samples"]["clear"], "build/service activity or incomplete load evidence during round")
            row.update(passed=True, real_ssh_execs=0, remote_effects=0, all_job_receipts_unchanged=True)
            p.save(args.out / "report.json", report)
        p.check_manifest(pinned)
        p.check_manifest(report["helpers"])
        for bundle in bundles.values():
            verify_variant(p, native, bundle)
        report["passed"] = all(row["passed"] for row in report["rounds"])
        if report["passed"]:
            report.update(real_ssh_execs=0, remote_effects=0)
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "reason": str(error)}
    finally:
        if active is not None:
            try:
                report["interrupted_shutdown"] = active.close()
            except BaseException as error:
                report["cleanup_error"] = type(error).__name__ + ": " + str(error)
        if load_samples is not None:
            try:
                report["interrupted_load_samples"] = load_samples.finish()
            except BaseException as error:
                report["load_cleanup_error"] = type(error).__name__ + ": " + str(error)
        try:
            report["summary"] = summarize(report)
            if report["passed"]:
                need(all(group["complete"] and group["successes"] == group["planned_calls"]
                         and group["ping"]["executed"] > 0 and group["ping"]["failed_executed"] == 0
                         for arm in report["summary"]["per_arm"].values()
                         for concurrency in arm.values() for group in concurrency.values()),
                     "raw journal inventory or success totals differ from the completed phase plan")
        except BaseException as error:
            report["passed"] = False
            report["summary_error"] = type(error).__name__ + ": " + str(error)
        if not report["passed"]:
            invalidate_comparisons(report.get("summary", {}))
        report["finished_utc"] = p.utc()
        p.save(args.out / "report.json", report)
    print(json.dumps({"report": str(args.out / "report.json"), "passed": report["passed"],
                      "error": report.get("error"), "summary_error": report.get("summary_error")}), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
