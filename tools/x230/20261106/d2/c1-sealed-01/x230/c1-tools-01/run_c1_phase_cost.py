#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Unsealed D2 C1 adapter for the unchanged R16 native observation driver.

This adapter has no child owner of its own. The only observation hook replaces
allocator.child_environment while the original Controller.__init__ calls it.
The original wrapper owns all launches, cells, waits, streams and close paths.
No trace is opened until the complete original ABBA reports eight normal closes.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import threading
import time
import types

sys.dont_write_bytecode = True
ROOT = Path("/home/qian/hepta-runtime-validation-cost-20261106-d2")
SPEC = {'schema': 'hepta-d2-c1-phase-cost-input/v1', 'sealed': True, 'root': '/home/qian/hepta-runtime-validation-cost-20261106-d2', 'reference_directory': '/home/qian/hepta-runtime-validation-cost-20261106-d2/c1-tools-01/reference', 'qualified_feature_binary': {'path': '/home/qian/hepta-runtime-validation-cost-20261106-d2/qualification-01/hepta-runtime', 'bytes': 14460184, 'sha256': 'ce071bf5216a0bb5a7ce5a6871c3020cf0537d659e1a3836d7655590f8754a98'}, 'qualification_report': {'bytes': 84034, 'path': '/home/qian/hepta-runtime-validation-cost-20261106-d2/qualification-01/report.json', 'sha256': '1cc52b4a0a86719c2da933872046d52ff42a21dcabb4ff59a21f440bbb5b9702'}, 'qualification_terminal': {'bytes': 731, 'path': '/home/qian/hepta-runtime-validation-cost-20261106-d2/qualification-terminal-status-01.json', 'sha256': '4b268e9d34b0e85e727a07e1586e772a1ee9a91c02a32a13f49332a815c9c1cf'}, 'qualified_source_map': {'bytes': 24368, 'path': '/home/qian/hepta-runtime-validation-cost-20261106-d2/qualification-01/source-map.json', 'sha256': '4bdbae5e8dea5d7534b5bde6961b44eaeaf5524553a788e171fee9fb2ecf5209'}, 'outer_input_manifest': {'path': '/home/qian/hepta-runtime-validation-cost-20261106-d2/c1-prerequisites-01.json', 'bytes': 7538, 'sha256': '39ee58937fdb05bd97bde4dc7c9ef1033b5744c7d52b6613bc0368f9af54ed63'}, 'profile_template': {'path': '/home/qian/hepta-runtime-optimization-20261023/r11-native-observation-abba-20261103-02/profile/profile.json', 'bytes': 836, 'sha256': 'fe1e9551b5b8812ad6ed3da018c282b7261f7caeb2f49e4dcfefba7ff784ab08'}, 'topology': {'path': '/home/qian/hepta-runtime-optimization-20261104-r16/benchmark-topology.json', 'bytes': 796, 'sha256': '8c0767d3318131a7d470d9cde8e327a59ce18adf022c8bc1b1d5a0fa9a865287'}, 'frozen_jobs': [{'path': '/home/qian/hepta-runtime-optimization-20261023/a31-frozen-originals-r01/1a16a4035ad-b1270-1.json', 'bytes': 880, 'sha256': 'a8982325aea4833461e2b6a76ca83f846b80b99a227298e97a0b279e2d9dfdb8'}, {'path': '/home/qian/hepta-runtime-optimization-20261023/a31-frozen-originals-r01/1a16a403e55-b1270-2.json', 'bytes': 877, 'sha256': 'bbb8a86161837ff0f197b345c25bc66224e3404473dea2ac46d1f44f3af43609'}, {'path': '/home/qian/hepta-runtime-optimization-20261023/a31-frozen-originals-r01/1a16a4046ac-b1270-3.json', 'bytes': 881, 'sha256': '4badc323518a6db1567162a2d7ef5d1209aa88375aba201ec6f3aab34bec61a8'}, {'path': '/home/qian/hepta-runtime-optimization-20261023/a31-frozen-originals-r01/1a16a40534e-b1270-4.json', 'bytes': 890, 'sha256': '79e18b1a42d84f8024b692dfd98a9f06fa1d6886bf5dc230248cfbde674f011c'}, {'path': '/home/qian/hepta-runtime-optimization-20261023/a31-frozen-originals-r01/1a16a405d21-b1270-5.json', 'bytes': 877, 'sha256': '9c89c598f35f6bc94572852fcc03feed6e8c798ee34db5095bd3b48813562dc6'}, {'path': '/home/qian/hepta-runtime-optimization-20261023/a31-frozen-originals-r01/1a16a40671b-b1270-6.json', 'bytes': 878, 'sha256': '5b737330fa5a75a458138e1848a044d2a77c062175d8eb9694a510ff20b53cde'}], 'benchmark_output': '/home/qian/hepta-runtime-validation-cost-20261106-d2/c1-observation-01', 'evidence_output': '/home/qian/hepta-runtime-validation-cost-20261106-d2/c1-adapter-evidence-01', 'socket_parent': '/home/qian/hd2c01'}
SCHEMA = "hepta-d2-c1-phase-cost-adapter/v1"
ORDER = "ABBA"
MODES = {"A": "off", "B": "on"}
ENV_KEYS = (
    "HEPTA_RUNTIME_PHASE_COST_MODE",
    "HEPTA_RUNTIME_PHASE_COST_OUTPUT",
    "HEPTA_RUNTIME_PHASE_COST_ELF_SHA256",
)
TRACE_NAME = "phase-cost.trace.jsonl"
SOCKET_PARENT = Path("/home/qian/hd2c01")
MAX_SOURCE = 256 * 1024
MAX_REPORT = 16 * 1024 * 1024
MAX_TRACE = 32 * 1024 * 1024
MAX_ELF = 128 * 1024 * 1024
REFERENCE = {
    "correlate_trace.py": (15615, "891f511e80273c5fb4a1a76ff3606b7de90827c3eab5d01bb3e283dba952cd84"),
    "run_native_observation.py": (3279, "7606648c99b2ff2bbf0bba58384e8cab609ac3899f838c0b80ba54d6288d20bb"),
    "x230_observation_benchmark.py": (37006, "4d96f0bf2da2562e788f48be7c37589ab3a513be5f9d8b2d741afe5c08ea9eed"),
    "allocator_environment.py": (5879, "f5c8e879c540b3f7cb1b7d3a7a0f5002c2f40c1a87963174b0b00470fa3a4525"),
    "observation_resources.py": (12382, "f3402d51cb37b2fe20f4351b3a81ec5990a9fdaff93a846d21c07ccd557cb894"),
    "summarize_trace.py": (15070, "ca0e7e0d7c670daec20e54c6703bc1849f80138224570ef5366abd60079c7927"),
}
MODULES = ("allocator_environment", "observation_resources",
           "x230_observation_benchmark", "_hepta_d2_original_wrapper", "_hepta_d2_trace_parser",
           "_hepta_d2_trace_correlation")


def need(value, reason):
    if not value:
        raise ValueError(reason)


def stamp(value):
    return (value.st_dev, value.st_ino, value.st_uid, value.st_gid, value.st_mode,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def direct(path):
    path = Path(path)
    need(path.is_absolute() and path.resolve() == path, "absolute direct path required")
    return path


def regular(path, maximum, retain=True):
    path = direct(path)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
         and before.st_uid == os.getuid() and before.st_size <= maximum,
         "owned bounded single-link input required: " + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        need(stamp(os.fstat(fd)) == stamp(before), "input open identity changed")
        digest, parts, size = hashlib.sha256(), [], 0
        while True:
            piece = os.read(fd, min(65536, maximum + 1 - size))
            if not piece:
                break
            size += len(piece)
            need(size <= maximum, "input byte bound exceeded")
            digest.update(piece)
            if retain:
                parts.append(piece)
        need(size == before.st_size and stamp(os.fstat(fd)) == stamp(before)
             == stamp(path.lstat()), "input changed while reading")
        identity = {"path": str(path), "bytes": size, "sha256": digest.hexdigest()}
        return (b"".join(parts) if retain else None), identity
    finally:
        os.close(fd)


def bound(pin, maximum, retain=True):
    need(isinstance(pin, dict) and set(pin) == {"path", "bytes", "sha256"},
         "exact path/bytes/SHA256 pin required")
    raw, identity = regular(pin["path"], maximum, retain)
    need(identity == pin, "frozen input identity differs: " + str(pin["path"]))
    return raw


def json_object(raw):
    def pairs(items):
        out = {}
        for key, value in items:
            need(key not in out, "duplicate JSON key")
            out[key] = value
        return out
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode()


def write_new(path, value):
    raw = encoded(value)
    need(len(raw) <= MAX_REPORT, "new evidence exceeds byte limit")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    directory = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return {"path": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def private_directory(path):
    path = direct(path)
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
         and stat.S_IMODE(info.st_mode) == 0o700, "private owned directory required")
    return path


def boot_id():
    fd = os.open("/proc/sys/kernel/random/boot_id", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        raw = os.read(fd, 129)
        need(0 < len(raw) <= 128 and not os.read(fd, 1), "bounded boot identity required")
        return raw.decode("ascii").strip()
    finally:
        os.close(fd)


def require_sealed():
    need(isinstance(SPEC, dict) and SPEC.get("sealed") is True,
         "D2 C1 adapter is unsealed; no runtime or filesystem output was started")
    need(set(SPEC) == {
        "schema", "sealed", "root", "reference_directory", "qualified_feature_binary",
        "qualification_report", "qualification_terminal", "qualified_source_map",
        "outer_input_manifest", "profile_template", "topology", "frozen_jobs",
        "benchmark_output", "evidence_output", "socket_parent",
    }, "unexpected or missing adapter input")
    need(SPEC["schema"] == "hepta-d2-c1-phase-cost-input/v1" and SPEC["root"] == str(ROOT),
         "D2 input schema/root differs")
    need(sys.platform == "linux" and not any(key in os.environ for key in ENV_KEYS),
         "Linux with no ambient diagnostic variables required")
    need(time.get_clock_info("monotonic").implementation == "clock_gettime(CLOCK_MONOTONIC)",
         "original Python and diagnostic wall clocks must share CLOCK_MONOTONIC")
    private_directory(ROOT)
    for name in ("benchmark_output", "evidence_output"):
        path = direct(SPEC[name])
        need(path.parent == ROOT and not os.path.lexists(path), "fresh direct D2 output required: " + name)
    need(SPEC["benchmark_output"] != SPEC["evidence_output"], "output namespaces overlap")
    need(SPEC["socket_parent"] == str(SOCKET_PARENT), "planned private socket namespace differs")
    private_directory(SOCKET_PARENT)
    need(not any(SOCKET_PARENT.iterdir()), "outer-created socket parent is not fresh and empty")
    need(direct(SPEC["reference_directory"]).is_relative_to(ROOT), "reference directory outside D2")
    need(SPEC["qualified_feature_binary"]["path"] == str(ROOT / "qualification-01/hepta-runtime"),
         "only the retained qualified feature ELF may run")
    need(SPEC["qualified_source_map"]["path"] == str(ROOT / "qualification-01/source-map.json"),
         "qualified source map path differs")
    need(SPEC["qualification_report"]["path"] == str(ROOT / "qualification-01/report.json"),
         "qualification report path differs")
    need(SPEC["qualification_terminal"]["path"] == str(ROOT / "qualification-terminal-status-01.json"),
         "original qualification terminal path differs")
    need(isinstance(SPEC["frozen_jobs"], list) and len(SPEC["frozen_jobs"]) == 6,
         "six exact original job files required")
    job_paths = [direct(pin["path"]) for pin in SPEC["frozen_jobs"]]
    need(len(set(job_paths)) == 6 and len({p.parent for p in job_paths}) == 1
         and all(p.suffix == ".json" for p in job_paths), "frozen job input paths differ")
    need(sorted(p.name for p in job_paths) == sorted(p.name for p in job_paths[0].parent.glob("*.json")),
         "frozen job directory contains an unbound JSON file")
    inputs = ("qualification_report", "qualification_terminal", "qualified_source_map", "outer_input_manifest")
    for name in inputs:
        bound(SPEC[name], MAX_REPORT)
    source_map = json_object(bound(SPEC["qualified_source_map"], MAX_REPORT))
    qualification = json_object(bound(SPEC["qualification_report"], MAX_REPORT))
    need(isinstance(source_map, dict) and len(source_map) == 222
         and qualification.get("qualified") is True
         and qualification.get("source") == str(ROOT / "source")
         and qualification.get("source_tested") == source_map
         and qualification.get("source_after") == source_map,
         "actual qualified diagnostic source map is not closed")
    # Native terminal, eight-stage inventory and feature-build proof are fully
    # verified by the sealed original outer binder, referenced in outer_input_manifest.
    # Hashing that receipt here does not recreate or replace its verifier.
    for name in ("profile_template", "topology"):
        bound(SPEC[name], MAX_SOURCE)
    for pin in SPEC["frozen_jobs"]:
        bound(pin, 65536)
    bound(SPEC["qualified_feature_binary"], MAX_ELF, False)
    return SPEC


def original_modules(reference):
    need(not any(name in sys.modules for name in MODULES), "original module name already occupied")
    raws, paths = {}, {}
    for name, (size, digest) in REFERENCE.items():
        path = reference / name
        raw, identity = regular(path, MAX_SOURCE)
        need((identity["bytes"], identity["sha256"]) == (size, digest), "original helper differs: " + name)
        raws[name], paths[name] = raw, path
    def load(name, filename):
        module = types.ModuleType(name)
        module.__file__ = str(paths[filename])
        module.__package__ = ""
        sys.modules[name] = module
        exec(compile(raws[filename], str(paths[filename]), "exec", optimize=0), module.__dict__)
        return module
    allocator = load("allocator_environment", "allocator_environment.py")
    load("observation_resources", "observation_resources.py")
    bench = load("x230_observation_benchmark", "x230_observation_benchmark.py")
    wrapper = load("_hepta_d2_original_wrapper", "run_native_observation.py")
    need(wrapper.bench is bench and bench.allocator is allocator
         and wrapper.ORIGINAL_CELL is bench.cell and wrapper.ORIGINAL_SAVE is bench.save_report,
         "original wrapper/module identities differ")
    return allocator, bench, wrapper, raws, paths, load


class EnvironmentBinding:
    def __init__(self, bench, original, spec):
        self.bench = bench
        self.original = original
        self.spec = spec
        self.thread = threading.get_ident()
        self.constructor_code = bench.Controller.__init__.__code__
        self.main_code = bench.main.__code__
        self.rows = []
        out = Path(spec["benchmark_output"])
        self.slots = tuple({
            "index": number * 2 + (phase == "restart"), "round": number, "arm": arm,
            "mode": MODES[arm], "phase": phase,
            "directory": str(out / ("round-" + str(number) + "-" + arm) / phase),
            "config": str(out / ("round-" + str(number) + "-" + arm) / "runtime.json"),
            "profile": str(out / "profile/profile.json"),
        } for number, arm in enumerate(ORDER) for phase in ("first", "restart"))

    def __call__(self, base, configuration):
        caller = sys._getframe(1)
        parent = None
        try:
            need(caller.f_code is self.constructor_code and threading.get_ident() == self.thread,
                 "diagnostic environment hook was called outside original Controller.__init__")
            parent = caller.f_back
            need(parent is not None and parent.f_code is self.main_code,
                 "controller was not constructed by original benchmark main")
            need(len(self.rows) < len(self.slots), "unexpected extra controller construction")
            slot = self.slots[len(self.rows)]
            locals_, main = caller.f_locals, parent.f_locals
            controller = locals_.get("self")
            need(type(controller) is self.bench.Controller
                 and str(controller.directory) == slot["directory"]
                 and str(controller.binary) == self.spec["qualified_feature_binary"]["path"]
                 and str(locals_.get("directory")) == slot["directory"]
                 and str(locals_.get("config")) == slot["config"]
                 and str(locals_.get("profile")) == slot["profile"]
                 and str(locals_.get("binary")) == self.spec["qualified_feature_binary"]["path"],
                 "original controller context differs from preregistered slot")
            need(main.get("number") == slot["round"] and main.get("version") == slot["arm"]
                 and main.get("active") is None
                 and locals_.get("workers") == 2 and locals_.get("path_prefix") is None
                 and locals_.get("file_pool") is False and locals_.get("env") is base
                 and locals_.get("allocator_values") is configuration,
                 "controller construction context or original dimensions changed")
            need(configuration == {"MALLOC_ARENA_MAX": "1"}
                 and not any(key in base or key in os.environ for key in ENV_KEYS),
                 "ambient diagnostic or allocator configuration differs")
            directory = private_directory(slot["directory"])
            trace = directory / TRACE_NAME
            need(not os.path.lexists(trace), "diagnostic trace must be a new file")
            result = self.original(base, configuration)
            need(not any(key in result for key in ENV_KEYS), "original allocator inserted diagnostic variables")
            added = dict(zip(ENV_KEYS, (slot["mode"], str(trace),
                                      self.spec["qualified_feature_binary"]["sha256"])))
            result.update(added)
            self.rows.append({**slot, "trace": str(trace), "added_environment": added,
                              "context_consumed_once": True,
                              "owner_identity_available_before_Popen": False})
            return result
        finally:
            del parent
            del caller


def closed_matrix(report, returncode, bindings):
    need(returncode == 0 and report.get("passed") is True and not report.get("error"),
         "original ABBA did not succeed; raw outputs retained without trace interpretation")
    need(report.get("order") == ORDER and report.get("concurrency") == [1]
         and report.get("calls_per_cell") == 192 and report.get("tokio_workers") == 2
         and report.get("effect_starts") == report.get("remote_mutation_tool_calls")
         == report.get("automatic_rpc_retries") == 0,
         "original read-only C1 matrix differs")
    need(report.get("binary_sha256") == dict.fromkeys("AB", SPEC["qualified_feature_binary"]["sha256"])
         and report.get("source_originals_unchanged") is True
         and report.get("binary_hashes_unchanged") is True
         and report.get("topology_manifest_unchanged") is True,
         "original binary/fixture/topology closure differs")
    measurement = report.get("r16_measurement", {})
    need(measurement.get("scripts_unchanged") is True
         and measurement.get("balanced_warmup_calls_per_cell") == 24
         and measurement.get("warmup_included_in_performance_denominator") is False,
         "original wrapper closure differs")
    rounds = report.get("rounds")
    need(isinstance(rounds, list) and len(rounds) == 4 and len(bindings) == 8,
         "complete ABBA and eight consumed controller contexts required")
    controllers = []
    for number, (arm, row) in enumerate(zip(ORDER, rounds)):
        need(row.get("index") == number and row.get("version") == arm and row.get("passed") is True,
             "original ABBA round identity or outcome differs")
        need(len(row.get("cells", [])) == 1, "C1-only original cell required")
        cell = row["cells"][0]
        warm = cell.get("warmup", {})
        need(cell.get("concurrency") == warm.get("concurrency") == 1
             and cell.get("calls") == cell.get("successes") == len(cell.get("rows", [])) == 192
             and warm.get("calls") == warm.get("successes") == len(warm.get("rows", [])) == 24
             and len(row.get("initial_complete_outputs", [])) == 6
             and len(row.get("restart_checks", [])) == 12,
             "original measured/warmup/preflight/restart counts differ")
        for phase, start_key, close_key in (("first", "startup", "shutdown"),
                                           ("restart", "restart_startup", "restart_shutdown")):
            startup, shutdown = row.get(start_key, {}), row.get(close_key, {})
            need(shutdown.get("exit_code") == 0 and shutdown.get("shutdown_method") == "stdin_eof"
                 and shutdown.get("observed_descendant_survivors") == []
                 and shutdown.get("reader_error") is None and shutdown.get("unmatched_responses") == 0
                 and shutdown.get("resources", {}).get("sampler_error") is None
                 and shutdown.get("transport_capture", {}).get("reader_eof") is True,
                 "original controller close proof incomplete; no sidecar is opened")
            need(type(startup.get("pid")) is int and type(startup.get("birth_ticks")) is int,
                 "original controller birth identity missing")
            groups = (
                [("preflight", row["initial_complete_outputs"], None),
                 ("warmup", warm["rows"], warm["raw_timing"]),
                 ("measured", cell["rows"], cell["raw_timing"])]
                if phase == "first" else [("restart", row["restart_checks"], None)]
            )
            controllers.append({"binding": bindings[len(controllers)], "startup": startup,
                                "shutdown": shutdown, "groups": groups})
    return controllers


def select_trace(controller, parser, bench, expected_boot, all_done_ns, next_start_ns, correlation):
    binding, startup, shutdown = controller["binding"], controller["startup"], controller["shutdown"]
    directory = Path(binding["directory"])
    capture = shutdown["transport_capture"]
    raw, raw_pin = regular(directory / "transport-responses.jsonl", MAX_REPORT)
    index, index_pin = regular(directory / "transport-responses.index.jsonl", MAX_REPORT)
    for observed, recorded, filename in (
        (raw_pin, capture["raw"], "transport-responses.jsonl"),
        (index_pin, capture["index"], "transport-responses.index.jsonl"),
    ):
        need(recorded.get("file") == filename and recorded.get("bytes") == observed["bytes"]
             and recorded.get("sha256") == observed["sha256"], "original transport identity differs")
    relative = directory.relative_to(ROOT).as_posix()
    originals = {relative + "/transport-responses.jsonl": raw,
                 relative + "/transport-responses.index.jsonl": index}

    class ClosedOriginalBytes:
        def read(self, member):
            need(member in originals, "correlation requested an unbound original byte stream")
            return originals[member]

    need(correlation.ROOT == str(ROOT), "correlation root differs from the sealed adapter")
    calls = correlation.transport_calls(ClosedOriginalBytes(), controller)
    trace, trace_pin = regular(binding["trace"], MAX_TRACE)
    summary = parser.summarize(trace, trace_pin["sha256"])
    lines = trace.splitlines()
    header, footer = json_object(lines[0]), json_object(lines[-1])
    need(header["mode"] == binding["mode"] and header["pid"] == startup["pid"]
         and header["start_ticks"] == startup["birth_ticks"] and header["boot_id"] == expected_boot
         and header["declared_elf_sha256"] == SPEC["qualified_feature_binary"]["sha256"]
         and header["elf_hash_verified_here"] is False,
         "trace mode/ELF/controller birth binding differs")
    need(startup["start_monotonic_ns"] <= header["start_monotonic_ns"] <= startup["ready_monotonic_ns"]
         and footer["end_monotonic_ns"] <= min(all_done_ns, next_start_ns),
         "trace lies outside original controller lifetime boundaries")
    selected = []
    result = {
        "binding": binding, "startup": startup, "trace": trace_pin,
        "raw_transport": raw_pin, "raw_transport_index": index_pin,
        "original_request_groups": {call["row_key"]: call for call in calls},
        "trace_summary": summary,
        "phase_cpu_available": binding["mode"] == "on",
        "category_phase_summaries": None,
        "whole_trace_cpu_is_measured_cell_cpu": False,
        "native_auditor_reexecuted_here": False,
        "wire_native_id_source": "absent on status/read; identity comes only from the bound trace",
        "off_empty_trace_is_zero_work_cpu_claim": False,
        "validation_whole_cpu_uses_parent_inclusive_field": True,
        "read_loop_phase_includes_original_reads_comparison_or_hash_and_cancellation_checks": True,
    }
    if binding["mode"] == "on":
        rows = [json_object(line) for line in lines[1:-1]]
        per_request, scopes = correlation.phase_values(rows, summary, parser)
        selected = correlation.correlate(calls, summary, scopes, per_request, result)
        result["new_selective_phase_arithmetic_reconciled_with_parser"] = True
        result["category_phase_summaries"] = {
            category: correlation.aggregate([item for item in selected if item["category"] == category], parser)
            for category in ("preflight", "warmup", "measured", "restart")
            if any(item["category"] == category for item in selected)
        }
        measured = [item for item in selected if item["category"] == "measured"]
        if measured:
            cells = [interval for category, _, interval in controller["groups"] if category == "measured"]
            need(len(cells) == 1, "measured controller has no unique original cell")
            result["measured_controller_cpu_comparison"] = correlation.measured_counter(
                {"raw_timing": cells[0]}, startup, measured)
    else:
        need(summary["requests"] == [], "OFF arm recorded request events")
    result["selected_on_requests"] = selected
    result["selected_on_counts"] = {name: sum(item["category"] == name for item in selected)
                                     for name in ("preflight", "warmup", "measured", "restart")}
    return result

def main():
    spec = require_sealed()  # Must precede imports of original code and all new outputs.
    need(len(sys.argv) == 1, "the sealed adapter accepts no protocol-changing command-line options")
    reference = direct(spec["reference_directory"])
    evidence = Path(spec["evidence_output"])
    evidence.mkdir(mode=0o700)
    write_new(evidence / "attempt-input.json", spec)
    original_argv, original_path = list(sys.argv), list(sys.path)
    modules_before = {name: sys.modules.get(name) for name in MODULES}
    original_dont_write_bytecode = sys.dont_write_bytecode
    allocator = bench = wrapper = binding = original_environment = None
    output = {
        "schema": SCHEMA, "sealed_input": spec, "order": ORDER, "modes": MODES,
        "original_returncode": None, "original_wrapper_returned": False,
        "controller_close_evidence_complete": False, "all_trace_reads_after_original_matrix": True,
        "trace_interpretation_started": False, "analysis_complete": False,
        "original_native_audit_required": True, "performance_acceptance_claim": False,
        "parent_held_agent_quiet90_and_compiler_monitor_required": True,
        "errors": [], "bindings": [], "traces": [],
    }
    self_before = regular(Path(__file__), MAX_SOURCE)[1]
    before_boot = boot_id()
    output["boot_id_before"] = before_boot
    begun = time.monotonic_ns()
    output["adapter_start_monotonic_ns"] = begun
    try:
        allocator, bench, wrapper, raws, paths, loader = original_modules(reference)
        original_environment = allocator.child_environment
        original_constructor = bench.Controller.__init__
        original_close = bench.Controller.close
        original_cell = wrapper.ORIGINAL_CELL
        original_popen = bench.subprocess.Popen
        binding = EnvironmentBinding(bench, original_environment, spec)
        allocator.child_environment = binding
        binary = spec["qualified_feature_binary"]["path"]
        sys.argv = [str(paths["run_native_observation.py"]),
                    "--baseline", binary, "--candidate", binary,
                    "--arena-max", "1", "--profile-template", spec["profile_template"]["path"],
                    "--topology", spec["topology"]["path"],
                    "--frozen-jobs", str(Path(spec["frozen_jobs"][0]["path"]).parent),
                    "--out", spec["benchmark_output"], "--socket-parent", spec["socket_parent"],
                    "--calls", "192", "--concurrency", "1", "--workers", "2",
                    "--order", ORDER, "--warmup-calls", "24"]
        output["original_argv"] = list(sys.argv)
        try:
            output["original_returncode"] = wrapper.main()
            output["original_wrapper_returned"] = True
        finally:
            # Only restore the environment hook. Ownership and cleanup remain
            # wholly in the unchanged original Controller and benchmark main.
            allocator.child_environment = original_environment
        all_done_ns = time.monotonic_ns()
        output["original_wrapper_return_monotonic_ns"] = all_done_ns
        output["bindings"] = list(binding.rows)
        report_raw, report_pin = regular(Path(spec["benchmark_output"]) / "report.json", MAX_REPORT)
        output["original_report"] = report_pin
        report = json_object(report_raw)
        need(bench.Controller.__init__ is original_constructor and bench.Controller.close is original_close
             and wrapper.ORIGINAL_CELL is original_cell and bench.subprocess.Popen is original_popen
             and bench.cell is wrapper.cell and bench.save_report is wrapper.save_report,
             "original controller/cell/close/Popen identity changed")
        controllers = closed_matrix(report, output["original_returncode"], binding.rows)
        output["controller_close_evidence_complete"] = True
        need(boot_id() == before_boot, "Linux boot identity changed")
        bound(spec["qualified_feature_binary"], MAX_ELF, False)
        for filename, (size, digest) in REFERENCE.items():
            raw, identity = regular(paths[filename], MAX_SOURCE)
            need((identity["bytes"], identity["sha256"]) == (size, digest), "original source changed")
        need(regular(Path(__file__), MAX_SOURCE)[1] == self_before, "adapter source changed")
        for name in ("qualification_report", "qualification_terminal", "qualified_source_map", "outer_input_manifest"):
            bound(spec[name], MAX_REPORT)
        parser = loader("_hepta_d2_trace_parser", "summarize_trace.py")
        correlation = loader("_hepta_d2_trace_correlation", "correlate_trace.py")
        output["trace_interpretation_started"] = True
        for index, controller in enumerate(controllers):
            next_start = (controllers[index + 1]["startup"]["start_monotonic_ns"]
                          if index + 1 < len(controllers) else all_done_ns)
            output["traces"].append(select_trace(controller, parser, bench, before_boot, all_done_ns, next_start, correlation))
        need(len(output["traces"]) == 8, "trace matrix is incomplete")
        selected = [item for trace in output["traces"] for item in trace["selected_on_requests"]]
        native_ids = [item["trace_native_request_id"] for item in selected]
        need(len(selected) == 468 and len(set(native_ids)) == 468,
             "ON native identities are incomplete or reused across controller generations")
        need(sum(item["category"] == "measured" for item in selected) == 384,
             "ON measured request coverage is incomplete")
        output["strict_on_request_bijection_count"] = len(selected)
        output["measured_on_request_count"] = 384
        output["measured_phase_summary"] = correlation.aggregate(
            [item for item in selected if item["category"] == "measured"], parser)
        output["wire_native_request_id_policy"] = "absent on original status/read responses; never synthesized"
        output["validation_whole_cost_field"] = "inclusive CPU of validation_worker and validation_owner"
        output["analysis_complete"] = True
    except BaseException as error:
        output["errors"].append({"type": type(error).__name__, "reason": str(error)[:1500]})
    finally:
        if allocator is not None and original_environment is not None:
            allocator.child_environment = original_environment
        if binding is not None:
            output["bindings"] = list(binding.rows)
        sys.argv, sys.path = original_argv, original_path
        sys.dont_write_bytecode = original_dont_write_bytecode
        for name, original_module in modules_before.items():
            if original_module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = original_module
        output["adapter_finish_monotonic_ns"] = time.monotonic_ns()
        output["adapter_source"] = self_before
        output["scope"] = (
            "diagnostic same-feature-ELF OFF/ON C1 only; original native validation, "
            "full owner/held-agent/quiet/compiler evidence remain mandatory external receipts")
        receipt = write_new(evidence / "adapter-report.json", output)
        print(json.dumps({"adapter_report": receipt, "original_returncode": output["original_returncode"],
                          "analysis_complete": output["analysis_complete"],
                          "errors": output["errors"]}, sort_keys=True), flush=True)
    return 0 if output["analysis_complete"] and not output["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
