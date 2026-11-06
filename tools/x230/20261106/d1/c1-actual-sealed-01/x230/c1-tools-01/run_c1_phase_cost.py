#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Unsealed D1 C1 adapter for the unchanged R16 native observation driver.

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
ROOT = Path("/home/qian/hepta-runtime-phase-cost-20261106-d1")
SPEC = {'schema': 'hepta-d1-c1-phase-cost-input/v1', 'sealed': True, 'root': '/home/qian/hepta-runtime-phase-cost-20261106-d1', 'reference_directory': '/home/qian/hepta-runtime-phase-cost-20261106-d1/c1-tools-01/reference', 'qualified_feature_binary': {'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/qualification-01/hepta-runtime', 'bytes': 14456088, 'sha256': '1d6f38950eefe34891827b5e0f71cb7b388ddbbb2f3fc339c3a0325e27ef11ad'}, 'qualification_report': {'bytes': 83976, 'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/qualification-01/report.json', 'sha256': '0fd74793651afcf0b24f010d4371a04c422da8fd4711cb288da40cf4d69ee437'}, 'qualification_terminal': {'bytes': 731, 'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/qualification-terminal-status-01.json', 'sha256': 'c06e447a3adf5eb6f8afd0533e898a3f6417ce61d52e0a31b66f5277a991f303'}, 'qualified_source_map': {'bytes': 24368, 'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/qualification-01/source-map.json', 'sha256': '98824381ae2009e909fc28e07087d8646d3131229e146c04ecd9f58c60a14133'}, 'outer_input_manifest': {'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/c1-prerequisites-01.json', 'bytes': 5063, 'sha256': '9d5ca9b3d4e276d8f7b830cf028eac9eded76ab3b0f560758279451989c966cb'}, 'profile_template': {'path': '/home/qian/hepta-runtime-optimization-20261023/r11-native-observation-abba-20261103-02/profile/profile.json', 'bytes': 836, 'sha256': 'fe1e9551b5b8812ad6ed3da018c282b7261f7caeb2f49e4dcfefba7ff784ab08'}, 'topology': {'path': '/home/qian/hepta-runtime-optimization-20261104-r16/benchmark-topology.json', 'bytes': 796, 'sha256': '8c0767d3318131a7d470d9cde8e327a59ce18adf022c8bc1b1d5a0fa9a865287'}, 'frozen_jobs': [{'path': '/home/qian/hepta-runtime-optimization-20261023/a31-frozen-originals-r01/1a16a4035ad-b1270-1.json', 'bytes': 880, 'sha256': 'a8982325aea4833461e2b6a76ca83f846b80b99a227298e97a0b279e2d9dfdb8'}, {'path': '/home/qian/hepta-runtime-optimization-20261023/a31-frozen-originals-r01/1a16a403e55-b1270-2.json', 'bytes': 877, 'sha256': 'bbb8a86161837ff0f197b345c25bc66224e3404473dea2ac46d1f44f3af43609'}, {'path': '/home/qian/hepta-runtime-optimization-20261023/a31-frozen-originals-r01/1a16a4046ac-b1270-3.json', 'bytes': 881, 'sha256': '4badc323518a6db1567162a2d7ef5d1209aa88375aba201ec6f3aab34bec61a8'}, {'path': '/home/qian/hepta-runtime-optimization-20261023/a31-frozen-originals-r01/1a16a40534e-b1270-4.json', 'bytes': 890, 'sha256': '79e18b1a42d84f8024b692dfd98a9f06fa1d6886bf5dc230248cfbde674f011c'}, {'path': '/home/qian/hepta-runtime-optimization-20261023/a31-frozen-originals-r01/1a16a405d21-b1270-5.json', 'bytes': 877, 'sha256': '9c89c598f35f6bc94572852fcc03feed6e8c798ee34db5095bd3b48813562dc6'}, {'path': '/home/qian/hepta-runtime-optimization-20261023/a31-frozen-originals-r01/1a16a40671b-b1270-6.json', 'bytes': 878, 'sha256': '5b737330fa5a75a458138e1848a044d2a77c062175d8eb9694a510ff20b53cde'}], 'benchmark_output': '/home/qian/hepta-runtime-phase-cost-20261106-d1/c1-observation-01', 'evidence_output': '/home/qian/hepta-runtime-phase-cost-20261106-d1/c1-adapter-evidence-01', 'socket_parent': '/home/qian/hd1c01'}
SCHEMA = "hepta-d1-c1-phase-cost-adapter/v1"
ORDER = "ABBA"
MODES = {"A": "off", "B": "on"}
ENV_KEYS = (
    "HEPTA_RUNTIME_PHASE_COST_MODE",
    "HEPTA_RUNTIME_PHASE_COST_OUTPUT",
    "HEPTA_RUNTIME_PHASE_COST_ELF_SHA256",
)
TRACE_NAME = "phase-cost.trace.jsonl"
SOCKET_PARENT = Path("/home/qian/hd1c01")
MAX_SOURCE = 256 * 1024
MAX_REPORT = 16 * 1024 * 1024
MAX_TRACE = 32 * 1024 * 1024
MAX_ELF = 128 * 1024 * 1024
REFERENCE = {
    "run_native_observation.py": (3279, "7606648c99b2ff2bbf0bba58384e8cab609ac3899f838c0b80ba54d6288d20bb"),
    "x230_observation_benchmark.py": (37006, "4d96f0bf2da2562e788f48be7c37589ab3a513be5f9d8b2d741afe5c08ea9eed"),
    "allocator_environment.py": (5879, "f5c8e879c540b3f7cb1b7d3a7a0f5002c2f40c1a87963174b0b00470fa3a4525"),
    "observation_resources.py": (12382, "f3402d51cb37b2fe20f4351b3a81ec5990a9fdaff93a846d21c07ccd557cb894"),
    "summarize_trace.py": (15057, "f6e65c2e206d4aa90143a17893e5e57c158bca9f8eec5f74897b19c3596e32c5"),
}
MODULES = ("allocator_environment", "observation_resources",
           "x230_observation_benchmark", "_hepta_d1_original_wrapper", "_hepta_d1_trace_parser")


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
         "D1 C1 adapter is unsealed; no runtime or filesystem output was started")
    need(set(SPEC) == {
        "schema", "sealed", "root", "reference_directory", "qualified_feature_binary",
        "qualification_report", "qualification_terminal", "qualified_source_map",
        "outer_input_manifest", "profile_template", "topology", "frozen_jobs",
        "benchmark_output", "evidence_output", "socket_parent",
    }, "unexpected or missing adapter input")
    need(SPEC["schema"] == "hepta-d1-c1-phase-cost-input/v1" and SPEC["root"] == str(ROOT),
         "D1 input schema/root differs")
    need(sys.platform == "linux" and not any(key in os.environ for key in ENV_KEYS),
         "Linux with no ambient diagnostic variables required")
    need(time.get_clock_info("monotonic").implementation == "clock_gettime(CLOCK_MONOTONIC)",
         "original Python and diagnostic wall clocks must share CLOCK_MONOTONIC")
    private_directory(ROOT)
    for name in ("benchmark_output", "evidence_output"):
        path = direct(SPEC[name])
        need(path.parent == ROOT and not os.path.lexists(path), "fresh direct D1 output required: " + name)
    need(SPEC["benchmark_output"] != SPEC["evidence_output"], "output namespaces overlap")
    need(SPEC["socket_parent"] == str(SOCKET_PARENT), "planned private socket namespace differs")
    private_directory(SOCKET_PARENT)
    need(not any(SOCKET_PARENT.iterdir()), "outer-created socket parent is not fresh and empty")
    need(direct(SPEC["reference_directory"]).is_relative_to(ROOT), "reference directory outside D1")
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
    wrapper = load("_hepta_d1_original_wrapper", "run_native_observation.py")
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


def select_trace(controller, parser, bench, expected_boot, all_done_ns, next_start_ns):
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
    index_rows = [json_object(line) for line in index.splitlines()]
    need(len(index_rows) == capture["frames"], "original transport index count differs")
    requests = {}
    for category, rows, interval in controller["groups"]:
        for row in rows:
            need(row.get("okay") is True and row.get("automatic_retry") is False,
                 "original request failed or was retried")
            proof = row["rpc"]["transport_response"]
            need(proof.get("file") == "transport-responses.jsonl"
                 and type(proof.get("sequence")) is int and 0 <= proof["sequence"] < len(index_rows),
                 "original transport proof differs")
            need({key: value for key, value in proof.items() if key != "file"} == index_rows[proof["sequence"]],
                 "request raw frame and original index differ")
            lo, size = proof["offset"], proof["bytes"]
            need(type(lo) is int and type(size) is int and 0 <= lo < lo + size <= len(raw),
                 "raw frame range invalid")
            frame = raw[lo:lo + size]
            need(frame.endswith(b"\n") and hashlib.sha256(frame).hexdigest() == proof["sha256"],
                 "original raw frame bytes differ")
            reply = json_object(frame)
            need(reply.get("id") == row["rpc"]["request_id"]
                 and hashlib.sha256(bench.canonical(reply)).hexdigest() == row["response_sha256"],
                 "original RPC identity or response hash differs")
            marker = reply.get("result", {}).get("_meta", {}).get("io.hepta.runtime/request-v8", {})
            native = marker.get("request_id")
            need(isinstance(native, str) and native and native not in requests
                 and marker.get("automatic_retry") is False and marker.get("delivery_proven") is False,
                 "unique original native request identity missing")
            call_interval = [row["start_monotonic_ns"], row["end_monotonic_ns"]]
            need(0 <= call_interval[0] <= call_interval[1], "original request time reversed")
            if interval is not None:
                need(interval["start_monotonic_ns"] <= call_interval[0]
                     <= call_interval[1] <= interval["end_monotonic_ns"],
                     "request outside its original cell interval")
            requests[native] = {
                "category": category, "operation": row["tool"], "host": row["host"],
                "job_id": row["job_id"], "rpc_id": row["rpc"]["request_id"],
                "call_interval_monotonic_ns": call_interval,
                "cell_interval_monotonic_ns": (
                    [interval["start_monotonic_ns"], interval["end_monotonic_ns"]]
                    if interval is not None else None),
            }
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
    if binding["mode"] == "on":
        need({item["native_request_id"] for item in summary["requests"]} == set(requests),
             "trace/native request sets differ")
        events = [json_object(line) for line in lines[1:-1]]
        scopes = {}
        for item in events:
            if item.get("type") == "event" and item["event"]["phase"] == "request":
                event = item["event"]
                need(event["request"] not in scopes, "duplicate original request span")
                scopes[event["request"]] = [event["start_monotonic_ns"], event["end_monotonic_ns"]]
        for item in summary["requests"]:
            match = requests[item["native_request_id"]]
            host_index = item["host_index"]
            need(item["operation"] == match["operation"] and type(host_index) is int
                 and summary["host_aliases"][host_index] == match["host"],
                 "trace request host/operation differs from native response")
            span = scopes[item["slot"]]
            need(match["call_interval_monotonic_ns"][0] <= span[0] <= span[1]
                 <= match["call_interval_monotonic_ns"][1],
                 "trace request span crosses original RPC boundaries")
            selected.append({**item, **match, "trace_request_interval_monotonic_ns": span})
    else:
        need(summary["requests"] == [], "OFF arm recorded request events")
    return {
        "binding": binding, "startup": startup, "trace": trace_pin,
        "raw_transport": raw_pin, "raw_transport_index": index_pin,
        "original_request_groups": requests, "trace_summary": summary,
        "selected_on_requests": selected,
        "selected_on_counts": {name: sum(item["category"] == name for item in selected)
                               for name in ("preflight", "warmup", "measured", "restart")},
        "whole_trace_cpu_is_measured_cell_cpu": False,
        "native_auditor_reexecuted_here": False,
    }


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
        parser = loader("_hepta_d1_trace_parser", "summarize_trace.py")
        output["trace_interpretation_started"] = True
        for index, controller in enumerate(controllers):
            next_start = (controllers[index + 1]["startup"]["start_monotonic_ns"]
                          if index + 1 < len(controllers) else all_done_ns)
            output["traces"].append(select_trace(controller, parser, bench, before_boot, all_done_ns, next_start))
        need(len(output["traces"]) == 8, "trace matrix is incomplete")
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
