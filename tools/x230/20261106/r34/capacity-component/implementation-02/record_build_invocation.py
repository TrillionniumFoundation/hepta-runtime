#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Record one actual, single-attempt offline Cargo stage inside its native job.

No entry point is run by source preparation. Missing actual inputs refuse before
Cargo. Native stdout/stderr contain only the retained Cargo stream bytes.
"""
import argparse
from contextlib import contextmanager
import ctypes
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time

import prepare_build as binding

BUILD_STAGES = ("fmt-check", "clippy-release", "release")
ORDER = [(arm, stage) for arm in ("A", "B") for stage in ("metadata-seed", "metadata-locked")]
ORDER += [(arm, stage) for arm in ("A", "B") for stage in BUILD_STAGES]
MAX_LOG = 32 * 1024 * 1024
INTERRUPTS = []


def now():
    return time.clock_gettime_ns(time.CLOCK_MONOTONIC)


def file_pin(path, raw):
    return {"path": str(path), "bytes": len(raw), "sha256": binding.sha(raw)}


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def private_directory(path):
    binding.need(path.is_absolute() and path.resolve(strict=True) == path, "indirect directory")
    info = path.lstat()
    binding.need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
                 and info.st_mode & 0o022 == 0, "directory is not owned and write-private")


@contextmanager
def build_lock(root):
    private_directory(root)
    path = root / "build.lock"
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(fd)
        binding.need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
                     and stat.S_IMODE(info.st_mode) == 0o600
                     and binding.stamp(info) == binding.stamp(path.lstat()), "unsafe component build lock")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def proc(pid):
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii", errors="surrogateescape")
    except (FileNotFoundError, ProcessLookupError):
        return None
    end = raw.rfind(") ")
    fields = raw[end + 2:].split()
    binding.need(end > 0 and len(fields) >= 20 and int(raw.split("(", 1)[0]) == pid,
                 "malformed /proc process identity")
    return {"pid": pid, "start_ticks": int(fields[19]), "process_group": int(fields[2]),
            "session": int(fields[3]), "parent": int(fields[1]), "state": fields[0]}


def birth(row):
    return {key: row[key] for key in ("pid", "start_ticks", "process_group", "session")}


def native_identity(row, clock):
    return {"kind": "proc_start_ticks", "value": clock["boot_id"] + ":" + str(row["start_ticks"])}


def cgroup_bytes(pid):
    with open(f"/proc/{pid}/cgroup", "rb") as stream:
        raw = stream.read(65537)
    binding.need(len(raw) <= 65536, "oversized native cgroup identity")
    return raw


def native_binding(supplied, input_path, root, arm, clock):
    job_id = os.environ.get("HEPTA_RUNTIME_JOB_ID")
    binding.need(isinstance(job_id, str) and re.fullmatch(r"[0-9a-f]+(?:-[0-9a-f]+)+", job_id),
                 "actual supervisor job ID missing")
    jobs = Path(supplied["native_jobs_root"])
    private_directory(jobs)
    job = jobs / job_id
    private_directory(job)
    deadline, waits = time.monotonic() + 5, 0
    while not all(os.path.lexists(job / name) for name in ("child.json", "launch.json")):
        binding.need(time.monotonic() < deadline and not INTERRUPTS,
                     "same native child metadata not published within five seconds; Cargo not started")
        waits += 1
        time.sleep(min(0.02, max(0, deadline - time.monotonic())))
    request_raw = binding.regular(job / "request.json", 1024 * 1024)
    child_raw = binding.regular(job / "child.json", 64 * 1024)
    launch_raw = binding.regular(job / "launch.json", 64 * 1024)
    request, child = json.loads(request_raw), json.loads(child_raw)
    launch = json.loads(launch_raw)
    own = proc(os.getpid())
    script = Path(__file__).absolute()
    expected = ["/usr/bin/python3", "-B", str(script), "--input", str(input_path)]
    binding.need(request.get("job_id") == job_id and request.get("job_dir") == str(job)
                 and [request.get("executable"), *request.get("args", [])] == expected
                 and request.get("cwd") == str(root / "arms" / arm)
                 and os.getcwd() == request["cwd"] and request.get("env") in (None, {})
                 and not request.get("stdin_path"), "native request does not bind this exact producer invocation")
    binding.need(re.fullmatch(r"[0-9a-f]{32}", request.get("launch_nonce", "")) is not None
                 and re.fullmatch(r"[0-9a-f]{64}", request.get("request_fingerprint", "")) is not None
                 and request.get("terminal_publication_protocol") == 1, "native request nonce/digest/protocol absent")
    binding.need(own is not None and child == {"pid": os.getpid(), "identity": native_identity(own, clock)},
                 "original native child metadata is not this live producer")
    unit = request.get("unit")
    binding.need(isinstance(unit, str) and re.fullmatch(r"[A-Za-z0-9_.@:-]+", unit) is not None
                 and launch.get("backend") in ("systemd", "detached") and launch.get("unit") == unit,
                 "original native backend/unit binding absent")
    actual_cgroup = cgroup_bytes(os.getpid())
    unit_directory = unit if unit.endswith(".service") else unit + ".service"
    memberships = [line.split(":", 2) for line in actual_cgroup.decode("ascii").splitlines()]
    systemd_contained = any(len(parts) == 3 and parts[:2] == ["0", ""]
                           and Path(parts[2]).name == unit_directory for parts in memberships)
    binding.need(launch["backend"] != "systemd" or systemd_contained,
                 "producer is not inside its original native systemd unit cgroup")
    timeout = supplied["timeout_seconds"]
    binding.need(type(timeout) is int and 1 <= timeout <= 6600
                 and type(request.get("timeout_seconds")) is int
                 and timeout + 240 <= request["timeout_seconds"] <= 7200,
                 "native outer timeout must leave at least 240 seconds beyond the Cargo budget")
    return {"job_id": job_id, "launch_nonce": request["launch_nonce"],
            "request_fingerprint": request["request_fingerprint"], "job_directory": str(job),
            "metadata_readiness_waits": waits, "producer_identity": birth(own),
            "native_timeout_seconds": request["timeout_seconds"],
            "native_unit": unit, "native_backend": launch["backend"],
            "original_systemd_cgroup_containment": launch["backend"] == "systemd" and systemd_contained,
            "hard_parent_loss_cleanup": "unknown without original final wait/closure; no later stage is allowed"}, request_raw, child_raw, launch_raw, actual_cgroup


def controlled_context(supplied, plan, root, arm):
    from seal_arm import expected_environment
    support = supplied["support_environment"]
    binding.need(isinstance(support, dict) and set(support) == {"HOME", "RUSTUP_HOME", "RUSTUP_TOOLCHAIN"}
                 and all(isinstance(value, str) and value for value in support.values()),
                 "actual explicit rustup/home support environment required")
    binding.need(support["HOME"] == os.environ.get("HOME"), "support HOME differs from original native job")
    for name in ("HOME", "RUSTUP_HOME"):
        private_directory(Path(support[name]))
    toolchain = support["RUSTUP_TOOLCHAIN"]
    binding.need(re.fullmatch(r"[A-Za-z0-9_.+-]+", toolchain) is not None, "explicit named rustup toolchain required")
    private_directory(Path(support["RUSTUP_HOME"]) / "toolchains" / toolchain)
    environment = {**expected_environment(plan, root), **support}
    # A fresh explicit env prevents inherited flags, wrappers, Cargo profiles,
    # linker overrides or credentials from becoming an unrecorded build input.
    inventory = []
    config_paths = set()
    for base in (root / "arms" / arm, Path(plan["arms"][arm]["source_root"])):
        for directory in (base, *base.parents):
            for name in (".cargo/config", ".cargo/config.toml", "rust-toolchain", "rust-toolchain.toml"):
                config_paths.add(directory / name)
    for name in ("config", "config.toml"):
        config_paths.add(Path(plan["cargo_home"]) / name)
    for path in sorted(config_paths):
        binding.need(not os.path.lexists(path), "unreviewed build configuration exists: " + str(path))
        inventory.append({"path": str(path), "exists": False})
    settings = Path(support["RUSTUP_HOME"]) / "settings.toml"
    if os.path.lexists(settings):
        inventory.append({**file_pin(settings, binding.regular(settings)), "exists": True})
    else:
        inventory.append({"path": str(settings), "exists": False})
    tools = {}
    requested_tools = {name: Path(plan[name]) for name in ("cargo", "rustc")}
    selected_bin = Path(support["RUSTUP_HOME"]) / "toolchains" / toolchain / "bin"
    requested_tools.update({"selected-" + name: selected_bin / name
                            for name in ("cargo", "rustc", "rustfmt", "cargo-fmt", "cargo-clippy", "clippy-driver")})
    for name, requested in requested_tools.items():
        resolved = requested.resolve(strict=True)
        raw = binding.regular(resolved, 128 * 1024 * 1024)
        binding.need(os.access(requested, os.X_OK), "actual toolchain executable is not executable")
        tools[name] = {"requested_path": str(requested), "resolved": file_pin(resolved, raw)}
    return environment, inventory, tools


def context_unchanged(inventory, tools):
    for row in inventory:
        path = Path(row["path"])
        binding.need(os.path.lexists(path) is row["exists"], "build configuration presence changed")
        if row["exists"]:
            binding.bound_file({key: row[key] for key in ("path", "bytes", "sha256")})
    for row in tools.values():
        binding.need(Path(row["requested_path"]).resolve(strict=True) == Path(row["resolved"]["path"]),
                     "toolchain executable resolution changed")
        binding.bound_file(row["resolved"], 128 * 1024 * 1024)


def checked_inputs(supplied, root, arm, stage):
    plan_raw, prep_raw = binding.regular(root / "input.json"), binding.regular(root / "preparation.json")
    plan, prep = json.loads(plan_raw), json.loads(prep_raw)
    binding.need(plan.get("schema") == "hepta-r34-capacity-component-build/v1"
                 and plan.get("status") == "sealed_actual_inputs"
                 and plan.get("output_directory") == str(root) and plan.get("compiler_jobs") == 1
                 and prep.get("schema") == "hepta-r34-capacity-component-preparation/v1"
                 and prep.get("plan_sha256") == binding.sha(plan_raw)
                 and prep.get("build_order") == ["A", "B"]
                 and prep.get("shared_target") == str(root / "target-component"), "prepared build input differs")
    for selected in ("A", "B"):
        runtime = plan["arms"][selected]
        binding.full_map(runtime["source_root"], runtime["compile_inputs"])
        binding.full_map(runtime["source_root"], runtime["include_inputs"])
        binding.qualified_arm(selected, runtime)
    for name, expected in prep["files"].items():
        if name.endswith("/Cargo.lock"):
            continue
        raw = binding.regular(root / name)
        binding.need(len(raw) == expected["bytes"] and binding.sha(raw) == expected["sha256"],
                     "prepared component source changed: " + name)
    source_manifest = json.loads(binding.bound_file(plan["component_source_manifest"]))
    binding.need(source_manifest.get("rust_source_state") == "formatted_source_frozen", "formatter freeze required")
    helpers = supplied["programs"]
    names = {"record_build_invocation.py", "prepare_build.py", "seal_arm.py"}
    binding.need(isinstance(helpers, dict) and set(helpers) == names, "fixed producer program bindings required")
    for name, pin in helpers.items():
        binding.need(pin["path"] == str(Path(__file__).absolute().with_name(name)), "producer helper path differs")
        binding.bound_file(pin)
    graph_pin = supplied.get("graph_receipt")
    if stage in BUILD_STAGES:
        graph = json.loads(binding.bound_file(graph_pin))
        binding.need(graph.get("schema") == "hepta-r34-capacity-component-graphs/v1" and graph.get("passed") is True
                     and graph.get("plan_sha256") == binding.sha(plan_raw)
                     and graph.get("preparation", {}).get("sha256") == binding.sha(prep_raw), "closed graph receipt required")
        for selected in ("A", "B"):
            binding.need(graph["locks"][selected]["path"] == str(root / "arms" / selected / "Cargo.lock"),
                         "component graph lock path differs")
            binding.bound_file(graph["locks"][selected])
            metadata_path = root / "build-stages" / (selected + "-metadata-locked") / "stdout.log"
            metadata_raw = binding.regular(metadata_path, MAX_LOG)
            binding.need(graph["metadata"][selected] == file_pin(metadata_path, metadata_raw),
                         "graph did not use the original retained locked-metadata stdout")
    else:
        binding.need(graph_pin is None, "metadata stage does not consume a future graph receipt")
        if stage == "metadata-seed":
            raw = binding.regular(root / "arms" / arm / "Cargo.lock")
            expected = prep["files"]["arms/" + arm + "/Cargo.lock"]
            binding.need(len(raw) == expected["bytes"] and binding.sha(raw) == expected["sha256"],
                         "metadata seed was already changed; no retry")
    return plan, file_pin(root / "input.json", plan_raw), file_pin(root / "preparation.json", prep_raw)


def stage_command(plan, root, arm, stage):
    from seal_arm import expected_commands
    if stage in BUILD_STAGES:
        return expected_commands(plan, root, arm)[stage]
    result = [plan["cargo"], "metadata", "--offline"]
    if stage == "metadata-locked":
        result.append("--locked")
    return result + ["--manifest-path", str(root / "arms" / arm / "Cargo.toml"),
                     "--format-version", "1", "--filter-platform", plan["target_triple"]]


def check_sequence(root, arm, stage, clock, environment, plan_pin):
    directory = root / "build-stages"
    position = ORDER.index((arm, stage))
    if position == 0:
        binding.need(not os.path.lexists(root / "target-component"),
                     "first metadata stage requires an entirely new component target")
    expected_names = {a + "-" + s for a, s in ORDER[:position + 1]}
    if os.path.lexists(directory):
        private_directory(directory)
        binding.need({path.name for path in directory.iterdir()} == expected_names,
                     "stage inventory differs; partial, repeated or out-of-order stages are not replayable")
    else:
        binding.need(False, "current original stage directory missing")
    previous_end = 0
    for earlier_arm, earlier_stage in ORDER[:position]:
        path = directory / (earlier_arm + "-" + earlier_stage) / "invocation.json"
        previous = json.loads(binding.regular(path))
        binding.need(previous.get("schema") == "hepta-r34-capacity-recorded-build-invocation/v1"
                     and previous.get("passed") is True and previous.get("clock") == clock
                     and previous.get("effective_environment") == environment
                     and previous.get("plan") == plan_pin
                     and previous.get("automatic_retries") == 0
                     and previous.get("cleanup", {}).get("closed") is True,
                     "earlier original stage did not close in the same environment/boot")
        previous_end = max(previous_end, previous["completed_monotonic_ns"])
    baseline = None
    if arm == "A":
        binding.need(not os.path.lexists(root / "artifacts" / "A") and not os.path.lexists(root / "artifacts" / "B"),
                     "A may not build after an artifact seal attempt")
    elif stage in BUILD_STAGES:
        path = root / "artifacts" / "A" / "build-report.json"
        raw = binding.regular(path)
        report = json.loads(raw)
        binding.need(report.get("schema") == "hepta-r34-capacity-component-arm-build/v1"
                     and report.get("passed") is True and report.get("arm") == "A"
                     and report.get("plan_sha256") == plan_pin["sha256"] and report.get("clock") == clock
                     and report.get("effective_environment") == environment,
                     "original A seal required before the first B build")
        binding.bound_file(report["binary"], 128 * 1024 * 1024)
        baseline = {"report": file_pin(path, raw), "binary": report["binary"],
                    "binary_preserved_monotonic_ns": report["binary_preserved_monotonic_ns"]}
        binding.need(not os.path.lexists(root / "artifacts" / "B"), "B artifact attempt already exists")
    return previous_end, baseline


def group_members(group):
    rows = []
    for path in Path("/proc").iterdir():
        if not path.name.isdigit():
            continue
        row = proc(int(path.name))
        if row is not None and row["process_group"] == group:
            rows.append(row)
    return rows


def own_children():
    return [int(value) for value in Path(f"/proc/self/task/{os.getpid()}/children").read_text().split()]


def child_exited(child):
    value = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    return value is not None and value.si_pid == child.pid


def run_child(command, cwd, environment, timeout, output, native_cgroup):
    row = {"pid": None, "identity": None, "returncode": None, "actual_waitpid": False,
           "timed_out": False, "signals": [], "closed": False, "errors": [],
           "scope": "original Cargo process group; adopted children separately checked"}
    child, original, streams = None, None, []
    try:
        # Adopt orphaned compiler/linker children so a dead Cargo leader cannot
        # hide them. This process has no earlier children and starts only Cargo.
        libc = ctypes.CDLL(None, use_errno=True)
        binding.need(libc.prctl(36, 1, 0, 0, 0) == 0 and not own_children(), "Linux child custody unavailable")
        parent_pid = os.getpid()

        def child_setup():
            # Linux-only, single-threaded parent. This protects direct Cargo,
            # not an invented wait or full descendant reap after parent loss.
            # A missing final invocation always blocks subsequent stages.
            if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent_pid:
                os._exit(127)

        for name in ("stdout", "stderr"):
            fd = os.open(output / (name + ".log"), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            streams.append(os.fdopen(fd, "wb", buffering=0))
        child = subprocess.Popen(command, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                                 stdout=streams[0], stderr=streams[1], start_new_session=True, umask=0o022,
                                 preexec_fn=child_setup)
        row["pid"] = child.pid
        original = proc(child.pid)
        binding.need(original is not None and original["process_group"] == child.pid
                     and original["session"] == child.pid, "original Cargo birth identity unavailable")
        row["identity"] = birth(original)
        binding.need(cgroup_bytes(child.pid) == native_cgroup, "Cargo left original native cgroup before observation")
        row["original_native_cgroup_sha256"] = binding.sha(native_cgroup)
        row["parent_death_signal"] = "SIGKILL"
        binding.create(output / "cargo-child.json", binding.encoded(row["identity"]))
        sync_dir(output)
        deadline = time.monotonic() + timeout
        while not child_exited(child):
            binding.need(not INTERRUPTS, "native producer interrupted")
            if time.monotonic() >= deadline:
                row["timed_out"] = True
                raise TimeoutError("original Cargo stage budget expired")
            binding.need(all(os.fstat(stream.fileno()).st_size <= MAX_LOG for stream in streams),
                         "Cargo log exceeded retained-stream acceptance bound")
            time.sleep(min(0.05, max(0, deadline - time.monotonic())))
    except BaseException as error:
        row["errors"].append({"type": type(error).__name__, "reason": str(error)[:3000]})
    finally:
        if child is not None:
            try:
                # Never reap the group leader before the last possible signal.
                # The retained zombie prevents PGID reuse during cleanup.
                live = [value for value in group_members(child.pid) if value["state"] != "Z"]
                if live and not row["errors"]:
                    row["errors"].append({"type": "ResidualChildren", "reason": "Cargo exited while its group still had live children"})
                for sig, seconds in ((signal.SIGINT, 120), (signal.SIGTERM, 10), (signal.SIGKILL, 10)):
                    if not live:
                        break
                    current = proc(child.pid)
                    binding.need(original is not None and current is not None and birth(current) == birth(original),
                                 "original Cargo identity changed; no unbound group signal")
                    os.killpg(child.pid, sig)
                    row["signals"].append({"signal": sig.name, "monotonic_ns": now()})
                    deadline = time.monotonic() + seconds
                    while time.monotonic() < deadline:
                        live = [value for value in group_members(child.pid) if value["state"] != "Z"]
                        if not live:
                            break
                        time.sleep(min(0.05, max(0, deadline - time.monotonic())))
                binding.need(not live and child_exited(child), "original compiler group failed to stop")
                waited, status = os.waitpid(child.pid, os.WNOHANG)
                binding.need(waited == child.pid, "original Cargo child was not actually reaped")
                child.returncode = os.waitstatus_to_exitcode(status)
                row["actual_waitpid"], row["returncode"] = True, child.returncode
                # Cargo's already-dead orphans are ours after subreaper adoption.
                # Escaped/live descendants fail closed; no unrelated group is signalled.
                row["adopted_reaped"] = []
                for pid in own_children():
                    current = proc(pid)
                    binding.need(current is not None and current["state"] == "Z",
                                 "live adopted compiler descendant remains outside closed group")
                    waited, status = os.waitpid(pid, os.WNOHANG)
                    binding.need(waited == pid, "adopted child reap not confirmed")
                    row["adopted_reaped"].append({"pid": pid, "identity": birth(current), "wait_status": status})
                row["owned_process_absent"] = proc(child.pid) is None
                row["owned_group_absent"] = not group_members(child.pid)
                row["adopted_children_absent"] = not own_children()
                binding.need(row["owned_process_absent"] and row["owned_group_absent"]
                             and row["adopted_children_absent"], "Cargo custody is not closed")
                row["closed"] = True
            except BaseException as error:
                row["errors"].append({"type": type(error).__name__, "reason": str(error)[:3000]})
        for stream in streams:
            try:
                stream.flush()
                os.fsync(stream.fileno())
            except BaseException as error:
                row["errors"].append({"type": type(error).__name__, "reason": str(error)[:3000]})
            finally:
                stream.close()
    return row


def forward(raw, fd):
    offset = 0
    while offset < len(raw):
        written = os.write(fd, raw[offset:offset + 65536])
        binding.need(written > 0, "native output pipe made no progress")
        offset += written
    return offset


def run(input_path):
    from seal_arm import expected_environment, local_clock_identity
    input_raw = binding.regular(input_path)
    supplied = json.loads(input_raw)
    binding.need(supplied.get("schema") == "hepta-r34-capacity-build-stage-input/v1"
                 and supplied.get("status") == "sealed_actual_inputs"
                 and (supplied.get("arm"), supplied.get("stage")) in ORDER,
                 "actual build stage input remains unsealed")
    binding.need(sys.platform == "linux" and os.geteuid() != 0
                 and all(hasattr(os, name) for name in ("waitid", "WNOWAIT", "P_PID")),
                 "native nonroot Linux process custody required")
    root, arm, stage = Path(supplied["prepared_root"]), supplied["arm"], supplied["stage"]
    clock = local_clock_identity()
    native, request_raw, child_raw, launch_raw, native_cgroup = native_binding(supplied, input_path, root, arm, clock)
    with build_lock(root):
        # Reserve this exact stage before expensive source/config preflight.
        # A failed preflight leaves its original create-only failure receipt.
        basic_plan_raw = binding.regular(root / "input.json")
        basic_plan = json.loads(basic_plan_raw)
        basic_prep = json.loads(binding.regular(root / "preparation.json"))
        binding.need(basic_plan.get("output_directory") == str(root)
                     and basic_prep.get("plan_sha256") == binding.sha(basic_plan_raw), "not the prepared component root")
        stages = root / "build-stages"
        prior_names = {a + "-" + s for a, s in ORDER[:ORDER.index((arm, stage))]}
        binding.need(not os.path.lexists(stages) and not prior_names
                     or os.path.lexists(stages) and {p.name for p in stages.iterdir()} == prior_names,
                     "partial, repeated or out-of-order stage is not replayable")
        stages.mkdir(mode=0o700, exist_ok=True)
        private_directory(stages)
        output = stages / (arm + "-" + stage)
        output.mkdir(mode=0o700)
        report = {"schema": "hepta-r34-capacity-recorded-build-invocation/v1", "passed": False,
                  "original_input_path": str(input_path),
                  "arm": arm, "stage": stage, "command": None, "cwd": str(root / "arms" / arm),
                  "environment": None, "effective_environment": None,
                  "automatic_retries": 0, "clock": clock, **native, "plan": None, "preparation": None,
                  "programs": supplied["programs"], "graph_receipt": supplied.get("graph_receipt"),
                  "configuration_inventory": None, "toolchain_executables": None,
                  "baseline_arm_before_b": None, "submitted_monotonic_ns": None,
                  "completed_monotonic_ns": None, "cleanup": None, "streams": {}, "errors": [],
                  "interrupts": INTERRUPTS, "cargo_started": False, "native_terminal_not_yet_published": True}
        try:
            for name, raw in (("input.json", input_raw), ("native-request.json", request_raw),
                              ("native-child.json", child_raw), ("native-launch.json", launch_raw),
                              ("native-cgroup.txt", native_cgroup)):
                binding.create(output / name, raw)
                report[name.rsplit(".", 1)[0].replace("-", "_")] = file_pin(output / name, raw)
            plan, plan_pin, prep_pin = checked_inputs(supplied, root, arm, stage)
            environment, inventory, tools = controlled_context(supplied, plan, root, arm)
            previous_end, baseline = check_sequence(root, arm, stage, clock, environment, plan_pin)
            command = stage_command(plan, root, arm, stage)
            report.update(command=command, environment=expected_environment(plan, root),
                          effective_environment=environment, plan=plan_pin, preparation=prep_pin,
                          configuration_inventory=inventory, toolchain_executables=tools, baseline_arm_before_b=baseline)
            context_unchanged(inventory, tools)
            own = proc(os.getpid())
            elapsed = (now() / 1e9) - own["start_ticks"] / os.sysconf("SC_CLK_TCK")
            binding.need(supplied["timeout_seconds"] + elapsed + 180 < native["native_timeout_seconds"]
                         and not INTERRUPTS, "native timeout no longer leaves cleanup margin")
            begin = now()
            binding.need(previous_end < begin and (baseline is None or baseline["binary_preserved_monotonic_ns"] < begin),
                         "foreign or future build ordering timestamp")
            report["submitted_monotonic_ns"] = begin
            intent_raw = binding.encoded(report)
            binding.create(output / "invocation-intent.json", intent_raw)
            report["invocation_intent"] = file_pin(output / "invocation-intent.json", intent_raw)
            sync_dir(output)
            sync_dir(stages)
            cleanup = run_child(command, report["cwd"], environment, supplied["timeout_seconds"], output, native_cgroup)
            report["cleanup"] = cleanup
            report["cargo_started"] = cleanup["pid"] is not None
            if os.path.lexists(output / "cargo-child.json"):
                report["cargo_child"] = file_pin(output / "cargo-child.json", binding.regular(output / "cargo-child.json"))
            binding.need(cleanup["closed"] and cleanup["actual_waitpid"] and cleanup["returncode"] == 0
                         and not cleanup["errors"] and not INTERRUPTS, "Cargo did not complete with fully closed custody")
            # Metadata-seed alone is allowed to change its new component lock.
            if stage == "metadata-seed":
                checked_inputs(supplied, root, arm, "metadata-locked")
            else:
                checked_inputs(supplied, root, arm, stage)
            context_unchanged(inventory, tools)
            binding.need(binding.regular(input_path) == input_raw
                         and binding.regular(Path(native["job_directory"]) / "request.json") == request_raw
                         and binding.regular(Path(native["job_directory"]) / "child.json") == child_raw
                         and binding.regular(Path(native["job_directory"]) / "launch.json") == launch_raw
                         and cgroup_bytes(os.getpid()) == native_cgroup,
                         "original invocation/native metadata changed")
        except BaseException as error:
            report["errors"].append({"type": type(error).__name__, "reason": str(error)[:3000]})
        # Both streams are retained even for a failed Cargo stage. Forward only
        # those bytes; all producer errors stay in the create-only JSON receipt.
        for name, fd in (("stdout", 1), ("stderr", 2)):
            path = output / (name + ".log")
            try:
                if not os.path.lexists(path):
                    binding.create(path, b"")
                raw = binding.regular(path, MAX_LOG)
                report["streams"][name] = {**file_pin(path, raw), "forwarded_bytes": forward(raw, fd)}
            except BaseException as error:
                report["errors"].append({"type": type(error).__name__, "reason": str(error)[:3000]})
        report["completed_monotonic_ns"] = now()
        report["passed"] = bool(report["cargo_started"] and not report["errors"] and not INTERRUPTS
                                and report["cleanup"]["closed"] and report["cleanup"]["returncode"] == 0)
        binding.create(output / "invocation.json", binding.encoded(report))
        sync_dir(output)
        sync_dir(stages)
        return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda number, _frame: INTERRUPTS.append({"signal": signal.Signals(number).name, "monotonic_ns": now()}))
    try:
        report = run(args.input)
        return 0 if report["passed"] else 1
    except BaseException:
        # No invented Cargo output or synthetic success envelope. Pre-Cargo
        # failures leave no successful invocation; existing partial names stay.
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
