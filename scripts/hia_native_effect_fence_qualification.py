"""Bind real effect-fence processes, kernel controls and original Rust replay.

Captured results never satisfy a fresh execution gate. This helper reads full
source, image, compile/pack receipts and process streams before accepting any
count. It supplies no effect decision or runtime authority.
"""
from __future__ import annotations
from collections import Counter
from pathlib import Path
import gzip
import hashlib
import json
import re
import struct
import sys
import tomllib
from types import SimpleNamespace

from hia_native_build import HEPTA_COMMIT, json_bytes
from hia_native_effect_fence_build import (COMPILE_FILES, MEMBER_SOURCES, PROFILE,
    inspect_embedded, module_evidence, process_stdout, receipt, relative, require, sha)

FOLDER = "effect-fence-rust-oracle"
PROFILE_SHA = "999a180187f5cc02d63240936e16c81ee59dc9a8cc9885f4943a2b54ac31b2ca"
COMPILER_SHA = "bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0"
DEFAULT_ELF = "26e53e9059772c99f1e296611f1f16b0668c9d4387f870299f90903a318bf144"
QUEUE_ELF = "c02f5e5880286b3f1b06dd694673e5910fc9d69aed51c2797382c6964541522f"
ORIGINAL_PINS = {
    "Cargo.lock": "7f39704b92d5fc762a98a5313949034db464ca9485827b19b5dde7aa69902d43",
    "Cargo.toml": "377e7dca547f0ff0d832fb28cf01862a6d84b4b6ed42c8b36dae9075cbbbb78f",
    "rustfmt.toml": "bce79651b2e2ff42e1c54b9a26c5e17af5222f9f65ab51d9563a48fd159dae84",
    "src/mcp/runtime/effect_owner_fence.rs": "1e2f2cd32289cd93915076981436b79c04a2756dfc184fa219f043a88f907207",
    "src/mcp/runtime/effect_owner_fence_acquisition_tests.rs": "4d294479590c8179fd241a9ecf7bd125345dc8768e11aa6dfcfa2ed383247b10",
}
TEST_FILES = ("test_fence_async.py", "test_fence_worker.py", "test_fence_lifetime.py",
    "test_fence_owner.py", "test_fence_kernel.py", "test_fence_packer.py",
    "test_fence_evidence.py",
    "fence_async_support.py", "effect_fence_test_support.py", "effect_fence_async_serial_adapter.py",
    "fence_worker_supervisor.py", "fence_kernel_supervisor.py")
ORACLE_FILES = ("oracle_effect_fence.rs", "fence_oracle/Cargo.toml", "fence_oracle/Cargo.lock",
    "fence_oracle/build.rs", "fence_oracle/original_access.rs", "oracle_effect_fence_async.rs",
    "async_oracle/Cargo.toml", "async_oracle/Cargo.lock", "async_oracle/build.rs",
    "async_oracle/original_async_access.rs", "async_oracle/original_async_runner.rs")
COUNTS = {
    "async": {"processes": 10, "closed_processes": 10, "requests": 111, "responses": 111},
    "worker": {"processes": 4, "closed_processes": 4, "requests": 38, "responses": 38},
    "lifetime": {"processes": 2, "closed_processes": 2, "requests": 49166, "responses": 49166},
    "owner": {"processes": 93, "closed_processes": 93, "requests": 212, "responses": 212},
    "kernel": {"processes": 19, "closed_processes": 19, "requests": 37, "responses": 37},
    "packer": {"native_calls": 98, "successful_packs": 2, "admission_refusals": 90,
        "capacity_refusals": 6, "cache_admissions": 1, "cache_refusals": 10},
}
SUITES = (
    ("test_fence_async.py", "HIA_FENCE_ASYNC_CORPUS_DIR", "async/report.json", 7, "async"),
    ("test_fence_worker.py", "HIA_FENCE_WORKER_CORPUS_DIR", "worker/report.json", 4, "worker"),
    ("test_fence_lifetime.py", "HIA_FENCE_LIFETIME_CORPUS_DIR", "lifetime/report.json", 2, "lifetime"),
    ("effect_fence_async_serial_adapter.py", "HIA_FENCE_CORPUS_DIR", "owner/owner-report.json", 10, "owner"),
    ("test_fence_kernel.py", "HIA_FENCE_KERNEL_CORPUS_DIR", "kernel/report.json", 3, "kernel"),
    ("test_fence_packer.py", "HIA_FENCE_PACKER_REPORT", "packer.json", 5, "packer"),
)
EVIDENCE_SUITE = ("test_fence_evidence.py", "HIA_FENCE_EVIDENCE_REPORT", "evidence.json", 5)
EVIDENCE_COUNTS = {"accepted_evidence_objects": 1, "completion_refusals": 10, "worker_trace_refusals": 10,
    "kernel_trace_refusals": 2, "artifact_refusals": 10, "process_refusals": 6,
    "new_native_calls": 0, "new_original_calls": 0}
ROW_SHA = {"async": "afe7782e5502bd804276da05bc362e1a3782a105976449dbe9d58609c934675a",
    "worker": "06694cf38047b098986f403321b969e4120c9a3970ce5aac4b3c5a9ba2e81dbd",
    "lifetime": "12a8a63e994c3849556b10653f5bdde0da8b7e3c150af43b4b6d2c342e6b4514",
    "owner": "7dc303c436957e8116e5d7aa96ef836c175e0cc0b110474b95aaf7076c3bb148",
    "kernel": "851b1e1c66acd388e652bcaa9c6dca7e99bfabddabdb1c03a233383ed20602ba"}
KERNEL_CASES = ("owner_replace", "owner_touch", "lock_replace", "authority_rebind", "state_rebind",
    "root_eintr", "owner_open_eintr", "lock_eintr", "owner_read_eintr", "owner_partial",
    "owner_partial_eio", "owner_close_eio", "job_replace", "job_touch", "jobs_changed",
    "predecessor_rebind", "scan_deadline", "job_read_eintr", "job_partial_eio")


def exact(actual, expected, message):
    require(json_bytes(actual) == json_bytes(expected), "effect fence evidence: " + message)


def read(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), "effect fence evidence file missing or symlinked")
    return path.read_bytes()


def object_at(path):
    value = json.loads(read(path))
    require(type(value) is dict, "effect fence evidence object differs")
    return value


def completion(value, tests):
    exact({key: value.get(key) for key in ("status", "tests_run", "failures", "errors", "skipped",
        "expected_failures", "unexpected_successes")}, {"status": "PASS", "tests_run": tests,
        "failures": 0, "errors": 0, "skipped": 0, "expected_failures": 0, "unexpected_successes": 0},
        "strict completed suite domain differs")


def source_pins(root, *, reference_root=None):
    root = Path(root)
    reference = root if reference_root is None else Path(reference_root)
    paths = set(MEMBER_SOURCES) | {PROFILE, "native/effect_fence_async_packer.hepta",
        "native/effect_fence_async_queue_fixture_packer.hepta", "scripts/hia_native_effect_fence_build.py",
        "scripts/hia_native_effect_fence_qualification.py", "scripts/hia_native_build.py",
        "scripts/hia_native_loader.py", "rustfmt.toml"}
    paths.update("tests/hia_native/" + name for name in (*TEST_FILES, *ORACLE_FILES))
    result = {name: sha(read(root / name)) for name in sorted(paths)}
    for name, expected in ORIGINAL_PINS.items():
        require(sha(read(reference / name)) == expected, "effect fence unchanged original source differs: " + name)
        result[name] = expected
    require(result[PROFILE] == PROFILE_SHA, "effect fence frozen source profile differs")
    return result


def artifact_evidence(root, output, report):
    """Verify both complete static artifacts, without invoking either owner."""
    root, output = Path(root), Path(output)
    built = output / "build"
    retained = {}
    def artifact(path):
        raw = read(path)
        retained[str(path.relative_to(output))] = sha(raw)
        return raw
    bootstrap = json.loads(artifact(built / "bootstrap/bootstrap.json"))
    dependency = bootstrap.get("dependency")
    require(bootstrap.get("schema") == "hepta.runtime.native-bootstrap.v1"
            and bootstrap.get("qualification") == "development_fixed_point"
            and bootstrap.get("matching_source_cold_qualified") is False
            and bootstrap.get("generation_sha256") == COMPILER_SHA
            and type(dependency) is dict and dependency.get("commit") == HEPTA_COMMIT
            and dependency.get("tree") == "8d8b0fb8d015fb7edab302498bb9ed4c74ab6f49"
            and report.get("compiler_commit") == HEPTA_COMMIT
            and report.get("compiler_image_sha256") == COMPILER_SHA,
            "effect fence compiler qualification differs")
    for label in ("B1", "B2", "B3"):
        require(sha(artifact(built / f"bootstrap/{label}.image.bin")) == COMPILER_SHA,
                "effect fence compiler fixed point changed")
    context = SimpleNamespace(identity=dependency, compiler_sha256=COMPILER_SHA)
    owner = report["modules"]["effect_fence"]
    require(owner.get("builder") == "effect_fence" and owner.get("source") == MEMBER_SOURCES[0],
            "effect fence qualification module registration differs")
    bundle_path = relative(output, owner["manifest"])
    bundle_raw = artifact(bundle_path)
    bundle = json.loads(bundle_raw)
    require(sha(bundle_raw) == owner["sha256"] == bundle_path.parent.name
            and bundle_path.parent.parent == built / "effect-fence-bundles"
            and bundle_raw == json_bytes(bundle), "effect fence actual bundle differs")
    exact({k: bundle.get(k) for k in ("schema", "compiler_commit", "compiler_sha256", "profile_sha256",
        "production_activated", "whole_runtime_replaced")},
        {"schema": "hepta.runtime.effect-fence-bundle.v1", "compiler_commit": HEPTA_COMMIT,
        "compiler_sha256": COMPILER_SHA, "profile_sha256": PROFILE_SHA,
        "production_activated": False, "whole_runtime_replaced": False}, "bundle compiler or scope differs")
    profile_raw = read(root / PROFILE)
    require(sha(profile_raw) == PROFILE_SHA, "effect fence source profile changed")
    profile = json.loads(profile_raw)
    require(set(bundle["members"]) == {"production", "queue_fixture"}, "effect fence bundle profiles differ")
    artifacts = {}
    for name, worker_limit, expected_elf in (("production", 512, DEFAULT_ELF), ("queue_fixture", 1, QUEUE_ELF)):
        row = bundle["members"][name]
        path = relative(built, row["manifest"])
        metadata_raw = artifact(path)
        metadata = json.loads(metadata_raw)
        require(sha(metadata_raw) == row["manifest_sha256"] and path.parent.parent == built / "effect-fence"
                and row["executable_sha256"] == expected_elf, "effect fence actual profile manifest differs")
        selected = profile["profiles"][name]
        expected = {"schema": "hepta.runtime.native-effect-fence.v1", "target": "linux-x86_64",
            "compiler_commit": HEPTA_COMMIT, "compiler_sha256": COMPILER_SHA, "profile": name,
            "profile_sha256": PROFILE_SHA, "worker_limit": worker_limit,
            "fixture_pool_profile": name == "queue_fixture", "executable": "effect-fence-async.elf",
            "elf_sha256": expected_elf, "elf_bytes": 809249, "prefix_bytes": 7717,
            "packer_manifest": "packer/manifest.json", "runtime_python_required": False,
            "runtime_libc_required": False, "fresh_cold_qualified": False, "registered_mcp_tool": False,
            "production_activated": False, "whole_runtime_replaced": False, "complete_effect_fence_owner": False}
        exact({k: metadata.get(k) for k in expected}, expected, "actual static profile contract differs")
        require(artifact(path.parent / "profile.json") == profile_raw and len(metadata["members"]) == 5,
                "effect fence actual five-image profile differs")
        images = []
        for index in range(6):
            packer = index == 5
            source_name = selected["packer_source"] if packer else MEMBER_SOURCES[index]
            source = read(root / source_name)
            child_name = "packer/manifest.json" if packer else f"member{index}/manifest.json"
            child_path = relative(path.parent, child_name)
            child_raw = artifact(child_path)
            child, image, inventory = module_evidence(child_path, source, context)
            for filename in (child["source"], child["image"], *COMPILE_FILES):
                artifact(child_path.parent / filename)
            if packer:
                require(metadata["packer_manifest_sha256"] == sha(child_raw)
                        and metadata["packer_source_sha256"] == sha(source) == selected["packer_source_sha256"]
                        and metadata["packer_image_sha256"] == sha(image), "effect fence actual packer changed")
                exact(metadata["packer_compile_files"], inventory, "packer compilation receipts changed")
                packer_image = image
            else:
                member = metadata["members"][index]
                frozen = profile["members"][index]
                exact({k: member.get(k) for k in frozen}, frozen, "compiled profile member changed")
                require(member["manifest"] == child_name and member["manifest_sha256"] == sha(child_raw)
                        and member["source_sha256"] == sha(source) and member["image_sha256"] == sha(image),
                        "effect fence actual compiled member changed")
                exact(member["compile_files"], inventory, "member compilation receipts changed")
                images.append(image)
        frame = b"HFFPACK2" + b"".join(struct.pack("<Q", len(image)) for image in images) + bytes(16) + b"".join(images)
        elf = artifact(path.parent / metadata["executable"])
        output_raw = artifact(path.parent / "pack.output.bin")
        pack_report = json.loads(artifact(path.parent / "pack.receipt.json"))
        require(artifact(path.parent / "pack.input.bin") == frame and metadata["pack_input_sha256"] == sha(frame)
                and pack_report["runner_sha256"] == dependency["files"]["tools/hia_selfhost_child.py"],
                "effect fence actual packing input/observer differs")
        exact(pack_report, metadata["pack_receipt"], "packer process receipt differs")
        receipt(pack_report, frame, output_raw, elf, sha(packer_image))
        request = json.loads(artifact(path.parent / "pack.request.json"))
        require(request["capacity"] == len(elf) and request["workspace_size"] == 4096
                and request["source_sha256"] == sha(frame) and request["image_sha256"] == sha(packer_image)
                and artifact(path.parent / "pack.stderr.log") == b"", "effect fence packer process limits differ")
        process_stdout(pack_report, artifact(path.parent / "pack.stdout.log"), capacity=len(elf), workspace=4096)
        inspect_embedded(elf, images, profile, selected)
        require(struct.unpack_from("<II", elf, 64) == (1, 5)
                and struct.unpack_from("<II", elf, 120) == (0x6474e551, 6),
                "effect fence static RX / non-executable stack segment differs")
        artifacts[name] = {"manifest": str(path.relative_to(output)), "manifest_sha256": sha(metadata_raw),
            "elf_sha256": sha(elf), "worker_limit": worker_limit, "image_sha256": [sha(image) for image in images]}
    return {"profiles": artifacts, "artifact_sha256": retained}


def completed_process(output, report, name):
    """Standalone equivalent of the outer qualifier's retained-process check."""
    checks = [item for item in report["checks"] if item.get("name") == name]
    require(len(checks) == 1, "effect fence suite requires one actual invocation")
    check = checks[0]
    stdout, stderr = read(output / (name + ".stdout")), read(output / (name + ".stderr"))
    summary = json.loads(stdout)
    require(check.get("exit_code") == 0 and type(check.get("exit_code")) is int
            and check.get("timed_out") is False and not check.get("start_error")
            and sha(stdout) == check.get("stdout_sha256") and sha(stderr) == check.get("stderr_sha256")
            and len(stdout) == check.get("stdout_bytes") and len(stderr) == check.get("stderr_bytes"),
            "effect fence actual suite process failed or changed")
    exact(summary, check.get("summary"), "actual process summary changed")
    return check, summary


def process_evidence(root, output, report, completed, filename, tests):
    check, summary = completed(output, report, filename)
    completion(summary, tests)
    exact(check.get("command", [])[1:], ["-I", "-B", str(root / "tests/hia_native" / filename)],
          "suite command is not the fixed source-owned invocation")
    require(check.get("timeout_seconds") == 180 and check.get("timed_out") is False,
            "effect fence suite time bound differs")
    stderr = read(output / (filename + ".stderr")).decode()
    require(len(re.findall(r"\.\.\. ok\n", stderr)) == tests
            and re.search(r"\nRan " + str(tests) + r" tests in [0-9.]+s\n\nOK\n\Z", stderr),
            "effect fence actual unittest completion differs")
    return check, summary


def actual_sources(root, names):
    return {name: sha(read(root / "tests/hia_native" / name)) for name in names}


def retained_reports(folder, rows, expected_names):
    require(type(rows) is list and len(rows) == len(expected_names)
            and [row.get("path") for row in rows] == list(expected_names), "effect fence retained report set differs")
    result = {}
    for item in rows:
        raw = read(relative(folder, item["path"]))
        require(len(raw) == item.get("bytes") and sha(raw) == item.get("sha256"),
                "effect fence complete retained trace differs")
        result[item["path"]] = raw
    return result


def _shared_lock_completions(trace):
    pending, completed = {}, []
    for line in trace.splitlines():
        match = re.fullmatch(r"(\d+)\s+flock\((\d+), LOCK_SH(.*)", line)
        if match:
            tid, descriptor, tail = int(match[1]), int(match[2]), match[3]
            require(tid not in pending, "effect fence duplicated unfinished shared-lock trace")
            if tail == " <unfinished ...>":
                pending[tid] = descriptor
            else:
                require(re.fullmatch(r"\)\s+= 0", tail) is not None, "effect fence shared lock did not complete")
                completed.append((tid, descriptor))
            continue
        match = re.fullmatch(r"(\d+)\s+<\.\.\. flock resumed>\)\s+= 0", line)
        if match:
            tid = int(match[1])
            require(tid in pending, "effect fence shared-lock completion has no entry")
            completed.append((tid, pending.pop(tid)))
    require(not pending, "effect fence shared-lock trace is incomplete")
    return completed


def worker_trace_evidence(root, value, *, mode, inherited, artifact):
    expected = {"schema": "hepta.effect-fence.actual-worker-fault.v1", "status": "PASS", "failure": None,
        "mode": mode, "inherited_blocked_sigill": inherited, "all_owned_tasks_reaped": True,
        "executable_sha256": artifact["elf_sha256"], "manifest_sha256": artifact["manifest_sha256"],
        "fault_is_synthetic": True, "kernel_sigill_is_actual": True,
        "supervisor_sha256": sha(read(root / "tests/hia_native/fence_worker_supervisor.py"))}
    exact({key: value.get(key) for key in expected}, expected, "actual worker trap identity differs")
    exits = value["exit_statuses"]
    require(type(exits) is dict and len(exits) == (3 if mode == "admission" else 6)
            and all(type(code) is int and code == 0 for code in exits.values()),
            "effect fence actual worker/task exit domain differs")
    events = value["events"]
    require(type(events) is list, "effect fence worker events missing")
    kinds = Counter(event.get("kind") for event in events)
    require(kinds["armed_fixed_owner_ud2"] == kinds["actual_kernel_sigill"] == kinds["worker_sys_exit"] == 1
            and kinds["retire_after_clear_tid"] == 2 and kinds["kernel_task_reaped"] == len(exits)
            and kinds["kernel_clone"] == kinds["initial_worker_mask"] == len(exits) - 1,
            "effect fence actual worker trap/retirement count differs")
    require(set(kinds) <= {"armed_fixed_owner_ud2", "actual_kernel_sigill", "worker_sys_exit",
        "retire_after_clear_tid", "kernel_task_reaped", "kernel_clone", "initial_worker_mask", "fault_cleanup_close"},
        "effect fence unknown worker event")
    armed = next(event for event in events if event["kind"] == "armed_fixed_owner_ud2")
    fault = next(event for event in events if event["kind"] == "actual_kernel_sigill")
    tid = armed["tid"]
    expected_mask = 8 if inherited else 0
    require(armed["owner_file_offset"] == 7717 and armed["initial_signal_mask"] == expected_mask
            and armed["cache_held"] == (1 if mode == "cache" else 0)
            and armed["trigger_syscall"] == (217 if mode == "cache" else 73)
            and armed["job_id"] == (2 if mode == "cache" else 1)
            and fault["tid"] == tid and type(fault["si_code"]) is int and fault["si_code"] > 0
            and fault["worker_signal_mask"] == 0 and fault["restored_original_instruction"] is True,
            "effect fence kernel signal or private worker context differs")
    require((bool(armed["borrowed_fds"])) == (mode == "cache")
            and len(set(armed["owned_fds"])) == len(armed["owned_fds"])
            and not set(armed["borrowed_fds"]) & set(armed["owned_fds"]),
            "effect fence owned and borrowed FD domains overlap")
    closed = [event["fd"] for event in events if event["kind"] == "fault_cleanup_close"]
    exact(closed, armed["owned_fds"], "worker cleanup did not close exactly its owned descriptors")
    require(all(event["tid"] == tid for event in events if event["kind"] in
        ("fault_cleanup_close", "worker_sys_exit")), "effect fence worker cleanup changed thread")
    require(next(event for event in events if event["kind"] == "worker_sys_exit")["status"] == 0,
            "effect fence worker did not use its non-process-fatal exit")
    positions = {kind: next(index for index, event in enumerate(events) if event["kind"] == kind)
                 for kind in ("armed_fixed_owner_ud2", "actual_kernel_sigill", "worker_sys_exit", "retire_after_clear_tid")}
    require(positions["armed_fixed_owner_ud2"] < positions["actual_kernel_sigill"]
            < positions["worker_sys_exit"] < positions["retire_after_clear_tid"],
            "effect fence worker trap/retirement order differs")
    for event in events:
        if event["kind"] == "initial_worker_mask":
            require(event["mask"] == expected_mask, "effect fence inherited worker mask differs")
        elif event["kind"] == "retire_after_clear_tid":
            require(event["clear_tid"] == event["kernel_return"] == 0
                    and event["job_id"] == armed["job_id"] and event["parent_mask"] == expected_mask
                    and event["tid"] == value["owned_parent"]
                    and event["address"] == armed[event["region"]],
                    "effect fence stack/context retired before kernel join or changed allocation")
    require({event["region"] for event in events if event["kind"] == "retire_after_clear_tid"}
            == {"stack", "context"}, "effect fence retirement region set differs")
    return {"mode": mode, "blocked_sigill_inherited": inherited, "actual_signal": True,
            "reaped_tasks": len(exits), "owned_descriptors_closed": len(closed), "borrowed_descriptors_retained": len(armed["borrowed_fds"])}


def kernel_trace_evidence(root, value, case, binary_sha, *, backend="native"):
    exact({key: value.get(key) for key in ("schema", "status", "failure", "case", "executable_sha256",
        "all_owned_tasks_reaped", "fault_count", "supervisor_sha256")},
        {"schema": "hepta.effect-fence.paired-kernel-control.v1", "status": "PASS", "failure": None,
        "case": case, "executable_sha256": binary_sha, "all_owned_tasks_reaped": True, "fault_count": 1,
        "supervisor_sha256": sha(read(root / "tests/hia_native/fence_kernel_supervisor.py"))},
        "paired kernel process identity differs")
    require(backend in ("native", "original"), "effect fence paired kernel backend differs")
    # The pinned original oracle has two Tokio scheduler threads plus its
    # parent and one blocking worker. Native admission has one worker; a
    # predecessor query starts one additional worker after admission.
    query = case in ("job_replace", "job_touch", "jobs_changed", "predecessor_rebind",
                     "scan_deadline", "job_read_eintr", "job_partial_eio")
    expected_tasks = 4 if backend == "original" else 3 if query else 2
    require(case in KERNEL_CASES and len(value["exit_statuses"]) == expected_tasks
            and str(value["parent_pid"]) in value["exit_statuses"]
            and all(type(code) is int and code == 0 for code in value["exit_statuses"].values()),
            "effect fence paired owned task cleanup differs")
    events = value["events"]
    require(len(events) == (2 if case in ("owner_partial_eio", "job_partial_eio") else 1),
            "effect fence paired event count differs")
    expected_kinds = (["actual_kernel_partial_read", "injected_errno"] if case.endswith("_partial_eio") else
        ["actual_kernel_partial_read"] if case == "owner_partial" else
        ["actual_close_then_injected_errno"] if case == "owner_close_eio" else
        ["actual_monotonic_scan_elapsed"] if case == "scan_deadline" else
        ["injected_errno"] if case.endswith("_eintr") else ["actual_fixture_mutation_after_read"])
    exact([event.get("kind") for event in events], expected_kinds, "paired kernel event order differs")
    normalized = []
    for event in events:
        event = dict(event)
        tid = event.pop("tid")
        require(str(tid) in value["exit_statuses"], "effect fence paired event escaped owned process")
        kind = event["kind"]
        if kind == "actual_monotonic_scan_elapsed":
            require(case == "scan_deadline" and type(event["paused_seconds"]) in (int, float)
                    and 30.05 <= event["paused_seconds"] < 180
                    and event["original_bound_seconds"] == 30 and event["clock_was_not_modified"] is True,
                    "effect fence original scan bound was altered")
            del event["paused_seconds"]
        elif kind == "actual_fixture_mutation_after_read":
            require(event["mutation"] == case and type(event["kernel_read_bytes"]) is int
                    and event["kernel_read_bytes"] > 0, "effect fence actual mutation boundary differs")
            # Fixture directory names differ; record byte lengths are not part
            # of the owner's error identity. The syscall did read real bytes.
            del event["kernel_read_bytes"]
        elif kind == "actual_kernel_partial_read":
            require(case in ("owner_partial", "owner_partial_eio", "job_partial_eio")
                    and event["bytes"] == 1, "effect fence partial read was not a real one-byte read")
        elif kind == "injected_errno":
            wanted = 5 if case.endswith("_partial_eio") else 4
            syscall = 257 if case in ("root_eintr", "owner_open_eintr") else 73 if case == "lock_eintr" else 0
            require(event["errno"] == wanted and event["syscall"] == syscall, "effect fence injected errno domain differs")
        elif kind == "actual_close_then_injected_errno":
            require(case == "owner_close_eio" and event["kernel_return"] == 0 and event["errno"] == 5,
                    "effect fence close descriptor was not actually retired")
        else:
            raise ValueError("effect fence unknown paired kernel event")
        normalized.append(event)
    return normalized


def rows_evidence(folder, kind, summary):
    name = "owner-cases.jsonl.gz" if kind == "owner" else "cases.jsonl.gz" if kind == "lifetime" else "cases.jsonl"
    packed = read(folder / name)
    raw = gzip.decompress(packed) if name.endswith(".gz") else packed
    require(sha(raw) == ROW_SHA[kind], "effect fence complete native response domain differs")
    rows = [json.loads(line) for line in raw.splitlines()]
    require(len(rows) == COUNTS[kind]["responses"], "effect fence retained response count differs")
    for index, row in enumerate(rows):
        wire, response = bytes.fromhex(row["input_hex"]), bytes.fromhex(row["output_hex"])
        require(wire.hex() == row["input_hex"] and response.hex() == row["output_hex"]
                and type(row["case"]) is str, "effect fence noncanonical retained bytes")
        if kind in ("owner", "kernel"):
            require(wire[:8] == b"HFFCMD01" and response[:8] == b"HFFRES01" and len(response) == 40
                    and row["ordinal"] == index and len(wire) == 40 + sum(struct.unpack_from("<2Q", wire, 24)),
                    "effect fence semantic frame shape differs")
        else:
            require(wire[:8] == b"HFFASY01" and len(wire) >= 64 and len(wire) == 64 + sum(struct.unpack_from("<2Q", wire, 40))
                    and response[:8] in (b"HFFASR01", b"HFFAST01")
                    and len(response) == (64 if response[:8] == b"HFFASR01" else 80),
                    "effect fence native lifecycle frame shape differs")
    key = "raw_sha256" if kind == "owner" else "cases_sha256"
    require(summary.get(key) == sha(raw), "effect fence corpus report digest differs")
    if kind == "lifetime":
        require(summary["cases_bytes"] == len(raw) and summary["gzip_bytes"] == len(packed)
                and summary["gzip_sha256"] == sha(packed), "effect fence lifetime corpus extent differs")
    return {"path": name, "sha256": sha(packed), "raw_sha256": sha(raw), "raw_bytes": len(raw), "rows": len(rows)}


def transport_evidence(folder, summary, *, owner):
    raw_file = read(folder / "async-transport.jsonl.gz")
    raw = gzip.decompress(raw_file)
    expected_rows = 379 if owner else 63
    if owner:
        expected = {"rows": summary["native_transport_rows"], "raw_bytes": summary["transport_raw_bytes"],
            "raw_sha256": summary["transport_raw_sha256"], "gzip_bytes": summary["transport_gzip_bytes"],
            "gzip_sha256": summary["transport_gzip_sha256"]}
    else:
        expected = summary["transport_corpus"]
    exact(expected, {"rows": expected_rows, "raw_bytes": len(raw), "raw_sha256": sha(raw),
        "gzip_bytes": len(raw_file), "gzip_sha256": sha(raw_file)}, "complete native transport corpus differs")
    rows = [json.loads(line) for line in raw.splitlines()]
    require(len(rows) == expected_rows, "effect fence transport row count differs")
    semantic = [json.loads(line) for line in (gzip.decompress(read(folder / "owner-cases.jsonl.gz"))
                if owner else read(folder / "cases.jsonl")).splitlines()]
    cursor = 0
    for row in semantic:
        source = bytes.fromhex(row["input_hex"])
        reply = bytes.fromhex(row["output_hex"])
        operation = struct.unpack_from("<Q", source, 8)[0]
        if operation != 4:
            created = rows[cursor]; cursor += 1
            message, response = bytes.fromhex(created["input_hex"]), bytes.fromhex(created["output_hex"])
            require(created["case"] == row["case"] and message[:8] == b"HFFASY01"
                    and struct.unpack_from("<Q", message, 8)[0] == (1 if operation == 1 else 4)
                    and struct.unpack_from("<Q", message, 24)[0] == operation
                    and message[32:56] == source[16:40] and message[64:] == source[40:]
                    and response[:8] == b"HFFASR01" and struct.unpack_from("<Q", response, 8)[0] == 0,
                    "effect fence semantic framing has a non-native creation")
            future = struct.unpack_from("<Q", response, 16)[0]
            require(future > 0, "effect fence real future is missing")
        returned = rows[cursor]; cursor += 1
        message, response = bytes.fromhex(returned["input_hex"]), bytes.fromhex(returned["output_hex"])
        require(returned["case"] == row["case"] and message[:8] == b"HFFASY01"
                and len(response) == 64 and response[:8] == b"HFFASR01"
                and struct.unpack_from("<Q", response, 8)[0] == 0,
                "effect fence semantic result did not come from the native transport")
        if operation == 4:
            require(struct.unpack_from("<Q", message, 8)[0] == 5 and reply[8:] == bytes(32)
                    and response[32:] == bytes(32), "effect fence release translation changed")
        else:
            require(struct.unpack_from("<2Q", message, 8) == (6, future)
                    and struct.unpack_from("<Q", response, 16)[0] == future
                    and response[32:] == reply[8:], "effect fence semantic response differs from the native owner")
    require(cursor == len(rows), "effect fence native transport has unbound trailing responses")
    return expected


def suite_evidence(root, folder, kind, summary, artifacts):
    exact(summary.get("counts"), COUNTS[kind], "actual suite counts differ")
    primary = artifacts["profiles"]["production"]
    source_sets = {
        "async": ("test_fence_async.py", "fence_async_support.py", "effect_fence_test_support.py"),
        "worker": ("test_fence_worker.py", "fence_worker_supervisor.py", "fence_async_support.py", "effect_fence_test_support.py"),
        "owner": ("test_fence_owner.py", "effect_fence_test_support.py"),
        "kernel": ("test_fence_kernel.py", "fence_kernel_supervisor.py", "fence_worker_supervisor.py",
            "effect_fence_test_support.py", "fence_async_support.py", "effect_fence_async_serial_adapter.py"),
    }
    if kind in source_sets:
        exact(summary.get("sources"), actual_sources(root, source_sets[kind]), "actual suite source set differs")
    result = {"counts": COUNTS[kind]}
    if kind != "packer":
        result["corpus"] = rows_evidence(folder, kind, summary)
        require(summary.get("complete_effect_fence_owner") is False and summary.get("whole_runtime_replaced") is False,
                "effect fence native suite overclaims integration")
    if kind == "async":
        exact(summary.get("profiles"), {"default": DEFAULT_ELF, "single_worker_fixture": QUEUE_ELF},
              "actual asynchronous profile identities differ")
        traces = retained_reports(folder, summary["traces"], ("unpolled.trace", "legacy.trace", "partial.trace",
            "required.trace", "queued-cancel.trace", "eof-queue.trace"))
        for name, raw in traces.items():
            trace = raw.decode()
            if name in ("queued-cancel.trace", "eof-queue.trace"):
                locked = _shared_lock_completions(trace)
                require(len(locked) == 4 and len({tid for tid, _ in locked}) == 4
                        and trace.count('".owner.json"') == 8,
                        "effect fence cancelled queued closures did not finish original validation")
            else:
                require("clone(" not in trace and '".owner.lock"' not in trace,
                        "effect fence unpolled/preflight path performed native effects")
        result["actual_syscall_traces"] = {name: sha(raw) for name, raw in traces.items()}
    elif kind == "worker":
        rows = retained_reports(folder, summary["kernel_reports"], ("admission-ordinary-mask.json",
            "admission-blocked-sigill.json", "cache-ordinary-mask.json", "cache-blocked-sigill.json"))
        result["worker_controls"] = [worker_trace_evidence(root, json.loads(raw),
            mode="cache" if name.startswith("cache") else "admission", inherited="blocked" in name, artifact=primary)
            for name, raw in rows.items()]
    elif kind == "lifetime":
        require(summary.get("source_sha256") == sha(read(root / "tests/hia_native/test_fence_lifetime.py"))
                and summary.get("elf_sha256") == DEFAULT_ELF
                and summary.get("manifest_sha256") == primary["manifest_sha256"], "effect fence actual lifetime artifact differs")
        observations = summary["observed_mapping_bytes"]
        require(len(observations) == 2 and observations[0]["case"] == "recycled-history"
                and observations[0]["historical_futures"] == 16386 and observations[0]["max_live_records"] == 1
                and observations[0]["before"] == observations[0]["after"]
                and observations[1]["case"] == "live-record-growth" and observations[1]["historical_futures"] == 8194
                and observations[1]["max_live_records"] == 8193
                and observations[1]["after"] - observations[1]["before"] == 1 << 20,
                "effect fence actual free-slot reuse or live growth changed")
        result["mapping_observations"] = observations
    elif kind == "owner":
        require(summary.get("binary_sha256") == DEFAULT_ELF and summary.get("backend") == "native-hia"
                and summary.get("native_owner_calls") == 212 and summary.get("original_owner_calls") == 0
                and summary.get("rows") == 212 and summary.get("counts_match") is True,
                "effect fence original semantic domain is not native execution")
        framing = object_at(folder / "async-framing.json")
        exact(framing.get("semantic_counts"), COUNTS["owner"], "serial fixture semantic counts differ")
        exact(framing.get("transport_counts"), {"processes": 93, "closed_processes": 0, "requests": 379, "responses": 379},
              "serial fixture real native transport counts differ")
        require(framing.get("framing_only") is True and framing.get("semantic_source_unchanged") is True
                and framing.get("native_processes_closed") == 93, "effect fence serial framing changed its owner")
        exact(framing.get("sources"), actual_sources(root, ("effect_fence_async_serial_adapter.py",
            "fence_async_support.py", "effect_fence_test_support.py")), "serial framing source differs")
        result["real_native_transport"] = transport_evidence(folder, framing, owner=True)
    elif kind == "kernel":
        require(summary.get("backend") == "native-hia" and summary.get("executable_sha256") == DEFAULT_ELF
                and summary.get("actual_owned_filesystem_races") is True
                and summary.get("synthetic_syscall_errors_declared") is True
                and summary.get("scan_deadline_seconds") == 30 and summary.get("deadline_or_clock_modified") is False,
                "effect fence actual kernel domain or original time bound differs")
        exact(summary.get("transport_counts"), {"processes": 19, "closed_processes": 0, "requests": 63, "responses": 63},
              "paired kernel actual native frame count differs")
        rows = retained_reports(folder, summary["kernel_reports"], tuple(case + ".json" for case in KERNEL_CASES))
        result["normalized_events"] = {case: kernel_trace_evidence(root, json.loads(rows[case + ".json"]), case, DEFAULT_ELF)
                                       for case in KERNEL_CASES}
        result["real_native_transport"] = transport_evidence(folder, summary, owner=False)
    elif kind == "packer":
        names = ("tests/hia_native/test_fence_packer.py", "scripts/hia_native_effect_fence_build.py",
            "scripts/hia_native_build.py", "scripts/hia_native_loader.py", PROFILE)
        exact(summary.get("sources"), {name: sha(read(root / name)) for name in names}, "packer/cache suite source differs")
        require(summary.get("cached_bootstrap_scope") == "development_fixed_point; no fresh cold replay",
                "effect fence cache control mislabels compiler qualification")
    return result


def native_evidence(root, output, report, completed=completed_process, *, reference_root=None):
    root, output = Path(root), Path(output)
    sources = source_pins(root, reference_root=reference_root)
    artifacts = artifact_evidence(root, output, report)
    corpus_root = output / FOLDER
    suites, files = {}, {}
    for filename, _, report_name, tests, kind in SUITES:
        check, actual = process_evidence(root, output, report, completed, filename, tests)
        path = corpus_root / report_name
        retained = object_at(path)
        exact(actual, retained, "actual process stdout differs from retained suite receipt")
        suites[kind] = suite_evidence(root, path.parent, kind, retained, artifacts)
        suites[kind]["stdout_sha256"] = check["stdout_sha256"]
        suites[kind]["stderr_sha256"] = check["stderr_sha256"]
        files[str(path.relative_to(output))] = sha(read(path))
        if kind != "packer":
            for child in sorted(path.parent.iterdir()):
                require(child.is_file() and not child.is_symlink(), "effect fence corpus has unexpected nested storage")
                files[str(child.relative_to(output))] = sha(read(child))
    return {"status": "PASS", "source_sha256": sources, **artifacts, "suites": suites,
        "corpus_sha256": files, "native_suite_groups": 31,
        "actual_native_owner_semantic_responses": 249,
        "actual_native_executable_processes": 128,
        "actual_native_executable_frames": 49757,
        "actual_native_packer_calls": 98,
        "native_cases_added_by_original_replay": 0,
        "trusted_startup_profile_only": True, "production_activated": False,
        "complete_original_tool_parity": False, "whole_runtime_replaced": False}


def qualification_evidence(root, output, report, completed=completed_process, *, reference_root=None):
    result = native_evidence(root, output, report, completed, reference_root=reference_root)
    filename, _, report_name, tests = EVIDENCE_SUITE
    check, summary = process_evidence(root, output, report, completed, filename, tests)
    exact(summary, object_at(output / FOLDER / report_name), "evidence-control process stdout differs")
    exact(summary.get("counts"), EVIDENCE_COUNTS, "evidence refusal/acceptance domain differs")
    exact(summary.get("sources"), {name: sha(read(root / name)) for name in
        ("tests/hia_native/test_fence_evidence.py", "scripts/hia_native_effect_fence_qualification.py")},
        "evidence checker or control source changed")
    return {**result, "evidence_controls": {"counts": EVIDENCE_COUNTS,
        "stdout_sha256": check["stdout_sha256"], "stderr_sha256": check["stderr_sha256"]},
        "native_suite_groups": 36, "mandatory_native_suites": 7}


def locked_original_dependencies(root):
    baseline = {(item["name"], item["version"]): (item.get("source"), item.get("checksum"))
                for item in tomllib.loads(read(root / "Cargo.lock").decode())["package"] if item.get("source")}
    result = {}
    for folder, expected in (("fence_oracle", 33), ("async_oracle", 41)):
        path = root / "tests/hia_native" / folder / "Cargo.lock"
        packages = [item for item in tomllib.loads(read(path).decode())["package"] if item.get("source")]
        require(len(packages) == expected and all(baseline.get((item["name"], item["version"]))
            == (item["source"], item.get("checksum")) for item in packages),
            "effect fence original locked dependency graph changed")
        result[folder] = {"registry_packages": expected, "lock_sha256": sha(read(path)),
            "exact_original_versions_and_checksums": True}
    return result


def generated_original_evidence(root, target):
    original = read(root / "src/mcp/runtime/effect_owner_fence.rs").decode()
    tests = read(root / "src/mcp/runtime/effect_owner_fence_acquisition_tests.rs").decode()
    output = {}
    for folder, crate, generated in (
        ("fence_oracle", "hia-effect-fence-reference", "original_effect_fence_reference.rs"),
        ("async_oracle", "hia-effect-fence-async-reference", "original_effect_fence_async_reference.rs")):
        matches = list((target / "release/build").glob(crate + "-*/out/" + generated))
        require(len(matches) == 1, "effect fence actual original build output is missing or ambiguous")
        path = matches[0]
        if folder == "fence_oracle":
            access = read(root / "tests/hia_native/fence_oracle/original_access.rs").decode()
            expected = f"#[allow(dead_code)]\nmod original {{\n{original}\n{access}\n}}\n"
        else:
            require(tests.count("#[test]\n") == 2 and tests.count('#[tokio::test(flavor = "current_thread")]\n') == 3,
                    "effect fence original five-body registration shape changed")
            bodies = tests.replace("#[test]\n", "").replace('#[tokio::test(flavor = "current_thread")]\n', "")
            access = read(root / "tests/hia_native/async_oracle/original_async_access.rs").decode().replace("//!", "//", 1)
            runner = read(root / "tests/hia_native/async_oracle/original_async_runner.rs").decode().replace("//!", "//", 1)
            expected = f"#[allow(dead_code)]\nmod original {{\n{original}\n{access}\nmod acquisition_cases {{\n{bodies}\n{runner}\n}}\n}}\n"
            require(read(path.parent / "original_effect_fence_acquisition_tests.rs") == tests.encode()
                    and read(path.parent / "original_acquisition_bodies.rs") == bodies.encode(),
                    "effect fence original acquisition bodies or assertions changed")
        require(read(path) == expected.encode() and read(path.parent / "original_effect_fence.rs") == original.encode(),
                "effect fence generated source replaced an original owner decision")
        output[crate] = {"generated_sha256": sha(read(path)), "original_owner_sha256": sha(original.encode()),
                        "access_only_glue": True}
    return output


def original_owner_result(root, folder, summary, binary_sha, native_folder):
    completion(summary, 10)
    exact(summary.get("counts"), COUNTS["owner"], "actual original owner process domain differs")
    require(summary.get("binary_sha256") == binary_sha and summary.get("backend") == "unchanged-original-rust"
            and summary.get("native_owner_calls") == 0 and summary.get("original_owner_calls") == 212
            and summary.get("rows") == 212 and summary.get("counts_match") is True,
            "effect fence original semantic replay used another owner")
    exact(summary.get("sources"), actual_sources(root, ("test_fence_owner.py", "effect_fence_test_support.py")),
          "original owner test source changed")
    corpus = rows_evidence(folder, "owner", summary)
    require(gzip.decompress(read(folder / "owner-cases.jsonl.gz")) ==
            gzip.decompress(read(native_folder / "owner-cases.jsonl.gz")),
            "effect fence original/native complete serial responses differ")
    return corpus


def original_kernel_result(root, folder, summary, binary_sha, native_folder, native_events):
    completion(summary, 3)
    exact(summary.get("counts"), COUNTS["kernel"], "actual original kernel process domain differs")
    require(summary.get("executable_sha256") == binary_sha and summary.get("backend") == "unchanged-original-rust"
            and summary.get("transport_counts") is None and summary.get("transport_corpus") is None
            and summary.get("actual_owned_filesystem_races") is True
            and summary.get("synthetic_syscall_errors_declared") is True
            and summary.get("scan_deadline_seconds") == 30 and summary.get("deadline_or_clock_modified") is False,
            "effect fence actual original kernel replay differs")
    exact(summary.get("sources"), actual_sources(root, ("test_fence_kernel.py", "fence_kernel_supervisor.py",
        "fence_worker_supervisor.py", "effect_fence_test_support.py", "fence_async_support.py",
        "effect_fence_async_serial_adapter.py")), "original paired kernel sources changed")
    corpus = rows_evidence(folder, "kernel", summary)
    require(read(folder / "cases.jsonl") == read(native_folder / "cases.jsonl"),
            "effect fence original/native kernel response bytes differ")
    rows = retained_reports(folder, summary["kernel_reports"], tuple(case + ".json" for case in KERNEL_CASES))
    normalized = {case: kernel_trace_evidence(root, json.loads(rows[case + ".json"]), case, binary_sha, backend="original")
                  for case in KERNEL_CASES}
    exact(normalized, native_events, "paired native/original real effect observations differ")
    return {"corpus": corpus, "normalized_events": normalized, "kernel_processes": 19}


def compare_original(root, output, report, rustc, completed, record_check, env):
    """Eight mandatory real subprocess checks; no captured PASS substitutes."""
    root, output, rustc = Path(root), Path(output), Path(rustc)
    before = qualification_evidence(root, output, report, completed)
    exact(before, report["effect_fence_evidence"], "native effect fence evidence changed before original replay")
    dependencies = locked_original_dependencies(root)
    folder = output / FOLDER
    original = folder / "original"
    require(not original.exists(), "effect fence original replay output already exists")
    original.mkdir(mode=0o700)
    target = original / "target"
    cargo, rustfmt = rustc.with_name("cargo"), rustc.with_name("rustfmt")
    require(cargo.is_file() and rustfmt.is_file() and rustc.is_file(), "effect fence exact Rust toolchain is incomplete")
    environment = dict(env)
    environment.update({"RUSTC": str(rustc), "RUSTFMT": str(rustfmt), "HIA_REFERENCE_RUNTIME": str(root),
                        "CARGO_TARGET_DIR": str(target)})
    environment["PATH"] = str(rustc.parent) + ":" + environment.get("PATH", "")
    for key in tuple(environment):
        if key.startswith("HIA_FENCE_"):
            del environment[key]
    names = []
    for key, crate in (("serial", "fence_oracle"), ("async", "async_oracle")):
        manifest = root / "tests/hia_native" / crate / "Cargo.toml"
        name = "effect-fence-rust-" + key + "-fmt"
        record_check(output, report, name=name, command=[str(cargo), "fmt", "--manifest-path", str(manifest),
            "--", "--check", "--config-path", str(root / "rustfmt.toml")], env=environment, timeout=180)
        names.append(name)
        name = "effect-fence-rust-" + key + "-compile"
        record_check(output, report, name=name, command=[str(cargo), "build", "--locked", "--release",
            "--manifest-path", str(manifest)], env=environment, timeout=180)
        names.append(name)
    generated = generated_original_evidence(root, target)
    binary = target / "release/hia-effect-fence-reference"
    async_binary = target / "release/hia-effect-fence-async-reference"
    binary_sha, async_sha = sha(read(binary)), sha(read(async_binary))
    observations = {}
    for kind, filename, tests, report_name in (("owner", "test_fence_owner.py", 10, "owner-report.json"),
                                             ("kernel", "test_fence_kernel.py", 3, "report.json")):
        directory = original / kind
        directory.mkdir(mode=0o700)
        local = dict(environment, HIA_FENCE_REFERENCE_BINARY=str(binary), HIA_FENCE_REFERENCE_SHA256=binary_sha)
        if kind == "owner":
            local["HIA_FENCE_CORPUS_DIR"] = str(directory)
        else:
            local.update(HIA_FENCE_KERNEL_BACKEND="original", HIA_FENCE_KERNEL_CORPUS_DIR=str(directory))
        name = "effect-fence-rust-" + kind + "-compare"
        executed = record_check(output, report, name=name, command=[sys.executable, "-I", "-B",
            str(root / "tests/hia_native" / filename)], env=local, timeout=180)
        names.append(name)
        summary = json.loads(executed.stdout)
        exact(summary, object_at(directory / report_name), "actual original suite stdout differs")
        require(len(re.findall(rb"\.\.\. ok\n", executed.stderr)) == tests
                and re.search(rb"\nRan " + str(tests).encode() + rb" tests in [0-9.]+s\n\nOK\n\Z", executed.stderr),
                "effect fence original suite did not complete every group")
        observations[kind] = (original_owner_result(root, directory, summary, binary_sha, folder / "owner") if kind == "owner"
            else original_kernel_result(root, directory, summary, binary_sha, folder / "kernel",
                                       before["suites"]["kernel"]["normalized_events"]))
    for mode, arguments, tests, message in (
        ("acquisition", [], 5, b"fixture acquisition panic must not grant admission"),
        ("cache-poison", ["--cache-poison-control"], 1, b"declared qualification panic while original cache lock is held")):
        name = "effect-fence-rust-" + mode + "-compare"
        executed = record_check(output, report, name=name, command=[str(async_binary), *arguments], env=environment, timeout=180)
        names.append(name)
        summary = json.loads(executed.stdout)
        completion(summary, tests)
        require(summary.get("original_owner_modified") is False and summary.get("native_cases_added") == 0
                and executed.stderr.count(message) == 1 and executed.stderr.count(b"panicked at") == 1,
                "effect fence original panic injection or scope differs")
        if mode == "acquisition":
            exact(summary.get("cases"), [
                "exclusive_fence_waiters_exceed_old_capacity_and_preserve_authority_after_cancellation",
                "cancelled_queued_fence_workers_complete_validation_without_leaking_authority",
                "unpolled_fence_acquisition_never_submits_a_worker",
                "fence_acquisition_success_error_and_panic_preserve_results",
                "acquired_shared_fence_outlives_the_acquisition_worker"], "original acquisition bodies changed")
            require(summary.get("original_test_bodies_modified") is False, "original async assertions were modified")
        else:
            exact({k: summary.get(k) for k in ("original_owner_calls", "actual_admissions", "actual_poisoned_queries",
                "declared_worker_panic_injections", "actual_permit_releases", "real_exclusive_lock_restored")},
                {"original_owner_calls": 5, "actual_admissions": 2, "actual_poisoned_queries": 2,
                "declared_worker_panic_injections": 1, "actual_permit_releases": 2, "real_exclusive_lock_restored": True},
                "actual original cache poisoning domain changed")
        observations[mode] = summary
    require(len(names) == 8 and sha(read(binary)) == binary_sha and sha(read(async_binary)) == async_sha,
            "effect fence actual original process set or binary changed")
    exact(source_pins(root), before["source_sha256"], "effect fence source changed during original compilation/replay")
    exact(qualification_evidence(root, output, report, completed), before, "effect fence native evidence changed during original replay")
    result = {"schema": "hepta.runtime.effect-fence.original-comparison.v1", "status": "PASS",
        "checks": names, "mandatory_actual_checks": 8, "original_binary_sha256": binary_sha,
        "original_async_binary_sha256": async_sha, "generated_original": generated, "locked_dependencies": dependencies,
        "observations": observations, "actual_original_semantic_responses": 249,
        "actual_original_kernel_processes": 112, "actual_original_acquisition_bodies": 5,
        "actual_original_cache_poison_controls": 1, "captured_native_semantic_responses": 249,
        "native_cases_added_by_original_replay": 0, "compiled_by_qualification_recipe": True,
        "source_sha256": before["source_sha256"], "production_activated": False,
        "complete_original_tool_parity": False, "whole_runtime_replaced": False}
    (folder / "original-comparison.json").write_bytes(json_bytes(result))
    return result
