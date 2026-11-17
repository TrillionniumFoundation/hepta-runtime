"""Validate the closed Linux entropy component and its retained observations.

This module checks evidence; it supplies no entropy and executes no runtime
policy. Compiler cold qualification remains owned by the aggregate qualifier.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
import tomllib

from hia_native_build import HEPTA_COMMIT

FOLDER = "system-entropy-rust-oracle"
KERNEL_RECEIPT = "kernel-native.json"
SUITES = (
    ("test_entropy_backend.py", "backend.json", "hepta.runtime.entropy-backend-test.v1", 11,
     {"native_calls": 1929, "synthetic_effect_completions": 1609, "completed_outputs": 183,
      "entropy_refusals": 19, "state_refusals": 50, "admission_refusals": 43, "capacity_refusals": 4}),
    ("test_entropy_packer.py", "packer.json", "hepta.runtime.entropy-packer-test.v1", 5,
     {"native_packer_calls": 42, "native_executables": 19, "malformed_effect_refusals": 17,
      "admission_refusals": 19, "capacity_refusals": 2, "dirty_return_refusals": 1,
      "cached_builder_admissions": 1, "cached_builder_commit_refusals": 2}),
    ("test_entropy_kernel_backend.py", KERNEL_RECEIPT, "hepta.runtime.entropy-kernel-backend-test.v1", 8,
     {"processes": 25, "request_frames": 56, "original_owner_calls": 0,
      "kernel_completions": 100, "injected_completions": 118,
      "successful_outputs": 46, "entropy_refusals": 10}),
    ("test_entropy_transport.py", "transport.json", "hepta.runtime.entropy-transport-test.v1", 6,
     {"native_processes": 13, "partial_frame_refusals": 5, "invalid_frame_refusals": 4,
      "cli_refusals": 3, "closed_output_controls": 1, "invalid_kernel_success_controls": 1}),
)
CORPUS_FILES = ("native-corpus.json", *(row[1] for row in SUITES))
KERNEL_SOURCES = ("test_entropy_kernel_backend.py", "entropy_backend_supervisor.py",
                  "entropy_test_support.py", "io_fault_supervisor.py")
ORACLE_SOURCES = ("tests/hia_native/oracle_system_entropy.rs",
                  "tests/hia_native/entropy_oracle/Cargo.toml", "tests/hia_native/entropy_oracle/Cargo.lock",
                  "tests/hia_native/entropy_oracle/build.rs", "tests/hia_native/entropy_oracle/original_access.rs")
ORIGINAL_SOURCE = "src/mcp/runtime/operation_crypto.rs"
ENTROPY = 0xfffffffd


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def read(path: Path) -> bytes:
    if not path.is_file() or path.is_symlink() or path.resolve() != path.absolute():
        raise ValueError("entropy evidence requires a regular, non-aliased file: " + str(path))
    return path.read_bytes()


def file_hash(path: Path) -> str:
    return digest(read(path))


def object_at(path: Path) -> dict:
    value = json.loads(read(path))
    if not isinstance(value, dict):
        raise ValueError("entropy evidence must be a JSON object")
    return value


def exact_counts(actual: object, expected: dict) -> None:
    if actual != expected or not isinstance(actual, dict) or any(
            type(value) is not int or value < 0 for value in actual.values()):
        raise ValueError("entropy count coverage differs")


def completion(report: dict, expected: int) -> None:
    wanted = {"tests_run": expected, "expected_tests": expected, "failures": 0, "errors": 0,
              "skipped": 0, "expected_failures": 0, "unexpected_successes": 0}
    if report.get("status") != "PASS" or any(
            type(report.get(key)) is not int or report[key] != value for key, value in wanted.items()):
        raise ValueError("entropy suite did not complete every required test")


def source_pins(root: Path) -> dict:
    paths = {"native/entropy_policy.hepta", "native/entropy_packer.hepta",
             "scripts/hia_native_entropy_build.py", "scripts/hia_native_entropy_qualification.py",
             ORIGINAL_SOURCE, *ORACLE_SOURCES}
    paths.update("tests/hia_native/" + name for name in KERNEL_SOURCES)
    paths.update("tests/hia_native/" + row[0] for row in SUITES)
    return {name: file_hash(root / name) for name in sorted(paths)}


def oracle_dependencies(root: Path) -> dict:
    lock = tomllib.loads(read(root / "tests/hia_native/entropy_oracle/Cargo.lock").decode())
    pins = {"ring": "0.17.14", "getrandom": "0.2.17", "libc": "0.2.191", "zeroize": "1.9.0"}
    result = {}
    for name, version in pins.items():
        matches = [row for row in lock["package"] if row["name"] == name]
        if len(matches) != 1 or matches[0]["version"] != version:
            raise ValueError("entropy oracle locked dependency differs: " + name)
        row = matches[0]
        if (row.get("source") != "registry+https://github.com/rust-lang/crates.io-index"
                or not isinstance(row.get("checksum"), str) or len(row["checksum"]) != 64):
            raise ValueError("entropy oracle dependency has no registry identity")
        result[name] = {key: row[key] for key in ("version", "source", "checksum")}
    return result


def native_receipt(receipt: dict, *, image: bytes, source: bytes, output: bytes, produced: bytes) -> None:
    expected = {"status": "returned", "abi_status": 0, "core_u32": len(produced),
                "result_u64": len(produced), "source_unchanged": True,
                "input_bytes": len(source), "input_sha256": digest(source),
                "source_sha256": digest(source), "artifact_sha256": digest(image),
                "image_sha256": digest(image), "output_sha256": digest(output),
                "forbidden_compiler_modules_loaded": []}
    if (any(receipt.get(key) != value for key, value in expected.items())
            or receipt.get("source_unchanged") is not True
            or any(type(receipt.get(key)) is not int for key in ("abi_status", "core_u32", "result_u64", "input_bytes"))
            or not 0 < len(produced) <= min(1 << 20, len(output)) or output[:len(produced)] != produced):
        raise ValueError("entropy native compilation/packing receipt differs")


def inspect_elf(raw: bytes) -> dict:
    if (len(raw) < 176 or raw[:16] != b"\x7fELF\x02\x01\x01" + bytes(9)
            or struct.unpack_from("<HHIQQQIHHHHHH", raw, 16)
            != (2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
            or struct.unpack_from("<IIQQQQQQ", raw, 64)
            != (1, 5, 0, 0x400000, 0x400000, len(raw), len(raw), 4096)
            or struct.unpack_from("<IIQQQQQQ", raw, 120)
            != (0x6474e551, 6, 0, 0, 0, 0, 0, 16)):
        raise ValueError("entropy static ELF headers differ")
    return {"bytes": len(raw), "dynamic_loader": False, "elf_type": "ET_EXEC", "entry": 0x4000b0,
            "interpreter": None, "libc": False, "machine": "EM_X86_64",
            "program_headers": ["PT_LOAD_RX", "PT_GNU_STACK_RW"], "sha256": digest(raw)}


def validate_artifacts(root: Path, output: Path, report: dict) -> dict:
    module = report["modules"]["system_entropy"]
    if module.get("builder") != "entropy" or module.get("source") != "native/entropy_policy.hepta":
        raise ValueError("entropy module is not bound to its custom builder")
    relative = Path(module["manifest"])
    if relative.is_absolute() or ".." in relative.parts or relative.parts[:2] != ("build", "entropy"):
        raise ValueError("entropy manifest escaped its build directory")
    manifest_path = output / relative
    metadata = object_at(manifest_path)
    if file_hash(manifest_path) != module.get("sha256"):
        raise ValueError("entropy top manifest changed")
    compiler = read(output / "build/bootstrap/B3.image.bin")
    if digest(compiler) != report["compiler_image_sha256"] or report["compiler_commit"] != HEPTA_COMMIT:
        raise ValueError("entropy pinned compiler changed")
    expected = {"schema": "hepta.runtime.native-entropy.v2", "target": "linux-x86_64",
                "transport": "fixed-24-byte-requests-u32-results", "compiler_commit": HEPTA_COMMIT,
                "compiler_sha256": digest(compiler), "executable": "native-entropy.elf",
                "policy_manifest": "policy.json", "packer_manifest": "packer.json",
                "request_bytes": 24, "maximum_entropy_bytes": 128, "workspace_bytes": 1024,
                "runtime_python_required": False, "runtime_libc_required": False,
                "registered_mcp_tool": False, "production_activated": False, "whole_runtime_replaced": False}
    if any(type(metadata.get(key)) is not type(value) or metadata[key] != value for key, value in expected.items()):
        raise ValueError("entropy executable manifest contract differs")
    directory = manifest_path.parent
    artifacts = {relative.as_posix(): file_hash(manifest_path)}
    images = {}
    for kind in ("policy", "packer"):
        source = read(root / "native" / ("entropy_" + kind + ".hepta"))
        image = read(directory / (kind + ".image.bin"))
        images[kind] = image
        sub = object_at(directory / (kind + ".json"))
        if (read(directory / (kind + ".hepta")) != source
                or metadata.get(kind + "_source_sha256") != digest(source)
                or metadata.get(kind + "_image_sha256") != digest(image)
                or metadata.get(kind + "_manifest_sha256") != file_hash(directory / (kind + ".json"))
                or sub.get("compiler_commit") != HEPTA_COMMIT or sub.get("compiler_sha256") != digest(compiler)
                or sub.get("source") != kind + ".hepta" or sub.get("source_sha256") != digest(source)
                or sub.get("image") != kind + ".image.bin" or sub.get("image_sha256") != digest(image)):
            raise ValueError("entropy source, flat image or submanifest changed: " + kind)
        compiled = output / "build/modules" / ("entropy-" + kind + "-" + digest(source)[:16])
        receipt = object_at(compiled / "module.receipt.json")
        native_receipt(receipt, image=compiler, source=source,
                       output=read(compiled / "module.output.bin"), produced=image)
        build_record = object_at(compiled / "build.json")
        bootstrap = object_at(output / "build/bootstrap/bootstrap.json")
        if (read(compiled / "module.input.bin") != source or read(compiled / "module.image.bin") != image
                or receipt.get("produced_sha256") != digest(image) or receipt.get("produced_bytes") != len(image)
                or build_record.get("compile_receipt") != receipt
                or build_record.get("compiler_dependency") != bootstrap.get("dependency")):
            raise ValueError("entropy retained compiler input/output receipts differ")
        for name in (kind + ".hepta", kind + ".json", kind + ".image.bin"):
            artifacts[(directory / name).relative_to(output).as_posix()] = file_hash(directory / name)
        for name in ("module.receipt.json", "module.input.bin", "module.output.bin", "module.image.bin", "build.json"):
            artifacts[(compiled / name).relative_to(output).as_posix()] = file_hash(compiled / name)
    elf = read(directory / "native-entropy.elf")
    inspection = inspect_elf(elf)
    if metadata.get("executable_sha256") != digest(elf) or metadata.get("inspection") != inspection:
        raise ValueError("entropy ELF artifact differs")
    frame = b"HIAENTP1" + struct.pack("<Q", len(images["policy"])) + images["policy"]
    if read(directory / "pack.input.bin") != frame:
        raise ValueError("entropy packer input differs")
    native_receipt(metadata["pack_receipt"], image=images["packer"], source=frame,
                   output=read(directory / "pack.output.bin"), produced=elf)
    for name in ("native-entropy.elf", "pack.input.bin", "pack.output.bin"):
        artifacts[(directory / name).relative_to(output).as_posix()] = file_hash(directory / name)
    return {"manifest_sha256": file_hash(manifest_path), "binary_sha256": digest(elf),
            "policy_source_sha256": metadata["policy_source_sha256"],
            "packer_source_sha256": metadata["packer_source_sha256"],
            "policy_image_sha256": digest(images["policy"]), "packer_image_sha256": digest(images["packer"]),
            "compiler_commit": HEPTA_COMMIT, "compiler_image_sha256": digest(compiler),
            "inspection": inspection, "artifact_sha256": artifacts}


def kernel_cases() -> list[tuple[str, list[int], list[int]]]:
    cached = [32, 32, 32, 32, 12, 0, 32]
    cases = [(mode, cached, cached) for mode in ("observe", "probe_enosys", "probe_eperm")]
    cases += [(mode, [32, 12], [32, 12]) for mode in ("eintr", "fallback_eintr")]
    cases += [(mode, [32], [ENTROPY]) for mode in ("eio", "enosys", "eagain", "zero")]
    cases += [(mode, [32, 12], [ENTROPY, 12]) for mode in (
        "partial_error", "fallback_partial_error", "fallback_open_error", "fallback_poll_error",
        "fallback_urandom_open_error", "fallback_read_error")]
    cases += [(mode, [32, 12], [32, 12]) for mode in (
        "probe_eintr", "probe_eio", "probe_eagain", "partial", "fallback_partial")]
    cases += [("observe", [size], [size]) for size in (0, 1, 12, 32, 128)]
    return cases


def normalized_kernel_report(root: Path, report: dict, *, original: bool, binary_sha256: str,
                             artifacts: dict | None = None) -> dict:
    """Check every retained event, permitting only the documented exit cleanup difference."""
    completion(report, 8)
    expected_counts = dict(SUITES[2][4])
    if original:
        expected_counts.update(original_owner_calls=56, kernel_completions=91)
    exact_counts(report.get("counts"), expected_counts)
    pins = {name: file_hash(root / "tests/hia_native" / name) for name in KERNEL_SOURCES}
    if (report.get("schema") != SUITES[2][2] or report.get("source_unchanged") is not True
            or report.get("source_sha256") != pins):
        raise ValueError("entropy kernel test source or completion identity differs")
    provenance = {"owner": "original Rust SystemEntropy" if original else "native HIA entropy policy and ELF packer",
                  "binary_sha256": binary_sha256}
    if not original:
        if not artifacts:
            raise ValueError("native entropy kernel observation requires its compiled artifact identity")
        provenance.update({name: artifacts[name] for name in (
            "manifest_sha256", "policy_source_sha256", "packer_source_sha256")})
    if report.get("provenance") != provenance:
        raise ValueError("entropy observed executable identity differs")
    traces = report.get("traces")
    cases = kernel_cases()
    if not isinstance(traces, list) or len(traces) != len(cases):
        raise ValueError("entropy kernel trace coverage differs")
    actual_counts = {key: 0 for key in expected_counts}
    normalized = []
    kinds = {"probe", "getrandom", "open_random", "poll", "close_random",
             "open_urandom", "read_urandom", "close_urandom"}
    for trace, (mode, sizes, codes) in zip(traces, cases):
        request = b"".join(b"HRENT001" + struct.pack("<QQ", size, 0) for size in sizes)
        wanted = {"mode": mode, "sizes": sizes, "codes": codes,
                  "request_sha256": digest(request), "output_lengths": [code if code <= 128 else 0 for code in codes],
                  "owned_child_reaped": True}
        if (not isinstance(trace, dict) or set(trace) != set(wanted) | {"events"}
                or any(trace.get(key) != value for key, value in wanted.items())
                or trace.get("owned_child_reaped") is not True
                or any(type(value) is not int for key in ("sizes", "codes", "output_lengths") for value in trace[key])):
            raise ValueError("entropy kernel case, frame or published length differs")
        events = trace["events"]
        if not isinstance(events, list):
            raise ValueError("entropy kernel events must be retained")
        counters, data_fds, cleaned = Counter(), set(), []
        for event in events:
            if not isinstance(event, dict) or event.get("kind") not in kinds:
                raise ValueError("entropy event kind differs")
            kind = event["kind"]
            counters[kind] += 1
            if type(event.get("call")) is not int or event["call"] != counters[kind]:
                raise ValueError("entropy per-effect sequence differs")
            keys = {"kind", "call", "completion"}
            if kind == "probe":
                keys.add("requested")
                if type(event.get("requested")) is not int or event["requested"] != 0:
                    raise ValueError("entropy backend probe differs")
            if kind in {"getrandom", "read_urandom"}:
                keys.update(("requested", "destination_delta"))
                size, offset = event.get("requested"), event.get("destination_delta")
                if (type(size) is not int or type(offset) is not int or not 1 <= size <= 128
                        or not 0 <= offset <= 128 - size):
                    raise ValueError("entropy effect buffer span differs")
            if kind in {"read_urandom", "close_random", "close_urandom"}:
                keys.add("device_fd")
                fd = event.get("device_fd")
                if type(fd) is not int or not 0 <= fd < (1 << 31):
                    raise ValueError("entropy owned descriptor identity differs")
                if kind == "read_urandom":
                    data_fds.add(fd)
            effect = event.get("completion")
            if effect == "kernel":
                actual_counts["kernel_completions"] += 1
            elif effect == "injected_error":
                keys.add("error")
                if type(event.get("error")) is not int or not 1 <= event["error"] <= 4095:
                    raise ValueError("entropy injected errno differs")
                actual_counts["injected_completions"] += 1
            elif effect in {"injected_return", "synthetic_partial_bytes"}:
                keys.add("returned")
                returned = event.get("returned")
                if (kind not in {"getrandom", "read_urandom"} or type(returned) is not int
                        or not 0 <= returned <= event["requested"]
                        or (effect == "synthetic_partial_bytes" and returned == 0)):
                    raise ValueError("entropy synthetic data completion differs")
                actual_counts["injected_completions"] += 1
            else:
                raise ValueError("entropy completion provenance differs")
            if set(event) != keys:
                raise ValueError("entropy event has missing or unrecognized evidence fields")
            if kind != "close_urandom":
                cleaned.append({key: value for key, value in event.items() if key != "device_fd"})
        if counters["probe"] != int(any(sizes)) or len(data_fds) > 1:
            raise ValueError("entropy backend probe or descriptor cache lifetime differs")
        expected_closes = int(bool(data_fds) and not original)
        if counters["close_urandom"] != expected_closes:
            raise ValueError("entropy cached descriptor EOF cleanup differs")
        if expected_closes and (events[-1]["kind"] != "close_urandom"
                                or events[-1]["device_fd"] not in data_fds
                                or events[-1]["completion"] != "kernel"):
            raise ValueError("entropy cached descriptor was not closed at EOF")
        if any(sizes):
            fallback = mode.startswith("fallback_") or mode in {"probe_enosys", "probe_eperm"}
            probe = events[0]
            if probe["kind"] != "probe" or bool(counters["read_urandom"]) != fallback:
                raise ValueError("entropy selected backend differs from the required case")
            if fallback and (probe.get("error") != (1 if mode == "probe_eperm" else 38)
                             or counters["getrandom"]):
                raise ValueError("entropy Linux default fallback selection differs")
        actual_counts["processes"] += 1
        actual_counts["request_frames"] += len(sizes)
        actual_counts["original_owner_calls"] += len(sizes) if original else 0
        actual_counts["successful_outputs"] += sum(code <= 128 for code in codes)
        actual_counts["entropy_refusals"] += codes.count(ENTROPY)
        normalized.append(dict(wanted, events=cleaned))
    exact_counts(actual_counts, expected_counts)
    return {"traces": normalized, "sha256": digest(json.dumps(normalized, sort_keys=True,
                                                              separators=(",", ":")).encode()),
            "cases": len(normalized), "source_sha256": pins, "counts": actual_counts,
            "normal_random_bytes_equality_claimed": False,
            "normalization": "Remove actual device_fd values and only the native final cached-descriptor close."}


def suite_evidence(root: Path, output: Path, report: dict, summary_fn, artifacts: dict) -> dict:
    receipts = {}
    for test, receipt, schema, count, counts in SUITES:
        check, observed = summary_fn(output, report, test)
        completion(observed, count)
        exact_counts(observed.get("counts"), counts)
        path = output / FOLDER / receipt
        retained = object_at(path)
        printed = {key: value for key, value in retained.items() if key != "traces"} if receipt == KERNEL_RECEIPT else retained
        if observed.get("schema") != schema or printed != observed:
            raise ValueError("entropy suite retained receipt differs: " + test)
        receipts[test] = {"receipt_sha256": file_hash(path), "stdout_sha256": check["stdout_sha256"],
                          "stderr_sha256": check["stderr_sha256"], "tests_run": count, "counts": counts}
        if test == "test_entropy_backend.py":
            exact_counts(observed.get("actions"), {"1": 83, "2": 777, "3": 34, "4": 33, "5": 28, "6": 27, "7": 627})
        elif test == "test_entropy_packer.py" and observed.get("cached_bootstrap_scope") != "development_fixed_point; no new cold qualification":
            raise ValueError("entropy cache regression changed its qualification claim")
    kernel = normalized_kernel_report(root, object_at(output / FOLDER / KERNEL_RECEIPT), original=False,
                                      binary_sha256=artifacts["binary_sha256"], artifacts=artifacts)
    return {"suites": receipts, "kernel": {key: value for key, value in kernel.items() if key != "traces"}}


def current_corpus(root: Path, output: Path, report: dict, summary_fn) -> dict:
    artifacts = validate_artifacts(root, output, report)
    suites = suite_evidence(root, output, report, summary_fn, artifacts)
    return {"schema": "hepta.runtime.system-entropy-native-corpus.v1", "status": "PASS",
            "source_sha256": source_pins(root), "oracle_dependencies": oracle_dependencies(root),
            "artifacts": artifacts, **suites,
            "runtime_scope": "Linux x86-64 serial workspace, complete 0..128-byte entropy requests",
            "original_runtime_lock_identical": False, "full_runtime_lock_build_claimed": False,
            "thread_safe_workspace_claimed": False, "normal_random_bytes_equality_claimed": False,
            "registered_mcp_tool": False, "production_activated": False, "whole_runtime_replaced": False,
            "rust_comparison_status": "PENDING"}


def capture_entropy_corpus(root: Path, output: Path, report: dict, summary_fn) -> None:
    corpus = current_corpus(root, output, report, summary_fn)
    path = output / FOLDER / "native-corpus.json"
    with path.open("x") as stream:
        stream.write(json.dumps(corpus, indent=2, sort_keys=True) + "\n")


def entropy_evidence(root: Path, output: Path, report: dict, summary_fn) -> dict:
    current = current_corpus(root, output, report, summary_fn)
    path = output / FOLDER / "native-corpus.json"
    if object_at(path) != current:
        raise ValueError("entropy retained source/image/trace corpus differs")
    return {"schema": "hepta.runtime.system-entropy-evidence.v1", "status": "PASS",
            "corpus_sha256": file_hash(path), "source_sha256": current["source_sha256"],
            "artifacts": current["artifacts"], "suites": current["suites"], "kernel": current["kernel"],
            "oracle_dependencies": current["oracle_dependencies"],
            "original_runtime_lock_identical": False, "thread_safe_workspace_claimed": False,
            "normal_random_bytes_equality_claimed": False, "production_activated": False,
            "whole_runtime_replaced": False}
