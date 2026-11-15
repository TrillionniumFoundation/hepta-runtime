"""Fresh original Rust replay and complete retained-byte publication admission.

This reader executes no result composition. It re-reads every logical input
and actual output, the fixed invocations, current sources, binaries and streams.
"""
from __future__ import annotations

import gzip
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
from types import SimpleNamespace

ORACLE = "tests/hia_native/result_publication_oracle"
FOLDER = "result-publication-original"
NATIVE_FOLDER = "result-publication"
COMPONENT = "result_publication"
SOURCE_FILES = ("Cargo.toml", "Cargo.lock", "src/main.rs", "source_manifest.json",
                "cases.py", "verify_sources.py", "run.py", "README.md")
CHECKS = ("result-publication-rust-compile", "result-publication-rust-compare")
BUILD_VARIABLES = ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_TARGET",
                   "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER")
PUBLISHER_CASES = (87, 89, 3, 20, 0)
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
SOURCE_CHECK = {
    "current_frozen_original_files_match": True,
    "source_commit": "2173a00ec314ebc0c5ada21e4cb60d8efdccb99a",
    "original_git_history_required": False,
    "original_append_function_unchanged": True,
    "original_dependency_lock_match": True,
    "registry_dependency_count": 73,
    "reference_domain": "append_hints with already-drained list plus locked SDK JSON",
    "protocol_version": "2025-06-18",
    "request_context_dedup_not_reimplemented": True,
}
ORIGINAL_SUMMARY = {
    "schema": "hepta.runtime.result-publication.original-replay.v1",
    "cases": 90, "mode_counts": [18, 33, 19, 20], "body_bytes": 88906008,
    "largest_body_bytes": 16777326, "original_append_function_executed": True,
    "post_drain_list_supplied_verbatim": True, "dedup_applied_by_composer": False,
    "serde_json": "1.0.151", "rmcp": "3.4.1",
    "protocol_normalization": "rmcp ServerResult::strip_result_type_for_legacy_peer (2025-06-18)",
    "native_scheduler_qualified": False, "filesystem_callers_replaced": False,
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def json_types(value):
    kind = type(value)
    require(kind in (dict, list, str, int, float, bool, type(None)),
            "original-reference value is not a strict JSON type")
    if kind is dict:
        require(all(type(key) is str for key in value), "original-reference JSON object key is not text")
        for item in value.values():
            json_types(item)
    elif kind is list:
        for item in value:
            json_types(item)
    elif kind is float:
        require(math.isfinite(value), "non-finite original-reference JSON number")


def encoded(value):
    json_types(value)
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("ascii")


def exact(actual, expected, message):
    # JSON equality preserves bool/int and int/float distinctions in receipts.
    require(encoded(actual) == encoded(expected), message)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate original-reference evidence field")
        result[key] = value
    return result


def invalid_constant(value):
    raise ValueError("non-finite original-reference JSON value: " + value)


def decode(raw):
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                       parse_constant=invalid_constant)
    json_types(value)
    return value


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def file_sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def finite(value, *, limit=None):
    require(type(value) in (int, float) and value >= 0,
            "original-reference elapsed value is not a finite nonnegative number")
    if type(value) is float:
        require(math.isfinite(value), "original-reference elapsed value is not finite")
    if limit is not None:
        require(value < limit, "original-reference elapsed exceeded its fixed deadline")


def integer(value, minimum=0):
    require(type(value) is int and value >= minimum,
            "original-reference integer field has the wrong type or range")


def digest_value(value):
    require(type(value) is str and SHA256.fullmatch(value) is not None,
            "original-reference digest field is not a SHA256")


def owned(root, relative):
    require(type(relative) is str and bool(relative), "original-reference artifact name is not text")
    name = Path(relative)
    require(not name.is_absolute() and ".." not in name.parts and name.as_posix() == relative,
            "original-reference artifact is not an owned relative path")
    path = root / name
    require(path.resolve(strict=True) == path.absolute()
            and stat.S_ISREG(path.lstat().st_mode),
            "original-reference artifact is not a regular unsymlinked file")
    return path


def oracle(root):
    name = "_hia_result_publication_original"
    path = root / ORACLE
    spec = importlib.util.spec_from_file_location(name, path / "run.py",
                                                submodule_search_locations=[str(path)])
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def qualification_evidence(root, output, report, completed):
    # Root owns the independent reader for eleven native groups and raw ACKs.
    from hia_native_result_publication_qualification import qualification_evidence as native
    value = native(root, output, report, completed)
    exact(value, report.get("result_publication_evidence"), "native result-publication evidence changed")
    require(type(report.get("modules")) is dict
            and type(report["modules"].get(COMPONENT)) is dict,
            "current result-publication builder bundle is missing")
    return value


def source_inputs(root):
    manifest = decode(owned(root, ORACLE + "/source_manifest.json").read_bytes())
    require(type(manifest) is dict and type(manifest.get("files")) is dict,
            "original source manifest is malformed")
    exact(sorted(manifest["files"]), ["Cargo.lock", "Cargo.toml", "src/mcp/server.rs"],
          "original source manifest input domain changed")
    paths = {ORACLE + "/" + name for name in SOURCE_FILES}
    paths.update(manifest["files"])
    paths.update(("scripts/hia_native_result_publication_reference.py",
                  "scripts/hia_native_result_publication_qualification.py"))
    return {name: file_sha(owned(root, name)) for name in sorted(paths)}


def commands(output, cargo):
    folder = output / FOLDER
    binary = folder / "cargo-target/debug/hepta-result-publication-original-oracle"
    return {
        CHECKS[0]: ([cargo, "build", "--locked", "--manifest-path", str(folder / "crate/Cargo.toml"),
                     "--target-dir", str(folder / "cargo-target")], 180, "build"),
        CHECKS[1]: ([str(binary), str(folder / "original-input.bin"),
                     str(folder / "original-output.bin")], 120, "original-replay"),
    }


def artifact_names():
    names = ["RESULT.json", "crate/Cargo.toml", "crate/Cargo.lock", "crate/src/main.rs",
             "crate/fixtures/original_append_hints.rs",
             "cargo-target/debug/hepta-result-publication-original-oracle",
             "original-input.bin", "original-output.bin"]
    names += [prefix + "." + suffix for prefix in ("build", "original-replay")
              for suffix in ("stdout", "stderr")]
    return ([FOLDER + "/" + name for name in names]
            + [name + "." + suffix for name in CHECKS for suffix in ("stdout", "stderr")])


def native_artifact_names():
    names = ["semantic-cases.jsonl", "publisher-cases.jsonl"]
    for cid in range(90):
        names.extend((f"semantic/{cid:04d}.input.bin.gz", f"semantic/{cid:04d}.native-output.bin.gz"))
    for cid in PUBLISHER_CASES:
        run_id = f"original-case-{cid:04d}"
        names.extend((f"publisher/{run_id}.input.bin.gz", f"elf/{run_id}.stdout.bin.gz"))
    return [NATIVE_FOLDER + "/" + name for name in names]


def process_receipts(output, report, build):
    require(type(report.get("checks")) is list, "original-reference process records are missing")
    receipts, elapsed, observed_order = {}, 0.0, []
    for item in report["checks"]:
        require(type(item) is dict, "original-reference process record is not an object")
        if item.get("name") in CHECKS:
            observed_order.append(item["name"])
    exact(observed_order, list(CHECKS), "original-reference process order, presence or uniqueness changed")
    for name, (command, timeout, duplicate) in commands(output, build["cargo"]).items():
        row = next(item for item in report["checks"] if item.get("name") == name)
        exact(row.get("command"), command, "original-reference fixed command changed")
        require(type(row.get("exit_code")) is int and row["exit_code"] == 0
                and row.get("timed_out") is False
                and ("start_error" not in row or row["start_error"] is None)
                and type(row.get("timeout_seconds")) is int and row["timeout_seconds"] == timeout,
                "original-reference process did not complete its fixed invocation")
        finite(row.get("elapsed_seconds"), limit=timeout)
        elapsed += row["elapsed_seconds"]
        for suffix in ("stdout", "stderr"):
            raw = owned(output, name + "." + suffix).read_bytes()
            integer(row.get(suffix + "_bytes"))
            digest_value(row.get(suffix + "_sha256"))
            require(row[suffix + "_bytes"] == len(raw) and row[suffix + "_sha256"] == sha(raw)
                    and raw == owned(output, FOLDER + "/" + duplicate + "." + suffix).read_bytes(),
                    "original-reference complete raw process stream changed")
            receipts[name + "." + suffix] = sha(raw)
        require(type(row.get("stdin_bytes")) is int and row["stdin_bytes"] == 0
                and row.get("stdin_sha256") == sha(b""), "original-reference process stdin custody changed")
        if name == CHECKS[1]:
            require(owned(output, name + ".stderr").read_bytes() == b"", "original Rust replay emitted unexpected stderr")
            summary = decode(owned(output, name + ".stdout").read_bytes())
            exact(summary, ORIGINAL_SUMMARY, "actual original Rust stdout summary changed")
            if "summary" in row:
                exact(row["summary"], summary, "recorded original Rust process summary changed")
    return receipts, elapsed


def corpus_rows(output):
    semantic, publishers = {}, []
    semantic_keys = {"case_id", "name", "mode", "is_error", "prefix_bytes", "base_bytes", "hint_count",
                     "input_path", "input_bytes", "input_sha256", "output_path", "output_bytes", "output_sha256"}
    publisher_keys = {"case_id", "run_id", "mode", "is_error", "input_path", "input_bytes",
                     "input_sha256", "output_path", "output_bytes", "output_sha256"}
    for kind, keys in (("semantic", semantic_keys), ("publisher", publisher_keys)):
        raw = owned(output, NATIVE_FOLDER + "/" + kind + "-cases.jsonl").read_bytes()
        for line in raw.splitlines():
            row = decode(line)
            require(type(row) is dict and set(row) == keys, "native semantic manifest fields changed")
            for key in ("case_id", "mode", "input_bytes", "output_bytes"):
                integer(row[key])
            require(row["case_id"] < 90 and row["mode"] < 4 and type(row["is_error"]) is bool,
                    "native semantic manifest identity or bool type changed")
            for key in ("input_sha256", "output_sha256"):
                digest_value(row[key])
            if kind == "semantic":
                require(row["case_id"] not in semantic and type(row["name"]) is str,
                        "duplicate or malformed semantic case")
                for key in ("prefix_bytes", "base_bytes", "hint_count"):
                    integer(row[key])
                cid = row["case_id"]
                require(row["input_path"] == f"semantic/{cid:04d}.input.bin.gz"
                        and row["output_path"] == f"semantic/{cid:04d}.native-output.bin.gz",
                        "native semantic artifact path changed")
                semantic[cid] = row
            else:
                cid = row["case_id"]
                expected_id = f"original-case-{cid:04d}"
                require(row["run_id"] == expected_id
                        and row["input_path"] == f"publisher/{expected_id}.input.bin.gz"
                        and row["output_path"] == f"elf/{expected_id}.stdout.bin.gz",
                        "actual ELF publication identity or path changed")
                publishers.append(row)
            for key in ("input_path", "output_path"):
                owned(output, NATIVE_FOLDER + "/" + row[key])
    exact(list(semantic), list(range(90)), "all ninety ordered semantic cases are required")
    exact([row["case_id"] for row in publishers], list(PUBLISHER_CASES),
          "all five ordered successful ELF publications are required")
    return semantic, publishers


def compare_input_bytes(root, output, runner, semantic):
    """Read existing files only; regenerate framing, never expected semantics."""
    saved = owned(output, FOLDER + "/original-input.bin")
    metadata, pins, compared, cursor = [], [], 0, 16
    with saved.open("rb") as stream:
        require(stream.read(16) == runner.cases.INPUT_MAGIC + struct.pack("<Q", 90),
                "complete original input header changed")
        for case in runner.cases.iter_cases():
            cid = case["case_id"]
            row = semantic[cid]
            exact({key: row[key] for key in ("case_id", "name", "mode", "is_error")},
                  {key: case[key] for key in ("case_id", "name", "mode", "is_error")},
                  "native logical input identity changed")
            raw = runner.cases.encode_cases([case])
            record = raw[16:]
            require(stream.read(len(record)) == record, "complete original input differs from independent generator")
            input_path = owned(output, NATIVE_FOLDER + "/" + row["input_path"])
            with gzip.open(input_path, "rb") as native:
                at = 0
                while at < len(raw):
                    chunk = native.read(min(1 << 20, len(raw) - at))
                    require(bool(chunk) and chunk == raw[at:at + len(chunk)],
                            "captured native input differs from independent generator")
                    at += len(chunk)
                require(not native.read(1), "captured native input has trailing bytes")
            exact([row["prefix_bytes"], row["base_bytes"], row["hint_count"],
                   row["input_bytes"], row["input_sha256"]],
                  [len(case["prefix"]), len(case["base"]), len(case["hints"]), len(raw), sha(raw)],
                  "native input metadata differs from complete input")
            metadata.append({"case_id": cid, "name": case["name"], "mode": case["mode"],
                "is_error": case["is_error"], "offset": cursor, "record_bytes": len(record),
                "prefix_bytes": len(case["prefix"]), "base_bytes": len(case["base"]),
                "hint_count": len(case["hints"]), "hint_bytes": sum(map(len, case["hints"]))})
            pins.append({"case_id": cid, "path": row["input_path"], "gzip_sha256": file_sha(input_path),
                         "bytes": len(raw), "sha256": sha(raw)})
            compared += len(raw)
            cursor += len(record)
        require(not stream.read(1) and len(metadata) == 90, "complete original input domain changed")
    require(cursor == 69804253 and compared == 69805677, "independent original input extent changed")
    return {"cases": 90, "independent_input_bytes": cursor, "independent_input_sha256": file_sha(saved),
            "captured_input_bytes_compared": compared, "every_captured_input_byte_equal": True,
            "cases_metadata": metadata, "input_pins": pins}


def original_sources(root, output, runner):
    manifest, original, append = runner.sources.checked_original(root / ORACLE, root)
    require(manifest["commit"] == SOURCE_CHECK["source_commit"]
            and manifest["protocol_version"] == "2025-06-18", "original source baseline changed")
    exact(manifest["library_versions"], {"rmcp": "3.4.1", "serde_json": "1.0.151"},
          "original locked serializer versions changed")
    count = runner.sources.check_dependency_subset(owned(root, ORACLE + "/Cargo.lock").read_bytes(),
                                                  original["Cargo.lock"])
    require(type(count) is int and count == 73, "original dependency subset changed")
    for name in ("Cargo.toml", "Cargo.lock", "src/main.rs"):
        require(owned(output, FOLDER + "/crate/" + name).read_bytes()
                == owned(root, ORACLE + "/" + name).read_bytes(),
                "materialized original crate differs from current input")
    require(owned(output, FOLDER + "/crate/fixtures/original_append_hints.rs").read_bytes() == append
            and len(append) == 258 and sha(append) == "c43a6dd030543e4ff52f750a6f75bb63f782ee3d5d0906d3ae392e19703abdec",
            "materialized original append_hints body changed")


def tool_hash(value):
    require(type(value) is str and Path(value).is_absolute(), "reference tool path is not absolute text")
    path = Path(value).resolve(strict=True)
    require(stat.S_ISREG(path.stat().st_mode), "reference tool is not a regular file")
    return file_sha(path)


def check_bundle(root, output, report, completed):
    root, output = Path(root).resolve(strict=True), Path(output).resolve(strict=True)
    bundle = report.get("result_publication_reference")
    require(type(bundle) is dict and bundle.get("schema") == "hepta.runtime.result-publication-reference.v1",
            "fresh result-publication original reference is missing")
    require(set(bundle) == {"schema", "source_sha256", "artifact_sha256", "native_artifact_sha256",
                            "native_evidence_sha256", "native_builder_bundle", "result", "build"},
            "original-reference bundle fields changed")
    exact(bundle.get("source_sha256"), source_inputs(root), "original-reference current source inputs changed")
    for key, names in (("artifact_sha256", artifact_names()), ("native_artifact_sha256", native_artifact_names())):
        require(type(bundle.get(key)) is dict and set(bundle[key]) == set(names),
                "original-reference fixed artifact inventory changed")
        for relative, expected in bundle[key].items():
            digest_value(expected)
            require(file_sha(owned(output, relative)) == expected, "original-reference retained artifact changed")
    build = bundle.get("build")
    require(type(build) is dict and set(build) == {"cargo", "rustc", "cargo_sha256", "rustc_sha256",
            "executable", "executable_sha256", "build_environment_policy", "ignored_inherited_build_variables"},
            "fresh original Cargo build custody is missing or malformed")
    binary_name = FOLDER + "/cargo-target/debug/hepta-result-publication-original-oracle"
    binary = owned(output, binary_name)
    binary_sha = file_sha(binary)
    exact(build.get("executable"), binary_name, "original executable path changed")
    require(build.get("executable_sha256") == binary_sha
            and tool_hash(build.get("cargo")) == build.get("cargo_sha256")
            and tool_hash(build.get("rustc")) == build.get("rustc_sha256"),
            "current original toolchain or executable identity changed")
    with binary.open("rb") as stream:
        head = stream.read(20)
    require(len(head) == 20 and head[:6] == b"\x7fELF\x02\x01"
            and struct.unpack_from("<H", head, 18)[0] == 62 and binary.stat().st_mode & 0o111,
            "original replay artifact is not an executable x86-64 ELF")
    exact(build.get("build_environment_policy"), list(BUILD_VARIABLES), "original build environment policy changed")
    ignored = build.get("ignored_inherited_build_variables")
    require(type(ignored) is list and all(type(name) is str for name in ignored),
            "ignored original build environment variables are malformed")
    exact(ignored, [name for name in BUILD_VARIABLES if name in ignored],
          "unknown, duplicate or reordered ignored build variable")
    processes, elapsed = process_receipts(output, report, build)
    for name, digest in processes.items():
        require(bundle["artifact_sha256"][name] == digest, "raw process stream inventory differs")
    result = decode(owned(output, FOLDER + "/RESULT.json").read_bytes())
    exact(result, bundle.get("result"), "original-reference retained result changed")
    require(type(result) is dict, "original-reference result is not an object")
    finite(result.get("seconds"))
    require(result["seconds"] + 1e-6 >= elapsed,
            "original-reference total elapsed is shorter than its actual processes")
    runner = oracle(root)
    original_sources(root, output, runner)
    semantic, _ = corpus_rows(output)
    inputs = compare_input_bytes(root, output, runner, semantic)
    original_output = owned(output, FOLDER + "/original-output.bin")
    require(original_output.stat().st_size == 88907464, "complete original output extent changed")
    outputs = runner.compare_output(output / NATIVE_FOLDER, original_output, semantic)
    publications = runner.compare_publications(output / NATIVE_FOLDER, original_output, semantic)
    exact({key: outputs[key] for key in ("cases", "compared_body_bytes", "largest_body_bytes",
                                        "bodies_over_eight_mib", "every_output_byte_equal")},
          {"cases": 90, "compared_body_bytes": 88906008, "largest_body_bytes": 16777326,
           "bodies_over_eight_mib": 8, "every_output_byte_equal": True},
          "complete owner-to-original byte domain changed")
    exact({key: publications[key] for key in ("runs", "compared_stdout_bytes", "every_stdout_byte_equal")},
          {"runs": 5, "compared_stdout_bytes": 25543155, "every_stdout_byte_equal": True},
          "complete actual ELF-to-original byte domain changed")
    expected = {"schema": "hepta.runtime.result-publication.fresh-original-replay.v1", "status": "PASS",
        "seconds": result["seconds"], "fresh_locked_build": True, "top_level_subprocesses": 2,
        "source_check": SOURCE_CHECK, "original_summary": ORIGINAL_SUMMARY,
        "input_comparison": inputs, "output_comparison": outputs, "publisher_output_comparison": publications,
        "native_manifest_sha256": file_sha(owned(output, NATIVE_FOLDER + "/semantic-cases.jsonl")),
        "original_output_sha256": file_sha(original_output), "rust_executable_sha256": binary_sha,
        "driver_sha256": file_sha(owned(root, ORACLE + "/src/main.rs")),
        "cargo_lock_sha256": file_sha(owned(root, ORACLE + "/Cargo.lock")),
        "native_syscall_ack_suite_required_separately": True, "native_scheduler_qualified": False,
        "filesystem_callers_replaced": False, "unbounded_api_equivalence_proved_by_finite_tests": False}
    exact(result, expected, "original-reference complete recomputed comparison or scope changed")
    native = qualification_evidence(root, output, report, completed)
    require(bundle.get("native_evidence_sha256") == sha(encoded(native)), "bound native evidence identity changed")
    exact(bundle.get("native_builder_bundle"), report["modules"][COMPONENT],
          "bound current native builder identity changed")
    return bundle


def comparison_receipt(bundle):
    result = bundle["result"]
    return {"schema": "hepta.runtime.result-publication-original-comparison.v1", "status": "PASS",
        "component": COMPONENT, "comparison": result["output_comparison"],
        "publisher_comparison": result["publisher_output_comparison"], "independent_semantic_cases": 90,
        "fresh_original_processes": 2, "shared_fresh_reference": FOLDER + "/RESULT.json",
        "shared_fresh_reference_sha256": bundle["artifact_sha256"][FOLDER + "/RESULT.json"],
        "native_cases_added_by_corpus_replay": 0, "native_scheduler_qualified": False,
        "filesystem_callers_replaced": False, "whole_runtime_replaced": False}


def compare_original(root, output, report, rustc, cargo, *, completed, record_check, environment):
    root, output = Path(root).resolve(strict=True), Path(output).resolve(strict=True)
    if "result_publication_reference" not in report:
        native = qualification_evidence(root, output, report, completed)
        require(not any(row.get("name") in CHECKS for row in report["checks"]),
                "orphaned original-reference processes cannot be silently reused")
        env = dict(environment())
        ignored = [name for name in BUILD_VARIABLES if name in env]
        for name in BUILD_VARIABLES:
            env.pop(name, None)
        env["RUSTC"] = str(rustc)
        env["CARGO_NET_OFFLINE"] = "false"
        cargo_sha, rustc_sha = tool_hash(str(cargo)), tool_hash(str(rustc))
        pins, invoked = source_inputs(root), []
        native_builder = decode(encoded(report["modules"][COMPONENT]))

        def capture(**kwargs):
            require(len(invoked) < len(CHECKS) and kwargs.get("name") == CHECKS[len(invoked)],
                    "unexpected original-reference process order")
            name = kwargs["name"]
            command, timeout, _ = commands(output, str(cargo))[name]
            exact(kwargs.get("command"), command, "unexpected original-reference fixed invocation")
            require(type(kwargs.get("timeout")) is int and kwargs["timeout"] == timeout
                    and kwargs.get("input_bytes") is None,
                    "unexpected original-reference deadline or stdin")
            actual_env = kwargs.get("env")
            require(type(actual_env) is dict and actual_env.get("RUSTC") == str(rustc)
                    and actual_env.get("CARGO_NET_OFFLINE") == "false"
                    and actual_env.get("CARGO_BUILD_JOBS") == "2"
                    and not any(name in actual_env for name in BUILD_VARIABLES),
                    "original-reference effective build environment changed")
            process = record_check(output, report, **kwargs)
            require(isinstance(process, subprocess.CompletedProcess)
                    and type(process.returncode) is int and process.returncode == 0
                    and type(process.stdout) is bytes and type(process.stderr) is bytes,
                    "record_check did not return an actual successful byte process result")
            rows = [row for row in report["checks"] if row.get("name") == name]
            require(len(rows) == 1, "record_check did not retain exactly one original process")
            rows[0].update(stdin_bytes=0, stdin_sha256=sha(b""))
            invoked.append(name)
            return process

        runner = oracle(root)
        result = runner.run(SimpleNamespace(output=output / FOLDER, runtime_root=root, cargo=str(cargo),
            corpus=output / NATIVE_FOLDER, publisher_corpus=output / NATIVE_FOLDER, offline=False),
            execute_callback=capture, environment=env)
        exact(invoked, list(CHECKS), "original-reference process set changed")
        exact(source_inputs(root), pins, "original-reference sources changed during actual replay")
        exact(qualification_evidence(root, output, report, completed), native,
              "native publication evidence changed during original replay")
        require(tool_hash(str(cargo)) == cargo_sha and tool_hash(str(rustc)) == rustc_sha,
                "original toolchain changed during actual replay")
        executable = FOLDER + "/cargo-target/debug/hepta-result-publication-original-oracle"
        report["result_publication_reference"] = {
            "schema": "hepta.runtime.result-publication-reference.v1", "source_sha256": pins,
            "artifact_sha256": {name: file_sha(owned(output, name)) for name in artifact_names()},
            "native_artifact_sha256": {name: file_sha(owned(output, name)) for name in native_artifact_names()},
            "native_evidence_sha256": sha(encoded(native)), "native_builder_bundle": native_builder,
            "result": result, "build": {"cargo": str(cargo), "rustc": str(rustc),
                "cargo_sha256": cargo_sha, "rustc_sha256": rustc_sha, "executable": executable,
                "executable_sha256": file_sha(owned(output, executable)),
                "build_environment_policy": list(BUILD_VARIABLES),
                "ignored_inherited_build_variables": ignored}}
    return comparison_receipt(check_bundle(root, output, report, completed))


def check_original_receipts(root, output, report, completed):
    results = report.get("original_rust_comparisons", {})
    require(type(results) is dict, "original comparison recipe table is malformed")
    if COMPONENT not in results:
        require(report.get("result_publication_reference") is None
                and not any(row.get("name") in CHECKS for row in report.get("checks", [])),
                "original publication build has no completed recipe")
        return
    bundle = check_bundle(root, output, report, completed)
    exact(results[COMPONENT], comparison_receipt(bundle),
          "original publication recipe lost its complete current comparison")
