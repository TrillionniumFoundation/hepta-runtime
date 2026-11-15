"""Fresh original Rust/Tokio replay and complete request-scope evidence admission.

This reader reconstructs only ABI framing and observations. It launches no
additional processes and preserves the unclosed production lifecycle claims.
"""
from __future__ import annotations

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
import tomllib
from types import SimpleNamespace

ORACLE = "tests/hia_native/request_scope_oracle"
FOLDER = "request-scope-original"
NATIVE_FOLDER = "request-scope"
COMPONENT = "request_scope_lifecycle"
SOURCE_FILES = ("Cargo.toml", "Cargo.lock", "source_manifest.json", "src/main.rs",
                "run.py", "verify_sources.py", "replay.py", "README.md")
CHECKS = ("request-scope-rust-compile", "request-scope-rust-compare")
BUILD_VARIABLES = ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_TARGET",
                   "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER")
RUNS = ("await", "cancel", "interleaved", "leases", "many-leases", "preexisting-context",
        "private-admission", "process-0", "process-1", "publisher-handoff", "refusals",
        "short-output", "unbound")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
SOURCE_CHECK = {
    "original_function_bodies_unchanged": True, "current_complete_sources_match": True,
    "git_history_required": False, "original_commit": "2173a00ec314ebc0c5ada21e4cb60d8efdccb99a",
    "registry_dependency_count": 14, "original_dependency_lock_match": True,
}
COUNTS = {
    "native_rows": 8414, "native_only_refusals": 46, "existing_context_fixture_rows": 13,
    "original_context_accessors": 49, "original_cache_methods": 24,
    "original_arc_observations": 8221, "scope_and_cache_lifecycle_adapters": 45,
    "continuation_poll_observations": 16, "compared_owner_payload_bytes": 1448,
}
PROBES = {
    "actual_owned_forget_all_after_cancel": True, "actual_spawn_does_not_inherit": True,
    "actual_tokio_abort_join_cancelled": True, "actual_tokio_panic_join": True,
    "cancelled_hints_discarded": True, "final_weak_upgrade_none": True,
    "owned_worker_survives_request_cancel_and_session_drop": True,
    "worker_only_releases_own_arc": True, "stdio_async_writer_implemented": False,
}
COMPARISON = {
    "native_trace_groups": 12, "compared_observations": 8355,
    "actual_original_scoped_future_polls": 94, "all_semantic_observations_equal": True,
    "actual_tokio_probes": PROBES,
}



def require(condition, message):
    if not condition:
        raise ValueError(message)


def json_types(value):
    kind = type(value)
    require(kind in (dict, list, str, int, float, bool, type(None)),
            "request-scope original value is not a strict JSON type")
    if kind is dict:
        require(all(type(key) is str for key in value), "request-scope original JSON object key is not text")
        for item in value.values():
            json_types(item)
    elif kind is list:
        for item in value:
            json_types(item)
    elif kind is float:
        require(math.isfinite(value), "non-finite request-scope original JSON number")


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
        require(key not in result, "duplicate request-scope original evidence field")
        result[key] = value
    return result


def invalid_constant(value):
    raise ValueError("non-finite request-scope original JSON value: " + value)


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
            "request-scope original elapsed value is not a finite nonnegative number")
    if type(value) is float:
        require(math.isfinite(value), "request-scope original elapsed value is not finite")
    if limit is not None:
        require(value < limit, "request-scope original elapsed exceeded its fixed deadline")


def integer(value, minimum=0):
    require(type(value) is int and value >= minimum,
            "request-scope original integer field has the wrong type or range")


def digest_value(value):
    require(type(value) is str and SHA256.fullmatch(value) is not None,
            "request-scope original digest field is not a SHA256")


def owned(root, relative):
    require(type(relative) is str and bool(relative), "request-scope original artifact name is not text")
    name = Path(relative)
    require(not name.is_absolute() and ".." not in name.parts and name.as_posix() == relative,
            "request-scope original artifact is not an owned relative path")
    path = root / name
    require(path.resolve(strict=True) == path.absolute()
            and stat.S_ISREG(path.lstat().st_mode),
            "request-scope original artifact is not a regular unsymlinked file")
    return path


def tool_hash(value):
    require(type(value) is str and Path(value).is_absolute(), "reference tool path is not absolute text")
    path = Path(value).resolve(strict=True)
    require(stat.S_ISREG(path.stat().st_mode), "reference tool is not a regular file")
    return file_sha(path)


def oracle(root):
    name = "_hia_request_scope_original"
    for key in tuple(sys.modules):
        if key == name or key.startswith(name + "."):
            del sys.modules[key]
    path = root / ORACLE
    spec = importlib.util.spec_from_file_location(name, path / "run.py",
                                                submodule_search_locations=[str(path)])
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def qualification_evidence(root, output, report, completed):
    from hia_native_request_scope_qualification import qualification_evidence as native
    value = native(root, output, report, completed)
    exact(value, report.get("request_scope_evidence"), "native evidence identity changed")
    require(type(report.get("modules")) is dict
            and type(report["modules"].get(COMPONENT)) is dict
            and type(report.get("request_scope_composition")) is dict,
            "current native builder or composition bundle is missing")
    for key in ("builder", "manifest", "sha256"):
        exact(report["modules"][COMPONENT].get(key), report["request_scope_composition"].get(key),
              "module is not the executed private composition")
    return value


def source_inputs(root):
    manifest = decode(owned(root, ORACLE + "/source_manifest.json").read_bytes())
    require(type(manifest) is dict and type(manifest.get("files")) is dict,
            "original source manifest is malformed")
    exact(sorted(manifest["files"]), ["Cargo.lock", "src/mcp/fs/delta.rs", "src/mcp/request_ctx.rs"],
          "original compiled source input domain changed")
    paths = {ORACLE + "/" + name for name in SOURCE_FILES}
    paths.update(manifest["files"])
    paths.update(("scripts/hia_native_request_scope_reference.py",
                  "scripts/hia_native_request_scope_qualification.py"))
    return {name: file_sha(owned(root, name)) for name in sorted(paths)}


def commands(output, cargo):
    folder = output / FOLDER
    binary = folder / "cargo-target/debug/hepta-request-scope-original-oracle"
    return {
        CHECKS[0]: ([cargo, "build", "--locked", "--manifest-path", str(folder / "crate/Cargo.toml"),
                     "--target-dir", str(folder / "cargo-target")], 180, "build"),
        CHECKS[1]: ([str(binary)], 120, "original-replay"),
    }


def artifact_names():
    names = ["RESULT.json", "crate/Cargo.toml", "crate/Cargo.lock", "crate/src/main.rs",
             "crate/fixtures/original_request_ctx.rs", "crate/fixtures/original_view_cache.rs",
             "cargo-target/debug/hepta-request-scope-original-oracle", "original-input.jsonl",
             "original-output.jsonl", "native-boundaries-not-original.json"]
    names += [prefix + "." + suffix for prefix in ("build", "original-replay")
              for suffix in ("stdout", "stderr")]
    return ([FOLDER + "/" + name for name in names]
            + [name + "." + suffix for name in CHECKS for suffix in ("stdout", "stderr")])


def native_artifact_names():
    return [NATIVE_FOLDER + "/native-corpus.json"] + [
        NATIVE_FOLDER + "/" + name + "." + kind + ".gz"
        for name in RUNS for kind in ("domains", "expected", "input", "stderr", "stdout")]


def process_receipts(output, report, build):
    require(type(report.get("checks")) is list, "process records are missing")
    require(all(type(row) is dict for row in report["checks"]), "process record is not an object")
    observed = [row["name"] for row in report["checks"] if row.get("name") in CHECKS]
    exact(observed, list(CHECKS), "process order, presence or uniqueness changed")
    receipts, records = {}, []
    for name, (command, timeout, duplicate) in commands(output, build["cargo"]).items():
        row = next(item for item in report["checks"] if item.get("name") == name)
        exact(row.get("command"), command, "fixed process command changed")
        require(type(row.get("exit_code")) is int and row["exit_code"] == 0
                and row.get("timed_out") is False
                and ("start_error" not in row or row["start_error"] is None)
                and type(row.get("timeout_seconds")) is int and row["timeout_seconds"] == timeout,
                "process did not complete its fixed invocation")
        finite(row.get("elapsed_seconds"), limit=timeout)
        for suffix in ("stdout", "stderr"):
            raw = owned(output, name + "." + suffix).read_bytes()
            integer(row.get(suffix + "_bytes"))
            digest_value(row.get(suffix + "_sha256"))
            require(row[suffix + "_bytes"] == len(raw) and row[suffix + "_sha256"] == sha(raw)
                    and raw == owned(output, FOLDER + "/" + duplicate + "." + suffix).read_bytes(),
                    "complete raw process stream changed")
            receipts[name + "." + suffix] = sha(raw)
        raw_input = owned(output, FOLDER + "/original-input.jsonl").read_bytes() if name == CHECKS[1] else b""
        integer(row.get("stdin_bytes"))
        require(row["stdin_bytes"] == len(raw_input) and row.get("stdin_sha256") == sha(raw_input),
                "complete process stdin custody changed")
        if name == CHECKS[1]:
            require(owned(output, name + ".stderr").read_bytes() == b"", "original replay wrote stderr")
        records.append(row)
    return receipts, records


class MemoryOutputs:
    """Capture only framing writes without modifying retained evidence."""
    def __init__(self):
        self.files = {}

    def __truediv__(self, name):
        require(name in ("original-input.jsonl", "native-boundaries-not-original.json"),
                "driver attempted an unexpected readback write")
        parent = self

        class Sink:
            def write_bytes(self, raw):
                require(type(raw) is bytes and name not in parent.files, "duplicate framing write")
                parent.files[name] = raw
                return len(raw)

            def write_text(self, raw):
                require(type(raw) is str, "framing text is not text")
                self.write_bytes(raw.encode("utf-8"))
                return len(raw)

        return Sink()


def original_sources(root, output):
    manifest = decode(owned(root, ORACLE + "/source_manifest.json").read_bytes())
    require(manifest.get("schema") == "hepta.runtime.request-scope.original-source.v1"
            and manifest.get("commit") == SOURCE_CHECK["original_commit"], "original baseline changed")
    original = {}
    for name, pin in manifest["files"].items():
        raw = owned(root, name).read_bytes()
        integer(pin.get("bytes"))
        digest_value(pin.get("sha256"))
        require(len(raw) == pin["bytes"] and sha(raw) == pin["sha256"], "complete original source changed")
        original[name] = raw
    for name in ("Cargo.toml", "Cargo.lock", "src/main.rs"):
        require(owned(output, FOLDER + "/crate/" + name).read_bytes()
                == owned(root, ORACLE + "/" + name).read_bytes(), "materialized crate source changed")
    require(owned(output, FOLDER + "/crate/fixtures/original_request_ctx.rs").read_bytes()
            == original["src/mcp/request_ctx.rs"], "complete original request_ctx body changed")
    cache = owned(output, FOLDER + "/crate/fixtures/original_view_cache.rs").read_bytes()
    require(len(cache) == 1552
            and sha(cache) == "a88d9b0ed1077b67809de2d31db045372414f1aab2c767e09d0dbeef8d147d6d",
            "complete original ViewCache struct/impl changed")
    extraction = manifest.get("extractions", {}).get("ViewCache", {})
    exact({key: extraction.get(key) for key in ("source", "bytes", "sha256")},
          {"source": "src/mcp/fs/delta.rs", "bytes": len(cache), "sha256": sha(cache)},
          "original cache extraction pin changed")
    lock = tomllib.loads(original["Cargo.lock"].decode("utf-8"))
    subset = tomllib.loads(owned(root, ORACLE + "/Cargo.lock").read_text())
    pins = {(row["name"], row["version"]): (row.get("source"), row.get("checksum"))
            for row in lock["package"]}
    packages = [row for row in subset["package"] if "source" in row]
    require(len(packages) == 14 and len({(p["name"], p["version"]) for p in packages}) == 14,
            "original dependency subset count changed")
    for package in packages:
        require(pins.get((package["name"], package["version"]))
                == (package["source"], package["checksum"]), "locked original dependency changed")
    package_pins = {p["name"]: p["version"] for p in packages}
    require(package_pins.get("tokio") == "1.53.1" and package_pins.get("serde_json") == "1.0.151",
            "original Tokio or serializer version changed")


def semantic_readback(root, output, runner):
    framing = MemoryOutputs()
    raw, expected, counts, native_hash = runner.prepare(output / NATIVE_FOLDER, framing)
    exact(counts, COUNTS, "original and private-control domains changed")
    require(len(raw) == 418422 and len(expected) == 12, "complete original input extent or trace domain changed")
    exact(sorted(framing.files), ["native-boundaries-not-original.json", "original-input.jsonl"],
          "framing artifact inventory changed")
    for name, value in framing.files.items():
        require(owned(output, FOLDER + "/" + name).read_bytes() == value,
                "complete original input framing or excluded domain changed")
    original = owned(output, FOLDER + "/original-output.jsonl").read_bytes()
    require(len(original) == 500708 and original == owned(output, FOLDER + "/original-replay.stdout").read_bytes(),
            "complete original stdout partition changed")
    rows = [decode(line) for line in original.splitlines()]
    require(len(rows) == 13, "original result row domain changed")
    for row in rows[:-1]:
        require(type(row) is dict and set(row) == {"trace", "observations", "actual_scoped_future_polls",
                "final_cache_dropped", "all_outside_poll_access_absent"}, "original result fields changed")
    exact(rows[-1], {"probe": "actual-tokio-lifetime", "result": PROBES}, "actual Tokio lifetime probes changed")
    compared = runner.compare(original, expected)
    exact(compared, COMPARISON, "complete original lifetime observations changed")
    return raw, original, native_hash, counts, compared


def check_bundle(root, output, report, completed):
    root, output = Path(root).resolve(strict=True), Path(output).resolve(strict=True)
    bundle = report.get("request_scope_reference")
    require(type(bundle) is dict and bundle.get("schema") == "hepta.runtime.request-scope-reference.v1",
            "fresh reference is missing")
    require(set(bundle) == {"schema", "source_sha256", "artifact_sha256", "native_artifact_sha256",
                            "native_evidence_sha256", "native_builder_bundle", "native_composition_bundle",
                            "result", "build"}, "reference bundle fields changed")
    exact(bundle.get("source_sha256"), source_inputs(root), "current source inputs changed")
    for key, names in (("artifact_sha256", artifact_names()), ("native_artifact_sha256", native_artifact_names())):
        require(type(bundle.get(key)) is dict and set(bundle[key]) == set(names), "fixed artifact inventory changed")
        for relative, expected in bundle[key].items():
            digest_value(expected)
            require(file_sha(owned(output, relative)) == expected, "retained artifact changed")
    build = bundle.get("build")
    require(type(build) is dict and set(build) == {"cargo", "rustc", "cargo_sha256", "rustc_sha256",
            "executable", "executable_sha256", "build_environment_policy", "ignored_inherited_build_variables"},
            "build custody is missing or malformed")
    binary_name = FOLDER + "/cargo-target/debug/hepta-request-scope-original-oracle"
    binary = owned(output, binary_name)
    binary_hash = file_sha(binary)
    exact(build.get("executable"), binary_name, "executable artifact path changed")
    require(build.get("executable_sha256") == binary_hash
            and tool_hash(build.get("cargo")) == build.get("cargo_sha256")
            and tool_hash(build.get("rustc")) == build.get("rustc_sha256"),
            "current executable or toolchain identity changed")
    with binary.open("rb") as stream:
        head = stream.read(20)
    require(len(head) == 20 and head[:6] == b"\x7fELF\x02\x01"
            and struct.unpack_from("<H", head, 18)[0] == 62 and binary.stat().st_mode & 0o111,
            "original replay is not an executable x86-64 ELF")
    exact(build.get("build_environment_policy"), list(BUILD_VARIABLES), "build environment policy changed")
    ignored = build.get("ignored_inherited_build_variables")
    require(type(ignored) is list and all(type(name) is str for name in ignored), "ignored variables are malformed")
    exact(ignored, [name for name in BUILD_VARIABLES if name in ignored], "ignored variable order or domain changed")
    receipts, processes = process_receipts(output, report, build)
    for name, digest in receipts.items():
        require(bundle["artifact_sha256"][name] == digest, "process stream inventory changed")
    result = decode(owned(output, FOLDER + "/RESULT.json").read_bytes())
    exact(result, bundle.get("result"), "retained result changed")
    require(type(result) is dict and type(result.get("processes")) is list
            and len(result["processes"]) == 2, "nested process record inventory changed")
    process_keys = {"name", "command", "timeout_seconds", "elapsed_seconds", "exit_code",
                    "stdin_bytes", "stdin_sha256", "stdout_bytes", "stdout_sha256", "stderr_bytes", "stderr_sha256"}
    for inner, outer in zip(result["processes"], processes, strict=True):
        require(type(inner) is dict and set(inner) == process_keys, "nested process fields changed")
        finite(inner.get("elapsed_seconds"), limit=outer["timeout_seconds"])
        require(inner["elapsed_seconds"] + 1e-6 >= outer["elapsed_seconds"], "nested elapsed is shorter than actual process")
        exact({key: inner[key] for key in process_keys - {"elapsed_seconds"}},
              {key: outer[key] for key in process_keys - {"elapsed_seconds"}}, "nested process custody changed")
    runner = oracle(root)
    original_sources(root, output)
    raw, original, native_hash, counts, compared = semantic_readback(root, output, runner)
    expected_result = {"schema": "hepta.runtime.request-scope-original-comparison.v1", "status": "PASS",
        "source_check": SOURCE_CHECK, "harness_sources": {name: file_sha(owned(root, ORACLE + "/" + name))
                                                         for name in SOURCE_FILES},
        "native_corpus_sha256": native_hash, "input_bytes": len(raw), "input_sha256": sha(raw),
        "output_bytes": len(original), "output_sha256": sha(original), "binary_sha256": binary_hash,
        "processes": result["processes"], "counts": counts, "comparison": compared,
        "native_boundary_refusals_not_original_semantics": True, "private_generations_are_adapter_labels": True,
        "expected_semantic_payloads_supplied_to_rust": False, "production_dispatcher_installed": False,
        "unbounded_cache_storage_closed": False, "stdio_async_writer_implemented": False}
    exact(result, expected_result, "complete recomputed original comparison or scope changed")
    native = qualification_evidence(root, output, report, completed)
    require(bundle.get("native_evidence_sha256") == sha(encoded(native)), "bound native evidence changed")
    exact(bundle.get("native_builder_bundle"), report["modules"][COMPONENT], "bound native builder changed")
    exact(bundle.get("native_composition_bundle"), report["request_scope_composition"], "bound native composition changed")
    return bundle


def comparison_receipt(bundle):
    result = bundle["result"]
    return {"schema": "hepta.runtime.request-scope-original-recipe.v1", "status": "PASS",
        "component": COMPONENT, "comparison": result["comparison"], "counts": result["counts"],
        "fresh_original_processes": 2, "shared_fresh_reference": FOLDER + "/RESULT.json",
        "shared_fresh_reference_sha256": bundle["artifact_sha256"][FOLDER + "/RESULT.json"],
        "native_cases_added_by_corpus_replay": 0, "production_dispatcher_installed": False,
        "legacy_callers_replaced": False, "unbounded_cache_storage_closed": False,
        "stdio_async_writer_implemented": False, "whole_runtime_replaced": False}


def compare_original(root, output, report, rustc, cargo, *, completed, record_check, environment):
    root, output = Path(root).resolve(strict=True), Path(output).resolve(strict=True)
    if "request_scope_reference" not in report:
        native = qualification_evidence(root, output, report, completed)
        require(type(report.get("checks")) is list
                and not any(row.get("name") in CHECKS for row in report["checks"]),
                "orphaned reference processes cannot be silently reused")
        env = dict(environment())
        ignored = [name for name in BUILD_VARIABLES if name in env]
        for name in BUILD_VARIABLES:
            env.pop(name, None)
        env["RUSTC"] = str(rustc)
        env["CARGO_NET_OFFLINE"] = "false"
        cargo_sha, rustc_sha = tool_hash(str(cargo)), tool_hash(str(rustc))
        pins, invoked = source_inputs(root), []
        native_builder = decode(encoded(report["modules"][COMPONENT]))
        native_composition = decode(encoded(report["request_scope_composition"]))

        def capture(**kwargs):
            require(len(invoked) < len(CHECKS) and kwargs.get("name") == CHECKS[len(invoked)],
                    "unexpected reference process order")
            name = kwargs["name"]
            command, timeout, _ = commands(output, str(cargo))[name]
            exact(kwargs.get("command"), command, "unexpected fixed invocation")
            stdin = kwargs.get("input_bytes")
            wanted = owned(output, FOLDER + "/original-input.jsonl").read_bytes() if name == CHECKS[1] else None
            require(type(kwargs.get("timeout")) is int and kwargs["timeout"] == timeout
                    and type(stdin) is type(wanted) and stdin == wanted, "unexpected deadline or complete stdin")
            actual_env = kwargs.get("env")
            require(type(actual_env) is dict and actual_env.get("RUSTC") == str(rustc)
                    and actual_env.get("CARGO_NET_OFFLINE") == "false"
                    and actual_env.get("CARGO_BUILD_JOBS") == "2"
                    and not any(name in actual_env for name in BUILD_VARIABLES), "effective build environment changed")
            process = record_check(output, report, **kwargs)
            require(isinstance(process, subprocess.CompletedProcess)
                    and type(process.returncode) is int and process.returncode == 0
                    and type(process.stdout) is bytes and type(process.stderr) is bytes,
                    "record_check did not return an actual successful byte process")
            rows = [row for row in report["checks"] if row.get("name") == name]
            require(len(rows) == 1, "record_check did not retain exactly one process")
            rows[0].update(stdin_bytes=len(stdin or b""), stdin_sha256=sha(stdin or b""))
            invoked.append(name)
            return process

        runner = oracle(root)
        result = runner.run(SimpleNamespace(output=output / FOLDER, runtime_root=root,
            corpus=output / NATIVE_FOLDER, cargo=str(cargo), rustc=str(rustc), offline=False),
            execute_callback=capture, environment=env)
        exact(invoked, list(CHECKS), "reference process set changed")
        exact(source_inputs(root), pins, "sources changed during actual replay")
        exact(qualification_evidence(root, output, report, completed), native, "native evidence changed during original replay")
        require(tool_hash(str(cargo)) == cargo_sha and tool_hash(str(rustc)) == rustc_sha,
                "toolchain changed during actual replay")
        executable = FOLDER + "/cargo-target/debug/hepta-request-scope-original-oracle"
        report["request_scope_reference"] = {"schema": "hepta.runtime.request-scope-reference.v1",
            "source_sha256": pins, "artifact_sha256": {name: file_sha(owned(output, name)) for name in artifact_names()},
            "native_artifact_sha256": {name: file_sha(owned(output, name)) for name in native_artifact_names()},
            "native_evidence_sha256": sha(encoded(native)), "native_builder_bundle": native_builder,
            "native_composition_bundle": native_composition, "result": result,
            "build": {"cargo": str(cargo), "rustc": str(rustc), "cargo_sha256": cargo_sha,
                "rustc_sha256": rustc_sha, "executable": executable,
                "executable_sha256": file_sha(owned(output, executable)),
                "build_environment_policy": list(BUILD_VARIABLES), "ignored_inherited_build_variables": ignored}}
    return comparison_receipt(check_bundle(root, output, report, completed))


def check_original_receipts(root, output, report, completed):
    results = report.get("original_rust_comparisons", {})
    require(type(results) is dict, "recipe table is malformed")
    if COMPONENT not in results:
        require(report.get("request_scope_reference") is None
                and not any(row.get("name") in CHECKS for row in report.get("checks", [])),
                "reference build has no completed recipe")
        return
    bundle = check_bundle(root, output, report, completed)
    exact(results[COMPONENT], comparison_receipt(bundle), "recipe lost its complete current comparison")
