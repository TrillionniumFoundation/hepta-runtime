#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Archive the fixed completed hash experiment; never compile, run, or retry it."""
import gzip
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import statistics
import sys
import tarfile
import tomllib


HOME_DIR = Path.home()
BASE = HOME_DIR / "hepta-runtime-optimization-20261023"
QUALIFIED_TARGET = HOME_DIR / ".local/state/hepta-runtime-native-dev-20261018/target-v61-diagnostic-a1"
OUTPUT = BASE / "publication-a26-r01" / "hash-probe-r02"
DIRECTORIES = {
    "bundle-r01": BASE / "a26-hash-probe-bundle-r01",
    "bundle-r02": BASE / "a26-hash-probe-bundle-r02",
    "build-r01": BASE / "a26-hash-probe-build-r01",
    "build-r02": BASE / "a26-hash-probe-build-r02",
    "run-r02": BASE / "a26-hash-probe-run-r02",
}
EXPECTED = {
    "bundle-r01": "5a4a7e8708438dc9ce106d09bf71e51b395265a25e054c1efc18e8951bcde988",
    "bundle-r02": "f5e0ae8d16e2f5d7243711d6e5079dbb6ffde38664202ea7b5c19c124226916b",
    "analysis": "a45ee6d07851ac84ffd6f876b694c71193382a517b4a5fc4761806630cbf25e7",
    "raw": "57866af3fe8a6ab8941d84bbe312cbe5ce4e06bff69212965c9f0188ef8a7c60",
    "r01-compile-stderr": "deca339d1a6ec8e37ff76239e849897832f59d6682077b8930fb2858c81b5dca",
    "plan": "55013928e7d7df87c0dd0944ba57ba5a56abe3ab226f89452b89c087cf96ee6e",
    "input-source": "d0ab0e319c39e9a56a75767f9d7d1aa1fed9ad7431221321149b7f10904ea767",
    "analyzer": "a3a753c4061dd6c95736692bbdd7a9441dc9971655aa44612ac0261726db64e8",
    "target": "fc47ea24323fdd5687c5aefae6fd0060faabfa8f2944c6a68f6a442fbe0dd131",
}
COMMON_FILES = {"PLAN.json", "PLAN.md", "hash_buffer_probe.rs", "prepare_hash_probe.py",
                "run_hash_probe.py", "summarize_hash_probe.py", "test_analysis.py"}
BUILD_TEXT_FILES = ("build.json", "PLAN.json", "PLAN.md", "hash_buffer_probe.input.rs",
                    "hash_buffer_probe.rs", "rustc-version.log", "format.stdout.log",
                    "format.stderr.log", "compile.stdout.log", "compile.stderr.log")
RUN_FILES = ("run-start.json", "run.json", "analysis.json", "raw.jsonl", "stderr.log")
LIMIT = 32 * 1024 * 1024


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def git_blob_sha1(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                       allow_nan=False) + "\n").encode()


def need(value, message):
    if not value:
        raise ValueError(message)


def unique(pairs):
    out = {}
    for key, value in pairs:
        need(key not in out, "duplicate JSON key")
        out[key] = value
    return out


def decode(raw):
    def reject(value):
        raise ValueError("non-finite JSON number: " + value)
    return json.loads(raw, object_pairs_hook=unique, parse_constant=reject)


def stamp(value):
    return [value.st_dev, value.st_ino, value.st_uid, value.st_mode, value.st_nlink,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns]


def permitted(path):
    return (path == Path("/usr/bin/ssh") or path.is_relative_to(BASE)
            or path.is_relative_to(QUALIFIED_TARGET)
            or path.is_relative_to(HOME_DIR / ".rustup/toolchains")
            or path.is_relative_to(HOME_DIR / ".cargo/registry/src"))


class Inputs:
    def __init__(self):
        self.files = {}
        self.payloads = {}
        self.checks = {}

    def check(self, label, value):
        need(label not in self.checks, "duplicate validation label")
        self.checks[label] = bool(value)
        return bool(value)

    def read(self, path, retain=False):
        path = Path(path)
        need(path.is_absolute() and permitted(path) and path == path.resolve(),
             "input outside fixed evidence/compiler roots or through a symlink")
        name = str(path)
        if name in self.files and (not retain or name in self.payloads):
            return self.files[name], self.payloads.get(name)
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        digest, chunks, size = hashlib.sha256(), [], 0
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            need(stat.S_ISREG(before.st_mode), "nonregular input")
            while block := stream.read(65536):
                digest.update(block)
                size += len(block)
                need(size <= before.st_size, "input grew during complete read")
                if retain:
                    need(size <= LIMIT, "retained input exceeds bound; no truncation allowed")
                    chunks.append(block)
            need(stamp(before) == stamp(os.fstat(stream.fileno())) == stamp(path.lstat())
                 and size == before.st_size, "input changed during complete read")
        item = {"path": name, "bytes": size, "sha256": digest.hexdigest(), "stamp": stamp(before)}
        if name in self.files:
            need(self.files[name] == item, "input changed between evidence reads")
        self.files[name] = item
        if retain:
            self.payloads[name] = b"".join(chunks)
        return item, self.payloads.get(name)

    def json(self, path):
        _item, raw = self.read(path, True)
        value = decode(raw)
        need(isinstance(value, dict), "JSON object required")
        return value

    def declared(self, label, value, expected_path=None):
        need(isinstance(value, dict) and isinstance(value.get("path"), str), "invalid file receipt")
        path = Path(value["path"])
        if expected_path is not None:
            self.check(label + ":path", path == expected_path)
            need(path == expected_path, "receipt path differs from fixed artifact")
        actual, _raw = self.read(path)
        self.check(label + ":content", all(value.get(key) == actual[key] for key in ("sha256", "bytes", "stamp")))
        return actual

    def declared_map(self, label, values, before_format=None, original_source=None):
        need(isinstance(values, dict) and values, "nonempty declared input map required")
        for index, (path, value) in enumerate(sorted(values.items())):
            self.check(label + ":key:" + str(index), isinstance(value, dict) and value.get("path") == path)
            if before_format is not None and path == str(before_format):
                self.check(label + ":preformat_source", all(value.get(key) == original_source.get(key)
                           for key in ("bytes", "sha256")))
            else:
                self.declared(label + ":input:" + str(index), value, Path(path))

    def final_stamps(self):
        for index, (path, value) in enumerate(sorted(self.files.items())):
            self.check("archive_input_unchanged:" + str(index), stamp(Path(path).lstat()) == value["stamp"])


class Sanitizer:
    """Keep every field, line and list item; redact private values in place."""
    # Keep the source's pattern literal from resembling an actual private path.
    private_path = re.compile(r"/(?:home|Users|root|tmp|var" + "/" + r"tmp|private|run/user|workspace)(?:/[^\s\"'<>;,}\])]+)?")
    address = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
    ipv6 = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f:.]*(?:%[\w.-]+)?(?![\w:])")
    private_keys = {"pid", "ppid", "parent_pid", "child_pid", "controller_pid", "owner_pid",
                    "birth", "birth_ticks", "start_ticks", "uid", "gid", "dev", "ino",
                    "username", "user", "token", "access_token", "refresh_token", "password",
                    "private_key", "ssh_auth_sock", "ssh_target", "controller_hostname"}

    def __init__(self, values):
        serialized = json.dumps(values, ensure_ascii=False)
        self.users = set(re.findall(r"/(?:home|Users)/([^/\s\"'\\]+)", serialized))

    @staticmethod
    def opaque(value):
        raw = canonical(value)
        return {"redacted": True, "canonical_value_sha256": sha(raw), "canonical_value_bytes": len(raw)}

    def string(self, value):
        if re.fullmatch("[0-9a-f]{64}", value):
            return value
        value = re.sub(r"/proc/\d+(?=/|\b)", "/proc/<pid>", value)
        value = self.private_path.sub(lambda match: "<private-path:" + sha(match[0].encode())[:12] + ">", value)
        value = self.address.sub("<network-address>", value)
        def address(match):
            try:
                ipaddress.IPv6Address(match[0].split("%", 1)[0])
                return "<network-address>"
            except ValueError:
                return match[0]
        value = self.ipv6.sub(address, value)
        value = re.sub(r"\b[\w.-]+@(?:[\w.-]+\b|\[[^\]]+\])", "<ssh-target>", value)
        value = re.sub(r"(?:ssh-(?:ed25519|rsa)|ecdsa-sha2-\S+)\s+[A-Za-z0-9+/=]+", "<ssh-key-redacted>", value)
        for user in sorted(self.users, key=len, reverse=True):
            value = re.sub(r"(?<![\w.-])" + re.escape(user) + r"(?![\w.-])", "<user>", value)
        return value

    def __call__(self, value):
        if isinstance(value, list):
            return [self(item) for item in value]
        if isinstance(value, dict):
            out = {}
            for key, item in value.items():
                public = self.string(key)
                need(public not in out, "sanitized key collision")
                if key.lower() in self.private_keys:
                    out[public] = self.opaque(item)
                elif key == "stamp" and isinstance(item, list) and len(item) == 8:
                    out[public] = [self.opaque(v) if i < 3 else self(v) for i, v in enumerate(item)]
                else:
                    out[public] = self(item)
            return out
        return self.string(value) if isinstance(value, str) else value


def gzip_bytes(raw):
    stream = io.BytesIO()
    with gzip.GzipFile(fileobj=stream, mode="wb", filename="", mtime=0, compresslevel=9) as output:
        output.write(raw)
    data = stream.getvalue()
    need(gzip.decompress(data) == raw, "gzip roundtrip differs")
    return data


def verify_bundle(inputs, label):
    root = DIRECTORIES[label]
    manifest = inputs.json(root / "SHA256.json")
    inputs.check(label + ":frozen_manifest", inputs.files[str(root / "SHA256.json")]["sha256"] == EXPECTED[label])
    expected = COMMON_FILES | ({"FAILED_ATTEMPT.md"} if label == "bundle-r02" else set())
    need(set(manifest.get("files", {})) == expected, "frozen bundle file set differs")
    for name in sorted(expected):
        item, _raw = inputs.read(root / name, True)
        declared = manifest["files"][name]
        inputs.check(label + ":file:" + name, all(item[key] == declared.get(key) for key in ("sha256", "bytes")))
    inputs.check(label + ":plan", manifest["files"]["PLAN.json"]["sha256"] == EXPECTED["plan"])
    inputs.check(label + ":measurement_source", manifest["files"]["hash_buffer_probe.rs"]["sha256"] == EXPECTED["input-source"])
    inputs.check(label + ":analyzer", manifest["files"]["summarize_hash_probe.py"]["sha256"] == EXPECTED["analyzer"])
    return manifest


def verify_build(inputs, label, bundle):
    root = DIRECTORIES[label]
    for name in BUILD_TEXT_FILES:
        inputs.read(root / name, True)
    value = inputs.json(root / "build.json")
    success = label == "build-r02"
    inputs.check(label + ":schema", value.get("schema") == "hepta-x230-full-file-hash-microprobe-build/v1")
    inputs.check(label + ":state", value.get("prepared") is True and value.get("compiled") is success
                 and value.get("compile_requested") is True and value.get("probe_executed") is False
                 and value.get("format_returncode") == 0 and value.get("compile_returncode") == (0 if success else 1)
                 and value.get("automatic_retries") == 0 and value.get("dependency_downloads") == 0
                 and ("error" not in value if success else isinstance(value.get("error"), dict)))
    source = root / "hash_buffer_probe.rs"
    original = inputs.declared(label + ":source_input", value["source_input"], root / "hash_buffer_probe.input.rs")
    inputs.check(label + ":same_measurement_source", original["sha256"] == EXPECTED["input-source"])
    inputs.check(label + ":source_before_format", value["source_before_format"].get("path") == str(source)
                 and all(value["source_before_format"].get(key) == original[key] for key in ("bytes", "sha256")))
    for key in ("source_after_format", "source_to_publish"):
        inputs.declared(label + ":" + key, value[key], source)
    inputs.declared_map(label + ":inputs_before_format", value["inputs_before_format"], source, original)
    inputs.declared_map(label + ":inputs_before", value["inputs_before"])
    inputs.check(label + ":formatted_input_binding", value["inputs_before"].get(str(source)) == value["source_to_publish"])
    if success:
        inputs.check(label + ":build_inputs_unchanged", value["inputs_before"] == value.get("inputs_after"))
        inputs.declared_map(label + ":inputs_after", value["inputs_after"])
        inputs.declared(label + ":binary", value["probe_binary"], root / "hash-buffer-probe")
    else:
        inputs.check(label + ":failed_build_has_no_after_or_binary_claim", "inputs_after" not in value
                     and "probe_binary" not in value and not (root / "hash-buffer-probe").exists())
        inputs.check(label + ":known_failure_log", inputs.files[str(root / "compile.stderr.log")]["sha256"]
                     == EXPECTED["r01-compile-stderr"])
    for group in ("format_logs", "compile_logs"):
        expected_logs = {"format.stdout.log", "format.stderr.log"} if group == "format_logs" else {
            "rustc-version.log", "compile.stdout.log", "compile.stderr.log"}
        need(set(value[group]) == expected_logs, "complete compiler/formatter log receipts required")
        for name, declared in value[group].items():
            inputs.declared(label + ":log:" + name, declared, root / name)
    for name in ("PLAN.json", "PLAN.md"):
        inputs.check(label + ":frozen_copy:" + name,
                     inputs.files[str(root / name)]["sha256"] == bundle["files"][name]["sha256"])
    for key in ("qualification", "independent_receipt", "qualified_runtime_binary", "rustfmt_config"):
        inputs.declared(label + ":" + key, value[key])
    qualification_path = Path(value["qualification"]["path"])
    independent_path = Path(value["independent_receipt"]["path"])
    need(qualification_path.is_relative_to(BASE) and independent_path.is_relative_to(BASE), "qualification outside fixed development root")
    qualification, independent = inputs.json(qualification_path), inputs.json(independent_path)
    inputs.check(label + ":qualified_provenance", qualification.get("schema") == "runtime-candidate-qualification/v1"
                 and qualification.get("qualified") is True and qualification.get("current_stage") == "complete"
                 and qualification.get("source_tested") == qualification.get("source_after")
                 and independent.get("schema") == "hepta-x230-qualification-independent-receipt/v1"
                 and independent.get("candidate") == "A26" and independent.get("qualified") is True
                 and independent.get("unmet_checks") == []
                 and independent.get("source_report_sha256") == value["qualification"]["sha256"])
    source_root = Path(qualification["source"])
    need(source_root.is_relative_to(BASE) and source_root.parent == BASE, "unexpected qualified source root")
    inputs.check(label + ":source_map", value["qualification_source_map_sha256"] == sha(
        json.dumps(qualification["source_after"], sort_keys=True, separators=(",", ":")).encode()))
    for name in ("Cargo.toml", "Cargo.lock", "rustfmt.toml", "src/mcp/runtime/ssh_observation_profile.rs"):
        item, _raw = inputs.read(source_root / name, True)
        inputs.check(label + ":qualified_source:" + name, item["sha256"] == qualification["source_after"].get(name))
    release_rows = [row for row in qualification["stages"] if row.get("name") == "release"]
    need(len(release_rows) == 1, "unique qualification release stage required")
    release_file = qualification_path.parent / "release.log"
    release_receipt, release_raw = inputs.read(release_file, True)
    inputs.check(label + ":release_log", release_rows[0].get("returncode") == 0
                 and release_rows[0].get("log_sha256") == release_receipt["sha256"])
    compiler_records = []
    for line in release_raw.splitlines():
        try:
            row = decode(line)
        except ValueError:
            continue
        if isinstance(row, dict):
            compiler_records.append(row)
    dependency_dir = Path(value["dependencies"]["ring"]["rlib"]["path"]).parent
    release_rlibs = {name for row in compiler_records if row.get("reason") == "compiler-artifact"
                     for name in row.get("filenames", [])
                     if Path(name).suffix == ".rlib" and Path(name).parent == dependency_dir}
    inputs.check(label + ":all_recorded_rlibs_bound", bool(release_rlibs) and release_rlibs == {
        name for name in value["inputs_before"] if Path(name).suffix == ".rlib"})
    runtime_records = [row for row in compiler_records if row.get("reason") == "compiler-artifact"
                       and row.get("target", {}).get("name") == "hepta-runtime"
                       and row.get("profile", {}).get("test") is False]
    need(len(runtime_records) == 1, "unique runtime compiler artifact required")
    runtime_record = runtime_records[0]
    runtime_binary, _raw = inputs.read(Path(runtime_record["executable"]))
    inputs.check(label + ":runtime_artifact_link", runtime_record.get("manifest_path") == str(source_root / "Cargo.toml")
                 and runtime_record.get("target", {}).get("src_path") == str(source_root / "src/main.rs")
                 and runtime_binary["sha256"] == value["qualified_runtime_binary"]["sha256"]
                 == qualification["binary"]["sha256"]
                 and qualification["binary"]["path"] == value["qualified_runtime_binary"]["path"])
    locked = tomllib.loads(inputs.payloads[str(source_root / "Cargo.lock")].decode())
    for name in ("ring", "libc"):
        dependency = value["dependencies"][name]
        inputs.check(label + ":artifact:" + name, dependency["compiler_artifact"] in compiler_records
                     and dependency["compiler_artifact"].get("reason") == "compiler-artifact"
                     and dependency["compiler_artifact"].get("target", {}).get("name") == name
                     and dependency["compiler_artifact"].get("profile", {}).get("test") is False
                     and dependency["rlib"]["path"] in dependency["compiler_artifact"].get("filenames", []))
        inputs.declared(label + ":rlib:" + name, dependency["rlib"])
        inputs.declared(label + ":manifest:" + name, dependency["manifest"])
        _item, manifest_raw = inputs.read(Path(dependency["manifest"]["path"]), True)
        package = tomllib.loads(manifest_raw.decode())["package"]
        inputs.check(label + ":locked_dependency:" + name, package.get("name") == name
                     and package.get("version") == dependency.get("version")
                     and dependency.get("lock_package") in locked["package"]
                     and dependency["lock_package"].get("name") == name
                     and dependency["lock_package"].get("version") == package.get("version")
                     and dependency["compiler_artifact"].get("package_id") == dependency.get("package_id"))
    native_paths, native_archives = set(), set()
    for record in compiler_records:
        if record.get("reason") != "build-script-executed" or record.get("package_id") != value["dependencies"]["ring"]["package_id"]:
            continue
        paths = [Path(path.removeprefix("native=")) for path in record.get("linked_paths", [])]
        native_paths.update(str(path) for path in paths)
        for library in record.get("linked_libs", []):
            need(library.startswith("static="), "unexpected native library kind")
            matches = [path / ("lib" + library.removeprefix("static=") + ".a") for path in paths
                       if (path / ("lib" + library.removeprefix("static=") + ".a")).is_file()]
            need(len(matches) == 1, "native archive does not have a unique recorded path")
            native_archives.add(str(matches[0]))
    inputs.check(label + ":native_artifacts_bound", value["native_search_paths"] == sorted(native_paths)
                 and native_archives == {name for name in value["inputs_before"] if Path(name).suffix == ".a"})
    command = value["compile_command"]
    expected_command = [command[0], "--edition=2021", "--crate-name", "hepta_hash_buffer_probe",
                        "-C", "opt-level=3", "-C", "debuginfo=0"]
    if success:
        expected_command += ["-C", "panic=abort"]
    expected_command += [str(source), "--extern", "ring=" + value["dependencies"]["ring"]["rlib"]["path"],
                         "--extern", "libc=" + value["dependencies"]["libc"]["rlib"]["path"],
                         "-L", "dependency=" + str(dependency_dir)]
    for path in value["native_search_paths"]:
        expected_command += ["-L", "native=" + path]
    expected_command += ["-o", str(root / "hash-buffer-probe")]
    inputs.check(label + ":exact_compiler_command", command == expected_command and command[0] in value["inputs_before"]
                 and value.get("qualified_toolchain") == "1.95.0")
    inputs.check(label + ":exact_formatter_command", value["format_command"] == [
        str(Path(command[0]).with_name("rustfmt")), "--edition", "2021", "--config-path",
        str(source_root / "rustfmt.toml"), str(source)])
    if success:
        inputs.declared(label + ":qualified_cargo_manifest", value["qualified_cargo_manifest"], source_root / "Cargo.toml")
        cargo = tomllib.loads(inputs.payloads[str(source_root / "Cargo.toml")].decode())
        inputs.check(label + ":panic_abi", value.get("qualified_release_panic_strategy") == "abort"
                     and cargo.get("profile", {}).get("release", {}).get("panic") == "abort"
                     and str(source_root / "Cargo.toml") in value["inputs_before"])
    return value


def verify_run(inputs, build):
    root = DIRECTORIES["run-r02"]
    for name in RUN_FILES:
        inputs.read(root / name, True)
    run, start, recorded = (inputs.json(root / name) for name in ("run.json", "run-start.json", "analysis.json"))
    raw = inputs.payloads[str(root / "raw.jsonl")]
    inputs.check("run:actual_raw_pin", len(raw) == 2741098 and sha(raw) == EXPECTED["raw"])
    inputs.check("run:actual_analysis_pin", inputs.files[str(root / "analysis.json")]["sha256"] == EXPECTED["analysis"])
    inputs.check("run:exact_single_successful_execution", run.get("schema") == "hepta-x230-full-file-hash-microprobe-run/v1"
                 and run.get("passed") is True and run.get("probe_launches") == 1 and run.get("probe_returncode") == 0
                 and run.get("automatic_retries") == 0 and run.get("interrupted") is False
                 and run.get("sigint_forwarded") is False and run.get("eligible_for_separate_runtime_candidate") is False
                 and all(key not in run for key in ("error", "collection_error", "signal_error")))
    inputs.check("run:prelaunch_record_linked", start.get("probe_launches") == 0 and start.get("passed") is False
                 and all(run.get(key) == value for key, value in start.items() if key not in ("probe_launches", "passed")))
    inputs.declared("run:build", run["build"], DIRECTORIES["build-r02"] / "build.json")
    inputs.check("run:all_build_inputs_unchanged", run["build_inputs_before_run"] == build["inputs_after"]
                 == run["build_inputs_after_run"])
    inputs.declared_map("run:inputs_before", run["build_inputs_before_run"])
    inputs.declared_map("run:inputs_after", run["build_inputs_after_run"])
    for key in ("probe_binary_before", "probe_binary_after"):
        inputs.check("run:" + key + ":build_link", run[key] == build["probe_binary"])
        inputs.declared("run:" + key, run[key], DIRECTORIES["build-r02"] / "hash-buffer-probe")
    inputs.check("run:fixed_target_unchanged", run["target_before"] == run["target_after"]
                 and run["target_before"]["sha256"] == EXPECTED["target"])
    for key in ("target_before", "target_after"):
        inputs.declared("run:" + key, run[key], Path("/usr/bin/ssh"))
    for key, name in (("raw", "raw.jsonl"), ("analysis", "analysis.json"), ("stderr", "stderr.log")):
        inputs.declared("run:" + key, run[key], root / name)
    for key, name in (("runner", "run_hash_probe.py"), ("analyzer", "summarize_hash_probe.py")):
        inputs.declared("run:" + key, run[key], DIRECTORIES["bundle-r02"] / name)
    inputs.check("run:chronology", type(run.get("finished_unix")) in (float, int)
                 and type(run.get("started_unix")) in (float, int) and run["finished_unix"] >= run["started_unix"])
    rows = [decode(line) for line in raw.splitlines()]
    recomputed = summarize(raw, run["probe_returncode"], run["target_before"]["sha256"])
    inputs.check("run:all_iterations_recomputed", recomputed == recorded
                 and recomputed.get("valid_complete_experiment") is True and recomputed.get("errors") == [])
    target = run["target_before"]["stamp"]
    target_stamp = dict(dev=target[0], ino=target[1], uid=target[2], mode=target[3], nlink=target[4], len=target[5],
                        mtime=list(divmod(target[6], 1_000_000_000)), ctime=list(divmod(target[7], 1_000_000_000)))
    inputs.check("run:independent_target_stamp", len(rows) == 37 and rows[1].get("stamp") == target_stamp)
    inputs.check("run:predeclared_keep_16KiB", recomputed.get("eligible_for_separate_runtime_candidate") is False
                 and recomputed.get("decision") == "keep the current 16 KiB buffer"
                 and recomputed.get("gates") == {"median_cpu_improvement_at_least_3_percent": False,
                     "at_least_7_blocks_cpu_improve": False,
                     "median_cpu_improvement_strictly_exceeds_2_MAD": False,
                     "median_wall_regression_at_most_2_percent": True})
    return run, start, recorded, recomputed, rows


# The original frozen analyzer's HEADER, integer(), and summarize() are inserted
# below verbatim at preparation time. No remote code is imported or executed.
HEADER = {
    "event": "plan", "schema": "hepta-x230-full-file-hash-microprobe/v1",
    "target": "/usr/bin/ssh", "maximum_file_bytes": 16777216,
    "variants": {"A": 16384, "B": 65536}, "reference_reads": 1,
    "warmup_order": "AB", "warmup_iterations_per_cell": 8, "blocks": 8,
    "order_per_block": "ABBA", "iterations_per_cell": 128,
    "measured_cells": 32, "measured_full_file_hashes": 4096,
}


def integer(value, minimum=0):
    return type(value) is int and value >= minimum


def summarize(raw, exit_code, expected_sha256):
    out = {"schema": "hepta-x230-full-file-hash-microprobe-analysis/v1",
           "raw_jsonl_sha256": hashlib.sha256(raw).hexdigest(), "raw_jsonl_bytes": len(raw),
           "process_exit_code": exit_code, "expected_target_sha256": expected_sha256,
           "valid_complete_experiment": False, "eligible_for_separate_runtime_candidate": False,
           "runtime_performance_conclusion": None, "decision": "no decision: incomplete or invalid experiment",
           "errors": [], "blocks": [], "no_success_filtering": True}
    errors, records = out["errors"], []

    def check(value, message):
        if not value:
            errors.append(message)
        return bool(value)

    check(type(exit_code) is int and exit_code == 0, "probe did not exit successfully")
    check(isinstance(expected_sha256, str) and re.fullmatch("[0-9a-f]{64}", expected_sha256) is not None,
          "independent complete-file SHA256 is missing")
    for number, line in enumerate(raw.splitlines(), 1):
        try:
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError("object expected")
            records.append(row)
        except (ValueError, UnicodeError) as error:
            errors.append("JSONL line " + str(number) + ": " + str(error))
    out["parsed_event_count"] = len(records)
    out["failure_events"] = [row for row in records if row.get("event") == "failure"]
    out["observed_cells"] = [{key: row.get(key) for key in
        ("phase", "block", "slot", "ordinal", "requested_iterations", "completed_iterations", "passed")}
        for row in records if row.get("event") == "cell"]
    expected_events = ["plan", "reference", *(["cell"] * 34), "complete"]
    check([row.get("event") for row in records] == expected_events,
          "event sequence is not exactly reference, two warmup cells, 32 measured cells, completion")
    if len(records) != len(expected_events):
        return out
    check(records[0] == HEADER, "fixed probe plan differs")
    reference = records[1]
    pin = reference.get("stamp")
    digest = reference.get("sha256")
    check(reference.get("event") == "reference" and digest == expected_sha256,
          "reference digest differs from independent target hash")
    check(isinstance(pin, dict) and set(pin) == {"dev", "ino", "uid", "mode", "nlink", "len", "mtime", "ctime"},
          "reference stamp is incomplete")
    if not isinstance(pin, dict):
        return out
    check(integer(pin.get("len"), 1) and pin["len"] <= 16777216
          and reference.get("bytes") == pin["len"], "reference byte bound or complete length differs")
    check(pin.get("uid") == 0 and pin.get("nlink") == 1 and integer(pin.get("mode"))
          and pin["mode"] & 0o6022 == 0 and pin["mode"] & 0o111 != 0, "reference inode policy differs")
    cells = records[2:-1]
    for offset, cell in enumerate(cells):
        warmup = offset < 2
        ordinal = offset if warmup else offset - 2
        block = None if warmup else ordinal // 4
        slot = "AB"[ordinal] if warmup else "ABBA"[ordinal % 4]
        count = 8 if warmup else 128
        label = ("warmup " if warmup else "measured ") + str(ordinal)
        check(cell.get("event") == "cell" and cell.get("phase") == ("warmup" if warmup else "measured")
              and cell.get("ordinal") == ordinal and cell.get("block") == block and cell.get("slot") == slot
              and cell.get("buffer_bytes") == HEADER["variants"][slot], label + " identity or order differs")
        check(cell.get("requested_iterations") == count and cell.get("completed_iterations") == count
              and cell.get("passed") is True, label + " did not complete all iterations")
        iterations = cell.get("iterations")
        if not check(isinstance(iterations, list) and len(iterations) == count, label + " iteration set differs"):
            continue
        cpu_values, wall_values = [], []
        for index, iteration in enumerate(iterations):
            if not check(isinstance(iteration, dict), label + " invalid iteration"):
                continue
            prefix = label + " iteration " + str(index)
            check(iteration.get("index") == index and iteration.get("verified") is True
                  and iteration.get("failure") is None, prefix + " failed or wrong index")
            check(all(iteration.get(key) == pin for key in ("before_fd", "after_fd", "after_path")),
                  prefix + " original fd/path stamp changed")
            read = iteration.get("read")
            check(isinstance(read, dict) and read.get("bytes") == pin.get("len")
                  and read.get("sha256") == digest and read.get("failure") is None
                  and integer(read.get("read_calls"), 1) and integer(read.get("interrupted_reads"))
                  and read["interrupted_reads"] < read["read_calls"], prefix + " complete read/hash differs")
            cpu, wall = iteration.get("read_hash_thread_cpu_ns"), iteration.get("read_hash_wall_ns")
            if check(integer(cpu, 1) and integer(wall, 1), prefix + " timing missing or nonpositive"):
                cpu_values.append(cpu)
                wall_values.append(wall)
        check(len(cpu_values) == count and cell.get("read_hash_thread_cpu_ns") == sum(cpu_values),
              label + " CPU total differs from all raw iterations")
        check(len(wall_values) == count and cell.get("read_hash_wall_ns") == sum(wall_values),
              label + " wall total differs from all raw iterations")
        check(integer(cell.get("whole_cell_wall_ns"), 1)
              and cell["whole_cell_wall_ns"] >= sum(wall_values), label + " whole-cell wall is inconsistent")
    final = records[-1]
    check(final == {"event": "complete", "passed": True, "measured_cells": 32,
                   "measured_full_file_hashes": 4096, "warmup_cells": 2, "warmup_full_file_hashes": 16,
                   "final_stamp": pin, "reference_sha256": digest}, "completion receipt differs")
    if errors:
        return out
    measured = cells[2:]
    for block in range(8):
        values = measured[block * 4:(block + 1) * 4]
        pair = {"block": block, "cell_ordinals": [row["ordinal"] for row in values]}
        for key, metric in (("read_hash_thread_cpu_ns", "cpu"), ("read_hash_wall_ns", "wall")):
            a = (values[0][key] + values[3][key]) / 2
            b = (values[1][key] + values[2][key]) / 2
            pair[metric + "_A_mean_ns"] = a
            pair[metric + "_B_mean_ns"] = b
            pair[metric + "_improvement_percent"] = 100 * (a - b) / a
        out["blocks"].append(pair)
    cpu = [row["cpu_improvement_percent"] for row in out["blocks"]]
    median = statistics.median(cpu)
    mad = statistics.median(abs(value - median) for value in cpu)
    wall = statistics.median(row["wall_improvement_percent"] for row in out["blocks"])
    gates = {"median_cpu_improvement_at_least_3_percent": median >= 3,
             "at_least_7_blocks_cpu_improve": sum(value > 0 for value in cpu) >= 7,
             "median_cpu_improvement_strictly_exceeds_2_MAD": median > 2 * mad,
             "median_wall_regression_at_most_2_percent": wall >= -2}
    eligible = all(gates.values())
    out.update(valid_complete_experiment=True, eligible_for_separate_runtime_candidate=eligible,
               decision="eligible for a separately qualified runtime candidate" if eligible else "keep the current 16 KiB buffer",
               median_paired_cpu_improvement_percent=median, paired_cpu_improvement_MAD_percent=mad,
               median_paired_wall_improvement_percent=wall,
               positive_cpu_blocks=sum(value > 0 for value in cpu), gates=gates)
    return out



def main():
    need(BASE.is_dir() and BASE == BASE.resolve(), "fixed development root missing or indirect")
    need(OUTPUT.parent.is_dir() and OUTPUT.parent == OUTPUT.parent.resolve(), "existing publication parent required")
    need(not os.path.lexists(OUTPUT), "publication output must be fresh")
    for root in DIRECTORIES.values():
        need(root.parent == BASE and root.is_dir() and root == root.resolve(), "fixed input directory missing or indirect")
    inputs = Inputs()
    bundles = {label: verify_bundle(inputs, label) for label in ("bundle-r01", "bundle-r02")}
    for name in COMMON_FILES - {"prepare_hash_probe.py"}:
        inputs.check("unchanged_frozen_scope:" + name,
                     bundles["bundle-r01"]["files"][name] == bundles["bundle-r02"]["files"][name])
    builds = {label: verify_build(inputs, label, bundles[label.replace("build", "bundle")])
              for label in ("build-r01", "build-r02")}
    inputs.check("same_qualified_dependency_provenance", all(builds["build-r01"].get(key) == builds["build-r02"].get(key)
                 for key in ("qualification", "independent_receipt", "qualified_runtime_binary", "dependencies",
                             "qualified_toolchain", "qualification_source_map_sha256")))
    run, start, analysis, recomputed, rows = verify_run(inputs, builds["build-r02"])
    inputs.final_stamps()
    checks = inputs.checks
    verified = bool(checks) and all(checks.values())
    receipts = {"bundles": bundles, "builds": builds, "run": run, "run_start": start,
                "recorded_analysis": analysis, "independently_recomputed_analysis": recomputed,
                "input_files": inputs.files, "checks": checks}
    clean = Sanitizer({"receipts": receipts, "raw_rows": rows})
    public_raw = b"".join(canonical(clean(row)) for row in rows)
    need(len(public_raw.splitlines()) == len(rows) == 37, "raw event loss during sanitization")
    public_rows = [decode(line) for line in public_raw.splitlines()]
    need(all(len(a.get("iterations", [])) == len(b.get("iterations", []))
             for a, b in zip(rows, public_rows)), "iteration loss during sanitization")
    outputs = {
        "probe-raw.complete.sanitized.jsonl.gz": gzip_bytes(public_raw),
        "receipts.complete.sanitized.json.gz": gzip_bytes(canonical(clean(receipts))),
    }
    transformations = {}
    frozen_tar = io.BytesIO()
    frozen_members = {}
    with tarfile.open(fileobj=frozen_tar, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for label, manifest in bundles.items():
            for name in ["SHA256.json", *sorted(manifest["files"])]:
                raw = inputs.payloads[str(DIRECTORIES[label] / name)]
                need(clean.string(raw.decode()) == raw.decode(), "frozen text would require redaction; refusing source rewrite")
                member_name = label + "/" + name
                member = tarfile.TarInfo(member_name)
                member.size, member.mode, member.mtime, member.uid, member.gid = len(raw), 0o644, 0, 0, 0
                archive.addfile(member, io.BytesIO(raw))
                frozen_members[member_name] = {"bytes": len(raw), "sha256": sha(raw)}
    outputs["frozen-bundles.inputs.tar.gz"] = gzip_bytes(frozen_tar.getvalue())
    with tarfile.open(fileobj=io.BytesIO(gzip.decompress(outputs["frozen-bundles.inputs.tar.gz"])), mode="r:") as archive:
        need([member.name for member in archive.getmembers()] == list(frozen_members), "frozen bundle member sequence differs")
        for member in archive.getmembers():
            raw = archive.extractfile(member).read()
            need(member.isfile() and frozen_members[member.name] == {"bytes": len(raw), "sha256": sha(raw)},
                 "frozen bundle byte loss in archive")
    repository_mapping = []
    for name in sorted(COMMON_FILES - {"hash_buffer_probe.rs"}):
        raw = inputs.payloads[str(DIRECTORIES["bundle-r02"] / name)]
        outputs["tools/" + name] = raw
        repository_mapping.append({"remote_source_relative_to_development_root": DIRECTORIES["bundle-r02"].name + "/" + name,
                                   "publication_source": "tools/" + name,
                                   "repository_path": "tools/x230/a26/hash-probe/" + name,
                                   "sha256": sha(raw), "role": "frozen r02 supporting source or plan"})
    repository_mapping.append({"remote_source_relative_to_development_root": DIRECTORIES["build-r02"].name + "/hash_buffer_probe.rs",
                               "publication_source": "build-r02/hash_buffer_probe.rs",
                               "repository_path": "tools/x230/a26/hash-probe/hash_buffer_probe.rs",
                               "sha256": builds["build-r02"]["source_to_publish"]["sha256"],
                               "role": "actual rustfmt output compiled into the measured standalone binary; takes precedence over draft input"})
    publisher_raw = Path(__file__).read_bytes()
    need(clean.string(publisher_raw.decode()) == publisher_raw.decode(), "publisher source unexpectedly needs redaction")
    outputs["tools/build_hash_probe_evidence.py"] = publisher_raw
    repository_mapping.append({"remote_source_relative_to_development_root": str(Path(__file__).resolve().relative_to(BASE)),
                               "publication_source": "tools/build_hash_probe_evidence.py",
                               "repository_path": "tools/x230/a26/hash-probe/build_hash_probe_evidence.py",
                               "sha256": sha(publisher_raw), "role": "read-only archival verifier for the fixed completed experiment"})
    for label in ("build-r01", "build-r02"):
        for name in BUILD_TEXT_FILES:
            if name == "build.json":
                continue  # The entire parsed receipt is retained above, without dropped keys.
            raw = inputs.payloads[str(DIRECTORIES[label] / name)]
            if name.endswith(".rs") or name in ("PLAN.json", "PLAN.md"):
                need(clean.string(raw.decode()) == raw.decode(), "actual source/plan needs redaction; refusing source alias")
                public = raw
            else:
                public = clean.string(raw.decode()).encode()
                need(len(public.splitlines()) == len(raw.splitlines()), "compiler log line loss")
            relative = label + "/" + name
            outputs[relative] = public
            transformations[relative] = {"original_sha256": sha(raw), "original_bytes": len(raw),
                                         "public_sha256": sha(public), "public_bytes": len(public)}
    stderr = inputs.payloads[str(DIRECTORIES["run-r02"] / "stderr.log")]
    outputs["run-r02/stderr.log"] = clean.string(stderr.decode()).encode()
    summary = {
        "schema": "hepta-x230-hash-probe-publication-summary/v1", "publication_verified": verified,
        "experiment_valid": recomputed["valid_complete_experiment"] if verified else False,
        "decision": "keep the current 16 KiB buffer" if verified else "no decision: publication verification failed",
        "runtime_performance_improvement_claim": None, "runtime_buffer_changed": False,
        "scope": "single-thread repeated complete reads and ring SHA256 of /usr/bin/ssh; same read/hash timing windows",
        "counts": {"reference_reads": 1, "warmup_cells": 2, "warmup_iterations_per_slot": 8,
                   "measured_cells": 32, "iterations_per_cell": 128, "measured_full_file_hashes": 4096,
                   "blocks": 8, "order_per_block": "ABBA", "raw_events_preserved": len(rows)},
        "metrics": {key: recomputed[key] for key in ("median_paired_cpu_improvement_percent",
                    "paired_cpu_improvement_MAD_percent", "positive_cpu_blocks", "median_paired_wall_improvement_percent")},
        "gates": recomputed["gates"], "all_eight_blocks": recomputed["blocks"],
        "eligible_for_separate_runtime_candidate": False,
        "r01_compile_failure": {"format_returncode": 0, "compile_returncode": 1, "probe_executed": False,
                                "compile_stderr_sha256": EXPECTED["r01-compile-stderr"],
                                "reason": "existing release rlibs require abort; initial standalone compiler defaulted to unwind"},
        "r02_build": {"format_returncode": 0, "compile_returncode": 0,
                      "panic_strategy": "abort, verified from qualified Cargo.toml",
                      "input_source_sha256": EXPECTED["input-source"],
                      "actual_formatted_compiled_source_sha256": builds["build-r02"]["source_to_publish"]["sha256"],
                      "probe_binary_sha256": builds["build-r02"]["probe_binary"]["sha256"],
                      "rlibs": {name: builds["build-r02"]["dependencies"][name]["rlib"]["sha256"] for name in ("ring", "libc")}},
        "raw_original": {"sha256": EXPECTED["raw"], "bytes": 2741098, "events": 37},
        "raw_public": {"file": "probe-raw.complete.sanitized.jsonl.gz", "uncompressed_sha256": sha(public_raw),
                       "uncompressed_bytes": len(public_raw), "events": 37, "rows_or_iterations_removed": 0},
        "recorded_analysis_sha256": EXPECTED["analysis"],
        "repository_mapping": repository_mapping,
        "limitations": ["This is a read/hash microprobe, not a runtime throughput or latency comparison.",
                        "It does not establish runtime memory or concurrency improvement.",
                        "Clock calls and fixed bookkeeping remain in the measured windows; metadata checks are outside them.",
                        "All declared warmup and measured cells are retained; no unfavorable cells were removed or rerun."],
        "unmet_publication_checks": [key for key, passed in checks.items() if not passed],
    }
    outputs["summary.json"] = canonical(clean(summary))
    outputs["SUMMARY.md"] = (
        "# Hash-buffer experiment: keep 16 KiB\n\n"
        "The complete fixed experiment passed its integrity checks: 32 measured cells, 128 full-file hashes per cell, "
        "eight ABBA blocks, and eight warmup iterations per buffer size. The measured region is the same read/hash "
        "window for both sizes; metadata checks occur outside it, and fixed clock/bookkeeping overhead remains.\n\n"
        "The median paired thread CPU improvement for 64 KiB was **0.920486%**, with **1.356476 percentage points MAD** "
        "and positive improvement in **5 of 8 blocks**. The median paired wall improvement was **0.919215%**. "
        "The CPU gates (at least 3%, at least 7 positive blocks, and improvement greater than twice MAD) all failed. "
        "The wall regression gate passed. The predeclared decision is **keep the current 16 KiB buffer**; "
        "no runtime speedup, memory reduction, or concurrency gain is established.\n\n"
        "The first standalone build failed after formatting because the existing qualified release rlibs use "
        "panic=abort while the initial probe compiler used unwind. That failed attempt, its exact source/input hashes "
        "and complete compiler logs are retained separately. No probe ran in that attempt. The second build verifies "
        "the qualified Cargo.toml panic strategy and adds -C panic=abort; its actual formatted compilation source is "
        "preserved under build-r02/hash_buffer_probe.rs. The measurement source, plan, and decision rules did not change.\n\n"
        "The compressed JSONL retains all 37 original events and all 4,096 measured plus 16 warmup iteration receipts, "
        "in their original order. Private paths and environment identities are replaced in place with stable receipts; "
        "the manifest retains both the complete original-byte hash and the published-byte hash. No rlib or executable "
        "body is included; their complete-file hashes and provenance receipts are retained.\n\n"
        + ("Publication verification passed.\n" if verified else "**Publication verification failed; consult summary.json. No performance decision is authorized by this archive.**\n")
    ).encode()
    if not verified:
        outputs["SUMMARY.md"] = b"# Hash-probe publication verification failed\n\nNo performance decision is authorized by this archive. Consult summary.json and the complete retained receipts for every unmet check.\n"
    manifest = {"schema": "hepta-x230-hash-probe-publication-manifest/v1", "verified": verified,
                "publisher_sha256": sha(publisher_raw), "checks": checks,
                "inputs": clean(inputs.files), "text_transformations": transformations,
                "raw_original_sha256": EXPECTED["raw"], "raw_original_bytes": 2741098,
                "raw_public_uncompressed_sha256": sha(public_raw), "raw_event_count": 37,
                "all_recorded_cells_and_iterations_retained": True,
                "frozen_bundle_input_members": frozen_members,
                "repository_mapping": repository_mapping,
                "binary_and_rlib_bodies_included": False, "probe_runs_started_by_publisher": 0,
                "builds_started_by_publisher": 0, "automatic_retries": 0,
                "outputs": {name: {"bytes": len(raw), "sha256": sha(raw), "git_blob_sha1": git_blob_sha1(raw)}
                            for name, raw in sorted(outputs.items())}}
    outputs["manifest.json"] = canonical(clean(manifest))
    # All reads, verification, sanitization, compression, and source checks finish
    # before creating the publication directory; no existing artifact is replaced.
    OUTPUT.mkdir(mode=0o700, parents=False, exist_ok=False)
    os.umask(0o077)
    for name, raw in outputs.items():
        path = OUTPUT / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    for directory in sorted({OUTPUT, *(path.parent for path in OUTPUT.rglob("*") if path.is_file())}, key=lambda p: len(p.parts), reverse=True):
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    print(json.dumps({"publication": "publication-a26-r01/hash-probe-r02", "verified": verified,
                      "decision": summary["decision"], "artifact_files": len(outputs),
                      "manifest_sha256": sha(outputs["manifest.json"]),
                      "manifest_git_blob_sha1": git_blob_sha1(outputs["manifest.json"]), "probe_executed": False}))
    return 0 if verified else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(json.dumps({"publication_failed": True, "type": type(error).__name__,
                          "reason": Sanitizer({}).string(str(error)), "probe_executed": False}), file=sys.stderr)
        sys.exit(1)
