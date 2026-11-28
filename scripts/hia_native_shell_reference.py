#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Build and replay unchanged original shell owners with their exact locked regex.

Native shards capture complete semantic inputs and native outputs. This separate
aggregate process freshly builds the original Rust, executes every original pure
test, regenerates the independent corpus, and compares every output byte. It
does not infer shell execution, production routing, or asynchronous ownership.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import time
import tomllib


ROOT = Path(__file__).resolve().parents[1]
ORACLE = ROOT / "tests/hia_native/shell_oracle"
SCHEMA = "hepta.runtime.shell-original-replay.v1"


def strict_json(raw: str):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"nonfinite JSON: {value}")))


def checked_pin(value: dict) -> dict:
    if (type(value) is not dict or set(value) != {"bytes", "sha256"}
            or type(value["bytes"]) is not int or value["bytes"] < 0
            or type(value["sha256"]) is not str
            or re.fullmatch("[0-9a-f]{64}", value["sha256"]) is None):
        raise ValueError("invalid physical byte pin")
    return value


def pin_bytes(raw: bytes) -> dict:
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def pin_file(path: Path) -> dict:
    state = hashlib.sha256()
    length = 0
    with path.open("rb") as stream:
        while block := stream.read(1 << 20):
            length += len(block)
            state.update(block)
    return {"bytes": length, "sha256": state.hexdigest()}


def _same(raw: bytes, pin: dict, name: str) -> None:
    if pin_bytes(raw) != checked_pin(pin):
        raise ValueError(f"original source bytes changed: {name}")


def original_sources(runtime: Path, oracle: Path = ORACLE) -> tuple[dict, dict[str, bytes]]:
    """Verify whole original files and then extract unchanged contiguous regions."""
    manifest = strict_json((oracle / "source_manifest.json").read_text())
    files = {}
    for name, pin in manifest["files"].items():
        files[name] = (runtime / name).read_bytes()
        _same(files[name], pin, name)
    for name, expected_blob in manifest["original_owner_git_blobs"].items():
        data = files[name]
        blob = hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()
        if blob != expected_blob:
            raise ValueError(f"original baseline Git blob changed: {name}")
    owner = files["src/mcp/fs/shell.rs"].decode("utf-8")
    tests = files["src/mcp/fs/shell_tests.rs"].decode("utf-8")
    start = owner.index("static SHELL_MISUSE_HINTS:")
    stop = owner.index("/// Delivers a finished background job")
    first = tests.index("#[test]\nfn stashing_commands_are_recognised")
    first_end = tests.index("#[cfg(unix)]\n#[tokio::test]", first)
    remaining = tests.index("#[test]\nfn test_clean_terminal_noise")
    last = tests.index("#[cfg(unix)]\n#[tokio::test]\nasync fn a_scratch_heredoc_and_a_piped_read_run", remaining)
    extracted = {
        "original_shell.rs": owner[start:stop].encode(),
        "original_shell_tests.rs": (tests[first:first_end] + tests[remaining:last]).encode(),
    }
    for name, data in extracted.items():
        _same(data, manifest["extractions"][name], name)
    names = re.findall(r"#\[test\]\nfn (\w+)\(", extracted["original_shell_tests.rs"].decode())
    if names != manifest["original_test_names"] or len(names) != 9:
        raise ValueError("original pure test set changed")
    original_lock = tomllib.loads(files["Cargo.lock"].decode())
    original_package = tomllib.loads(files["Cargo.toml"].decode())
    oracle_package = tomllib.loads((oracle / "Cargo.toml").read_text())
    if (original_package["dependencies"]["regex"] != "1.13.1"
            or oracle_package["dependencies"]["regex"] != "=1.13.1"):
        raise ValueError("original/oracle regex version or default-feature declaration changed")
    subset_lock = tomllib.loads((oracle / "Cargo.lock").read_text())
    original_by_key = {(row["name"], row["version"]): row for row in original_lock["package"]}
    dependencies = [row for row in subset_lock["package"] if "source" in row]
    if sorted(row["name"] for row in dependencies) != sorted(manifest["dependency_names"]):
        raise ValueError("oracle dependency closure changed")
    for row in dependencies:
        if row != original_by_key.get((row["name"], row["version"])):
            raise ValueError(f"dependency differs from original full lock: {row['name']}")
    provenance = {
        "schema": "hepta.runtime.shell-original-source-check.v1",
        "source_commit": manifest["commit"],
        "original_owner_baseline_commit": manifest["original_owner_baseline_commit"],
        "original_owner_git_blobs": manifest["original_owner_git_blobs"],
        "target": manifest["target"],
        "files": manifest["files"], "extractions": manifest["extractions"],
        "original_function_bodies_unchanged": True,
        "all_original_pure_tests_retained": True,
        "original_test_names": names,
        "original_dependency_lock_match": True,
        "original_regex_default_features_match": True,
        "registry_dependency_count": len(dependencies),
        "registry_dependencies": dependencies,
    }
    return provenance, extracted


def materialize(runtime: Path, destination: Path, oracle: Path = ORACLE) -> dict:
    provenance, extracted = original_sources(runtime, oracle)
    destination.mkdir(parents=True, exist_ok=False)
    (destination / "src").mkdir()
    (destination / "fixtures").mkdir()
    template = {}
    for name in ("Cargo.toml", "Cargo.lock", "src/main.rs"):
        data = (oracle / name).read_bytes()
        (destination / name).write_bytes(data)
        template[name] = pin_bytes(data)
    for name, data in extracted.items():
        (destination / "fixtures" / name).write_bytes(data)
    provenance["test_transport_sources"] = template
    (destination / "source-receipt.json").write_text(json.dumps(provenance, indent=2) + "\n")
    return provenance


def _process(command: list[str], cwd: Path, output: Path, label: str,
             timeout: float, *, env: dict, stdin: Path | None = None) -> dict:
    stdout, stderr = output / f"{label}.stdout", output / f"{label}.stderr"
    start = time.monotonic()
    error = None
    code = None
    with stdout.open("wb") as out, stderr.open("wb") as err:
        source = stdin.open("rb") if stdin else None
        try:
            run = subprocess.run(command, cwd=cwd, env=env, stdin=source,
                                 stdout=out, stderr=err, timeout=timeout, check=False)
            code = run.returncode
        except subprocess.TimeoutExpired:
            error = "deadline_exceeded"
        except OSError as exc:
            error = f"{type(exc).__name__}: {exc}"
        finally:
            if source:
                source.close()
    result = {"command": command, "cwd": str(cwd), "timeout_seconds": timeout,
              "duration_seconds": time.monotonic() - start,
              "exit_code": code, "error": error,
              "stdout": {"path": stdout.name, **pin_file(stdout)},
              "stderr": {"path": stderr.name, **pin_file(stderr)},
              "passed": code == 0 and error is None}
    (output / f"{label}.execution.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def _cases_module(runtime: Path):
    location = runtime / "tests/hia_native/shell_oracle/cases.py"
    spec = importlib.util.spec_from_file_location("_shell_original_cases", location)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _inside(folder: Path, name: str) -> Path:
    relative = Path(name)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("corpus path is not an ordinary relative descendant")
    if folder.is_symlink():
        raise ValueError("symlinked corpus root")
    cursor = folder
    for member in relative.parts:
        cursor = cursor / member
        if cursor.is_symlink():
            raise ValueError("symlinked corpus member")
    path = (folder / relative).resolve(strict=True)
    if not path.is_relative_to(folder.resolve()) or not path.is_file():
        raise ValueError("missing or escaped corpus member")
    return path


def verify_corpus(runtime: Path, corpus: Path, mode: str, output: Path) -> dict:
    cases = _cases_module(runtime)
    index = strict_json(_inside(corpus, "native-corpus.json").read_text())
    if (index.get("schema") != "hepta.runtime.shell-native-corpus.v1"
            or index.get("mode") != mode or index.get("status") != "PASS"):
        raise ValueError("native semantic corpus did not complete")
    for key in ("semantic_case_count", "transport_control_count"):
        if type(index.get(key)) is not int or index[key] < 0:
            raise ValueError("native corpus count is not an exact integer")
    members = {}
    for name in ("input.bin", "native-output.bin", "cases.jsonl"):
        path = _inside(corpus, name)
        if pin_file(path) != checked_pin(index["files"][name]):
            raise ValueError(f"native corpus member bytes differ: {name}")
        members[name] = path
    rows = [strict_json(line) for line in members["cases.jsonl"].read_text().splitlines()]
    for row in rows:
        for key in ("input_bytes", "native_return", "output_bytes", "output_capacity", "workspace_capacity"):
            if type(row.get(key)) is not int or row[key] < 0:
                raise ValueError(f"semantic row {key} is not an exact integer")
    independent = output / "independent-input.bin"
    count = 0
    categories = {}
    with members["input.bin"].open("rb") as native, independent.open("xb") as fresh:
        for case in cases.iter_cases(mode, runtime):
            if count >= len(rows):
                raise ValueError("native corpus omits independent semantic cases")
            row = rows[count]
            encoded = struct.pack("<Q", len(case["input"])) + case["input"]
            if native.read(len(encoded)) != encoded:
                raise ValueError(f"native input differs from independent case {case['id']}")
            expected = {"id": case["id"], "category": case["category"],
                        "input_bytes": len(case["input"]),
                        "input_sha256": hashlib.sha256(case["input"]).hexdigest()}
            if any(row.get(key) != value for key, value in expected.items()):
                raise ValueError(f"native semantic row differs: {case['id']}")
            fresh.write(encoded)
            count += 1
            categories[case["category"]] = categories.get(case["category"], 0) + 1
        if native.read(1) or count != len(rows) or count != index.get("semantic_case_count"):
            raise ValueError("extra/missing native corpus records")
    return {"input": independent, "native_output": members["native-output.bin"],
            "rows": rows, "receipt": {
                "mode": mode, "semantic_cases": count, "categories": categories,
                "all_input_bytes_regenerated_and_equal": True,
                "independent_input": {"path": independent.name, **pin_file(independent)},
                "native_corpus_members": index["files"],
                "native_transport_controls_excluded": index.get("transport_control_count", 0)}}


def compare_outputs(original: Path, native: Path, rows: list[dict]) -> dict:
    total = 0
    with original.open("rb") as expected, native.open("rb") as actual:
        for row in rows:
            a, b = expected.read(8), actual.read(8)
            if len(a) != 8 or a != b:
                raise ValueError(f"original/native output frame differs: {row['id']}")
            length, = struct.unpack("<Q", a)
            if length != row.get("output_bytes") or length != row.get("native_return"):
                raise ValueError(f"native output length receipt differs: {row['id']}")
            remaining = length
            state = hashlib.sha256()
            while remaining:
                size = min(1 << 20, remaining)
                left, right = expected.read(size), actual.read(size)
                if len(left) != size or left != right:
                    raise ValueError(f"original/native output bytes differ: {row['id']} offset {length - remaining}")
                state.update(right)
                remaining -= size
            if state.hexdigest() != row.get("output_sha256"):
                raise ValueError(f"native output hash receipt differs: {row['id']}")
            total += length
        if expected.read(1) or actual.read(1):
            raise ValueError("unexpected original/native trailing output")
    return {"semantic_cases_compared": len(rows), "semantic_body_bytes_compared": total,
            "every_output_byte_equal": True, "original_output": pin_file(original),
            "native_output": pin_file(native)}


def run(args) -> dict:
    runtime = args.runtime.resolve(strict=True)
    output = args.output.absolute()
    output.mkdir(parents=True, exist_ok=False)
    result = {"schema": SCHEMA, "status": "FAIL", "mode": args.mode,
              "whole_runtime_replaced": False, "production_shell_execution_qualified": False,
              "processes": []}
    try:
        crate = output / "crate"
        result["source_provenance"] = materialize(runtime, crate, runtime / "tests/hia_native/shell_oracle")
        env = os.environ.copy()
        exact_remove = {"RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_TARGET",
                        "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTC_BOOTSTRAP",
                        "RUSTDOCFLAGS", "CARGO_ENCODED_RUSTDOCFLAGS", "RUSTC"}
        removed = sorted(key for key in env if key in exact_remove
                         or key.startswith(("CARGO_TARGET_", "CARGO_BUILD_", "CARGO_PROFILE_")))
        for key in removed:
            env.pop(key, None)
        result["removed_build_environment_names"] = removed
        executables = {}
        for key, requested in (("rustc", args.rustc), ("cargo", args.cargo)):
            found = shutil.which(requested, path=env.get("PATH"))
            if not found:
                raise ValueError(f"requested {key} executable is unavailable")
            launch = Path(found).absolute()
            resolved = launch.resolve(strict=True)
            if not resolved.is_file() or not os.access(launch, os.X_OK):
                raise ValueError(f"requested {key} is not an executable file")
            executables[key] = {"launch_path": str(launch), "resolved_path": str(resolved),
                                **pin_file(resolved)}
        result["build_tools"] = executables
        rustc, cargo = executables["rustc"]["launch_path"], executables["cargo"]["launch_path"]
        env["RUSTC"] = rustc
        env["CARGO_TARGET_DIR"] = str(output / "target")
        common = [cargo, "--manifest-path", str(crate / "Cargo.toml")]
        offline = ["--offline"] if args.offline else []
        commands = [
            ("rustc-version", [rustc, "--version", "--verbose"], 30),
            ("build", [common[0], "build", *common[1:], "--locked", "--release", *offline], args.build_timeout),
            ("original-tests", [common[0], "test", *common[1:], "--locked", "--release", *offline,
                                "--", "--nocapture", "--test-threads=1"], args.test_timeout),
        ]
        for name, command, timeout in commands:
            for tool in executables.values():
                if pin_file(Path(tool["resolved_path"])) != {key: tool[key] for key in ("bytes", "sha256")}:
                    raise ValueError("selected build executable changed")
            process = _process(command, crate, output, name, timeout, env=env)
            result["processes"].append(process)
            if not process["passed"]:
                raise RuntimeError(f"original {name} process failed")
            if name == "rustc-version":
                version = (output / "rustc-version.stdout").read_text()
                if not re.search(r"^rustc 1\.95\.0(?:\s|$)", version, re.M):
                    raise ValueError("original replay requires the pinned Rust 1.95.0")
                result["rustc_version"] = version
        test_stdout = (output / "original-tests.stdout").read_text(errors="strict")
        names = result["source_provenance"]["original_test_names"]
        for name in names:
            if f"test original::tests::{name} ... ok" not in test_stdout:
                raise ValueError(f"actual original test did not pass: {name}")
        if "9 passed; 0 failed; 0 ignored" not in test_stdout:
            raise ValueError("original pure tests were skipped or incomplete")
        result["original_test_count"] = len(names)
        executable = output / "target/release/hepta-shell-original-oracle"
        result["executable"] = {"path": str(executable), **pin_file(executable)}
        verified = verify_corpus(runtime, args.corpus.resolve(strict=True), args.mode, output)
        result["input_verification"] = verified["receipt"]
        replay = _process([str(executable), args.mode], crate, output, "replay", args.replay_timeout,
                          env=env, stdin=verified["input"])
        result["processes"].append(replay)
        if not replay["passed"]:
            raise RuntimeError("original semantic replay failed")
        result["comparison"] = compare_outputs(output / "replay.stdout", verified["native_output"], verified["rows"])
        result["status"] = "PASS"
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rustc", default="rustc")
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--mode", choices=("terminal", "gate"), required=True)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--build-timeout", type=float, default=180)
    parser.add_argument("--test-timeout", type=float, default=120)
    parser.add_argument("--replay-timeout", type=float, default=120)
    args = parser.parse_args()
    result = run(args)
    print(json.dumps({"status": result["status"], "mode": args.mode,
                      "report": str(args.output.absolute() / "result.json"),
                      "processes": len(result["processes"]),
                      "original_test_count": result.get("original_test_count", 0),
                      "comparison": result.get("comparison"), "error": result.get("error")}, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
