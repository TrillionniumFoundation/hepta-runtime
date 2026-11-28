"""Connect both file-lock components to actual aggregate process evidence.

The state corpus is a required input of the composed service. All six suites
stay in order on one partition; original recipes rebuild and execute their
own source-pinned Rust owners. Retained observations never replace those runs.
"""
from __future__ import annotations

from pathlib import Path
import re
import sys

import hia_native_file_lock_qualification as locks
import hia_native_file_lock_service_qualification as service
from hia_native_file_lock_build import exact, read, require, sha, obj

COMPONENTS = {
    "file_locks": {
        "source": "native/file_lock_state.hepta", "folder": "file-locks",
        "tests": ("test_file_lock_state.py", "test_file_lock_key.py", "test_file_lock_evidence.py"),
        "original": "compare_file_locks_original.py", "check": "file-locks-rust-compare",
    },
    "file_lock_service": {
        "source": "native/file_lock_service.hepta", "folder": "file-lock-service",
        "tests": ("test_file_lock_service.py", "test_file_lock_service_contract.py",
                  "test_file_lock_service_evidence.py"),
        "original": "compare_file_lock_service_original.py", "check": "file-lock-service-rust-compare",
    },
}
ORDERED_SUITES = tuple(name for owner in COMPONENTS.values() for name in owner["tests"])


def bundle(output, report, key):
    owner = report["modules"][key]
    require(owner.get("builder") == key and owner.get("source") == COMPONENTS[key]["source"],
            "file-lock aggregate owner registry differs: " + key)
    relative = Path(owner["manifest"])
    require(not relative.is_absolute() and ".." not in relative.parts and relative.name == "manifest.json",
            "file-lock bundle must be an owned relative manifest")
    return output / relative


def test_commands(root, output, report):
    state = output / "file-locks/state"
    key = output / "file-locks/key"
    native = output / "file-lock-service/native"
    contract = output / "file-lock-service/contract"
    lock_bundle = bundle(output, report, "file_locks")
    service_bundle = bundle(output, report, "file_lock_service")
    arguments = {
        "test_file_lock_state.py": ["--bundle", lock_bundle, "--output", state],
        "test_file_lock_key.py": ["--bundle", lock_bundle, "--output", key],
        "test_file_lock_evidence.py": ["--bundle", lock_bundle, "--state-corpus", state,
            "--key-corpus", key, "--state-stdout", output / "test_file_lock_state.py.stdout",
            "--key-stdout", output / "test_file_lock_key.py.stdout", "--output", output / "file-locks/controls"],
        "test_file_lock_service.py": ["--bundle", service_bundle, "--state-corpus", state,
            "--output", native],
        "test_file_lock_service_contract.py": ["--bundle", service_bundle, "--output", contract],
        "test_file_lock_service_evidence.py": ["--bundle", service_bundle, "--state-corpus", state,
            "--native-corpus", native, "--native-stdout", output / "test_file_lock_service.py.stdout",
            "--contract-corpus", contract, "--contract-stdout", output / "test_file_lock_service_contract.py.stdout",
            "--output", output / "file-lock-service/controls"],
    }
    return {name: [sys.executable, "-I", "-B", str(root / "tests/hia_native" / name), *map(str, arguments[name])]
            for name in ORDERED_SUITES}


def completed_process(output, report, completed, name, command):
    check, summary = completed(output, report, name)
    require(check.get("command") == command and type(check.get("exit_code")) is int
        and check["exit_code"] == 0 and check.get("timed_out") is False
        and not check.get("start_error") and type(check.get("timeout_seconds")) is int
        and check["timeout_seconds"] == 180, "actual file-lock process contract differs: " + name)
    locks.duration(check.get("elapsed_seconds"), "actual file-lock process exceeded its original deadline")
    for channel in ("stdout", "stderr"):
        raw = read(output / (name + "." + channel))
        require(type(check.get(channel + "_bytes")) is int and check[channel + "_bytes"] == len(raw)
            and check[channel + "_sha256"] == sha(raw), "actual file-lock process stream differs: " + name)
    stderr = read(output / (name + ".stderr"))
    if name == "test_file_lock_service.py":
        require(re.fullmatch(rb"(?:test_[^\r\n]+ \.\.\. ok\n){3}\n-{70}\nRan 3 tests in [0-9]+\.[0-9]+s\n\nOK\n", stderr)
                is not None, "actual composed lock suite did not complete all three unittest groups")
    else:
        exact(stderr, b"", "unexpected file-lock process diagnostics: " + name)
    return {key: check[key] for key in ("command", "exit_code", "timed_out", "timeout_seconds",
        "stdout_bytes", "stderr_bytes", "stdout_sha256", "stderr_sha256")}, summary


def qualification_evidence(root, output, report, completed, key):
    manifest = bundle(output, report, key)
    exact(sha(read(manifest)), report["modules"][key]["sha256"], "registered file-lock bundle changed")
    commands = test_commands(root, output, report)
    processes = {name: completed_process(output, report, completed, name, commands[name])[0]
                 for name in COMPONENTS[key]["tests"]}
    state = output / "file-locks/state"
    hepta = Path(report["compiler_checkout"])
    if key == "file_locks":
        native = locks.native_evidence(manifest, state, output / "file-locks/key", source_root=root,
            hepta=hepta, state_stdout=output / "test_file_lock_state.py.stdout",
            key_stdout=output / "test_file_lock_key.py.stdout")
        controls = locks.controls_evidence(output / "file-locks/controls", native, source_root=root,
            stdout=output / "test_file_lock_evidence.py.stdout")
        domains = {"native": native, "controls": controls}
    else:
        # Admit the producer's actual completion as well as the complete corpus.
        producer = "test_file_lock_state.py"
        processes[producer] = completed_process(output, report, completed, producer, commands[producer])[0]
        native = service.native_evidence(manifest, output / "file-lock-service/native", state,
            source_root=root, hepta=hepta, stdout=output / "test_file_lock_service.py.stdout")
        contract = service.contract_evidence(manifest, output / "file-lock-service/contract",
            source_root=root, stdout=output / "test_file_lock_service_contract.py.stdout")
        controls = service.controls_evidence(output / "file-lock-service/controls", native, contract,
            source_root=root, stdout=output / "test_file_lock_service_evidence.py.stdout")
        domains = {"native": native, "contract": contract, "controls": controls}
    return {"schema": "hepta.runtime." + COMPONENTS[key]["folder"] + "-completed-evidence.v1",
        "status": "PASS", **domains, "completed_processes": processes,
        "production_activated": False, "whole_runtime_replaced": False, "old_stack_removal_qualified": False}


def original_command(root, output, report, rustc, key):
    item = COMPONENTS[key]
    command = [sys.executable, "-I", "-B", str(root / "tests/hia_native" / item["original"]),
        "--root", str(root), "--bundle", str(bundle(output, report, key)),
        "--state-corpus", str(output / "file-locks/state"),
        "--output", str(output / (item["folder"] + "-original")),
        "--rustc", str(rustc), "--cargo", str(rustc.with_name("cargo")),
        "--rustfmt", str(rustc.with_name("rustfmt"))]
    if key == "file_lock_service":
        command += ["--native-corpus", str(output / "file-lock-service/native"),
                    "--native-stdout", str(output / "test_file_lock_service.py.stdout")]
    return command


def retained_original(root, output, report, rustc, completed, key):
    item = COMPONENTS[key]
    process, _ = completed_process(output, report, completed, item["check"],
                                  original_command(root, output, report, rustc, key))
    directory = output / (item["folder"] + "-original")
    manifest = bundle(output, report, key)
    arguments = {"source_root": root, "stdout": output / (item["check"] + ".stdout")}
    if key == "file_locks":
        result = locks.original_evidence(directory, manifest, output / "file-locks/state", **arguments)
    else:
        result = service.original_evidence(directory, manifest, output / "file-lock-service/native",
            output / "test_file_lock_service.py.stdout", output / "file-locks/state", **arguments)
    selected = obj(directory / "result.json")["tools"]
    exact({name: row["path"] for name, row in selected.items()},
          {name: str(rustc.with_name(name)) for name in ("rustc", "cargo", "rustfmt")},
          "file-lock reference selected another toolchain")
    return {**result, "completed_process": process, "compiled_by_qualification_recipe": True}


def compare_original(root, output, report, rustc, completed, record_check, env, key):
    before = qualification_evidence(root, output, report, completed, key)
    exact(before, report[key + "_evidence"], "native file-lock evidence changed before original replay")
    record_check(output, report, name=COMPONENTS[key]["check"],
        command=original_command(root, output, report, rustc, key), env=env, timeout=180)
    result = retained_original(root, output, report, rustc, completed, key)
    exact(qualification_evidence(root, output, report, completed, key), before,
          "native file-lock evidence changed during original replay")
    return result
