#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Fresh CI-only current typed owner build, original comparison and byte custody."""
from __future__ import annotations
from pathlib import Path
import argparse
import ast
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import B3, HEPTA, SCOPE, canonical, decode, owned, pin, require, source_evidence


def run_process(output, name, argv, *, data=b"", env=None, cwd=None, limit=180):
    folder = output / "processes"; folder.mkdir(exist_ok=True)
    require(not (folder / (name + ".json")).exists(), "process label reused")
    stdin = folder / (name + ".stdin"); stdin.write_bytes(data)
    receipt = dict(argv=[str(x) for x in argv], cwd=str(cwd or output), limit_seconds=limit,
                   started_ns=time.monotonic_ns(), timed_out=False,
                   selected_env={key: env[key] for key in ("CARGO_HOME", "CARGO_TARGET_DIR", "RUSTC", "RUSTUP_TOOLCHAIN") if env and key in env})
    with stdin.open("rb") as inp, (folder / (name + ".stdout")).open("xb") as out, (folder / (name + ".stderr")).open("xb") as err:
        child = subprocess.Popen(receipt["argv"], cwd=receipt["cwd"], env=env, stdin=inp, stdout=out, stderr=err, start_new_session=True)
        receipt["pid"] = child.pid
        try:
            receipt["returncode"] = child.wait(timeout=limit)
        except subprocess.TimeoutExpired:
            receipt["timed_out"] = True
            os.killpg(child.pid, signal.SIGKILL)
            receipt["returncode"] = child.wait()
    receipt["elapsed_ns"] = time.monotonic_ns() - receipt["started_ns"]
    receipt["streams"] = {suffix: pin(folder / (name + "." + suffix)) for suffix in ("stdin", "stdout", "stderr")}
    (folder / (name + ".json")).write_bytes(canonical(receipt))
    require(receipt["returncode"] == 0 and not receipt["timed_out"], "process failed: " + name)
    return receipt


def build(source, hepta, output):
    from hia_native_build import NativeBuild
    source_evidence(source)
    builder = NativeBuild(hepta, output / "build")
    members = {}
    for name in ("serde_json_span", "text_file_write_params"):
        manifest = builder.compile(name.replace("_", "-"), source / "native" / (name + ".hepta"), standalone=None, buffer_profile="history.v1")
        meta = decode(manifest.read_bytes())
        members[name] = dict(manifest=manifest.relative_to(output).as_posix(), manifest_sha256=pin(manifest)["sha256"],
            source_sha256=meta["source_sha256"], image_sha256=meta["image_sha256"])
    dep = output / "compiler-source"; dep.mkdir()
    for name in builder.identity["files"]:
        target = dep / name; target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(hepta / name, target)
    receipt = dict(schema="hepta.runtime.text-publisher.typed-build.v1", members=members,
        compiler_commit=HEPTA, compiler_sha256=B3, compiler_cold_qualified=False)
    (output / "build/typed-params.json").write_bytes(canonical(receipt))
    return receipt


def check_processes(output):
    names = ("author", "native-build", "rust-version", "cargo-fetch", "cargo-metadata", "cargo-build", "original", "native")
    result = {}
    for name in names:
        receipt = decode(owned(output, "processes/" + name + ".json").read_bytes())
        require(receipt["returncode"] == 0 and receipt["timed_out"] is False and receipt["limit_seconds"] == 180
            and 0 <= receipt["elapsed_ns"] < 181_000_000_000 and type(receipt["pid"]) is int and receipt["pid"] > 0,
            "actual process did not complete within original limit: " + name)
        for suffix in ("stdin", "stdout", "stderr"):
            require(receipt["streams"][suffix] == pin(owned(output, "processes/" + name + "." + suffix)), "complete process stream changed")
        result[name] = receipt
    require(owned(output, "processes/rust-version.stdout").read_text().startswith("rustc 1.95.0 "), "wrong actual Rust compiler")
    require(owned(output, "processes/original.stderr").read_bytes() == b"" and owned(output, "processes/native.stderr").read_bytes() == b"", "semantic process wrote stderr")
    require("--locked" in result["cargo-fetch"]["argv"] and "--locked" in result["cargo-metadata"]["argv"] and "--offline" in result["cargo-metadata"]["argv"] and "--locked" in result["cargo-build"]["argv"] and "--offline" in result["cargo-build"]["argv"], "actual locked/offline build contract changed")
    origin = decode(owned(output, "ORIGIN.json").read_bytes())
    at = Path(origin["output"]); source = at / "source"; rust = Path(origin["rust_bin"])
    py = [origin["python"], "-I", "-S", "-B"]
    expected = {
        "author": py + [str(source / "authoring/author_params.py"), "--source", str(source), "--hepta", origin["hepta"], "--output", str(at / "authored")],
        "native-build": py + [str(source / "scripts/run_ci.py"), "build", "--source", str(source), "--hepta", origin["hepta"], "--output", str(at)],
        "rust-version": [str(rust / "rustc"), "--version", "--verbose"],
        "cargo-fetch": [str(rust / "cargo"), "fetch", "--locked", "--manifest-path", str(at / "reference/Cargo.toml")],
        "cargo-metadata": [str(rust / "cargo"), "metadata", "--locked", "--offline", "--format-version", "1", "--manifest-path", str(at / "reference/Cargo.toml")],
        "cargo-build": [str(rust / "cargo"), "build", "--locked", "--offline", "--manifest-path", str(at / "reference/Cargo.toml")],
        "original": [str(at / "rust-target/debug/hepta-text-publisher-params-original-oracle")],
        "native": py + [str(source / "scripts/native_capture.py"), "--qualification", str(at)],
    }
    for name, argv in expected.items():
        require(result[name]["argv"] == argv and result[name]["cwd"] == str(at), "actual process command changed: " + name)
    require(decode(owned(output, "processes/native.stdout").read_bytes()) == decode(owned(output, "native/capture-result.json").read_bytes()), "native actual stdout differs from capture receipt")
    return result


def read_all(source, output):
    import params_cases
    from read_params import read_capture, compare_original
    from registry_evidence import inventory
    source, output = Path(source), Path(output)
    src = source_evidence(source)
    require(source_evidence(output / "source") == src, "retained source differs from caller-admitted source")
    processes = check_processes(output)
    require(owned(output, "processes/original.stdin").read_bytes() == params_cases.encoded(), "original input domain differs")
    require(owned(output, "reference/Cargo.lock").read_bytes() == owned(source, "reference/Cargo.lock").read_bytes(), "fresh Cargo lock changed")
    for name in ("text_file_write_params.hepta", "text_file_write_params_composition.json"):
        require(owned(output, "authored/" + name).read_bytes() == owned(source, "native/" + name).read_bytes(), "source author did not reproduce frozen HIA bytes")
    for path in sorted((source / "reference").rglob("*")):
        if path.is_file():
            require(path.read_bytes() == owned(output, "reference/" + path.relative_to(source / "reference").as_posix()).read_bytes(), "original fixture source changed")
    registry = inventory(source, output)
    require(registry == decode(owned(output, "registry-evidence.json").read_bytes()), "registry complete evidence differs")
    binary = owned(output, "rust-target/debug/hepta-text-publisher-params-original-oracle")
    require(pin(binary) == decode(owned(output, "original-binary.json").read_bytes()), "actual original binary changed")
    origin = decode(owned(output, "ORIGIN.json").read_bytes())
    require(processes["original"]["argv"] == [str(Path(origin["output"]) / "rust-target/debug/hepta-text-publisher-params-original-oracle")], "original command used another binary")
    native = read_capture(source, output)
    original = compare_original(output, native)
    return dict(status="COMPLETE_TYPED_COMPARISON_PASS", source=src, native={key: value for key, value in native.items() if key != "results"},
                original=original, registry_packages=registry["used_registry_packages"], scope=SCOPE)


def execute(source, hepta, rust_bin, output):
    require(not output.exists(), "qualification output must be fresh")
    output.mkdir(parents=True)
    origin = dict(source=str(source), hepta=str(hepta), rust_bin=str(rust_bin), output=str(output), python=sys.executable)
    (output / "ORIGIN.json").write_bytes(canonical(origin))
    source_evidence(source)
    shutil.copytree(source, output / "source")
    for path in (output / "source").rglob("*"):
        if path.is_file(): path.chmod(0o644)
    source = output / "source"
    py = [sys.executable, "-I", "-S", "-B"]
    run_process(output, "author", py + [source / "authoring/author_params.py", "--source", source, "--hepta", hepta, "--output", output / "authored"])
    for name in ("text_file_write_params.hepta", "text_file_write_params_composition.json"):
        require((output / "authored" / name).read_bytes() == (source / "native" / name).read_bytes(), "authored HIA/proof differs from frozen source")
    run_process(output, "native-build", py + [source / "scripts/run_ci.py", "build", "--source", source, "--hepta", hepta, "--output", output])
    shutil.copytree(source / "reference", output / "reference")
    env = dict(os.environ)
    env.update(CARGO_HOME=str(output / "cargo-home"), CARGO_TARGET_DIR=str(output / "rust-target"),
               RUSTC=str(rust_bin / "rustc"), RUSTUP_TOOLCHAIN="1.95.0", PATH=str(rust_bin) + os.pathsep + env.get("PATH", ""))
    run_process(output, "rust-version", [rust_bin / "rustc", "--version", "--verbose"], env=env)
    cargo = rust_bin / "cargo"; manifest = output / "reference/Cargo.toml"
    run_process(output, "cargo-fetch", [cargo, "fetch", "--locked", "--manifest-path", manifest], env=env)
    run_process(output, "cargo-metadata", [cargo, "metadata", "--locked", "--offline", "--format-version", "1", "--manifest-path", manifest], env=env)
    run_process(output, "cargo-build", [cargo, "build", "--locked", "--offline", "--manifest-path", manifest], env=env)
    from registry_evidence import inventory
    (output / "registry-evidence.json").write_bytes(canonical(inventory(source, output, capture=True)))
    binary = output / "rust-target/debug/hepta-text-publisher-params-original-oracle"
    (output / "original-binary.json").write_bytes(canonical(pin(binary)))
    import params_cases
    run_process(output, "original", [binary], data=params_cases.encoded(), env=env)
    run_process(output, "native", py + [source / "scripts/native_capture.py", "--qualification", output])
    result = read_all(source, output)
    (output / "comparison.json").write_bytes(canonical(result))
    from reader_controls import create, verify
    create(source, output, output.parent / (output.name + "-reader-controls"))
    from readonly import guarded
    control_root = output.parent / (output.name + "-reader-controls")
    def complete_read():
        evidence = read_all(source, output)
        evidence["physical_controls"] = verify(source, output, control_root)
        return evidence
    result = guarded(complete_read, roots=[output, control_root])
    (output.parent / (output.name + "-readonly.json")).write_bytes(canonical(result))
    print(json.dumps({"status": result["evidence"]["status"], "cases": result["evidence"]["native"]["cases"], "guards": len(result["probes"])}, sort_keys=True))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode", choices=("check", "build", "run", "verify"))
    p.add_argument("--source", required=True, type=Path)
    p.add_argument("--hepta", type=Path)
    p.add_argument("--rust-bin", type=Path)
    p.add_argument("--output", type=Path)
    a = p.parse_args(); source = a.source.resolve(strict=True)
    if a.mode == "check":
        evidence = source_evidence(source)
        for path in source.rglob("*.py"): ast.parse(path.read_bytes(), filename=str(path))
        print(json.dumps(dict(status="SOURCE_ONLY_PASS", files=len(evidence["files"])), sort_keys=True))
    elif a.mode == "build":
        print(json.dumps(build(source, a.hepta.resolve(strict=True), a.output.resolve(strict=True)), sort_keys=True))
    elif a.mode == "run":
        execute(source, a.hepta.resolve(strict=True), a.rust_bin.resolve(strict=True), a.output.absolute())
    else:
        from readonly import guarded
        from reader_controls import verify
        output = a.output.resolve(strict=True)
        control_root = output.parent / (output.name + "-reader-controls")
        def complete_read():
            evidence = read_all(source, output)
            evidence["physical_controls"] = verify(source, output, control_root)
            return evidence
        value = guarded(complete_read, roots=[source, output, control_root])
        print(json.dumps(value, sort_keys=True))


if __name__ == "__main__":
    main()
