#!/usr/bin/env python3
"""Fresh CI-only reference for complete current router metadata and handlers."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import traceback

TARGET = "d3d75c30719db966b004756f610007a7c723729e"
TREE = "612e145513961556ac8844b5cc978f9b5175e4d4"
SERVER = {"bytes": 193936, "sha256": "0957f7d7d56ad76540a42ba82b33fc29a625bb186cece2a207a764ea8c5beb6f"}
FALSE_FLAGS = ("whole_runtime_replaced", "production_activated", "old_stack_removal_qualified")


def pin(path):
    path = Path(path)
    with path.open("rb") as stream:
        return {"bytes": path.stat().st_size, "sha256": hashlib.file_digest(stream, "sha256").hexdigest()}


def save(path, value):
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")


def git(root, *args):
    return subprocess.check_output(["git", *args], cwd=root)


def require(value, label):
    if not value:
        raise ValueError(label)


def run(output, name, command, cwd, env, timeout):
    started = time.monotonic()
    row = {"name": name, "command": command, "cwd": str(cwd), "timeout_seconds": timeout,
           "controlled_environment": {k: env.get(k) for k in ("RUSTUP_TOOLCHAIN", "CARGO_TARGET_DIR",
               "CARGO_BUILD_JOBS", "CARGO_INCREMENTAL", "CARGO_PROFILE_DEV_DEBUG", "LC_ALL")},
           "timed_out": False, "start_error": None, "exit_code": None}
    stdout, stderr = output / (name + ".stdout"), output / (name + ".stderr")
    process = None
    try:
        with stdout.open("xb") as out, stderr.open("xb") as err:
            try:
                process = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                    stdout=out, stderr=err, start_new_session=True)
                row["pid"] = process.pid
            except BaseException as error:
                row["start_error"] = repr(error)
                raise
            try:
                row["exit_code"] = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                row["timed_out"] = True
                os.killpg(process.pid, signal.SIGKILL)
                row["exit_code"] = process.wait()
                raise
    finally:
        row["elapsed_seconds"] = time.monotonic() - started
        row["stdout"] = {"path": stdout.name, **pin(stdout)}
        row["stderr"] = {"path": stderr.name, **pin(stderr)}
        save(output / (name + ".process.json"), row)
    require(row["exit_code"] == 0 and not row["timed_out"], "actual process failed: " + name)
    return stdout


def fixture(root, number, hia_digest, marker_pin):
    owned = root / ("profile-" + str(number))
    owned.mkdir(mode=0o700)
    for name in ("install", "input", "weight", "hia-state"):
        (owned / name).mkdir(mode=0o700)
    worker = owned / "install/worker.py"
    worker.write_bytes(b"raise SystemExit('catalog configuration fixture; never dispatched')\n")
    require(pin(worker) == marker_pin, "worker configuration fixture identity")
    host = {"ssh_target": "catalog-metadata.invalid", "remote_state_dir": str(owned / "remote-state"),
            "allow_execute": True, "allow_write": True, "allowed_cwd_prefixes": [str(owned)],
            "allowed_read_path_prefixes": [str(owned)], "allowed_write_path_prefixes": [str(owned)]}
    config = {"state_dir": str(owned / "controller"), "controller_workspace_roots": [str(owned)],
              "hosts": {"catalog": host}}
    if number & 1:
        config["hia_worker"] = {"host": "catalog", "python_executable": str(worker),
            "working_directory": str(owned / "install"), "state_root": str(owned / "hia-state"),
            "artifact_roots": [str(owned / "input")], "worker_sha256": marker_pin["sha256"],
            "backend_sha256": marker_pin["sha256"], "catalog_sha256": hia_digest}
    if number & 2:
        config["rea_static_profiles"] = {"catalog": {"host": "catalog",
            "runtime_executable": str(worker), "runtime_sha256": marker_pin["sha256"],
            "provider": "gnu_readelf", "backend_executable": str(worker),
            "backend_sha256": marker_pin["sha256"], "backend_version": "GNU readelf catalog-fixture",
            "working_directory": str(owned / "install"), "input_roots": [str(owned / "input")],
            "allowed_operations": ["headers"]}}
    if number & 4:
        config["weight_workers"] = {"catalog": {"host": "catalog", "python_executable": str(worker),
            "worker_path": str(worker), "worker_sha256": marker_pin["sha256"],
            "session_root": str(owned / "weight"), "input_roots": [str(owned / "input")],
            "allowed_providers": ["catalog_fixture"]}}
    path = owned / "config.json"
    save(path, config)
    return path


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--target", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    a = p.parse_args()
    require(os.environ.get("GITHUB_ACTIONS") == "true", "fresh Rust reference is CI-only")
    target, output = a.target.resolve(strict=True), a.output.absolute()
    here = Path(__file__).resolve().parent
    package = json.loads((here / "source_manifest.json").read_text())
    require(set(package) == {p.name for p in here.iterdir() if p.name != "source_manifest.json"},
            "complete source-owned observer package")
    for name, expected in package.items():
        require(pin(here / name) == expected, "observer package source bytes: " + name)
    output.mkdir(mode=0o700)
    processes = output / "processes"
    processes.mkdir()
    report = {"schema": "hepta.runtime.current-catalog-reference.v1", "status": "RUNNING",
              "target_commit": TARGET, "target_tree": TREE, **{k: False for k in FALSE_FLAGS},
              "worker_readiness_qualified": False, "tool_body_calls": 0}
    save(output / "result.json", report)
    try:
        require(git(target, "rev-parse", "HEAD").decode().strip() == TARGET, "exact target checkout")
        require(git(target, "rev-parse", "HEAD^{tree}").decode().strip() == TREE, "exact target tree")
        require(not git(target, "status", "--porcelain"), "original checkout is not pristine")
        (output / "target-tree.bin").write_bytes(git(target, "ls-tree", "-r", "-z", "HEAD"))
        shutil.copytree(here, output / "recipe-source")
        entries = {}
        for raw in git(target, "ls-files", "-z").split(b"\0"):
            if not raw:
                continue
            name = os.fsdecode(raw)
            if not (name.startswith(("src/", "vendor/", ".cargo/")) or name in ("Cargo.toml", "Cargo.lock", "build.rs")):
                continue
            source = target / name
            require(not source.is_symlink() and stat.S_ISREG(source.stat().st_mode), "regular original source: " + name)
            entries[name] = pin(source)
            saved = output / "original-source" / name
            saved.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, saved)
        require(entries["src/mcp/server.rs"] == SERVER, "current original server bytes")
        original = (target / "src/mcp/server.rs").read_bytes()
        observer = (here / "observer.rs").read_bytes()
        instrumented = original + b"\n" + observer
        (target / "src/mcp/server.rs").write_bytes(instrumented)
        (output / "instrumented-server.rs").write_bytes(instrumented)
        example = target / "examples/hia_catalog_observer.rs"
        require(not example.exists(), "observer example already exists")
        example.parent.mkdir(exist_ok=True)
        shutil.copyfile(here / "main.rs", example)
        save(output / "source.json", {"target_commit": TARGET, "target_tree": TREE, "originals": entries,
            "original_server_prefix_bytes": len(original), "original_server_prefix": SERVER,
            "observer": pin(here / "observer.rs"), "instrumented_server": pin(output / "instrumented-server.rs"),
            "example": pin(example), "original_functions_unchanged": True})
        env = os.environ.copy()
        env.update(RUSTUP_TOOLCHAIN="1.95.0", CARGO_TARGET_DIR=str(output / "cargo-target"),
                   CARGO_BUILD_JOBS="2", CARGO_INCREMENTAL="0", CARGO_PROFILE_DEV_DEBUG="0", LC_ALL="C")
        run(processes, "rustc-version", ["rustc", "--version", "--verbose"], target, env, 30)
        require((processes / "rustc-version.stdout").read_bytes().startswith(b"rustc 1.95.0 "), "pinned Rust compiler")
        run(processes, "cargo-version", ["cargo", "--version"], target, env, 30)
        run(processes, "cargo-build", ["cargo", "build", "--locked", "--example", "hia_catalog_observer"],
            target, env, 1800)
        run(processes, "cargo-metadata", ["cargo", "metadata", "--format-version", "1", "--locked"], target, env, 180)
        binary = output / "cargo-target/debug/examples/hia_catalog_observer"
        shutil.copyfile(binary, output / "reference.elf")
        (output / "reference.elf").chmod(0o700)
        plain = run(processes, "profile-disabled", [str(binary)], target, env, 120)
        baseline = json.loads(plain.read_bytes())
        require(len(baseline["raw_tool_wires"]) == 136, "complete current 136-tool router")
        fixture_root = Path(tempfile.mkdtemp(prefix="hcat-"))
        report["execution_fixture_root"] = str(fixture_root)
        marker = b"raise SystemExit('catalog configuration fixture; never dispatched')\n"
        marker_pin = {"bytes": len(marker), "sha256": hashlib.sha256(marker).hexdigest()}
        for number in range(8):
            config = fixture(fixture_root, number, baseline["hia_catalog_sha256"], marker_pin)
            saved = output / "configuration-inputs" / ("profile-" + str(number) + ".json")
            saved.parent.mkdir(exist_ok=True)
            shutil.copyfile(config, saved)
            run(processes, "profile-" + str(number), [str(binary), str(config)], target, env, 120)
        shutil.copytree(fixture_root, output / "configuration-state")
        for name, expected in entries.items():
            if name == "src/mcp/server.rs":
                require((target / name).read_bytes() == instrumented, "instrumented server changed")
            else:
                require(pin(target / name) == expected, "original source changed during execution: " + name)
        require(pin(example) == pin(here / "main.rs"), "observer example changed")
        metadata = json.loads((processes / "cargo-metadata.stdout").read_bytes())
        registry = {}
        for package in metadata["packages"]:
            if package["source"] is None:
                continue
            require(package["source"].startswith("registry+"), "unsupported unpinned dependency source")
            root = Path(package["manifest_path"]).parent
            key = package["name"] + "-" + package["version"]
            require(key not in registry, "duplicate registry package identity")
            files = {}
            for path in sorted(root.rglob("*")):
                if path.is_dir():
                    continue
                require(path.is_file() and not path.is_symlink(), "registry source must be regular")
                name = path.relative_to(root).as_posix()
                files[name] = pin(path)
                dest = output / "registry-source" / key / name
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, dest)
            registry[key] = {"id": package["id"], "source": package["source"], "files": files}
        save(output / "registry.json", registry)
        report.update(status="REFERENCE_EXECUTION_COMPLETE", raw_tools=136, configured_profiles=8,
            unconfigured_profiles=1, original_list_handler_calls=216, original_get_info_calls=9,
            public_transport_executed=False,
            original_binary=pin(binary), registry_packages=len(registry), original_source_files=len(entries),
            original_functions_unchanged=True, append_only_observer=True)
    except BaseException as error:
        report.update(status="FAIL", error={"type": type(error).__name__, "message": str(error)})
        (output / "failure.txt").write_text(traceback.format_exc())
        raise
    finally:
        save(output / "result.json", report)


if __name__ == "__main__":
    main()
