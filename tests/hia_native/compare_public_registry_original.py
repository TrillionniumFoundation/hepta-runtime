#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Fresh locked SDK/config/execution reference against the real fixed HIA ELF."""
from pathlib import Path
import argparse
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from public_registry_registry import REMOVED_ENVIRONMENT, source_pins
from hia_native_public_registry_reference import prepare_original_reference, check_project
from hia_native_public_registry_qualification import verify_build, verify_cases

sha = lambda raw: hashlib.sha256(raw).hexdigest()
encoded = lambda value: (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
SDK_SHA = "5b6317cd8c13e3ec9033cf2aa5aa92cd743f0f4f8a93cddc42ea0ae6ce3b8898"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--build", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--cargo", required=True, type=Path)
    parser.add_argument("--rustc", required=True, type=Path)
    parser.add_argument("--rustfmt", required=True, type=Path)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    root = args.repo.resolve(strict=True)
    if root != ROOT:
        raise ValueError("public reference driver is not owned by the selected source root")
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    build = args.build.resolve(strict=True)
    native = verify_build(root, build)
    bundle = json.loads(build.read_bytes())
    manifest = Path(bundle["executable"]["path"])
    meta = json.loads(manifest.read_bytes())
    binary = manifest.parent / meta["executable"]
    pins = source_pins(root)
    before = sha(build.read_bytes())
    cargo, rustc, rustfmt = (p.absolute() for p in (args.cargo, args.rustc, args.rustfmt))
    env = {k: v for k, v in os.environ.items() if not k.startswith("HIA_") and k not in REMOVED_ENVIRONMENT}
    env.update(RUSTC=str(rustc), CARGO_TARGET_DIR=str(output / "target"), CARGO_NET_OFFLINE="true" if args.offline else "false")
    begun = time.monotonic()
    result = {"schema": "hepta.public-registry.original-result.v1", "status": "RUNNING", "sources": pins,
        "build_sha256": before, "native_build_evidence": native,
        "cargo": str(cargo), "rustc": str(rustc), "rustfmt": str(rustfmt),
        "tool_sha256": {str(p): sha(p.resolve(strict=True).read_bytes()) for p in (cargo, rustc, rustfmt)},
        "processes": [], "artifacts": {}, "fresh_actual_cargo_build": False,
        "native_processes_in_recipe": 0, "original_processes_in_recipe": 0,
        "native_responses_in_recipe": 0, "original_responses_in_recipe": 0,
        "public_audit_result_lifecycle_closed": False,
        "environment": {"removed": list(REMOVED_ENVIRONMENT), "removed_prefixes": ["HIA_"],
            "RUSTC": str(rustc), "CARGO_TARGET_DIR": str(output / "target"), "offline": args.offline}}

    def save():
        result["elapsed_seconds"] = time.monotonic() - begun
        (output / "result.json").write_bytes(encoded(result))

    def keep(path):
        result["artifacts"][path.relative_to(output).as_posix()] = sha(path.read_bytes())

    def run(name, command, cwd, timeout):
        started = time.monotonic()
        code, timed, start_error = None, False, None
        try:
            process = subprocess.run(list(map(str, command)), cwd=cwd, env=env,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
            out, err, code = process.stdout, process.stderr, process.returncode
        except subprocess.TimeoutExpired as error:
            out, err, timed = error.stdout or b"", error.stderr or b"", True
        except OSError as error:
            out, err, start_error = b"", b"", repr(error)
        for suffix, raw in (("stdout", out), ("stderr", err)):
            path = output / (name + "." + suffix)
            path.write_bytes(raw)
            keep(path)
        record = {"name": name, "command": list(map(str, command)), "cwd": str(cwd), "exit_code": code,
            "timed_out": timed, "start_error": start_error, "timeout_seconds": timeout,
            "elapsed_seconds": time.monotonic() - started, "stdout_sha256": sha(out), "stdout_bytes": len(out),
            "stderr_sha256": sha(err), "stderr_bytes": len(err)}
        result["processes"].append(record)
        save()
        if timed or start_error is not None or code != 0:
            raise ValueError("actual public reference process failed: " + name)
        return out, err

    save()
    try:
        project = output / "project"
        prepared = prepare_original_reference(root, project)
        for name in [*prepared["files"], "reference-inputs.json"]:
            keep(project / name)
        version, err = run("rustc-version", [rustc, "--version", "--verbose"], root, 10)
        if err or b"release: 1.95.0\n" not in version:
            raise ValueError("public original requires the explicit Rust 1.95 toolchain")
        # Stable rustfmt accepts this single-file boundary through --config;
        # reading skip_children from a config file ignores it as unstable and
        # would traverse cfg(test) modules outside the original projection.
        run("rustfmt-check", [rustfmt, "--edition", "2021", "--check", "--config",
            "hard_tabs=true,skip_children=true", project / "mcp/oracle_mcp.rs"], root, 15)
        run("cargo-fetch", [cargo, "fetch", "--locked", *(["--offline"] if args.offline else [])], project, 120)
        cargo_home = Path(env.get("CARGO_HOME", str(Path.home() / ".cargo")))
        caches = list((cargo_home / "registry/cache").glob("*/rmcp-3.4.1.crate"))
        if len(caches) != 1:
            raise ValueError("locked SDK crate is not unique")
        crate = caches[0].read_bytes()
        if sha(crate) != SDK_SHA:
            raise ValueError("locked SDK crate changed")
        sdk = cargo_home / "registry/src" / caches[0].parent.name / "rmcp-3.4.1"
        sdk_files = {}
        with tarfile.open(fileobj=io.BytesIO(crate), mode="r:gz") as archive:
            for item in archive:
                if not item.isfile() or not item.name.startswith("rmcp-3.4.1/"):
                    continue
                name = item.name.removeprefix("rmcp-3.4.1/")
                raw = archive.extractfile(item).read()
                path = sdk / name
                if path.is_symlink() or path.read_bytes() != raw or name in sdk_files:
                    raise ValueError("installed SDK bytes differ from the locked crate")
                sdk_files[name] = {"bytes": len(raw), "sha256": sha(raw)}
                retained = output / "sdk" / name
                retained.parent.mkdir(parents=True, exist_ok=True)
                retained.write_bytes(raw)
                keep(retained)
        if len(sdk_files) != 175 or sum(name.startswith("src/") for name in sdk_files) != 65:
            raise ValueError("complete SDK source domain changed")
        (output / "rmcp-3.4.1.crate").write_bytes(crate)
        keep(output / "rmcp-3.4.1.crate")
        result.update(sdk_crate_sha256=SDK_SHA, sdk_files=sdk_files, sdk_installed_files_verified=175, sdk_source_files_verified=65,
            locked_registry_dependencies=100, config_source_blocks=54, public_server_blocks=10, hia_catalog_predicate_blocks=1)
        run("cargo-build", [cargo, "build", "--release", "--locked", "--bin", "hia-runtime-config-mcp",
            *(["--offline"] if args.offline else [])], project, 120)
        result["fresh_actual_cargo_build"] = True
        original = output / "target/release/hia-runtime-config-mcp"
        result["original_binary"] = {"path": str(original), "bytes": original.stat().st_size,
            "sha256_before": sha(original.read_bytes())}
        keep(original)
        catalog, err = run("catalog", [original, "--catalog"], project, 15)
        expected = json.loads((root / "tests/hia_native/public_registry_catalog.json").read_bytes())
        if err or catalog != (expected["legacy"] + "\n" + expected["modern"] + "\n").encode():
            raise ValueError("actual original schema/catalog bytes differ")
        for label, executable in (("native", binary), ("original", original)):
            run(label + "-sessions", [sys.executable, "-I", "-B", root / "tests/hia_native/run_public_registry_cases.py",
                "--binary", executable, "--output", output / label, "--label", label], root, 120)
            checked = verify_cases(root, output / label, sha(executable.read_bytes()), label)
            result[label + "_processes_in_recipe"] = checked["sessions"]
            result[label + "_responses_in_recipe"] = checked["responses"]
            for name in ("cases.json", "output.jsonl", "processes.jsonl", "result.json"):
                keep(output / label / name)
        left, right = (output / "native/output.jsonl").read_bytes(), (output / "original/output.jsonl").read_bytes()
        if left != right:
            raise ValueError("complete actual native/original session outputs differ")
        result.update(complete_output_sha256=sha(left), complete_output_bytes=len(left), complete_byte_equality=True)
        check_project(root, project, prepared)
        if (source_pins(root) != pins or sha(build.read_bytes()) != before
                or verify_build(root, build) != native or sha(original.read_bytes()) != result["original_binary"]["sha256_before"]):
            raise ValueError("public reference input or executable changed during replay")
        for name, row in sdk_files.items():
            if sha((sdk / name).read_bytes()) != row["sha256"]:
                raise ValueError("installed SDK source changed during replay")
        result["original_binary"]["sha256_after"] = result["original_binary"]["sha256_before"]
        result["status"] = "PASS"
    except BaseException as error:
        result.update(status="FAIL", error=type(error).__name__ + ": " + str(error))
        raise
    finally:
        save()
        print(json.dumps({key: value for key, value in result.items()
            if key not in ("sources", "native_build_evidence", "processes", "artifacts", "sdk_files")}, sort_keys=True))


if __name__ == "__main__":
    main()
