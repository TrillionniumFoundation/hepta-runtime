"""Fresh locked Rust build and full original public-workdir/regex comparison."""
from pathlib import Path
import argparse
import hashlib
import io
import json
import os
import signal
import subprocess
import sys
import tarfile
import time
import tomllib

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
REMOVED_ENV = ("RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTC_BOOTSTRAP", "RUSTFLAGS",
               "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_TARGET", "RUST_TARGET_PATH")
IDENTITY_SHA256 = "2404cf048d5dddf8c0b43635c91eac4abe6968b299477398887d783fff45c4b5"


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def regular(root, name):
    require(isinstance(name, str) and name and not Path(name).is_absolute()
            and all(x not in ("", ".", "..") for x in name.split("/")), "original input path differs")
    path = root
    for part in name.split("/"):
        path /= part
        require(not path.is_symlink(), "original input contains a symlink")
    require(path.is_file(), "original input is not a file")
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repo", "native-manifest", "output", "cargo", "rustc", "rustfmt"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    root = args.repo.resolve(strict=True)
    out = args.output.resolve()
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    reference = root / "tests/hia_native/workdir_service_oracle"
    identity_raw = (reference / "source-identity.json").read_bytes()
    require(SHA(identity_raw) == IDENTITY_SHA256, "workdir original source identity differs")
    identity = json.loads(identity_raw)
    files = identity["files"]
    require(identity["schema"] == "hepta.workdir.original-project.v1"
            and identity["locked_registry_dependencies"] == 100
            and identity["remote_effects_are_unreachable_fences"] is True, "original project scope differs")
    project = out / "project"
    project.mkdir(mode=0o700)
    for name, pin in files.items():
        raw = regular(reference, name).read_bytes()
        require((len(raw), SHA(raw)) == (pin["bytes"], pin["sha256"]), "original source changed: " + name)
        target = project / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    (project / "source-identity.json").write_bytes(identity_raw)
    extraction = json.loads((project / "extraction.json").read_bytes())
    for name, pin in extraction["original_inputs"].items():
        raw = regular(root, name).read_bytes()
        require((len(raw), SHA(raw)) == (pin["bytes"], pin["sha256"]), "original runtime source changed: " + name)
    production = {(p["name"], p["version"]): p for p in tomllib.loads((project / "original-runtime.lock").read_text())["package"]}
    dependencies = [p for p in tomllib.loads((project / "Cargo.lock").read_text())["package"] if "source" in p]
    require(len(dependencies) == 100, "original dependency count differs")
    for package in dependencies:
        original = production[(package["name"], package["version"])]
        require(package["source"] == original["source"] and package["checksum"] == original["checksum"],
                "original locked dependency differs")
    sdk_package = next(p for p in dependencies if p["name"] == "rmcp")
    require(sdk_package["version"] == "3.4.1" and sdk_package["checksum"] == identity["sdk_crate_sha256"],
            "actual SDK lock differs")
    cargo_home = Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo")))
    caches = list((cargo_home / "registry/cache").glob("*/rmcp-3.4.1.crate"))
    require(len(caches) == 1, "exact SDK crate cache not unique")
    crate = caches[0].read_bytes()
    require(SHA(crate) == identity["sdk_crate_sha256"], "SDK crate checksum differs")
    sdk = cargo_home / "registry/src" / caches[0].parent.name / "rmcp-3.4.1"
    sdk_files = {}
    with tarfile.open(fileobj=io.BytesIO(crate), mode="r:gz") as archive:
        for member in archive.getmembers():
            if member.isdir():
                continue
            require(member.isfile() and member.name.startswith("rmcp-3.4.1/"), "SDK archive entry differs")
            name = member.name.removeprefix("rmcp-3.4.1/")
            raw = archive.extractfile(member).read()
            require(regular(sdk, name).read_bytes() == raw, "installed SDK source differs")
            sdk_files[name] = dict(bytes=len(raw), sha256=SHA(raw))
    require(len(sdk_files) == 175, "complete SDK source inventory differs")
    env = dict(os.environ)
    for name in REMOVED_ENV:
        env.pop(name, None)
    for name in list(env):
        if name.startswith("HIA_"):
            env.pop(name)
    (out / "tmp").mkdir(mode=0o700)
    env.update(RUSTC=str(args.rustc), RUSTFMT=str(args.rustfmt),
               CARGO_TARGET_DIR=str(out / "target"), TMPDIR=str(out / "tmp"))
    source_names = ("tests/hia_native/compare_workdir_service_original.py", "tests/hia_native/probe_workdir_original.py",
        "tests/hia_native/compare_workdir_original.py", "tests/hia_native/test_workdir_service_regex.py",
        "tests/hia_native/test_workdir_params.py", "scripts/hia_native_loader.py")
    source_pins = {name: SHA(regular(root, name).read_bytes()) for name in source_names}
    manifest_path = args.native_manifest.resolve(strict=True)
    manifest = json.loads(manifest_path.read_bytes())
    native = manifest_path.parent / manifest["executable"]
    require(SHA(native.read_bytes()) == manifest["elf_sha256"] and len(manifest["members"]) == 21,
            "selected native workdir executable differs")
    native_sha = SHA(native.read_bytes())
    started = time.monotonic()
    report = dict(schema="hepta.workdir.fresh-original-comparison.v1", status="FAIL", checks=[],
        original_source_identity_sha256=IDENTITY_SHA256, original_project_files=files,
        source_sha256=source_pins, native_manifest_sha256=SHA(manifest_path.read_bytes()),
        native_executable_sha256=native_sha, locked_registry_dependencies=100, sdk_files=sdk_files,
        sdk_crate_sha256=SHA(crate), sdk_installed_files_verified=175,
        removed_environment_keys=list(REMOVED_ENV), rust_runtime_fallback=False,
        remote_effects_are_unreachable_fences=True, remote_execution_qualified=False,
        production_activated=False, whole_runtime_replaced=False, old_stack_removal_qualified=False)
    def save():
        (out / "result.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    def run(name, argv):
        begin = time.monotonic()
        process = subprocess.Popen(argv, cwd=project, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True)
        timed = False
        try:
            stdout, stderr = process.communicate(timeout=180)
        except subprocess.TimeoutExpired:
            timed = True
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate(timeout=3)
        record = dict(name=name, command=argv, pid=process.pid, exit_code=process.returncode,
            timed_out=timed, reaped=True, timeout_seconds=180, elapsed_seconds=time.monotonic() - begin)
        for channel, raw in (("stdout", stdout), ("stderr", stderr)):
            (out / (name + "." + channel)).write_bytes(raw)
            record[channel + "_bytes"] = len(raw)
            record[channel + "_sha256"] = SHA(raw)
        report["checks"].append(record)
        save()
        require(not timed and process.returncode == 0, (name, record, stderr[-12000:].decode(errors="replace")))
        return stdout
    try:
        version = run("rust-version", [str(args.rustc), "-vV"]).decode()
        require(version.startswith("rustc 1.95.0 "), "original compiler version differs")
        report["rust_version"] = version
        run("format-check", [str(args.rustfmt), "--check", "--edition", "2021", "--config",
                              "hard_tabs=true,skip_children=true", str(project / "owner/oracle_workdir.rs")])
        run("build", [str(args.cargo), "build", "--release", "--locked", "--offline", "--manifest-path",
                       str(project / "Cargo.toml"), "--bin", "hia-workdir-reference"])
        binary = out / "target/release/hia-workdir-reference"
        binary_sha = SHA(binary.read_bytes())
        report["original_executable_sha256"] = binary_sha
        report["probe"] = json.loads(run("original-probe", [sys.executable, "-I", "-B",
            str(root / "tests/hia_native/probe_workdir_original.py"), str(out)]))
        require(report["probe"]["status"] == "PASS" and report["probe"]["typed_cases"] == 680
                and report["probe"]["public_cases"] == 15 and report["probe"]["priority_cases"] == 3,
                "complete fresh original probe differs")
        by_name = {row["name"]: row for row in manifest["members"]}
        report["parameters"] = json.loads(run("fresh-parameter-join", [sys.executable, "-I", "-B",
            str(root / "tests/hia_native/test_workdir_params.py"), "--manifest",
            str(manifest_path.parent / by_name["params"]["manifest"]), "--value-manifest",
            str(manifest_path.parent / by_name["value"]["manifest"]), "--cases",
            str(out / "probe-v1/parameters.json"), "--output", str(out / "parameters")]))
        require(report["parameters"]["status"] == "PASS" and report["parameters"]["native_cases"] == 680,
                "fresh original parameter join incomplete")
        report["public"] = json.loads(run("complete-public", [sys.executable, "-I", "-B",
            str(root / "tests/hia_native/compare_workdir_original.py"), "--native-manifest", str(manifest_path),
            "--original", str(binary), "--parameter-cases", str(out / "probe-v1/parameters.json"),
            "--output", str(out / "public")]))
        require(report["public"]["status"] == "PASS"
                and report["public"]["actual_native_requests"] == report["public"]["actual_original_requests"] == 1537
                and report["public"]["actual_native_processes"] == report["public"]["actual_original_processes"] == 74,
                "complete original public domain differs")
        report["regex"] = json.loads(run("installed-regex", [sys.executable, "-I", "-B",
            str(root / "tests/hia_native/test_workdir_service_regex.py"), "--manifest", str(manifest_path),
            "--original", str(binary), "--original-sha256", binary_sha, "--output", str(out / "regex")]))
        require(report["regex"]["status"] == "PASS"
                and report["regex"]["native_processes"] == report["regex"]["original_processes"] == 18
                and report["regex"]["native_requests"] == report["regex"]["original_requests"] == 36,
                "complete original regex configuration domain differs")
        for name, pin in files.items():
            require(SHA(regular(project, name).read_bytes()) == pin["sha256"]
                    and SHA(regular(reference, name).read_bytes()) == pin["sha256"], "original source changed during execution")
        require(all(SHA(regular(root, name).read_bytes()) == digest for name, digest in source_pins.items())
                and SHA(native.read_bytes()) == native_sha
                and SHA(binary.read_bytes()) == binary_sha
                and SHA(manifest_path.read_bytes()) == report["native_manifest_sha256"],
                "source or executable changed during comparison")
        report.update(status="PASS", source_unchanged=True, elapsed_seconds=time.monotonic() - started)
    except BaseException as error:
        report["error"] = repr(error)
        raise
    finally:
        save()
    print(json.dumps({k: v for k, v in report.items() if k not in ("checks", "sdk_files", "original_project_files")}, sort_keys=True))


if __name__ == "__main__":
    main()
