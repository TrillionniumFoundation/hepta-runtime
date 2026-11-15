#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Locate qualified existing A26 artifacts and optionally compile, never run, the probe."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import tomllib


HERE = Path(__file__).resolve().parent


def need(value, message):
    if not value:
        raise ValueError(message)


def stamp(value):
    return (value.st_dev, value.st_ino, value.st_uid, value.st_mode, value.st_nlink,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def receipt(path, include_bytes=False):
    path = Path(path)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode), "regular nonsymlink input required: " + str(path))
    digest = hashlib.sha256()
    chunks = []
    captured_bytes = 0
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        need(stamp(before) == stamp(os.fstat(stream.fileno())), "input changed while opening")
        while block := stream.read(1024 * 1024):
            digest.update(block)
            if include_bytes:
                chunks.append(block)
                captured_bytes += len(block)
                need(captured_bytes <= 32 * 1024 * 1024, "text input exceeds fixed bound")
        need(stamp(before) == stamp(os.fstat(stream.fileno())) == stamp(path.lstat()),
             "input changed while hashing")
    value = {"path": str(path), "sha256": digest.hexdigest(), "bytes": before.st_size,
             "stamp": list(stamp(before))}
    return (value, b"".join(chunks)) if include_bytes else value


def write_new(path, data):
    with path.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def checkpoint(directory, report):
    temporary = directory / "build.json.next"
    write_new(temporary, (json.dumps(report, indent=2, sort_keys=True) + "\n").encode())
    os.replace(temporary, directory / "build.json")
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def parse_artifacts(raw):
    records = []
    for line in raw.decode().splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            records.append(row)
    return records


def select_dependency(records, name, locked):
    found = [row for row in records
             if row.get("reason") == "compiler-artifact"
             and row.get("target", {}).get("name") == name
             and row.get("profile", {}).get("test") is False
             and "lib" in row.get("target", {}).get("kind", [])
             and any(Path(value).suffix == ".rlib" for value in row.get("filenames", []))]
    need(len(found) == 1, "unique release compiler-artifact required for " + name)
    row = found[0]
    paths = [Path(value) for value in row["filenames"] if Path(value).suffix == ".rlib"]
    need(len(paths) == 1 and paths[0].is_absolute(), "unique absolute rlib required for " + name)
    manifest_receipt, raw_manifest = receipt(Path(row["manifest_path"]), True)
    package = tomllib.loads(raw_manifest.decode())["package"]
    need(package["name"] == name and isinstance(package["version"], str), "dependency manifest mismatch")
    source, fragment = row["package_id"].rsplit("#", 1)
    version = package["version"]
    need(fragment in (version, name + "@" + version), "compiler package ID/version mismatch")
    matches = [value for value in locked["package"] if value["name"] == name
               and value["version"] == version and value.get("source") == source]
    need(len(matches) == 1, "compiler dependency absent or ambiguous in qualified Cargo.lock")
    return {"name": name, "version": version, "package_id": row["package_id"],
            "compiler_artifact": row, "manifest": manifest_receipt, "rlib": receipt(paths[0]),
            "lock_package": matches[0]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qualification", type=Path, required=True)
    parser.add_argument("--qualification-receipt", type=Path, required=True)
    parser.add_argument("--rustc", type=Path, required=True,
                        help="already installed actual rustc executable; rustup proxy is rejected")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--compile", action="store_true",
                        help="compile once only after the complete A26 series has finished")
    args = parser.parse_args()
    output = args.output_dir.absolute()
    need(not os.path.lexists(output), "fresh output directory required")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.mkdir(mode=0o700)
    os.umask(0o077)
    result = {"schema": "hepta-x230-full-file-hash-microprobe-build/v1", "prepared": False,
              "compiled": False, "probe_executed": False, "compile_requested": args.compile,
              "started_unix": time.time(), "automatic_retries": 0, "dependency_downloads": 0}
    checkpoint(output, result)
    try:
        qreceipt, qraw = receipt(args.qualification.absolute(), True)
        ireceipt, iraw = receipt(args.qualification_receipt.absolute(), True)
        qualification, independent = json.loads(qraw), json.loads(iraw)
        need(qualification.get("schema") == "runtime-candidate-qualification/v1"
             and qualification.get("qualified") is True
             and qualification.get("current_stage") == "complete", "qualification is not complete")
        need(independent.get("schema") == "hepta-x230-qualification-independent-receipt/v1"
             and independent.get("candidate") == "A26" and independent.get("qualified") is True
             and independent.get("source_report_sha256") == qreceipt["sha256"]
             and independent.get("unmet_checks") == [], "independent A26 qualification receipt differs")
        need(qualification.get("source_tested") == qualification.get("source_after"),
             "qualification source maps differ")
        source = Path(qualification["source"])
        need(source.is_absolute() and source.is_dir() and not source.is_symlink(), "qualified source root missing")
        need(not output.is_relative_to(source), "probe output must be separate from qualified source")
        lock_receipt, lock_raw = receipt(source / "Cargo.lock", True)
        cargo_manifest, cargo_raw = receipt(source / "Cargo.toml", True)
        release_profile = tomllib.loads(cargo_raw.decode()).get("profile", {}).get("release", {})
        need(release_profile.get("panic") == "abort",
             "qualified release Cargo.toml must specify panic=abort for the existing release rlibs")
        profile_receipt = receipt(source / "src/mcp/runtime/ssh_observation_profile.rs")
        format_config, format_raw = receipt(source / "rustfmt.toml", True)
        need(tomllib.loads(format_raw.decode()).get("hard_tabs") is True,
             "qualified rustfmt configuration does not require hard tabs")
        for value in (lock_receipt, cargo_manifest, profile_receipt, format_config):
            relative = str(Path(value["path"]).relative_to(source))
            need(qualification["source_after"].get(relative) == value["sha256"], "qualified source input changed")
        binary_receipt = receipt(Path(qualification["binary"]["path"]))
        need(binary_receipt["sha256"] == qualification["binary"]["sha256"], "qualified A26 binary changed")
        releases = [row for row in qualification["stages"] if row.get("name") == "release"]
        need(len(releases) == 1 and releases[0].get("returncode") == 0, "unique successful release stage required")
        release = releases[0]
        release_receipt, release_raw = receipt(args.qualification.absolute().parent / "release.log", True)
        need(release_receipt["sha256"] == release["log_sha256"], "release compiler-artifact log changed")
        command = release["command"]
        need(len(command) > 2 and Path(command[0]).name == "cargo"
             and re.fullmatch(r"\+\d+\.\d+\.\d+", command[1]) is not None,
             "explicit qualified stable toolchain required")
        toolchain = command[1][1:]
        need(toolchain == "1.95.0", "this frozen experiment requires the qualified 1.95.0 toolchain")
        records = parse_artifacts(release_raw)
        runtime = [row for row in records if row.get("reason") == "compiler-artifact"
                   and row.get("target", {}).get("name") == "hepta-runtime"
                   and row.get("profile", {}).get("test") is False]
        need(len(runtime) == 1 and Path(runtime[0]["manifest_path"]) == source / "Cargo.toml"
             and Path(runtime[0]["target"]["src_path"]) == source / "src/main.rs",
             "release log does not identify qualified runtime source")
        need(receipt(Path(runtime[0]["executable"]))["sha256"] == binary_receipt["sha256"],
             "original compiler artifact differs from qualified runtime copy")
        locked = tomllib.loads(lock_raw.decode())
        deps = {name: select_dependency(records, name, locked) for name in ("ring", "libc")}
        dependency_dir = Path(deps["ring"]["rlib"]["path"]).parent
        need(Path(deps["libc"]["rlib"]["path"]).parent == dependency_dir
             and dependency_dir == Path(runtime[0]["executable"]).parent / "deps",
             "selected dependencies are not in the actual release artifact directory")
        # Hash every release rlib available to rustc from this dependency directory.
        # Paths come exclusively from this qualification's compiler-artifact records.
        rlibs = sorted({str(Path(value)) for row in records if row.get("reason") == "compiler-artifact"
                        for value in row.get("filenames", [])
                        if Path(value).suffix == ".rlib" and Path(value).parent == dependency_dir})
        need(bool(rlibs), "no release rlibs recorded")
        native_paths, native_archives = set(), set()
        for row in records:
            if row.get("reason") != "build-script-executed" or row.get("package_id") != deps["ring"]["package_id"]:
                continue
            paths = []
            for value in row.get("linked_paths", []):
                path = Path(value.removeprefix("native="))
                need(path.is_absolute() and path.is_dir(), "ring native search path missing")
                paths.append(path)
                native_paths.add(str(path))
            for value in row.get("linked_libs", []):
                need(value.startswith("static="), "unexpected ring link-library kind")
                name = value.removeprefix("static=")
                need(re.fullmatch(r"[A-Za-z0-9_]+", name) is not None, "unexpected ring archive name")
                matches = [path / ("lib" + name + ".a") for path in paths if (path / ("lib" + name + ".a")).is_file()]
                need(len(matches) == 1, "unique recorded ring native archive required")
                native_archives.add(str(matches[0]))
        rustc = args.rustc.resolve(strict=True)
        need(args.rustc.is_absolute() and rustc.name == "rustc", "actual installed rustc required, not rustup proxy")
        rustfmt = rustc.with_name("rustfmt").resolve(strict=True)
        need(rustfmt.parent == rustc.parent and rustfmt.name == "rustfmt",
             "rustfmt must be the actual executable from the same installed toolchain")
        for name in ("hash_buffer_probe.rs", "PLAN.json", "PLAN.md"):
            _, raw = receipt(HERE / name, True)
            write_new(output / name, raw)
        write_new(output / "hash_buffer_probe.input.rs", (output / "hash_buffer_probe.rs").read_bytes())
        format_command = [str(rustfmt), "--edition", "2021", "--config-path", format_config["path"],
                          str(output / "hash_buffer_probe.rs")]
        compile_command = [str(rustc), "--edition=2021", "--crate-name", "hepta_hash_buffer_probe",
                           "-C", "opt-level=3", "-C", "debuginfo=0", "-C", "panic=abort",
                           str(output / "hash_buffer_probe.rs"),
                           "--extern", "ring=" + deps["ring"]["rlib"]["path"],
                           "--extern", "libc=" + deps["libc"]["rlib"]["path"],
                           "-L", "dependency=" + str(dependency_dir)]
        for path in sorted(native_paths):
            compile_command += ["-L", "native=" + path]
        compile_command += ["-o", str(output / "hash-buffer-probe")]
        paths = sorted(set(rlibs) | native_archives | {str(rustc), str(rustfmt), str(args.qualification.absolute()),
            str(args.qualification_receipt.absolute()), release_receipt["path"], lock_receipt["path"], cargo_manifest["path"],
            profile_receipt["path"], format_config["path"], binary_receipt["path"], str(HERE / "prepare_hash_probe.py"),
            *(value["manifest"]["path"] for value in deps.values()),
            *(str(output / name) for name in ("hash_buffer_probe.rs", "hash_buffer_probe.input.rs", "PLAN.json", "PLAN.md"))})
        before = {path: receipt(Path(path)) for path in paths}
        result.update(prepared=True, qualification=qreceipt, independent_receipt=ireceipt,
                      qualified_runtime_binary=binary_receipt, qualified_toolchain=toolchain,
                      qualified_cargo_manifest=cargo_manifest, qualified_release_panic_strategy="abort",
                      dependencies=deps, native_search_paths=sorted(native_paths),
                      compile_command=compile_command, inputs_before=before,
                      format_command=format_command, rustfmt_config=format_config,
                      source_input=before[str(output / "hash_buffer_probe.input.rs")],
                      source_before_format=before[str(output / "hash_buffer_probe.rs")],
                      qualification_source_map_sha256=hashlib.sha256(json.dumps(
                          qualification["source_after"], sort_keys=True, separators=(",", ":")).encode()).hexdigest())
        checkpoint(output, result)
        if args.compile:
            version = subprocess.run([str(rustc), "-vV"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
            write_new(output / "rustc-version.log", version.stdout)
            need(version.returncode == 0, "installed compiler version lookup failed")
            fields = dict(line.split(": ", 1) for line in version.stdout.decode().splitlines() if ": " in line)
            need(fields.get("release") == toolchain and fields.get("host") == "x86_64-unknown-linux-gnu",
                 "installed compiler differs from qualified x230 toolchain")
            with (output / "format.stdout.log").open("xb") as stdout, (output / "format.stderr.log").open("xb") as stderr:
                formatted = subprocess.run(format_command, stdout=stdout, stderr=stderr, check=False)
                for stream in (stdout, stderr):
                    stream.flush()
                    os.fsync(stream.fileno())
            result["format_returncode"] = formatted.returncode
            result["format_logs"] = {name: receipt(output / name) for name in ("format.stdout.log", "format.stderr.log")}
            result["source_after_format"] = receipt(output / "hash_buffer_probe.rs")
            need(formatted.returncode == 0, "standalone source formatting failed; inputs and logs retained")
            formatted_inputs = {path: receipt(Path(path)) for path in paths}
            changed = [path for path in paths if before[path] != formatted_inputs[path]]
            need(set(changed) <= {str(output / "hash_buffer_probe.rs")},
                 "formatting changed an input other than the independent source copy")
            result["inputs_before_format"] = before
            before = formatted_inputs
            result["inputs_before"] = before
            result["source_to_publish"] = before[str(output / "hash_buffer_probe.rs")]
            checkpoint(output, result)
            with (output / "compile.stdout.log").open("xb") as stdout, (output / "compile.stderr.log").open("xb") as stderr:
                compiled = subprocess.run(compile_command, stdout=stdout, stderr=stderr, check=False)
                for stream in (stdout, stderr):
                    stream.flush()
                    os.fsync(stream.fileno())
            result["compile_returncode"] = compiled.returncode
            result["compile_logs"] = {name: receipt(output / name) for name in
                                      ("rustc-version.log", "compile.stdout.log", "compile.stderr.log")}
            need(compiled.returncode == 0, "standalone compilation failed; all logs retained")
            result["probe_binary"] = receipt(output / "hash-buffer-probe")
        after = {path: receipt(Path(path)) for path in paths}
        result["inputs_after"] = after
        need(before == after, "bound build inputs changed")
        result["compiled"] = args.compile
    except BaseException as error:
        result["error"] = {"type": type(error).__name__, "reason": str(error)}
    finally:
        result["finished_unix"] = time.time()
        checkpoint(output, result)
    print(json.dumps({"build": str(output / "build.json"), "prepared": result["prepared"],
                      "compiled": result["compiled"], "probe_executed": False, "error": result.get("error")}))
    return 0 if "error" not in result else 1


if __name__ == "__main__":
    sys.exit(main())
