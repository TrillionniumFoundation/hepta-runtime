"""Fresh current get_info handshake observations; Rust execution is restricted to CI."""
from pathlib import Path
import argparse, hashlib, json, os, shutil, subprocess, sys, time
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from cases import cases
from exact_rust_build import Recorder, build_exact_oracle
from prepare_reference import prepare

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
NAME = "current-get-info-handshake-oracle"


def put(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "rust-bin", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    assert os.environ.get("CI") == "true", "Rust execution is restricted to CI."
    source = args.source.resolve(strict=True);rust = args.rust_bin.resolve(strict=True)
    output = args.output.absolute()
    from verify_reference import check_source
    source_pin = check_source(source)
    prepare(source, output)
    inputs = json.loads((source / "SOURCE_INPUTS.json").read_bytes())
    corpus = cases();put(output / "CORPUS.json", corpus)
    summary = dict(schema="hepta.current-get-info.handshake-reference.v1", status="RUNNING",
                   source_manifest=source_pin, completed_sessions=0, expected_sessions=54,
                   fresh_target_sdk_built=False, actual_target_sdk_executed=False,
                   native_graph_executed=False, full_sdk_qualified=False,
                   full_public_protocol_qualified=False, production_activated=False, old_path_removed=False)
    started = time.monotonic();processes = []
    def checkpoint():
        summary["elapsed_seconds"] = time.monotonic() - started
        put(output / "SUMMARY.json", summary);put(output / "processes.json", processes)
    checkpoint()
    try:
        environment = dict(PATH=str(rust) + os.pathsep + os.environ.get("PATH", ""),
                           RUSTC=str(rust / "rustc"), CARGO_TARGET_DIR=str(output / "rust-build"))
        prefetch = Recorder(output, "evidence/cache-prefetch", environment)
        version = prefetch.run("rustc-version", [rust / "rustc", "--version", "--verbose"], timeout=180)
        assert version.decode().splitlines()[0].startswith("rustc 1.95.0 ")
        seed = (output / "cache-seed/Cargo.lock").read_bytes()
        prefetch.run("cargo-fetch-locked", [rust / "cargo", "fetch", "--locked", "--manifest-path",
                     output / "cache-seed/Cargo.toml"], timeout=180)
        assert (output / "cache-seed/Cargo.lock").read_bytes() == seed
        binary, receipt, _ = build_exact_oracle(output, "oracle", NAME, rust)
        subset = json.loads((output / "evidence/target-lock-subset.json").read_bytes())
        sdk = next(row for row in subset["registry_source_verification"] if row["name"] == "rmcp")
        assert sdk["version"] == "3.9.0" and sdk["checksum"] == inputs["sdk"]["registry_checksum"]
        for name, expected in inputs["sdk"]["source_files"].items():
            assert sdk["source_files"][name] == expected, name
        metadata = json.loads((output / "evidence/rust-build-processes/metadata-offline.stdout").read_bytes())
        archives = output / "registry-archives";archives.mkdir();custody = []
        for package in metadata["packages"]:
            if not package.get("source"):
                continue
            crate = Path(package["manifest_path"]).parent
            original = crate.parent.parent.parent / "cache" / crate.parent.name / (crate.name + ".crate")
            raw = original.read_bytes();destination = archives / (crate.name + ".crate")
            destination.write_bytes(raw)
            custody.append(dict(name=package["name"], version=package["version"], source=package["source"],
                                path=str(destination.relative_to(output)), bytes=len(raw), sha256=SHA(raw)))
        retained = output / "reference-bin" / NAME;retained.parent.mkdir()
        shutil.copyfile(binary, retained);retained.chmod(0o500)
        assert SHA(retained.read_bytes()) == receipt["binary_sha256"]
        receipt.update(registry_archive_custody=custody,
                       retained_binary_relative_path=str(retained.relative_to(output)))
        put(output / "BUILD.json", receipt)
        summary["fresh_target_sdk_built"] = True;checkpoint()
        for index, case in enumerate(corpus):
            folder = output / ("case-" + str(index).zfill(3));folder.mkdir()
            data = (json.dumps(case, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
            (folder / "stdin.jsonl").write_bytes(data)
            begin = time.monotonic();timed_out = False
            try:
                process = subprocess.run([str(retained)], input=data, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, cwd=output, env={"PATH": "", "LC_ALL": "C.UTF-8"}, timeout=60)
                stdout, stderr, code = process.stdout, process.stderr, process.returncode
            except subprocess.TimeoutExpired as error:
                stdout, stderr, code, timed_out = error.stdout or b"", error.stderr or b"", None, True
            (folder / "stdout.jsonl").write_bytes(stdout);(folder / "stderr.txt").write_bytes(stderr)
            processes.append(dict(index=index, label=case["label"], folder=folder.name,
                exit_code=code, timed_out=timed_out, deadline_seconds=60,
                elapsed_seconds=time.monotonic() - begin, executable_sha256=receipt["binary_sha256"],
                stdin=dict(bytes=len(data), sha256=SHA(data)), stdout=dict(bytes=len(stdout), sha256=SHA(stdout)),
                stderr=dict(bytes=len(stderr), sha256=SHA(stderr))))
            checkpoint()
            assert code == 0 and not timed_out and not stderr, case["label"]
            summary["completed_sessions"] += 1;checkpoint()
        receipt["actual_target_sdk_executed"] = True;put(output / "BUILD.json", receipt)
        summary.update(status="CAPTURED", actual_target_sdk_executed=True);checkpoint()
        command = [sys.executable, "-I", "-B", str(source / "scripts/verify_reference.py"),
                   "--source", str(source), "--run", str(output)]
        check = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
        (output / "readonly.stdout").write_bytes(check.stdout);(output / "readonly.stderr").write_bytes(check.stderr)
        assert check.returncode == 0 and not check.stderr, "independent reference reader"
        verified = json.loads(check.stdout)
        assert verified["status"] == "READONLY_CURRENT_GET_INFO_HANDSHAKE54_PASS"
        summary.update(status="PASS", responses=324, modern_ping_method_not_found_responses=54,
                       real_negotiated_peer_info_observations=54, readonly_verified=True)
    except BaseException as error:
        summary.update(status="FAIL", error=repr(error));raise
    finally:
        checkpoint()
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
