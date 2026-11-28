"""Fresh locked original-Rust replay of the complete local atomic-write domain.

This is qualification code. Both writers execute real kernel effects in newly
owned fixtures; the unchanged Rust owner supplies the reference. No production
filesystem behavior is implemented here.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import time
import traceback

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
for path in (HERE, ROOT / 'scripts'):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
from atomic_write_kernel import run as run_kernel
from hia_native_atomic_write_build import inspect_bundle
from hia_native_atomic_write_qualification import (
    OWN_FILES, policy_evidence, kernel_evidence, original_fixture_retirement,
)

ORIGINAL = "e55ce4df73d6e0b70e4065900d317f6b7329670ab6fcba44979ca69dcac80590"
CLEARED = ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_TARGET",
           "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTC_BOOTSTRAP")
SOURCES = OWN_FILES


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(path):
    digest = hashlib.sha256()
    count = 0
    with Path(path).open("rb") as stream:
        while part := stream.read(1 << 20):
            digest.update(part)
            count += len(part)
    return {"bytes": count, "sha256": digest.hexdigest()}


def write_json(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def expand(path, destination):
    digest = hashlib.sha256()
    count = 0
    with gzip.open(path, "rb") as source, Path(destination).open("xb") as target:
        while part := source.read(1 << 20):
            target.write(part)
            digest.update(part)
            count += len(part)
    return {"bytes": count, "sha256": digest.hexdigest()}


def framed_count(path, length_bytes):
    count = 0
    with Path(path).open("rb") as stream:
        while header := stream.read(length_bytes):
            if len(header) != length_bytes:
                raise ValueError("truncated original replay length")
            size = int.from_bytes(header, "little")
            if size > 512 << 20:
                raise ValueError("unbounded original replay record")
            remaining = size
            while remaining:
                part = stream.read(min(remaining, 1 << 20))
                if not part:
                    raise ValueError("truncated original replay record")
                remaining -= len(part)
            count += 1
    return count


def compare_files(left, right):
    at = 0
    with Path(left).open("rb") as a, Path(right).open("rb") as b:
        while True:
            x, y = a.read(1 << 20), b.read(1 << 20)
            if x != y:
                raise ValueError(f"original output differs at block {at}")
            if not x:
                return
            at += len(x)


def compare(runtime, native_manifest, policy_corpus, destination, *, rustc, cargo, offline=False):
    runtime = Path(runtime).resolve(strict=True)
    native_manifest = Path(native_manifest).resolve(strict=True)
    policy_corpus = Path(policy_corpus).resolve(strict=True)
    destination = Path(destination).resolve()
    destination.mkdir(mode=0o700)
    started = time.monotonic()
    source_pins = {name: identity(ROOT / name) for name in SOURCES}
    reference = runtime / "src/mcp/fs/text_editing.rs"
    original_bytes = reference.read_bytes()
    if sha(original_bytes) != ORIGINAL:
        raise ValueError("original atomic_write source differs from the retained owner")
    begin = original_bytes.index(b"pub async fn atomic_write(")
    end = original_bytes.index(b"\nconst LF_ENDING:", begin)
    unchanged_owner = original_bytes[begin:end]
    native_meta = json.loads(native_manifest.read_bytes())
    artifact = inspect_bundle(native_manifest, source_root=ROOT)
    native = native_manifest.parent / native_meta["executable"]
    native_identity = identity(native)
    if native_identity["sha256"] != native_meta["executable_sha256"]:
        raise ValueError("actual native executable hash differs")
    if native_meta["policy_source_sha256"] != source_pins["native/atomic_write.hepta"]["sha256"]:
        raise ValueError("actual native policy differs from current source")
    if native_meta["packer_source_sha256"] != source_pins["native/atomic_write_packer.hepta"]["sha256"]:
        raise ValueError("actual native fixed boundary differs from current source")
    # Rustup dispatches by argv[0]. Resolving its cargo/rustc symlink would
    # execute "rustup build" instead of the selected Cargo command in CI.
    rustc, cargo = Path(rustc).absolute(), Path(cargo).absolute()
    if not rustc.is_file() or not cargo.is_file():
        raise FileNotFoundError('the selected Rust compiler and Cargo must exist')
    env = dict(os.environ)
    removed = sorted(name for name in CLEARED if name in env)
    for name in CLEARED:
        env.pop(name, None)
    env.update(RUSTC=str(rustc), CARGO_TARGET_DIR=str(destination / "target"),
               HIA_REFERENCE_RUNTIME=str(runtime), TMPDIR=str(destination / "tmp"))
    (destination / "tmp").mkdir(mode=0o700)
    result = {"schema": "hepta.runtime.atomic-write-original-comparison.v2",
              "status": "RUNNING", "source_files": source_pins, "steps": [],
              "execution_directory": str(destination), "execution_source_root": str(ROOT),
              "execution_reference_root": str(runtime), "artifact_evidence": artifact,
              "environment": {key: env[key] for key in ('RUSTC', 'CARGO_TARGET_DIR', 'HIA_REFERENCE_RUNTIME', 'TMPDIR')},
              "offline": offline,
              "removed_environment_names": removed, "cleared_environment_names": list(CLEARED),
              "original_source_sha256": ORIGINAL, "original_owner_sha256": sha(unchanged_owner),
              "native_manifest": identity(native_manifest), "native_binary": native_identity,
              "rustc": {"path": str(rustc), **identity(rustc)},
              "cargo": {"path": str(cargo), **identity(cargo)}}

    def execute(name, argv, *, input_path=None, timeout=120, cwd=ROOT):
        before = time.monotonic()
        record = {"name": name, "argv": list(map(str, argv)), "timeout": timeout}
        stdout_path, stderr_path = destination / (name + ".stdout"), destination / (name + ".stderr")
        try:
            with stdout_path.open("xb") as out, stderr_path.open("xb") as err:
                incoming = Path(input_path).open("rb") if input_path else None
                try:
                    # The process inherits this qualification driver's owned
                    # process group. An outer deadline cannot orphan it.
                    child = subprocess.run(argv, stdin=incoming, stdout=out, stderr=err,
                                           env=env, cwd=cwd, timeout=timeout)
                finally:
                    if incoming:
                        incoming.close()
            record["exit_code"] = child.returncode
            if child.returncode:
                raise RuntimeError(f"{name} failed: {child.returncode}")
        except subprocess.TimeoutExpired:
            record.update(timed_out=True, exit_code=None)
            raise
        finally:
            record.update(elapsed=time.monotonic() - before,
                          stdout=identity(stdout_path), stderr=identity(stderr_path))
            result["steps"].append(record)
        return stdout_path

    try:
        version = execute("rustc-version", [str(rustc), "-Vv"], timeout=10).read_text()
        result["rustc"]["version"] = version
        if not version.startswith('rustc 1.95.0 ') or '\nrelease: 1.95.0\n' not in version or '\nhost: x86_64-unknown-linux-gnu\n' not in version:
            raise ValueError('the original std/Linux-GNU owner requires the pinned Rust 1.95.0 reference')
        argv = [str(cargo), "build", "--release", "--locked", "--manifest-path",
                str(HERE / "atomic_write_oracle/Cargo.toml")]
        if offline:
            argv.append("--offline")
        execute("original-build", argv)
        copied = list((destination / "target/release/build").glob("hia-atomic-write-original-*/out/atomic_write_original.rs"))
        if len(copied) != 1 or copied[0].read_bytes() != unchanged_owner:
            raise ValueError("locked original build did not compile the complete unchanged owner")
        result["compiled_original_owner"] = {"file": str(copied[0].relative_to(destination)), **identity(copied[0])}
        original = destination / "target/release/hia-atomic-write-original"
        result["original_binary"] = identity(original)
        properties = execute("original-properties", [str(original), "--properties"], timeout=10)
        compare_files(properties, HERE / "atomic_write_rust_io_properties.txt")
        result["original_error_display_property_rows"] = 4095
        result["original_nul_and_writezero_properties"] = 2
        result['policy_evidence'] = policy_evidence(policy_corpus, artifact, source_root=ROOT)
        corpus = json.loads((policy_corpus / "result.json").read_bytes())
        if corpus.get("status") != "PASS" or corpus.get("path_cases") != 88807:
            raise ValueError("native path corpus is incomplete")
        if corpus["identity"]["source_sha256"] != source_pins["native/atomic_write.hepta"]["sha256"]:
            raise ValueError("native path corpus source differs")
        requests, answers = destination / "path-requests.bin", destination / "path-native.bin"
        input_id = expand(policy_corpus / "path-requests.bin.gz", requests)
        output_id = expand(policy_corpus / "path-native-output.bin.gz", answers)
        if input_id != {"bytes": corpus["requests_bytes"], "sha256": corpus["requests_sha256"]}:
            raise ValueError("native path requests differ")
        if output_id != {"bytes": corpus["outputs_bytes"], "sha256": corpus["outputs_sha256"]}:
            raise ValueError("native path output differs")
        if framed_count(requests, 8) != 88807 or framed_count(answers, 4) != 88807:
            raise ValueError("native path corpus frame count differs")
        actual = execute("original-path", [str(original)], input_path=requests, timeout=30)
        compare_files(actual, answers)
        result["path"] = {"status": "PASS", "cases": 88807, "requests": input_id, "output": identity(actual)}
        native_kernel = run_kernel(native, destination / "native-kernel")
        original_kernel = run_kernel(original, destination / "original-kernel")
        for name, value in (("native_kernel", native_kernel), ("original_kernel", original_kernel)):
            result[name] = {k: v for k, v in value.items() if k != "observations"}
            if value["status"] != "PASS" or value["cases"] != 151 or value["requests"] != 171:
                raise ValueError("actual kernel comparison domain is incomplete")
        result['kernel_evidence'] = {}
        for name, binary_id in (('native', native_identity), ('original', result['original_binary'])):
            observed = kernel_evidence(destination / (name + '-kernel'), binary_id['sha256'], source_root=ROOT)
            result['kernel_evidence'][name] = {key: value for key, value in observed.items() if key != 'observations'}
        if identity(native) != native_identity or identity(original) != result["original_binary"]:
            raise ValueError("executed binary changed during comparison")
        if inspect_bundle(native_manifest, source_root=ROOT) != artifact:
            raise ValueError('qualified native artifact changed during original comparison')
        if source_pins != {name: identity(ROOT / name) for name in SOURCES} or reference.read_bytes() != original_bytes:
            raise ValueError("source changed during original comparison")
        # Pairwise semantic differences must remain a failing result, but cannot
        # strand inaccessible live fixtures after their full evidence is saved.
        result['fixture_retirement'] = original_fixture_retirement(
            destination, result['kernel_evidence'], create=True)
        mismatches = []
        if len(native_kernel["observations"]) != len(original_kernel["observations"]):
            raise ValueError("kernel observation length differs")
        for native_row, original_row in zip(native_kernel["observations"], original_kernel["observations"], strict=True):
            for field in ("name", "request_bytes", "request_sha256", "stdout_hex", "semantic_snapshot", "normalized_trace"):
                if native_row[field] != original_row[field]:
                    mismatches.append({"name": native_row["name"], "field": field,
                                       "native": native_row[field], "original": original_row[field]})
        write_json(destination / "mismatches.json", mismatches)
        if mismatches:
            raise ValueError(f"{len(mismatches)} actual original kernel comparisons differ")
        if identity(native) != native_identity or identity(original) != result["original_binary"]:
            raise ValueError("executed binary changed during comparison")
        if inspect_bundle(native_manifest, source_root=ROOT) != artifact:
            raise ValueError('qualified native artifact changed during original comparison')
        if source_pins != {name: identity(ROOT / name) for name in SOURCES} or reference.read_bytes() != original_bytes:
            raise ValueError("source changed during original comparison")
        result.update(status="PASS", kernel_cases=151, kernel_requests=171,
                      complete_actual_kernel_comparisons=151, rust_path_cases=88807,
                      original_atomic_write_requests=171, local_linux_gnu_only=True,
                      remote_ssh_parity=False, production_activated=False, whole_runtime_replaced=False)
    except BaseException as error:
        result.update(status="FAIL", failure=repr(error), traceback=traceback.format_exc())
        raise
    finally:
        result["elapsed"] = time.monotonic() - started
        write_json(destination / "result.json", result)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--runtime", type=Path, default=ROOT)
    p.add_argument("--native-manifest", type=Path, required=True)
    p.add_argument("--policy-corpus", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--rustc", type=Path, default=shutil.which("rustc"))
    p.add_argument("--cargo", type=Path, default=shutil.which("cargo"))
    p.add_argument("--offline", action="store_true")
    args = p.parse_args()
    if not args.rustc or not args.cargo:
        p.error("actual Rust compiler and Cargo are required")
    result = compare(args.runtime, args.native_manifest, args.policy_corpus, args.output,
                     rustc=args.rustc, cargo=args.cargo, offline=args.offline)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
