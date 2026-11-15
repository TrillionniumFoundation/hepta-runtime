"""Fresh locked original Rust replay of actual native lifetime observations."""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import subprocess
import time

if __package__:
    from .verify_sources import materialize
    from .replay import canonical, compare, prepare, sha
else:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from verify_sources import materialize
    from replay import canonical, compare, prepare, sha

HERE = Path(__file__).resolve().parent
FILES = ("Cargo.toml", "Cargo.lock", "source_manifest.json", "src/main.rs", "run.py", "verify_sources.py", "replay.py", "README.md")


def run(args, execute_callback=None, environment=None):
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    before = {name: sha((HERE / name).read_bytes()) for name in FILES}
    source = materialize(HERE, args.runtime_root.resolve(), output / "crate")
    raw, expected, counts, native_hash = prepare(args.corpus.resolve(), output)
    env = dict(os.environ if environment is None else environment)
    for name in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_TARGET", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER"):
        env.pop(name, None)
    env["CARGO_BUILD_JOBS"] = "2"
    env["CARGO_NET_OFFLINE"] = "true" if getattr(args, "offline", False) else "false"
    if getattr(args, "rustc", None):
        env["RUSTC"] = str(args.rustc)
    records = []

    def execute(name, command, timeout, input_bytes, stem):
        started = time.monotonic()
        if execute_callback:
            result = execute_callback(name=name, command=command, timeout=timeout, env=env, input_bytes=input_bytes)
        else:
            result = subprocess.run(command, input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    timeout=timeout, env=env)
        elapsed = time.monotonic() - started
        if not isinstance(result.stdout, bytes) or not isinstance(result.stderr, bytes):
            raise ValueError("reference process did not return raw streams")
        for suffix, data in (("stdout", result.stdout), ("stderr", result.stderr)):
            (output / (stem + "." + suffix)).write_bytes(data)
        records.append({"name": name, "command": command, "timeout_seconds": timeout, "elapsed_seconds": elapsed,
                        "exit_code": result.returncode, "stdin_bytes": len(input_bytes or b""), "stdin_sha256": sha(input_bytes or b""),
                        "stdout_bytes": len(result.stdout), "stdout_sha256": sha(result.stdout),
                        "stderr_bytes": len(result.stderr), "stderr_sha256": sha(result.stderr)})
        if result.returncode != 0:
            (output / "failed-processes.json").write_text(canonical(records) + "\n")
            raise ValueError("original process failed: " + name)
        return result

    target = output / "cargo-target"
    command = [str(args.cargo), "build", "--locked", "--manifest-path", str(output / "crate/Cargo.toml"), "--target-dir", str(target)]
    if getattr(args, "offline", False):
        command.insert(3, "--offline")
    execute("request-scope-rust-compile", command, 180, None, "build")
    binary = target / "debug/hepta-request-scope-original-oracle"
    binary_hash = sha(binary.read_bytes())
    result = execute("request-scope-rust-compare", [str(binary)], 120, raw, "original-replay")
    if result.stderr:
        raise ValueError("original replay wrote unexpected stderr")
    (output / "original-output.jsonl").write_bytes(result.stdout)
    compared = compare(result.stdout, expected)
    if before != {name: sha((HERE / name).read_bytes()) for name in FILES} or sha(binary.read_bytes()) != binary_hash:
        raise ValueError("reference source/binary changed during replay")
    report = {"schema": "hepta.runtime.request-scope-original-comparison.v1", "status": "PASS",
              "source_check": source, "harness_sources": before, "native_corpus_sha256": native_hash,
              "input_bytes": len(raw), "input_sha256": sha(raw), "output_bytes": len(result.stdout), "output_sha256": sha(result.stdout),
              "binary_sha256": binary_hash, "processes": records, "counts": counts, "comparison": compared,
              "native_boundary_refusals_not_original_semantics": True, "private_generations_are_adapter_labels": True,
              "expected_semantic_payloads_supplied_to_rust": False, "production_dispatcher_installed": False,
              "unbounded_cache_storage_closed": False, "stdio_async_writer_implemented": False}
    (output / "RESULT.json").write_text(canonical(report) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cargo", type=Path, required=True)
    parser.add_argument("--rustc", type=Path)
    parser.add_argument("--offline", action="store_true")
    print(canonical(run(parser.parse_args())))
