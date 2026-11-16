"""Fresh CI build and first actual SDK carrier execution; no native parity claim."""
from pathlib import Path
import argparse
import json
import os
import shutil
import sys
from receipt_support import ROOT, PIN, regular, read_json, require, put, process


def run(target, rust_bin, output):
    require(os.environ.get("GITHUB_ACTIONS") == "true", "Rust execution is CI-only")
    target, rust_bin = (Path(value).resolve(strict=True) for value in (target, rust_bin))
    output = Path(output).absolute()
    output.mkdir(parents=True, exist_ok=False)
    profile = read_json(ROOT / "source-profile.json")
    source = output / "source"
    source.mkdir()
    for name, identity in profile["files"].items():
        raw = regular(ROOT / name)
        require(PIN(raw) == identity, "candidate source identity: " + name)
        destination = source / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
    shutil.copyfile(ROOT / "source-profile.json", source / "source-profile.json")
    report = {"schema": "hepta.batch-sdk-reference-development.v1", "status": "RUNNING",
        "target_commit": "d3d75c30719db966b004756f610007a7c723729e",
        "source_profile": PIN(regular(source / "source-profile.json")), "checks": [],
        "native_compared": False, "public_batch_qualified": False,
        "full_async_cancellation_qualified": False, "whole_runtime_replaced": False}
    put(output / "result.json", report)
    def step(name, argv, cwd=output):
        row, stdout, stderr = process(output / "processes", name, argv, cwd=cwd, timeout=180)
        report["checks"].append(row)
        put(output / "result.json", report)
        return stdout, stderr
    try:
        identity, _ = step("target-identity", ["git", "-C", target, "rev-parse", "HEAD"])
        require(identity == (report["target_commit"] + "\n").encode(), "original target commit")
        step("target-prefetch", [rust_bin / "cargo", "fetch", "--locked"], target)
        step("original-build", [sys.executable, "-B", source / "build_reference.py", "--rust-bin", rust_bin,
            "--target", target, "--core", source / "core", "--output", output / "original"])
        step("original-smoke", [sys.executable, "-B", source / "smoke_original.py",
            "--binary", output / "original/bin/hepta-batch-sdk-current-original-oracle", "--output", output / "smoke"])
        report.update(status="PASS", fresh_original_build=True, original_smoke=read_json(output / "smoke/result.json"))
    except BaseException as error:
        report.update(status="FAIL", failure=repr(error))
        raise
    finally:
        put(output / "result.json", report)
    print(json.dumps({key: report[key] for key in ("status", "fresh_original_build", "native_compared", "public_batch_qualified")}, sort_keys=True))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--target", type=Path, required=True)
    p.add_argument("--rust-bin", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    run(a.target, a.rust_bin, a.output)
