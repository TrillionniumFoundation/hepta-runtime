"""Fresh owned graph builds; all previous failures and source packages stay immutable."""
from pathlib import Path
import argparse
import json
import os
import shutil
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import command, pin, put, require
from source_check import source

def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("package", "hepta", "output"):
        p.add_argument("--" + name, type=Path, required=True)
    p.add_argument("--manifest-sha256", required=True)
    a = p.parse_args()
    package = a.package.resolve(strict=True)
    hepta = a.hepta.resolve(strict=True)
    out = a.output.resolve()
    require(not out.exists(), "fresh build output already exists")
    admitted = source(package, a.manifest_sha256, syntax=True)
    out.mkdir(parents=True)
    put(out/"BUILD_ORIGIN.json", {"package": str(package), "hepta": str(hepta),
        "output": str(out), "manifest_sha256": a.manifest_sha256,
        "source_admission": admitted, "pid": os.getpid(),
        "git_head": os.environ.get("GITHUB_SHA"), "run_id": os.environ.get("GITHUB_RUN_ID"),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "fresh_direct_members": 92, "packed_hia_members": 8,
        "same_ci_member_reuse_entries": ["journal", "trace"]})
    port, graph = package/"port", package/"graph/source"
    py = [sys.executable, "-I", "-S", "-B"]
    command(out, "fresh-worker", py + [str(port/"worker-source/tests/hia_native/blocking_worker/worker_build.py"),
        "--source-root", str(port/"worker-source"), "--hepta", str(hepta),
        "--capture", str(out/"worker"),
        "--source-pins-sha256", "6b5983d351b380b53f5838dc7ca8adac523d6c95ac12df51c3f975faf60d53c2"])
    command(out, "fresh-port", py + [str(port/"recipe/build_capability.py"),
        "--package", str(port), "--hepta", str(hepta), "--worker-build", str(out/"worker"),
        "--output", str(out/"port"), "--package-sha256",
        "2563acb466285cc6d9fbf3f91508b1ea0785904230263bcdea5866c30f801bb1"])
    for label in ("production", "journal", "trace"):
        directory = out/label
        directory.mkdir()
        shutil.copytree(out/"worker/build/bootstrap", directory/"bootstrap")
        argv = py + [str(graph/"scripts/public_nine_build.py"),
            "--hepta", str(hepta), "--build", str(directory), "--name", "task-pump",
            "--bellman-port-build", str(out/"port/build-v3"),
            "--bellman-port-package", str(port), "--bellman-worker-build", str(out/"worker")]
        if label != "production":
            argv += ["--member-manifests-json", str(out/"same-ci-members.json"), "--private-pump-fixture"]
        if label == "trace":
            argv.append("--private-pump-trace")
        command(out, "build-" + label, argv)
        manifest = directory/"task-pump/manifest.json"
        result = json.loads(manifest.read_bytes())
        require(len(result["members"]) == 92, "direct graph member count changed")
        require(all(row["fresh_compile"] is (label == "production") for row in result["members"]),
                "fresh compilation or same-CI member reuse differs")
        if label == "production":
            put(out/"same-ci-members.json", {row["name"]: row["manifest"] for row in result["members"]})
    command(out, "read-build", py + [str(package/"ci/read_build.py"),
        "--package", str(package), "--build", str(out), "--manifest-sha256", a.manifest_sha256])
    report = json.loads((out/"processes/read-build.stdout").read_bytes())
    require(report["status"] == "FRESH_PUMP_GRAPH_BUILD_READBACK_PASS", "build reader did not pass")
    put(out/"BUILD_PASS.json", {"status": "FRESH_PUMP_GRAPH_BUILD_READBACK_PASS",
        "reader_stdout": pin(out/"processes/read-build.stdout"),
        "source_manifest_sha256": a.manifest_sha256,
        "runtime_hia_images": 100, "direct_fresh_members": 92, "packed_hia_members": 8,
        "public_semantic_qualification": False, "async_qualification": False,
        "fresh_cold_qualified": False})
    command(out, "physical-controls", py + [str(package/"ci/build_controls.py"),
        "--package", str(package), "--build", str(out), "--manifest-sha256", a.manifest_sha256])
    print(json.dumps(report, sort_keys=True))

if __name__ == "__main__":
    main()
