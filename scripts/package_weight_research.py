"""Retain already-built Linux research executables with exact source identities.

This packages outputs after the normal CI gates; it does not build, deploy,
run models, or assert compatibility with an installed runtime.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile


BINARIES = (
    ("target/release/hepta-runtime", "bin/hepta-runtime"),
    (
        "target/release/examples/weight-source-bound-research",
        "bin/weight-source-bound-research",
    ),
    (
        "target/release/examples/weight-smallhcsn-research",
        "bin/weight-smallhcsn-research",
    ),
    (
        "target/release/examples/weight-smallhcsn-hidden-research",
        "bin/weight-smallhcsn-hidden-research",
    ),
)


def command(root, *args):
    return subprocess.check_output(args, cwd=root, text=True).strip()


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def stage_binary(root, source, stage, target):
    original = root / source
    info = original.lstat()
    if not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111:
        raise ValueError(f"expected a regular executable: {source}")
    before = digest(original)
    destination = stage / target
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(original, destination)
    destination.chmod(0o755)
    if digest(destination) != before or digest(original) != before:
        raise ValueError(f"executable changed during packaging: {source}")
    return {
        "path": target,
        "build_path": source,
        "bytes": destination.stat().st_size,
        "sha256": before,
        "mode": "0755",
    }


def package(root, output):
    if not output.is_absolute():
        raise ValueError("output directory must be absolute")
    if command(root, "git", "status", "--porcelain", "--untracked-files=no"):
        raise ValueError("tracked source changed during CI")
    source = command(root, "git", "rev-parse", "HEAD")
    tree = command(root, "git", "rev-parse", "HEAD^{tree}")
    rustc = command(root, "rustc", "--version")
    cargo = command(root, "cargo", "--version")
    if not rustc.startswith("rustc 1.95.0 ") or not cargo.startswith("cargo 1.95.0 "):
        raise ValueError("research executable requires the pinned CI toolchain")
    output.mkdir(parents=True, exist_ok=False)
    stage = output / "payload"
    stage.mkdir()
    files = [stage_binary(root, source, stage, target) for source, target in BINARIES]
    manifest = {
        "schema": "hepta.weight.research-executable-package.v1",
        "source_commit": source,
        "source_tree": tree,
        "cargo_lock_sha256": digest(root / "Cargo.lock"),
        "rustc": rustc,
        "cargo": cargo,
        "build_command": "cargo build --locked --all-features --release --bins --examples",
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "files": files,
        "model_execution_performed": False,
        "deployment_performed": False,
        "production_eligible": False,
    }
    encoded = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    (output / "manifest.json").write_text(encoded, encoding="utf-8")
    (stage / "manifest.json").write_text(encoded, encoding="utf-8")
    archive = output / "weight-source-bound-research.tar.gz"
    with tarfile.open(archive, "w:gz") as stream:
        stream.add(stage / "manifest.json", arcname="manifest.json")
        for entry in files:
            stream.add(stage / entry["path"], arcname=entry["path"])
    print(json.dumps({"source_commit": source, "archive_sha256": digest(archive), "files": files}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    package(Path(__file__).resolve().parents[1], args.output_dir)


if __name__ == "__main__":
    main()
