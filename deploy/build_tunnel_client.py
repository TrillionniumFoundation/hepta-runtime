#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Build the pinned tunnel-client with Hepta's explicit zero-concurrency mode."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

DEPLOY = Path(__file__).resolve().parent
MANIFEST = DEPLOY / "tunnel-client-source.json"


def digest(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def load_manifest(path: Path = MANIFEST) -> tuple[dict, Path]:
    manifest = json.loads(path.read_text())
    if manifest.get("schema") != 1:
        raise ValueError("unsupported tunnel-client source manifest")
    patch = (path.parent / manifest["patch"]).resolve()
    if not patch.is_relative_to(path.parent.resolve()):
        raise ValueError("patch must be inside the deployment directory")
    if digest(patch) != manifest["patch_sha256"]:
        raise ValueError("tunnel-client patch checksum mismatch")
    return manifest, patch


def run(args: list[str], *, cwd: Path | None = None, env: dict | None = None) -> None:
    subprocess.run(args, cwd=cwd, env=env, check=True)


def read(args: list[str], *, cwd: Path | None = None, env: dict | None = None) -> str:
    return subprocess.check_output(args, cwd=cwd, env=env, text=True).strip()


def checkout_source(manifest: dict, destination: Path, source: Path | None) -> None:
    if source is None:
        run(["git", "init", "--quiet", str(destination)])
        run(["git", "remote", "add", "origin", manifest["repository"]], cwd=destination)
        run(["git", "fetch", "--quiet", "--depth", "1", "origin", manifest["commit"]], cwd=destination)
    else:
        # Clone the committed object database; ignore local edits and untracked files.
        run(["git", "clone", "--quiet", "--no-checkout", "--local", str(source), str(destination)])
    run(["git", "checkout", "--quiet", "--detach", manifest["commit"]], cwd=destination)
    if read(["git", "rev-parse", "HEAD"], cwd=destination) != manifest["commit"]:
        raise ValueError("tunnel-client source commit mismatch")
    if read(["git", "status", "--porcelain"], cwd=destination):
        raise ValueError("tunnel-client source is not pristine before patching")


def build_arguments(go: str, manifest: dict, flavor: str, output: Path) -> list[str]:
    package = "./cmd/client" if flavor == "full" else "./cmd/client-runtime"
    prefix = "github.com/openai/tunnel-client/pkg/version"
    patched_revision = f'{manifest["commit"]}.{manifest["patch_id"]}'
    ldflags = " ".join([
        "-s", "-w", f"-X {prefix}.GitSHA={patched_revision}",
        f'-X {prefix}.GoVersion=go{manifest["go_version"]}',
        f"-X {prefix}.Flavor={flavor}",
        f"-X '{prefix}.BuildFlags=-trimpath -buildvcs=false'",
    ])
    return [go, "build", "-mod=readonly", "-trimpath", "-buildvcs=false",
            "-ldflags", ldflags, "-o", str(output), package]


def atomic_copy(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    handle, name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    os.close(handle)
    temporary = Path(name)
    try:
        shutil.copyfile(source, temporary)
        temporary.chmod(0o755)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--flavor", choices=("runtime", "full"), default="runtime",
                        help="full preserves the Homebrew client's admin/doctor commands")
    parser.add_argument("--output", type=Path, help="build to this artifact path without installing a service")
    parser.add_argument("--install-dir", type=Path, default=Path("/usr/local/bin"))
    parser.add_argument("--source-dir", type=Path, help="reuse a local Git object database at the pinned commit")
    parser.add_argument("--go-bin", default="go", help="Go executable; the manifest pins GOTOOLCHAIN")
    parser.add_argument("--goos", help="optional cross-compilation target")
    parser.add_argument("--goarch", help="optional cross-compilation architecture")
    parser.add_argument("--test", action="store_true", help="run the affected Go packages before building")
    args = parser.parse_args()
    manifest, patch = load_manifest()
    env = os.environ.copy()
    env.update(GOTOOLCHAIN=f'go{manifest["go_version"]}', GOWORK="off", CGO_ENABLED="0", GOFLAGS="")
    version = read([args.go_bin, "env", "GOVERSION"], env=env)
    if version != f'go{manifest["go_version"]}':
        raise ValueError(f"expected Go {manifest['go_version']}, got {version}")
    host_os = read([args.go_bin, "env", "GOHOSTOS"], env=env)
    host_arch = read([args.go_bin, "env", "GOHOSTARCH"], env=env)
    target_os, target_arch = args.goos or host_os, args.goarch or host_arch
    destination = (args.output or args.install_dir / "tunnel-client").expanduser().resolve()
    with tempfile.TemporaryDirectory(prefix="hepta-tunnel-build-") as temporary:
        source = Path(temporary) / "source"
        checkout_source(manifest, source, args.source_dir.resolve() if args.source_dir else None)
        run(["git", "apply", "--check", str(patch)], cwd=source)
        run(["git", "apply", str(patch)], cwd=source)
        if args.test:
            test_env = dict(env, GOOS=host_os, GOARCH=host_arch)
            packages = ["./pkg/runtimeconfig", "./pkg/dispatcher/internal"]
            if args.flavor == "full":
                packages.append("./cmd/client")
            run([args.go_bin, "test", "-mod=readonly", *packages], cwd=source, env=test_env)
        binary = Path(temporary) / "tunnel-client"
        env.update(GOOS=target_os, GOARCH=target_arch)
        run(build_arguments(args.go_bin, manifest, args.flavor, binary), cwd=source, env=env)
        atomic_copy(binary, destination)
    receipt = {
        "schema": 1, "source_version": manifest["version"], "source_commit": manifest["commit"],
        "patch_id": manifest["patch_id"], "patch_sha256": manifest["patch_sha256"],
        "go_version": version, "flavor": args.flavor, "goos": target_os, "goarch": target_arch,
        "binary_sha256": digest(destination), "output": str(destination),
        "mcp_max_concurrent_requests_zero": "unbounded",
    }
    destination.with_name(destination.name + ".build.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
