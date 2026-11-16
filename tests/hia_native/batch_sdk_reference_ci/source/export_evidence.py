"""Archive exact owned evidence, including nonregular failure-fixture metadata."""
from pathlib import Path
import argparse
import hashlib
import io
import json
import os
import stat
import tarfile

BINARIES = {"hepta-batch-sdk-current-original-oracle"}


def export(root, output):
    root, output = Path(root).absolute(), Path(output).absolute()
    assert root.resolve(strict=True) == root and not output.is_relative_to(root)
    output.mkdir(parents=True, exist_ok=False)
    files, nodes, paths, omitted = {}, {}, [], []
    def visit(base):
        for entry in sorted(os.scandir(base), key=lambda x: os.fsencode(x.name)):
            path = Path(entry.path)
            name = path.relative_to(root).as_posix()
            assert name != "artifact-manifest.json"
            info = entry.stat(follow_symlinks=False)
            # These are the only build intermediates, never reader inputs.
            # Both exact fresh executables are preserved at their recorded paths.
            if name.startswith("original/target/") and name != "original/target/release" and name not in {
                    "original/target/release/" + binary for binary in BINARIES}:
                omitted.append({"path_hex": os.fsencode(name).hex(), "reason": "Rust build intermediate"})
                continue
            node = {"path_hex": os.fsencode(name).hex(), "mode": stat.S_IMODE(info.st_mode)}
            if stat.S_ISDIR(info.st_mode):
                node["kind"] = "directory"
                nodes[name] = node
                visit(path)
            elif stat.S_ISREG(info.st_mode):
                with path.open("rb") as stream:
                    digest = hashlib.file_digest(stream, "sha256").hexdigest()
                files[name] = {"bytes": info.st_size, "sha256": digest}
                node.update(kind="file", **files[name])
                nodes[name] = node
                paths.append(path)
            elif stat.S_ISLNK(info.st_mode):
                node.update(kind="symlink", target_hex=os.fsencode(os.readlink(path)).hex())
                nodes[name] = node
            else:
                kind = "fifo" if stat.S_ISFIFO(info.st_mode) else "socket" if stat.S_ISSOCK(info.st_mode) else "device"
                node.update(kind=kind, device=info.st_rdev)
                nodes[name] = node
    visit(root)
    manifest = {"schema": "hepta.runtime.batch-sdk-reference-development-artifact.v1", "files": files, "nodes": nodes,
        "omitted_build_intermediates": omitted, "nonregular_nodes_are_metadata_only": True,
        "native_executed": False, "complete_original_sources_and_streams": True,
        "public_batch_qualified": False}
    raw = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
    archive = output / "batch-sdk-reference.tar.gz"
    with tarfile.open(archive, "w:gz", compresslevel=6) as tar:
        for path in sorted(paths):
            name = path.relative_to(root).as_posix()
            metadata = tarfile.TarInfo(name)
            metadata.size = files[name]["bytes"]
            metadata.mode = nodes[name]["mode"]
            with path.open("rb") as stream:
                tar.addfile(metadata, stream)
        metadata = tarfile.TarInfo("artifact-manifest.json")
        metadata.size, metadata.mode = len(raw), 0o600
        tar.addfile(metadata, io.BytesIO(raw))
    with archive.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    result = {"archive": archive.name, "bytes": archive.stat().st_size, "sha256": digest,
        "regular_files": len(files), "nodes": len(nodes), "complete_archive": True,
        "manifest": {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}}
    (output / "archive.json").write_text(json.dumps(result, sort_keys=True) + "\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(export(args.input, args.output), sort_keys=True))
