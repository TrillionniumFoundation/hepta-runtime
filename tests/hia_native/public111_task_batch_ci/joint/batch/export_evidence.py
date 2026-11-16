"""Archive exact owned inputs, streams and explicit failed-fixture metadata."""
from pathlib import Path
import argparse
import hashlib
import io
import json
import os
import stat
import tarfile

PACKAGE = "hepta-batch-sdk-current-original-oracle"
FIXTURES = {"workspaces/private-" + name for name in ("typed-legacy", "typed-modern", "filesystem", "session")}
FIXTURES.update("workspaces/stdio-" + name for name in ("legacy", "modern"))


def export(root, output):
    root, output = Path(root).absolute(), Path(output).absolute()
    assert root.resolve(strict=True) == root and not output.is_relative_to(root)
    output.mkdir(parents=True, exist_ok=False)
    report = json.loads((root / "result.json").read_bytes())
    passed = report.get("status") == "PASS"
    files, nodes, paths, omitted, unreadable = {}, {}, [], [], []
    def fixture(name):
        return any(name == prefix or name.startswith(prefix + "/") for prefix in FIXTURES)
    def visit(base):
        for entry in sorted(os.scandir(base), key=lambda item: os.fsencode(item.name)):
            path = Path(entry.path)
            name = path.relative_to(root).as_posix()
            assert name != "artifact-manifest.json"
            info = entry.stat(follow_symlinks=False)
            if name.startswith("original/target/") and name not in {
                    "original/target/release", "original/target/release/" + PACKAGE}:
                omitted.append({"path_hex": os.fsencode(name).hex(), "reason": "Rust build intermediate"})
                continue
            in_fixture = fixture(name)
            assert not (passed and in_fixture), "completed fixture was not retired"
            node = {"path_hex": os.fsencode(name).hex(), "mode": stat.S_IMODE(info.st_mode)}
            if stat.S_ISDIR(info.st_mode):
                node["kind"] = "directory"
                nodes[name] = node
                try:
                    visit(path)
                except PermissionError as error:
                    assert in_fixture and not passed
                    node["readdir_errno"] = error.errno
            elif stat.S_ISREG(info.st_mode):
                assert info.st_nlink == 1 or in_fixture, "unadmitted aliased evidence file"
                try:
                    with path.open("rb") as stream:
                        digest = hashlib.file_digest(stream, "sha256").hexdigest()
                except OSError as error:
                    assert in_fixture and not passed
                    node.update(kind="unreadable-file", bytes=info.st_size, read_errno=error.errno)
                    nodes[name] = node
                    unreadable.append(name)
                    continue
                after = path.lstat()
                assert (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) == (
                    after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                files[name] = {"bytes": info.st_size, "sha256": digest}
                node.update(kind="file", **files[name])
                nodes[name] = node
                paths.append(path)
            else:
                assert in_fixture and not passed, "nonregular node outside an exact failed fixture"
                if stat.S_ISLNK(info.st_mode):
                    node.update(kind="symlink", target_hex=os.fsencode(os.readlink(path)).hex())
                else:
                    kind = "fifo" if stat.S_ISFIFO(info.st_mode) else "socket" if stat.S_ISSOCK(info.st_mode) else "device"
                    node.update(kind=kind, device=info.st_rdev)
                nodes[name] = node
    visit(root)
    manifest = {"schema": "hepta.runtime.batch-public-complete-artifact.v1", "files": files, "nodes": nodes,
        "recipe_status": report.get("status"), "omitted_build_intermediates": omitted,
        "unreadable_failed_fixture_files": unreadable, "nonregular_nodes_are_metadata_only": True,
        "all_observed_regular_file_bytes_retained": not unreadable,
        "public_batch_production_qualified": False, "whole_runtime_replaced": False}
    raw = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
    archive = output / "batch-public-complete.tar.gz"
    with tarfile.open(archive, "w:gz", compresslevel=6) as tar:
        for path in sorted(paths):
            name = path.relative_to(root).as_posix()
            metadata = tarfile.TarInfo(name)
            metadata.size, metadata.mode = files[name]["bytes"], nodes[name]["mode"]
            with path.open("rb") as stream:
                tar.addfile(metadata, stream)
        metadata = tarfile.TarInfo("artifact-manifest.json")
        metadata.size, metadata.mode = len(raw), 0o600
        tar.addfile(metadata, io.BytesIO(raw))
    with archive.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    result = {"archive": archive.name, "bytes": archive.stat().st_size, "sha256": digest,
        "regular_files": len(files), "nodes": len(nodes), "recipe_status": report.get("status"),
        "unreadable_failed_fixture_files": len(unreadable),
        "manifest": {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}}
    (output / "archive.json").write_text(json.dumps(result, sort_keys=True) + "\n")
    return result


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    print(json.dumps(export(a.input, a.output), sort_keys=True))
