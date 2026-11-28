#!/usr/bin/env python3
"""Export complete reference inputs and outputs; exclude compiler intermediates."""
from pathlib import Path
import argparse
import hashlib
import json
import tarfile

p = argparse.ArgumentParser()
p.add_argument("--source", required=True, type=Path)
p.add_argument("--output", required=True, type=Path)
a = p.parse_args()
source, output = a.source.absolute(), a.output.absolute()
output.mkdir(mode=0o700)
files = {}
selected = []
for path in sorted(source.rglob("*")):
    relative = path.relative_to(source)
    if relative.parts[0] == "cargo-target":
        continue
    if path.is_symlink():
        raise ValueError("unexpected reference symlink")
    selected.append(path)
    if path.is_file():
        with path.open("rb") as stream:
            files[relative.as_posix()] = {"bytes": path.stat().st_size,
                "sha256": hashlib.file_digest(stream, "sha256").hexdigest()}
manifest = source / "artifact-manifest.json"
manifest.write_text(json.dumps({"schema": "hepta.runtime.current-catalog-artifact.v1", "files": files,
    "only_excluded_directory": "cargo-target", "complete_process_streams_retained": True},
    sort_keys=True, separators=(",", ":")) + "\n")
selected.append(manifest)
archive = output / "catalog-reference.tar.gz"
with tarfile.open(archive, "w:gz", compresslevel=6) as tar:
    for path in selected:
        tar.add(path, arcname=path.relative_to(source).as_posix(), recursive=False)
with archive.open("rb") as stream:
    digest = hashlib.file_digest(stream, "sha256").hexdigest()
metadata = {"archive": archive.name, "bytes": archive.stat().st_size, "sha256": digest,
            "files": len(files) + 1, "complete_archive": True,
            "reference_status": json.loads((source / "result.json").read_text())["status"]}
(output / "archive.json").write_text(json.dumps(metadata, sort_keys=True) + "\n")
print(json.dumps(metadata, sort_keys=True))
