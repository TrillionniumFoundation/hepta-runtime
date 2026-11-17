"""Lossless complete-byte archive; no native/Rust execution or semantic repair."""
from pathlib import Path
import argparse
import hashlib
import io
import json
import os
import stat
import sys
import tarfile
ROOT = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT))
from common import encoded, loads, pin, read, require, files, source


def run(workspace, archive):
    identity = source()
    logical = {}
    objects = {}
    roots = [("source", ROOT), ("run", workspace / "run")]
    for label, root in roots:
        if not root.exists():
            continue
        for name, row in files(root).items():
            path = root / name
            key = "objects/" + row["sha256"] + "-" + format(row["mode"], "03o")
            logical[label + "/" + name] = dict(row, object=key)
            if key in objects:
                require(objects[key][0] == row, "complete repeated object identity")
            else:
                objects[key] = (row, path)
    gate_path = workspace / "run/GATE.json"
    gate = loads(read(gate_path)) if gate_path.is_file() else dict(status="NO_FINAL_GATE")
    manifest = dict(schema="hepta.audit-pinned-anchor.archive.v1",
        git_head=os.environ.get("GITHUB_SHA"), run_id=os.environ.get("GITHUB_RUN_ID"),
        source_manifest_sha256=identity, files=logical, gate=gate,
        fresh_original_producer=True, exporter_original_rust_replay=0, archive_and_hot_cache_qualified=False,
        begin_finish_caller_qualified=False, public_handler_qualified=False, whole_runtime_replaced=False)
    body = encoded(manifest)
    with tarfile.open(archive, "w:gz", compresslevel=1) as target:
        for name, (row, path) in sorted(objects.items()):
            raw = read(path)
            require(pin(raw) == {k: row[k] for k in ("bytes", "sha256")}, "unchanged complete export object")
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(raw), row["mode"]
            target.addfile(info, io.BytesIO(raw))
        info = tarfile.TarInfo("artifact-manifest.json")
        info.size, info.mode = len(body), 0o644
        target.addfile(info, io.BytesIO(body))
    seen = {}
    with tarfile.open(archive, "r|gz") as retained:
        while entry := retained.next():
            require(entry.isfile() and entry.name not in seen, "unique regular complete exported member")
            with retained.extractfile(entry) as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            seen[entry.name] = dict(bytes=entry.size, sha256=digest, mode=entry.mode)
            retained.members.clear()
    expected = {name: row for name, (row, _) in objects.items()}
    expected["artifact-manifest.json"] = dict(**pin(body), mode=0o644)
    require(seen == expected, "every completed TAR byte and mode re-read")
    for _, root in roots:
        if root.exists():
            # Reread every complete logical file, even when its contents were deduplicated.
            current = files(root)
            label = next(label for label, item in roots if item == root)
            wanted = {name[len(label) + 1:]: {k: row[k] for k in ("bytes", "sha256", "mode")}
                      for name, row in logical.items() if name.startswith(label + "/")}
            require(current == wanted, "every logical file remains complete after export")
    require(source() == identity, "unchanged complete export source")
    with archive.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    report = dict(schema="hepta.audit-pinned-anchor.archive-read.v1", status=gate["status"],
        bytes=archive.stat().st_size, sha256=digest, logical_files=len(logical),
        logical_bytes=sum(row["bytes"] for row in logical.values()), unique_objects=len(objects),
        source_manifest_sha256=identity, all_objects_and_modes_reread=True, all_logical_files_reread=True,
        exporter_native_or_rust_executions=0, exporter_original_rust_replay=0, public_handler_qualified=False)
    archive.with_suffix(archive.suffix + ".json").write_bytes(encoded(report))
    print(encoded(report).decode(), end="")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--workspace", type=Path, required=True)
    p.add_argument("--archive", type=Path, required=True)
    a = p.parse_args()
    run(a.workspace.resolve(strict=True), a.archive.absolute())
