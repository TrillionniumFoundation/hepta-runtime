"""Extract only complete regular-file qualification archives, checking every byte."""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import json
import os
import tarfile


def pin(path):
    with Path(path).open("rb") as stream:
        value = hashlib.file_digest(stream, "sha256").hexdigest()
    return dict(bytes=Path(path).stat().st_size, sha256=value)


def safe(name):
    path = PurePosixPath(name)
    assert name and not path.is_absolute() and ".." not in path.parts
    assert str(path) == name and "\\" not in name
    return Path(*path.parts)


def extract(kind, archive, index_path, output):
    archive = Path(archive).resolve(strict=True)
    index_path = Path(index_path).resolve(strict=True)
    output = Path(output).absolute()
    assert not output.exists()
    index = json.loads(index_path.read_bytes())
    assert pin(archive) == {key: index[key] for key in ("bytes", "sha256")}
    if kind == "authority":
        assert index["status"] == "READONLY_PUBLIC102_AUTHORITY259_HANDSHAKE324_PUBLIC90_TRANSPORT24_PASS"
        assert index["complete_archive_reread"] is True and index["readonly_export_reader_error"] is None
    else:
        assert kind == "batch" and index["recipe_status"] == "PASS"
        assert index["unreadable_failed_fixture_files"] == 0
    output.mkdir(parents=True)
    rows, directories, manifest = {}, set(), None
    with tarfile.open(archive, "r:gz") as tar:
        for item in tar:
            relative = safe(item.name)
            path = output / relative
            assert item.name not in rows and item.name not in directories
            assert path.absolute().is_relative_to(output)
            if item.isdir():
                path.mkdir(parents=True, exist_ok=True)
                directories.add(item.name)
                continue
            assert item.isfile() and not item.issym() and not item.islnk()
            path.parent.mkdir(parents=True, exist_ok=True)
            digest, size = hashlib.sha256(), 0
            with tar.extractfile(item) as source, path.open("xb") as destination:
                while block := source.read(1 << 20):
                    destination.write(block)
                    digest.update(block)
                    size += len(block)
            assert size == item.size
            path.chmod(item.mode & 0o777)
            rows[item.name] = dict(bytes=size, sha256=digest.hexdigest())
            if item.name == "artifact-manifest.json":
                manifest = json.loads(path.read_bytes())
    assert manifest is not None
    declared = manifest["files"]
    assert set(rows) == set(declared) | {"artifact-manifest.json"}
    assert {name: value for name, value in rows.items() if name != "artifact-manifest.json"} == declared
    if kind == "authority":
        assert manifest["complete_source_and_captures"] is True
        assert directories == set(manifest["directories"])
        assert len(rows) == index["files"] and len(directories) == index["directories"]
        assert sum(row["bytes"] for row in rows.values()) == index["uncompressed_bytes"]
    else:
        assert rows["artifact-manifest.json"] == index["manifest"]
        assert len(declared) == index["regular_files"]
        assert manifest["recipe_status"] == "PASS" and manifest["unreadable_failed_fixture_files"] == []
        assert manifest["all_observed_regular_file_bytes_retained"] is True
        assert not directories
        for name, node in manifest["nodes"].items():
            assert os.fsencode(name).hex() == node["path_hex"]
            path = output / safe(name)
            assert node["kind"] in ("file", "directory")
            if node["kind"] == "directory":
                path.mkdir(parents=True, exist_ok=True)
                directories.add(name)
            else:
                assert name in declared and declared[name] == {key: node[key] for key in ("bytes", "sha256")}
        assert len(manifest["nodes"]) == index["nodes"]
    return dict(status="COMPLETE_QUALIFICATION_ARCHIVE_HASH_PASS", kind=kind,
        archive=pin(archive), archive_index=pin(index_path), regular_files=len(rows),
        regular_bytes=sum(row["bytes"] for row in rows.values()), directories=len(directories),
        native_or_rust_executions=0, all_declared_regular_bytes_recovered=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", choices=("authority", "batch"), required=True)
    for name in ("archive", "index", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(extract(args.kind, args.archive, args.index, args.output), sort_keys=True))
