"""Materialize the unchanged SDK oracle from the current pinned Rust owners.

Only the small reference harness and lock subset live under tests/. Complete
original modules are read from this checkout, checked byte for byte, and copied
into the qualification output. The native producer reads the input generator;
it neither compiles nor executes the Rust reference.
"""
from pathlib import Path
import hashlib
import json
import os
import stat

ORACLE = "tests/hia_native/filesystem_sdk_oracle"
FOLDER = "filesystem-public/reference-source"
MANIFEST = ORACLE + "/source_manifest.json"
SCHEMA = "hepta.runtime.filesystem-public-reference-source.v1"
ORIGINALS = {
    "Cargo.lock": "Cargo.lock",
    "Cargo.toml": "Cargo.toml",
    "config.rs": "src/mcp/runtime/config.rs",
    "delta.rs": "src/mcp/fs/delta.rs",
    "effect_owner_fence.rs": "src/mcp/runtime/effect_owner_fence.rs",
    "mcp_mod.rs": "src/mcp/mod.rs",
    "parity_ops.rs": "src/mcp/fs/parity_ops.rs",
    "remote.rs": "src/mcp/fs/remote.rs",
    "request_ctx.rs": "src/mcp/request_ctx.rs",
    "server.rs": "src/mcp/server.rs",
    "text_editing.rs": "src/mcp/fs/text_editing.rs",
}
HARNESS = ("cases.py", "oracle/Cargo.lock", "oracle/Cargo.toml",
           "oracle/src/driver.rs", "oracle/verify_sources.py", "run.py")


def need(value, message):
    if not value:
        raise ValueError("FS public reference source: " + message)


def pin(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def decode(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def canonical(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, allow_nan=False,
                       separators=(",", ":")) + "\n").encode()


def relative(name):
    need(type(name) is str and name and "\\" not in name and "\x00" not in name,
         "invalid relative source name")
    path = Path(name)
    need(not path.is_absolute() and all(part not in ("", ".", "..") for part in name.split("/")),
         "source name escapes its owner")
    return path


def regular(root, name):
    root = Path(root).absolute()
    need(not root.is_symlink() and root.resolve(strict=True) == root, "source root crosses a symlink")
    path = root / relative(name)
    need(path.resolve(strict=True) == path and stat.S_ISREG(path.lstat().st_mode),
         "source is not a regular unsymlinked file: " + name)
    return path


def source_evidence(root):
    root = Path(root).absolute()
    manifest_path = regular(root, MANIFEST)
    raw = manifest_path.read_bytes()
    document = decode(raw)
    need(type(document) is dict and document.get("schema") == SCHEMA, "source manifest schema")
    for field in ("original_reference_source_unchanged", "originals_materialized_from_current_repository"):
        need(document.get(field) is True, field)
    for field in ("original_full_router_executed", "original_config_loader_executed"):
        need(document.get(field) is False, field)
    expected = {name: ORACLE + "/" + name for name in HARNESS}
    expected.update({"oracle/original/" + name: path for name, path in ORIGINALS.items()})
    need(type(document.get("files")) is dict and set(document["files"]) == set(expected),
         "exact 17-file original input closure")
    materialized, sources = {}, {MANIFEST: pin(raw)}
    for name, source in sorted(expected.items()):
        row = document["files"][name]
        need(type(row) is dict and set(row) == {"source", "bytes", "sha256"}
             and row["source"] == source and type(row["bytes"]) is int and row["bytes"] >= 0,
             "source mapping differs: " + name)
        body = regular(root, source).read_bytes()
        need(pin(body) == {key: row[key] for key in ("bytes", "sha256")}, "source bytes differ: " + name)
        sources[source] = pin(body)
        materialized[name] = body
    row = document.get("reference_reader")
    reader_name = ORACLE + "/strict_reference.py"
    need(type(row) is dict and set(row) == {"source", "bytes", "sha256"}
         and row["source"] == reader_name and type(row["bytes"]) is int,
         "unchanged reference reader mapping")
    reader = regular(root, reader_name).read_bytes()
    need(pin(reader) == {key: row[key] for key in ("bytes", "sha256")}, "unchanged reference reader bytes")
    sources[reader_name] = pin(reader)
    return document, materialized, dict(sorted(sources.items()))


def materialize(root, output):
    root, output = Path(root).absolute(), Path(output).absolute()
    document, bodies, sources = source_evidence(root)
    destination = output / FOLDER
    need(output.resolve(strict=True) == output and not output.is_symlink(), "output root is not real")
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    need(destination.parent.resolve(strict=True) == destination.parent, "output parent crosses a symlink")
    if destination.exists() or destination.is_symlink():
        return verify_materialized(root, output)
    destination.mkdir(mode=0o700)
    for name, body in bodies.items():
        path = destination / relative(name)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(body)
        path.chmod(0o600)
    proof = {"schema": "hepta.runtime.filesystem-public-reference-materialization.v1",
             "execution_source_root": str(root), "execution_output_root": str(output),
             "reference_source": FOLDER, "source_manifest": pin(regular(root, MANIFEST).read_bytes()),
             "source_files": sources, "materialized_files": {name: pin(body) for name, body in sorted(bodies.items())},
             "original_files_copied_from_current_checkout": len(ORIGINALS),
             "new_rust_processes": 0, "original_semantics_executed": False}
    with (destination / "MATERIALIZATION.json").open("xb") as stream:
        stream.write(canonical(proof))
    return verify_materialized(root, output)


def verify_materialized(root, output):
    root, output = Path(root).absolute(), Path(output).absolute()
    document, bodies, sources = source_evidence(root)
    destination = output / FOLDER
    proof = decode(regular(destination, "MATERIALIZATION.json").read_bytes())
    expected = {"schema": "hepta.runtime.filesystem-public-reference-materialization.v1",
                "reference_source": FOLDER, "source_manifest": pin(regular(root, MANIFEST).read_bytes()),
                "source_files": sources, "materialized_files": {name: pin(body) for name, body in sorted(bodies.items())},
                "original_files_copied_from_current_checkout": len(ORIGINALS),
                "new_rust_processes": 0, "original_semantics_executed": False}
    need(type(proof) is dict and set(proof) == set(expected) | {"execution_source_root", "execution_output_root"},
         "complete materialization proof")
    need(all(proof[key] == value and type(proof[key]) is type(value) for key, value in expected.items()),
         "materialization proof differs from current source")
    for key in ("execution_source_root", "execution_output_root"):
        value = proof[key]
        need(type(value) is str and Path(value).is_absolute() and ".." not in Path(value).parts,
             "invalid recorded execution root")
    found, directories = set(), set()
    for base, dirs, names in os.walk(destination, followlinks=False):
        for name in dirs:
            item = Path(base) / name
            need(stat.S_ISDIR(item.lstat().st_mode), "unexpected source directory kind")
            directories.add(item.relative_to(destination).as_posix())
        for name in names:
            item = Path(base) / name
            found.add(item.relative_to(destination).as_posix())
    need(found == set(bodies) | {"MATERIALIZATION.json"}, "unexpected materialized input file")
    expected_directories = {str(parent) for name in bodies for parent in Path(name).parents if str(parent) != "."}
    need(directories == expected_directories, "unexpected materialized input directory")
    artifacts = {}
    for name, body in bodies.items():
        actual = regular(destination, name).read_bytes()
        need(actual == body, "materialized original changed: " + name)
        artifacts[FOLDER + "/" + name] = pin(actual)
    artifacts[FOLDER + "/MATERIALIZATION.json"] = pin(regular(destination, "MATERIALIZATION.json").read_bytes())
    return {"schema": "hepta.runtime.filesystem-public-reference-source-evidence.v1", "status": "PASS",
            "proof": proof, "source_sha256": {name: item["sha256"] for name, item in sources.items()},
            "artifact_sha256": {name: item["sha256"] for name, item in sorted(artifacts.items())},
            "artifact_bytes": {name: item["bytes"] for name, item in sorted(artifacts.items())},
            "new_rust_processes": 0, "original_semantics_executed": False}
