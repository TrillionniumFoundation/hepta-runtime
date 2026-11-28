# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Prepare complete retained observations and the exact locked SDK reference.

Preparation runs neither HIA nor Rust. The reference wrapper records SDK values;
the runtime get_info body and every registry package are independently pinned.
"""
from pathlib import Path
import hashlib
import io
import json
import tarfile
import tomllib

sha = lambda raw: hashlib.sha256(raw).hexdigest()
encoded = lambda value: (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
PROJECT_FILES = {"Cargo.toml", "Cargo.lock", "original-runtime.lock", "rustfmt.toml",
                 "oracle_connection_context.rs", "oracle_message_decode.rs", "oracle_transport_decode.rs",
                 "generated_get_info.rs"}


def need(condition, message):
    if not condition:
        raise ValueError("connection reference: " + message)


def read(path):
    path = Path(path)
    need(path.is_file() and not path.is_symlink(), "not a regular file: " + str(path))
    return path.read_bytes()


def prepare_cases(root, target):
    folder = Path(root) / "tests/hia_native"
    index = json.loads(read(folder / "connection_reference_cases.json"))
    need(index["schema"] == "hepta.sdk-connection.reference-cases.v1", "case schema changed")
    need(index["cases"] == {"message-core": 1321, "message-boundaries": 3461, "transport-core": 1343,
                            "lifecycle-core": 1621, "lifecycle-matrix": 582}, "case domain changed")
    need(index["retained_actual_original_observations"] is True and index["fresh_execution"] is False,
         "retained observations were misclassified")
    raw = read(folder / index["archive"])
    need((len(raw), sha(raw)) == (index["archive_bytes"], index["archive_sha256"]), "case archive changed")
    target = Path(target)
    target.mkdir(parents=True, exist_ok=False)
    seen = set()
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as stream:
        for entry in stream:
            name = entry.name
            need(entry.isfile() and name in index["files"] and name not in seen and not Path(name).is_absolute()
                 and ".." not in Path(name).parts, "unknown/unsafe/duplicate case entry")
            body = stream.extractfile(entry).read()
            want = index["files"][name]
            need((len(body), sha(body), body.count(b"\n")) == (want["bytes"], want["sha256"], want["lines"]), "case bytes changed")
            path = target / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
            seen.add(name)
    need(seen == set(index["files"]), "case inventory incomplete")
    return index


def check_project(project, metadata):
    project = Path(project)
    for name, want in metadata["files"].items():
        raw = read(project / name)
        need((len(raw), sha(raw)) == (want["bytes"], want["sha256"]), "project input changed: " + name)


def prepare_original_reference(root, target):
    root = Path(root).resolve(strict=True)
    source = root / "tests/hia_native/connection_reference"
    metadata = json.loads(read(source / "source-identity.json"))
    need(metadata["schema"] == "hepta.sdk-connection.original-project.v1", "project schema changed")
    need(set(metadata["files"]) == PROJECT_FILES, "exact original project inventory differs")
    check_project(source, metadata)
    originals = {}
    for name, want in metadata["original_sources"].items():
        raw = read(root / name)
        blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        need((len(raw), sha(raw), blob) == (want["bytes"], want["sha256"], want["git_blob"]), "original source changed: " + name)
        originals[name] = raw
    for block in metadata["original_blocks"]:
        raw = originals[block["source"]][block["offset"]:block["offset"] + block["bytes"]]
        need(sha(raw) == block["sha256"], "original method slice changed")
        destination = read(source / block["target"])
        need(destination[block["target_offset"]:block["target_offset"] + len(raw)] == raw, "included method is not unchanged")
    need(len(metadata["original_blocks"]) == 1, "original runtime method domain changed")
    need(read(source / "original-runtime.lock") == originals["Cargo.lock"], "original dependency lock changed")
    original = {(row["name"], row["version"]): row for row in tomllib.loads(originals["Cargo.lock"].decode())["package"] if "checksum" in row}
    packages = []
    for row in tomllib.loads(read(source / "Cargo.lock").decode())["package"]:
        if "checksum" not in row:
            continue
        expected = original.get((row["name"], row["version"]))
        need(expected is not None and row["source"] == expected["source"] and row["checksum"] == expected["checksum"], "registry dependency changed")
        packages.append({key: row[key] for key in ("name", "version", "source", "checksum")})
    need(len(packages) == metadata["registry_packages"] == 100, "registry closure changed")
    sdk = [row for row in packages if row["name"] == "rmcp"]
    need(len(sdk) == 1 and sdk[0]["version"] == "3.4.1"
         and sdk[0]["checksum"] == "5b6317cd8c13e3ec9033cf2aa5aa92cd743f0f4f8a93cddc42ea0ae6ce3b8898", "SDK crate changed")
    target = Path(target)
    target.mkdir(parents=True, exist_ok=False)
    for name in metadata["files"]:
        need(Path(name).name == name, "project path escaped")
        (target / name).write_bytes(read(source / name))
    receipt = {"schema": "hepta.sdk-connection.original-preparation.v1", "files": metadata["files"],
               "packages": packages, "original_sources": metadata["original_sources"], "original_blocks": metadata["original_blocks"],
               "source_identity_sha256": sha(read(source / "source-identity.json")), "shared_actual_cargo_build": True,
               "native_or_rust_execution_during_preparation": False}
    (target / "reference-inputs.json").write_bytes(encoded(receipt))
    check_project(target, receipt)
    return receipt
