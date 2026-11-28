"""Source-only custody for the exact current-target OwnerScope reference.

This module never maps native code, starts a process, edits a lockfile, or writes
a report. Package admission is a source check, not evidence that Cargo accepted
the authored reduced feature closure.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tomllib

TARGET_COMMIT = "d3d75c30719db966b004756f610007a7c723729e"
TARGET_PINS = {
    "Cargo.toml": "bf00111f6ec88df9df4d0d1d14c125a64ce4f6bdc6724ba20e70498f56dcae7f",
    "Cargo.lock": "1509860cac0e7f26e6a845edfec1c87ae3bd92380ecaa357457e5263e861d631",
    "src/main.rs": "1d8b3d12621d5a30a09d76e49d27b2fab2304cb82bcc7526403a662f85b51fd1",
    "src/mcp/runtime/caller_scope.rs": "1db8a3f4235339d8a7aef6e247ddc8f42f4791a26efe4dd298490421b8ca1d9a",
    "src/mcp/runtime/operation_crypto.rs": "a48463ef35ca41d0aa8ef64fcaeb9d3245773052221789a38d18d52ced891633",
    "src/mcp/runtime/search_jobs.rs": "d24a8e03a636cc0ed570fed36ea4d4505c285ddc3e963053c2496f683c127537"
}
ORACLE_PINS = {
    "tests/hia_native/oracle_caller_owner_export.rs": "1b24ae84529128a07f18e4c1a25367ca68bdc07937527343e3c0a0b6c5c2dc5f",
    "tests/hia_native/owner_export_oracle/build.rs": "3389d43fa58b01f99a455a7361d4a3c6d5e3065d56a913be151c43831be7a654",
    "tests/hia_native/owner_export_oracle/Cargo.toml": "47ac7a054b9b7511536547e9d0529ca34b758bd1ac4a65796166b49c01899c01",
    "tests/hia_native/owner_export_oracle/Cargo.lock": "c62037f5edf9d45f7134f8f8fc2ac91d04f536ce60455d2b1a3953931d2b920c",
    "tests/hia_native/owner_export_oracle/original_access.rs": "6f4ac6024d3e529754c3e89d55b34721e215f9e99afc33616d05805f12361aab",
    "tests/hia_native/owner_export_oracle/crypto_access.rs": "e208c3c669d2589f8aa7046d7763a74fbffb79f34e8ae58d98dd0443fb9a740e"
}
LOCAL_PACKAGE = "hia-caller-owner-export-reference"
ORACLE = Path("tests/hia_native/owner_export_oracle")
REFERENCE = Path("tests/hia_native/caller_owner_export/reference")


def require(condition, message):
    if not condition:
        raise ValueError("owner export original source: " + message)


def read(path):
    path = Path(path).absolute()
    require(path.is_file() and not path.is_symlink() and path.resolve() == path,
            "source must be an exact regular non-aliased path")
    return path.read_bytes()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def source_files(root):
    root = Path(root).resolve(strict=True)
    result = {}
    for name, expected in TARGET_PINS.items():
        raw = read(root / REFERENCE / name)
        require(sha(raw) == expected, "target file differs: " + name)
        result[(REFERENCE / name).as_posix()] = {"bytes": len(raw), "sha256": expected}
    for name, expected in ORACLE_PINS.items():
        raw = read(root / name)
        require(sha(raw) == expected, "original fixture differs: " + name)
        result[name] = {"bytes": len(raw), "sha256": expected}
    return result


def generated_source(root):
    root = Path(root).resolve(strict=True)
    source_files(root)
    reference = root / REFERENCE
    caller = read(reference / "src/mcp/runtime/caller_scope.rs").decode()
    crypto = read(reference / "src/mcp/runtime/operation_crypto.rs").decode()
    search = read(reference / "src/mcp/runtime/search_jobs.rs").decode()
    main = read(reference / "src/main.rs").decode()
    start = '#[derive(Clone)]\nstruct HttpAuth {'
    stop = "/// Run the MCP server over authenticated Streamable HTTP in every tool mode."
    require(main.count(start) == main.count(stop) == 1, "current HTTP segment boundary differs")
    auth_begin, auth_end = main.index(start), main.index(stop)
    require(auth_begin < auth_end, "HTTP segment order differs")
    auth = main[auth_begin:auth_end]
    owner_start = "pub fn new_owner_id() -> Result<String> {"
    owner_stop = "\nfn instance()"
    require(search.count(owner_start) == search.count(owner_stop) == 1,
            "owner entropy segment boundary differs")
    begin, end = search.index(owner_start), search.index(owner_stop)
    require(begin < end, "owner entropy segment order differs")
    owner = search[begin:end]
    access = read(root / ORACLE / "original_access.rs").decode()
    crypto_access = read(root / ORACLE / "crypto_access.rs").decode()
    generated = (
        "#[allow(dead_code)]\nmod mcp {\npub mod runtime {\npub mod operation_crypto {\n"
        + crypto + "\n" + crypto_access + "\n}\npub mod caller_scope {\n"
        + caller + "\n" + access + "\n}\npub mod owner_reference {\n"
        + "use anyhow::{Context, Result};\nuse std::io::Read;\n"
        + owner + "\n}\n}\n}\n" + auth
    )
    return {
        "original_authority_reference.rs": generated.encode(),
        "original_auth_segment.rs": auth.encode(),
        "original_owner_segment.rs": owner.encode(),
    }


def _identity(row):
    return (row["name"], row["version"], row.get("source"))


def _dependency(rows, text):
    require(type(text) is str and bool(text), "lock dependency spelling differs")
    parts = text.split(" ")
    name = parts[0]
    version = parts[1] if len(parts) > 1 and not parts[1].startswith("(") else None
    candidates = [row for row in rows if row.get("name") == name
                  and (version is None or row.get("version") == version)]
    require(len(candidates) == 1, "lock dependency is missing or ambiguous: " + text)
    return _identity(candidates[0])


def dependencies(root):
    root = Path(root).resolve(strict=True)
    source_files(root)
    target = tomllib.loads(read(root / REFERENCE / "Cargo.lock").decode())["package"]
    actual = tomllib.loads(read(root / ORACLE / "Cargo.lock").decode())["package"]
    manifest = tomllib.loads(read(root / ORACLE / "Cargo.toml").decode())
    require(manifest["package"]["name"] == LOCAL_PACKAGE
            and manifest["package"]["version"] == "0.0.0"
            and manifest["package"]["edition"] == "2021"
            and manifest["package"]["publish"] is False,
            "local reference package identity differs")
    locals_ = [row for row in actual if "source" not in row]
    require(len(locals_) == 1 and locals_[0]["name"] == LOCAL_PACKAGE
            and locals_[0]["version"] == "0.0.0", "local package lock differs")
    target_rows = {_identity(row): row for row in target}
    require(len(target_rows) == len(target), "target package identity repeats")
    identities = [_identity(row) for row in actual]
    require(len(set(identities)) == len(actual), "reference package identity repeats")
    registry = []
    for row in actual:
        if "source" not in row:
            continue
        key = _identity(row)
        require(row["source"] == "registry+https://github.com/rust-lang/crates.io-index",
                "non-registry reference dependency")
        expected = target_rows.get(key)
        require(expected is not None and row.get("checksum") == expected.get("checksum"),
                "version/checksum differs from the exact target: " + row["name"])
        selected = {_dependency(actual, item) for item in row.get("dependencies", [])}
        allowed = {_dependency(target, item) for item in expected.get("dependencies", [])}
        require(selected <= allowed, "reference feature edge is absent from target: " + row["name"])
        registry.append({"name": row["name"], "version": row["version"],
                         "source": row["source"], "checksum": row["checksum"]})
    pinned = {name: [row["version"] for row in actual if row["name"] == name]
              for name in ("rmcp", "rmcp-macros", "tokio")}
    require(pinned == {"rmcp": ["3.9.0"], "rmcp-macros": ["3.9.0"], "tokio": ["1.53.3"]},
            "current SDK/runtime dependency differs")
    require(len(actual) == 133, "authored package count differs")
    return {
        "target_commit": TARGET_COMMIT,
        "reference_lock_sha256": ORACLE_PINS[(ORACLE / "Cargo.lock").as_posix()],
        "target_lock_sha256": TARGET_PINS["Cargo.lock"],
        "locked_package_count": len(actual),
        "registry_packages": sorted(registry, key=lambda row: (row["name"], row["version"])),
        "registry_versions_and_checksums_match_target": True,
        "feature_edges_are_target_subsets": True,
        "cargo_locked_acceptance_inferred_from_source": False,
    }


def evidence(root):
    files = source_files(root)
    generated = generated_source(root)
    return {
        "schema": "hepta.runtime.owner-export.original-source.v1",
        "target_commit": TARGET_COMMIT,
        "source_inputs": {"files": files},
        "generated_sources": {name: {"bytes": len(raw), "sha256": sha(raw)}
                              for name, raw in sorted(generated.items())},
        "dependencies": dependencies(root),
        "new_original_processes": 0,
        "current_http_listener_qualified": False,
        "concurrent_session_binding_qualified": False,
        "whole_runtime_replaced": False,
    }
