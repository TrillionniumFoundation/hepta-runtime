# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Prepare original installed configuration and unchanged public method slices."""
from pathlib import Path
import hashlib
import json

from hia_native_config_reference import prepare_original_reference as prepare_config, check_project as check_files

sha = lambda raw: hashlib.sha256(raw).hexdigest()
encoded = lambda value: (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def source_blocks(root, oracle):
    root = Path(root)
    data = json.loads((root / "tests/hia_native/public_registry_reference/source-identity.json").read_bytes())
    server = (root / data["original_source"]).read_bytes()
    if sha(server) != data["original_sha256"] or len(data["blocks"]) != 10:
        raise ValueError("original server source or exact method set differs")
    for name, row in data["blocks"].items():
        raw = server[row["offset"]:row["offset"] + row["bytes"]]
        if sha(raw) != row["sha256"] or oracle[row["target_offset"]:row["target_offset"] + len(raw)] != raw:
            raise ValueError("original public method body differs: " + name)
    row = data["hia_tools_block"]
    original = (root / row["source"]).read_bytes()
    raw = original[row["offset"]:row["offset"] + row["bytes"]]
    if (sha(original) != row["source_sha256"] or sha(raw) != row["sha256"]
            or oracle[row["target_offset"]:row["target_offset"] + len(raw)] != raw):
        raise ValueError("original fixed HIA catalog predicate differs")
    if data["test_only_registry_projection"] is not True or data["outer_audit_result_lifecycle_closed"] is not False:
        raise ValueError("original projection scope broadened")
    for description in data["descriptions"].values():
        if server.count(description["attribute"].encode()) != 1:
            raise ValueError("original tool declaration changed")
    return data


def prepare_original_reference(root, project):
    root, project = Path(root).resolve(strict=True), Path(project)
    base = prepare_config(root, project)
    base_raw = (project / "reference-inputs.json").read_bytes()
    oracle = (root / "tests/hia_native/public_registry_reference/oracle_mcp.rs").read_bytes()
    blocks = source_blocks(root, oracle)
    if base["source_block_count"] != 54 or len(base["packages"]) != 100:
        raise ValueError("complete original config/execution dependency domain changed")
    if any(target["path"] == "mcp/oracle_mcp.rs"
           for row in json.loads((root / "tests/hia_native/config_reference_sources.json").read_bytes())["source_blocks"]
           for target in row["targets"]):
        raise ValueError("public wrapper replacement would modify an original config body")
    (project / "mcp/oracle_mcp.rs").write_bytes(oracle)
    (project / "config-reference-inputs.json").write_bytes(base_raw)
    files = dict(base["files"])
    files["mcp/oracle_mcp.rs"] = {"bytes": len(oracle), "sha256": sha(oracle)}
    files["config-reference-inputs.json"] = {"bytes": len(base_raw), "sha256": sha(base_raw)}
    result = {"schema": "hepta.public-registry.original-project.v1", "files": files,
        "base_config_preparation_sha256": sha(base_raw), "original_sources": base["original_sources"],
        "packages": base["packages"], "config_source_blocks": 54, "public_server_blocks": 10,
        "hia_catalog_predicate_blocks": 1, "public_blocks": blocks,
        "original_outer_call_tool_included": False, "public_audit_result_lifecycle_closed": False}
    (project / "reference-inputs.json").write_bytes(encoded(result))
    check_project(root, project, result)
    return result


def check_project(root, project, expected):
    root, project = Path(root), Path(project)
    check_files(project, expected)
    base = json.loads((root / "tests/hia_native/config_reference_sources.json").read_bytes())
    require_names = set(base["files"]) | {"config-reference-inputs.json"}
    if set(expected["files"]) != require_names or expected["original_sources"] != base["original_sources"]:
        raise ValueError("original reference file/source inventory changed")
    for name, row in base["files"].items():
        raw = (project / name).read_bytes()
        if name == "mcp/oracle_mcp.rs":
            if raw != (root / "tests/hia_native/public_registry_reference/oracle_mcp.rs").read_bytes():
                raise ValueError("whole public original projection changed")
        elif (len(raw), sha(raw)) != (row["bytes"], row["sha256"]):
            raise ValueError("whole original config/execution reference changed: " + name)
    if len(base["source_blocks"]) != 54:
        raise ValueError("original config/execution block set changed")
    for row in base["source_blocks"]:
        raw = (root / row["source"]).read_bytes()[row["offset"]:row["offset"] + row["bytes"]]
        if sha(raw) != row["sha256"]:
            raise ValueError("original config/execution source block changed")
        for target in row["targets"]:
            if (project / target["path"]).read_bytes()[target["offset"]:target["offset"] + len(raw)] != raw:
                raise ValueError("copied original config/execution block changed")
    if source_blocks(root, (project / "mcp/oracle_mcp.rs").read_bytes()) != expected["public_blocks"]:
        raise ValueError("exact original public source binding changed")
    for name, row in expected["original_sources"].items():
        raw = (root / name).read_bytes()
        blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        if (len(raw), sha(raw), blob) != (row["bytes"], row["sha256"], row["git_blob"]):
            raise ValueError("original source changed during public replay: " + name)
