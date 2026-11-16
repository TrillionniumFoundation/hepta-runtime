#!/usr/bin/env python3
"""Compose exact current Batch/Text functions with a new real SDK test carrier.

No Rust process is started. The original whole-file inputs and every included
production span are verified independently of native images and expected wires.
"""
from pathlib import Path
import argparse
import hashlib
import json
import tomllib

TARGET = "d3d75c30719db966b004756f610007a7c723729e"


def pin(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "git_blob": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()}


def original_function(raw, anchor, ending):
    assert raw.count(anchor) == 1, anchor
    start = raw.index(anchor)
    end = raw.index(ending, start) + len(ending)
    return raw[start:end], start, end


def compose(baseline, core):
    manifest_raw = (baseline / "source_manifest.json").read_bytes()
    manifest = json.loads(manifest_raw)
    assert manifest["target_commit"] == TARGET
    assert len(manifest["exact_original_items"]) == 106 and len(manifest["files"]) == 34
    for name, identity in manifest["files"].items():
        assert pin((baseline / name).read_bytes()) == identity, name
    target_profile = json.loads((core / "reference/target-source.json").read_bytes())
    assert target_profile["commit"] == TARGET
    targets = {}
    for name, expected in target_profile["files"].items():
        raw = (core / "reference/target" / name).read_bytes()
        identity = pin(raw)
        assert dict(bytes=identity["bytes"], sha256=identity["sha256"], git_blob_sha=identity["git_blob"]) == expected, name
        targets[name] = raw
    for name, expected in manifest["target_files"].items():
        raw = (baseline / "target" / name).read_bytes()
        assert pin(raw) == expected, name
        if name in targets:
            assert targets[name] == raw
        targets[name] = raw
    body_proof = json.loads((core / "reference/project/source-extraction.json").read_bytes())
    assert body_proof["target_commit"] == TARGET and len(body_proof["body_fragments"]) == 15
    output = {}
    for name, identity in body_proof["body_fragments"].items():
        raw = (core / "reference/project/original" / name).read_bytes()
        assert {k: pin(raw)[k] for k in ("bytes", "sha256")} == identity
        assert any(raw in whole for whole in targets.values()), name
        output["original/" + name] = raw
    preserved = (
        "src/types.rs", "src/original_session.rs", "src/original_config.rs",
        "src/mcp/runtime/effect_owner_fence.rs", "src/original_file_ops.rs",
        "src/original_gateway.rs", "src/original_dispatch.rs", "src/original_sftp_unavailable.rs",
        "src/cache_observer.rs", "src/history_observer.rs", "src/lock_observer.rs",
    )
    for name in preserved:
        output[name] = (baseline / name).read_bytes()
    output["src/batch_types.rs"] = (core / "reference/project/src/original.rs").read_bytes()
    server = targets["src/mcp/server.rs"]
    batch, batch_start, batch_end = original_function(server, b"\tasync fn batch_edit(", b"\n\t}\n")
    dispatch, dispatch_start, dispatch_end = original_function(targets["src/mcp/fs/core.rs"],
        b"pub async fn execute_batch_edit(", b"\n}\n")
    info, info_start, info_end = original_function(server, b"\tfn get_info(&self)", b"\n\t}\n")
    mkdir, mkdir_start, mkdir_end = original_function(targets["src/mcp/fs/remote.rs"],
        b"pub async fn io_create_dir_all(", b"\n}\n")
    note, note_start, note_end = original_function(targets["src/mcp/fs/delta.rs"],
        b"pub fn note_create(", b"\n}\n")
    capability = b'const CLAUDE_CHANNEL_CAPABILITY: &str = "claude/channel";'
    assert server.count(capability) == 1
    output["src/original_batch_gateway.rs"] = b"impl OctofsServer {\n" + batch + b"}\n"
    output["src/original_batch_dispatch.rs"] = dispatch
    output["src/original_get_info.rs"] = (capability + b"\ntrait OriginalInfo { fn get_info(&self) -> ServerConfig; }\n"
        + b"impl OriginalInfo for OctofsServer {\n" + info + b"}\n")
    output["src/original_mkdir.rs"] = mkdir
    output["src/original_note_create.rs"] = note
    output["src/main.rs"] = (Path(__file__).parent / "public_reference_main.rs").read_bytes()
    old_name = b"hepta-text-editor-gateway-local-original-oracle"
    new_name = b"hepta-batch-sdk-current-original-oracle"
    for name in ("Cargo.toml", "Cargo.lock"):
        raw = (baseline / name).read_bytes()
        assert raw.count(old_name) == 1
        output[name] = raw.replace(old_name, new_name)
    resolved_lock = (Path(__file__).parent / "resolved-lock.toml").read_bytes()
    lock_origin = json.loads((Path(__file__).parent / "lock-origin.json").read_bytes())
    package_key = lambda package: (package["name"], package["version"], package.get("source", ""))
    assert sorted(tomllib.loads(output["Cargo.lock"].decode())["package"], key=package_key) == sorted(
        tomllib.loads(resolved_lock.decode())["package"], key=package_key)
    assert pin(output["Cargo.lock"])["sha256"] == lock_origin["old_sha256"]
    assert pin(resolved_lock)["sha256"] == lock_origin["new_sha256"]
    output["Cargo.lock"] = resolved_lock
    exact_items = []
    compiled = {name: raw for name, raw in output.items() if name.endswith(".rs")}
    for old in manifest["exact_original_items"]:
        raw = targets[old["target"]][old["start"]:old["end"]]
        assert pin(raw) == {k: old[k] for k in ("bytes", "sha256", "git_blob")}
        locations = []
        for name, container in compiled.items():
            if raw in container:
                assert container.count(raw) == 1, name
                at = container.index(raw)
                locations.append({"container": name, "start": at, "end": at + len(raw)})
        assert locations, old["declaration"]
        exact_items.append({k: v for k, v in old.items() if k != "compiled_spans"} | {"compiled_spans": locations})
    added = []
    for name, start, end, target, raw in (
        ("batch_edit", batch_start, batch_end, "src/mcp/server.rs", batch),
        ("execute_batch_edit", dispatch_start, dispatch_end, "src/mcp/fs/core.rs", dispatch),
        ("get_info", info_start, info_end, "src/mcp/server.rs", info),
        ("io_create_dir_all", mkdir_start, mkdir_end, "src/mcp/fs/remote.rs", mkdir),
        ("note_create", note_start, note_end, "src/mcp/fs/delta.rs", note),
    ):
        assert targets[target][start:end] == raw
        added.append({"declaration": name, "target": target, "start": start, "end": end, **pin(raw)})
    proof = {"schema": "hepta.batch-sdk-current.original-source.v1", "target_commit": TARGET,
        "baseline_manifest": pin(manifest_raw), "target_files": {name: pin(raw) for name, raw in targets.items()},
        "preserved_original_items": exact_items, "preserved_body_fragments": body_proof["body_fragments"],
        "preserved_parameter_fragments": body_proof["parameter_fragments"], "additional_exact_spans": added,
        "original_get_info_name_and_body_unchanged": True,
        "fixture_lock_origin": lock_origin,
        "new_wrapper": pin(output["src/main.rs"]), "files": {name: pin(raw) for name, raw in output.items()},
        "real_sdk_serve_transport": True, "real_parameters_extractor_and_method_adapter": True,
        "target_gateway_and_full_local_functions": True, "complete_target_call_tool_router": False,
        "fresh_rust_build": False, "native_original_comparison": False,
        "full_async_cancellation_qualified": False, "remote_sftp_qualified": False,
        "public_batch_qualified": False, "whole_runtime_replaced": False}
    output["SOURCE.json"] = (json.dumps(proof, sort_keys=True, indent=2) + "\n").encode()
    return output, proof


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--baseline", type=Path, required=True)
    p.add_argument("--core", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    output, proof = compose(a.baseline.resolve(strict=True), a.core.resolve(strict=True))
    a.output.mkdir(parents=True, exist_ok=False)
    for name, raw in output.items():
        path = a.output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    print(json.dumps({"status": "SOURCE_EXTRACTED", "files": len(output),
        "preserved_original_items": len(proof["preserved_original_items"]),
        "preserved_body_fragments": len(proof["preserved_body_fragments"]),
        "additional_exact_spans": len(proof["additional_exact_spans"]),
        "fresh_rust_build": False}, sort_keys=True))


if __name__ == "__main__":
    main()
