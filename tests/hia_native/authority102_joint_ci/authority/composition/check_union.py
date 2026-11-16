"""Reproduce the exact isolated Batch-on-Authority source composition, without execution."""
from pathlib import Path
import argparse
import copy
import hashlib
import importlib.util
import json
import sys

sys.dont_write_bytecode = True
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
ENCODE = lambda value: (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
BINDING = "41a42a6247d8b4bf0ccee11e743bad28285273637b9f824fcbf2f0bf9bad0726"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def inputs(root):
    raw = (root / "native/runtime_mcp_sources.json").read_bytes()
    binding = json.loads(raw)
    result = {}
    for name, wanted in binding["sources"].items():
        path = Path(name)
        assert not path.is_absolute() and ".." not in path.parts
        data = (root / path).read_bytes()
        assert wanted == dict(bytes=len(data), sha256=SHA(data)), name
        result[name] = data
    return raw, binding, result


def summary(source):
    source = Path(source)
    base_raw, base, originals = inputs(source / "authority-before")
    batch_raw, batch, _ = inputs(source / "batch-before")
    raw, final, actual = inputs(source / "source")
    assert SHA(raw) == BINDING and len(actual) == 217
    extension = final["authority_batch_union"]
    assert extension["authority_binding"] == SHA(base_raw)
    assert extension["batch_binding"] == SHA(batch_raw)
    assert extension["author_sha256"] == SHA((source / "composition/author_union.py").read_bytes())
    proof = json.loads(actual["native/runtime_mcp_batch_composition.json"])
    assert proof["entry_ast_byte_exact"] is True and proof["baseline_functions"] == 70
    assert proof["functions"] == 73 and proof["fixed_child"] == 13
    assert proof["other_phases_and_original_functions_unchanged"] is True
    assert proof["source_sha256"] == SHA(actual["native/runtime_mcp.hepta"])
    return dict(status="EXACT_AUTHORITY102_SOURCE_COMPOSITION_PASS",
        authority_sources=len(originals), batch_sources=len(batch["sources"]), joint_sources=len(actual),
        authority_binding_sha256=SHA(base_raw), batch_binding_sha256=SHA(batch_raw),
        joint_binding_sha256=SHA(raw), frontend_source_sha256=proof["source_sha256"],
        retained_authority_frontend_functions=70, composed_frontend_functions=73,
        retained_entry_ast_exact=True, private_descriptor_offset=8192, engine_bytes=16384,
        child13_global_slot47=True, original_corpus_changed=False, original_rust_changed=False,
        native_or_rust_executions=0, semantic_qualification_claimed=False)


def verify(source, hepta):
    source = Path(source).resolve(strict=True)
    transform = load("_retained_authority102_author", source / "composition/author_union.py")
    base_raw, base, originals = inputs(source / "authority-before")
    assert SHA(base_raw) == transform.BASE_BINDING
    batch_raw, selected, batch = inputs(source / "batch-before")
    target_raw, _, expected = inputs(source / "source")
    files = dict(originals)
    generated = {"native/runtime_mcp.hepta", "native/runtime_mcp_composition.json",
        "native/runtime_mcp_batch_composition.json"}
    merged = {"scripts/public_nine_build.py", "scripts/hia_native_runtime_mcp_build.py",
        "scripts/text_editor_create_private_pack.py", "scripts/runtime_mcp_extra_engine.S",
        "scripts/runtime_mcp_filesystem_fixture.S", "scripts/runtime_mcp_filesystem_front_fixture.S",
        "scripts/runtime_mcp_transport.S"}
    files.update({name: raw for name, raw in batch.items() if name not in generated | merged})
    dynamic = load("_batch_dynamic_author", source / "composition/batch/authoring/author_frontend_dynamic.py")
    front, proof = dynamic.compose(source / "authority-before", Path(hepta).resolve(strict=True),
        SHA(originals["native/runtime_mcp.hepta"]))
    assert set(front) == generated and proof["baseline_functions"] == 70 and proof["functions"] == 73
    files.update(front)
    for name, function in {
        "scripts/public_nine_build.py": transform.merge_builder,
        "scripts/hia_native_runtime_mcp_build.py": transform.merge_default,
        "scripts/text_editor_create_private_pack.py": transform.merge_packer,
        "scripts/runtime_mcp_filesystem_fixture.S": transform.merge_fixture,
        "scripts/runtime_mcp_transport.S": transform.merge_transport,
    }.items():
        files[name] = function(originals[name].decode()).encode()
    files["scripts/runtime_mcp_extra_engine.S"] = transform.merge_engine(
        originals["scripts/runtime_mcp_extra_engine.S"].decode(),
        batch["scripts/runtime_mcp_extra_engine.S"].decode()).encode()
    assert files == expected
    binding = copy.deepcopy(base)
    for name in ("sdk_internal_projection_growth", "sdk_request_internal_capacity", "bounded_access_performance"):
        binding[name] = copy.deepcopy(selected[name])
    extension = copy.deepcopy(selected["rebuilt_batch_extension"])
    extension.update(base_members=91, physical_members=102,
        base_binding=dict(bytes=len(base_raw), sha256=SHA(base_raw)),
        frontend_composition=SHA(front["native/runtime_mcp_batch_composition.json"]))
    binding["rebuilt_batch_extension"] = extension
    binding["authority_batch_union"] = {
        "schema": "hepta.runtime.authority-batch-union-source.v1",
        "authority_commit": transform.BASE_COMMIT, "authority_binding": transform.BASE_BINDING,
        "batch_commit": transform.BATCH_COMMIT, "batch_binding": SHA(batch_raw),
        "batch_profile": transform.BATCH_PROFILE,
        "author_sha256": SHA((source / "composition/author_union.py").read_bytes()),
        "baseline_members": 91, "batch_members_added": 11, "expected_physical_members": 102,
        "retained_frontend_child12": 56, "added_frontend_child13": 47,
        "engine_bytes": 16384, "descriptor_offset": 8192,
        "batch_context_offset": 416, "batch_install_offset": 424,
        "authority_context_offset": 432, "authority_callback_offset": 488,
        "scope_cache_input_window_closed": False, "full_async_cancellation_qualified": False,
        "fresh_joint_graph_qualified": False, "whole_runtime_replaced": False,
    }
    binding["sources"] = {name: dict(bytes=len(raw), sha256=SHA(raw)) for name, raw in sorted(files.items())}
    assert ENCODE(binding) == target_raw
    return summary(source)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--hepta", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.source, args.hepta), sort_keys=True))
