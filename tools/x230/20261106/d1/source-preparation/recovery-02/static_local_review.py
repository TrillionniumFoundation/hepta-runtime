#!/usr/bin/env python3
"""Read-only preparation checks. No Rust, qualifier entry, test, or host execution."""
import argparse
import ast
import hashlib
import json
import pathlib
import runpy
import sys
import tomllib

EXPECTED = json.loads(r'''{"QUALIFICATION_AND_DIAGNOSTIC_PLAN.md":{"bytes":13323,"sha256":"6aebae889a001e9c478dd5b788904b254e877db33b3349f52e1c4d9c9c87ea51"},"README.md":{"bytes":18696,"sha256":"26b83e77b496b66654f26db3bd88729f8e3b6641355e87817acb068837d6d9a7"},"baseline-source-map.json":{"bytes":24156,"sha256":"c3415beaf7697b3eb07a763ef24f424138de80af31acfd6c224cf682f3c67cbd"},"candidate-source-map.json":{"bytes":24368,"sha256":"42da71c2097c2c469346b9eed1cbc3a5be4773ee5d3b0a3df87aa72463350723"},"candidate.patch":{"bytes":64987,"sha256":"3940b39d5cdde7d4b76ba1e94f49ca461c6964b1edb2c2f44506fdf7c8a50523"},"diagnostic-entry.py":{"bytes":3463,"sha256":"6dd6d02b1ac1af75ed79dce6ff092c2f047139f63e06016df320104fa6d684c6"},"edit-ledger.json":{"bytes":13084,"sha256":"e28e87f59b24894a0d3df75080ba5d40347129f45bb3e94036517d7657f95f8d"},"input.json":{"bytes":53222,"sha256":"d2c45351d8a11a1f472c06e68689c43e8ab821ee3c93428057de401644fb59cc"},"line-diff-helpers.js":{"bytes":4148,"sha256":"ed92bac45986f2ee3ea4648b49a2a1ea57c27db6af5e62a6506933a676f5b80a"},"materialize_static.py":{"bytes":11037,"sha256":"b337bdf93d342c8205063466217e74efe73841e9431a5be23b81940bd14ca7c7"},"recovery-status.json":{"bytes":502,"sha256":"630bbbf71f4fd552bc638bbb597193561087895bf98292c1e94a866b05fdc3e3"},"references/AGENTS.md":{"bytes":5699,"sha256":"60f96c3186ff0089ce3535100bff48727838bc3a2ff71bead26938a129c93a56"},"references/architecture.md":{"bytes":5789,"sha256":"ee8b940d0aa2dd51ef74d7be2c6a394d1fc8e34e98cc33946b34aab882bf7ede"},"references/diagnostic-plan-01.json":{"bytes":6320,"sha256":"d17dddaa2a562def1e05215919283361e34636a268bc97f680d73b6bd62def50"},"references/qualify.py":{"bytes":7661,"sha256":"95717717fd5421f2e31dbce24e2f8821696f57d779ce93e988ed66764159552d"},"references/tool-authoring.md":{"bytes":2833,"sha256":"aba42b64b17432878dcbced7b8071a70962bdd46c273437078cc7c9a992a6af6"},"rust-static-helpers.js":{"bytes":4725,"sha256":"1dc6c456f170b6fd14a54b6b74583ca797416a0fd7900dd8d61eeab9845ba02a"},"source-index.json":{"bytes":58376,"sha256":"ca0b16befb8e6712a30361a9ce0030379a5d949b7441bf3d05232e492b913284"},"source/Cargo.toml":{"bytes":3210,"sha256":"1bdaba4ffc14e8763b5f11eb042fc79b4ea6b15313c6acf05ec1d611807883bb"},"source/src/main.rs":{"bytes":11200,"sha256":"64435a8ecd089a2dd16c1db074dbc452ef01ae070f6bbbbcde4d11088e52d522"},"source/src/mcp/runtime/jobs.rs":{"bytes":187577,"sha256":"baa9186159053909f282e6e2c87ea901b2ad7f3972ddf4a945107008329be25c"},"source/src/mcp/runtime/mod.rs":{"bytes":5054,"sha256":"8abaf18c7c90d695e3054db431bf04bbb6002318c6dddfa29c231aa1ec4bd0e7"},"source/src/mcp/runtime/phase_cost.rs":{"bytes":23399,"sha256":"7742b05391d59f22048a31a8b130cae860d60f5eb45a21ef1341ab02f80f613c"},"source/src/mcp/runtime/phase_cost_tests.rs":{"bytes":5265,"sha256":"ec2690cc763486450f875fb07991ba146d52186a4df48dcadb0a47860333c5a9"},"source/src/mcp/runtime/ssh.rs":{"bytes":17056,"sha256":"32a2230fbd0bd16c2bd963eaa31168e02dcec3f4705a52196f606ed3f216d40c"},"source/src/mcp/runtime/ssh_observation_agent_timeout_tests.rs":{"bytes":15122,"sha256":"d9a10bc0128f563846043113141346c49e7e860109c73116d986c55a61b5d678"},"source/src/mcp/runtime/ssh_observation_maintenance_tests.rs":{"bytes":19717,"sha256":"15c35899a91eff5b9b1e2e24efc93f45c4a4f0ce15b419b792f35add4debd65b"},"source/src/mcp/runtime/ssh_observation_pool.rs":{"bytes":67199,"sha256":"f971de30417aff742ec547751b03a4a873b343df90ba1e093bfcc75d96ebbc71"},"source/src/mcp/runtime/ssh_observation_pool_tests.rs":{"bytes":92474,"sha256":"2c4842a9a8d313657eaf0e25e1352dc7c505f686a1e0b18dfe75f38c6c990384"},"source/src/mcp/runtime/ssh_observation_validation.rs":{"bytes":5788,"sha256":"b4a5c12f0f4d20c094df3dfe689343d203b1a7d376bcdec994ab57e6d9214567"},"source/src/mcp/server.rs":{"bytes":119170,"sha256":"5dafdd79236d87bf117dfc12fe0de474ec647f9ed5517834756b5ab707a1d50c"},"static-review.json":{"bytes":7060,"sha256":"c1bc08486e06d4b992ee822c087a4c4f0c44b6eb1c5d53b611fecc241981cfbc"},"summarize_trace.py":{"bytes":15057,"sha256":"f6e65c2e206d4aa90143a17893e5e57c158bca9f8eec5f74897b19c3596e32c5"},"transfer-bytes.js":{"bytes":3977,"sha256":"50fbb44a4e84a40dcc9505eba2899c5b6cee958900675bed8976311168a93eda"}}''')
BASELINE_SUBSET = ["Cargo.lock","Cargo.toml","src/main.rs","src/mcp/runtime/jobs.rs","src/mcp/runtime/mod.rs","src/mcp/runtime/ssh.rs","src/mcp/runtime/ssh_observation_agent_timeout_tests.rs","src/mcp/runtime/ssh_observation_maintenance_tests.rs","src/mcp/runtime/ssh_observation_pool.rs","src/mcp/runtime/ssh_observation_pool_tests.rs","src/mcp/runtime/ssh_observation_validation.rs","src/mcp/server.rs"]


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package-root", required=True)
    parser.add_argument("--baseline-subset", required=True)
    args = parser.parse_args()
    root, baseline_root = pathlib.Path(args.package_root), pathlib.Path(args.baseline_subset)
    # This loads only reviewed stdlib imports/function definitions. Its __main__
    # materializer, all qualifier code, and all Rust sources remain unexecuted.
    helper = runpy.run_path(str(root / "materialize_static.py"), run_name="static_review_only")
    regular = helper["regular"]
    members = {path: regular(root / path) for path in EXPECTED}
    for path, identity in EXPECTED.items():
        assert len(members[path]) == identity["bytes"] and digest(members[path]) == identity["sha256"], path
    original_map = json.loads(members["baseline-source-map.json"])
    assert digest(members["baseline-source-map.json"]) == "c3415beaf7697b3eb07a763ef24f424138de80af31acfd6c224cf682f3c67cbd"
    originals = {path: regular(baseline_root / path) for path in BASELINE_SUBSET}
    assert all(digest(raw) == original_map[path] for path, raw in originals.items())
    changed = helper["apply_unified"](members["candidate.patch"], originals)
    declaration = json.loads(members["input.json"])
    candidate_map = json.loads(members["candidate-source-map.json"])
    source_index = json.loads(members["source-index.json"])["files"]
    assert len(original_map) == 220 and len(candidate_map) == 222
    assert sorted(changed) == declaration["changed_paths"] and len(changed) == 13
    assert declaration["baseline_compile_inputs"] == original_map
    assert declaration["candidate_compile_inputs"] == candidate_map
    assert digest(members["candidate.patch"]) == declaration["patch_sha256"]
    assert all(changed[path] == members["source/" + path] and digest(changed[path]) == candidate_map[path] for path in changed)
    assert {row["path"]: row["sha256"] for row in source_index} == candidate_map
    assert all(candidate_map[path] == original_map[path] for path in candidate_map if path not in changed)
    assert set(candidate_map) - set(original_map) == {
        "src/mcp/runtime/phase_cost.rs", "src/mcp/runtime/phase_cost_tests.rs",
    }
    for row in source_index:
        if row["path"] in changed:
            raw = changed[row["path"]]
            git = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
            assert git == row["git_blob"] and len(raw) == row["bytes"]
    old_toml = tomllib.loads(originals["Cargo.toml"].decode())
    new_toml = tomllib.loads(changed["Cargo.toml"].decode())
    old_features = old_toml.get("features", {})
    assert old_features == {}
    new_features = new_toml.pop("features")
    assert new_features == {"phase-cost-diagnostics": []}
    assert new_toml == old_toml
    assert candidate_map["Cargo.lock"] == digest(originals["Cargo.lock"])
    assert all(raw.startswith(b"// Copyright 2026 Muvon Un Limited\n") for path, raw in changed.items() if path.endswith(".rs"))
    old_tail = originals["src/mcp/runtime/mod.rs"].split(b"pub mod binary;", 1)[1]
    new_tail = changed["src/mcp/runtime/mod.rs"].split(b"pub mod binary;", 1)[1]
    assert old_tail == new_tail
    ast_paths = sorted(path for path in members if path.endswith(".py"))
    trees = {}
    for path in ast_paths:
        trees[path] = ast.parse(members[path].decode("utf-8"), filename=path)
    selections = {}
    for node in ast.walk(trees["references/qualify.py"]):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "stage" and len(node.args) >= 2 and isinstance(node.args[0], ast.Constant):
            name = node.args[0].value
            if name in ("clippy", "test-build", "release"):
                argv = node.args[1]
                assert isinstance(argv, ast.BinOp) and isinstance(argv.op, ast.Add)
                assert isinstance(argv.left, ast.Name) and argv.left.id == "cargo"
                flags = ast.literal_eval(argv.right)
                assert "--all-features" in flags
                selections[name] = ["/home/qian/.cargo/bin/cargo", "+1.95.0", *flags]
    assert set(selections) == {"clippy", "test-build", "release"}
    own = regular(pathlib.Path(__file__))
    print(json.dumps({
        "schema": "hepta-r24-phase-cost-local-static-receipt/v1",
        "revision": "recovery-02",
        "python": sys.version,
        "runner": {"bytes": len(own), "sha256": digest(own)},
        "package_inputs_read": EXPECTED,
        "package_input_count": len(members),
        "original_subset_read": {path: {"bytes": len(raw), "sha256": digest(raw)} for path, raw in originals.items()},
        "local_original_subset_count": len(originals),
        "scope": "12 local originals plus 13 candidate files; unchanged 209 map rows checked against the pinned complete R24 map; prior pure-JS receipt separately verified all 220 original contents",
        "candidate_map_count": len(candidate_map),
        "independent_python_patch_apply_exact": True,
        "python_ast_parsed": ast_paths,
        "cargo_toml_original_features": old_features,
        "cargo_toml_candidate_features": new_features,
        "dependencies_lock_release_settings_unchanged": True,
        "original_qualifier_all_features_argv": selections,
        "qualifier_entry_executed": False,
        "materializer_entry_executed": False,
        "rust_compiled": False, "rustfmt_run": False, "rust_tests_run": False,
        "remote_calls": 0, "diagnostic_executed": False,
        "performance_acceptance_claim": False,
        "static_checks_completed": True,
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
