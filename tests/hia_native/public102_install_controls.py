"""Check the installed 102 graph and the retained historical-profile Batch proof closure.

The refusals here are source-admission controls; they perform no HIA or Rust work.
"""
from pathlib import Path
import argparse, ast, copy, hashlib, json, stat
EXPECTED = {"joint_profile_sha256":"5ff90d433a604920d689f56ffd38e3c95e622f0ab5b72bc143d500d4c9e6404d","graph_binding_sha256":"41a42a6247d8b4bf0ccee11e743bad28285273637b9f824fcbf2f0bf9bad0726","historical_profile_sha256":"838c64d03e996620654b74cff772698c67527c4dde32bfe09686d7a7105ccd72","historical_restore_sha256":"773eaecb910b80216ab4926bea2c1ba7271d7312b1c0b4384741ae07ef3620d0","global_profile_sha256":"9ae0d998f509b362dcd2bba6f1e89eadd00d84e8ece0fc6f2f7b4f22d06c3171","global_qualifier_sha256":"0795796513f1e4f7d646713970facfc6ff04b13c0b2fffafcee4a3ebfdde6412","entry_sha256":"712c5df80aeb2e433a8ebf5a0b3241c06c2b7fe65cc99de8732c6eadcff3109e","materializer_sha256":"3a84fe8073aecd9fc5dda9303c909c9cb93f2fece14f18b3c5a9f317d9736b8c","qualifier_sha256":"856e0aeac174390bfe30f805e362c7f5c7626b9795202432ddd271e60c7bb0d5"}
KEEP = ("native/batch_plan_input_performance.json", "scripts/author_input_fixed.py",
    "scripts/performance_baselines/batch_plan_input.hepta")
GLOBAL_OWNERS = ("native/batch_apply.hepta", "native/batch_plan.hepta",
    "native/batch_plan_input.hepta", "native/batch_render.hepta",
    "native/batch_write.hepta", "native/file_lock_service.hepta", "native/line_verify.hepta")
NEW_PUBLIC_OWNERS = ("native/batch_body_adapter.hepta", "native/batch_call.hepta",
    "native/batch_gateway.hepta", "native/batch_params.hepta")
def raw(root, name):
    relative = Path(name)
    assert not relative.is_absolute() and ".." not in relative.parts
    path = root / relative
    info = path.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and path.resolve(strict=True) == path.absolute()
    return path.read_bytes()
def pin(value):
    return dict(bytes=len(value), sha256=hashlib.sha256(value).hexdigest(),
        git_blob=hashlib.sha1(b"blob " + str(len(value)).encode() + b"\0" + value).hexdigest())
def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
def constant(text, name):
    rows = [node.value for node in ast.parse(text).body if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
    assert len(rows) == 1
    return ast.literal_eval(rows[0])
def admitted(state):
    assert state["current_images"] == 102 and state["current_graph_files"] == 218
    assert state["historical_images"] == 58 and state["historical_restore_files"] == 119
    assert state["historical_restore_sha256"] == EXPECTED["historical_restore_sha256"]
    assert state["graph_binding"] == EXPECTED["graph_binding_sha256"]
    assert state["global_profile"] == state["reader_profile"] == EXPECTED["global_profile_sha256"]
    removed = state["removed"]
    assert len(removed) == len(set(removed)) == 75
    assert set(NEW_PUBLIC_OWNERS) <= set(removed)
    assert not (set(GLOBAL_OWNERS) | set(KEEP)).intersection(removed)
    assert state["global_keep"] == list(KEEP)
    assert set(KEEP) <= set(state["global_source_files"])
    assert {"author_input_fixed.py", "performance_baselines/batch_plan_input.hepta"} <= set(state["registry_script_literals"])
    assert state["full_sdk_qualified"] is False and state["production_activated"] is False
    return True
def run(source, joint):
    master_raw = raw(joint, "joint-source.json")
    assert pin(master_raw)["sha256"] == EXPECTED["joint_profile_sha256"]
    master = json.loads(master_raw)
    expected = {name.removeprefix("installed/"): value for name, value in master["files"].items()
        if name.startswith("installed/")}
    assert len(expected) == 224
    installed = {name: pin(raw(source, name)) for name in expected}
    assert installed == expected
    profile_raw = raw(source, "tests/hia_native/historical_public58/PROFILE.json")
    assert pin(profile_raw)["sha256"] == EXPECTED["historical_profile_sha256"]
    profile = json.loads(profile_raw)
    graph = {name.removeprefix("authority/source/"): value for name, value in master["files"].items()
        if name.startswith("authority/source/")}
    assert profile["current_graph_files"] == graph
    assert {**graph, **profile["current_authority_profile_files"]} == expected
    for name, value in profile["restore"].items():
        assert pin(raw(source / "tests/hia_native/historical_public58/source", name)) == value
    global_raw = raw(source, "native/batch_plan_input_sources.json")
    global_profile = json.loads(global_raw)
    global_roles = {name: ("tests/hia_native/historical_public58/source/" + name
        if name in profile["restore"] else name) for name in global_profile}
    global_actual = {name: pin(raw(source, path)) for name, path in global_roles.items()}
    assert {name: value["sha256"] for name, value in global_actual.items()} == global_profile
    reader_raw = raw(source, "scripts/hia_native_batch_plan_input_qualification.py")
    assert pin(reader_raw)["sha256"] == EXPECTED["global_qualifier_sha256"]
    qualifier_raw = raw(source, "scripts/qualify_hia_runtime_native.py")
    assert pin(qualifier_raw)["sha256"] == EXPECTED["qualifier_sha256"]
    sources = [node for node in ast.parse(qualifier_raw).body if isinstance(node, ast.FunctionDef) and node.name == "sources"]
    assert len(sources) == 1
    literals = {node.value for node in ast.walk(sources[0]) if isinstance(node, ast.Constant) and isinstance(node.value, str)}
    state = dict(current_images=profile["current_default_images"], current_graph_files=len(graph),
        historical_images=profile["historical_images"], historical_restore_files=len(profile["restore"]),
        historical_restore_sha256=pin(encoded(profile["restore"]))["sha256"],
        graph_binding=profile["current_default_graph_binding_sha256"],
        global_profile=pin(global_raw)["sha256"], reader_profile=constant(reader_raw, "SOURCE_PROFILE"),
        removed=profile["remove_current_public_only"], global_keep=profile["retained_global_batch_input_paths"],
        global_source_files=list(global_profile), registry_script_literals=sorted(literals),
        full_sdk_qualified=profile["full_sdk_qualified"], production_activated=profile["production_activated"])
    assert admitted(state)
    controls = (
        ("previous-default-count", lambda x: x.update(current_images=91)),
        ("missing-public-owner-exclusion", lambda x: x["removed"].remove(NEW_PUBLIC_OWNERS[0])),
        ("global-proof-excluded", lambda x: x["removed"].__setitem__(0, KEEP[0])),
        ("global-owner-excluded", lambda x: x["removed"].__setitem__(0, GLOBAL_OWNERS[0])),
        ("stale-global-profile", lambda x: x.update(reader_profile="0" * 64)),
        ("missing-global-proof", lambda x: x["global_source_files"].remove(KEEP[1])),
        ("missing-registry-source-custody", lambda x: x["registry_script_literals"].remove("author_input_fixed.py")),
        ("historical-restore-changed", lambda x: x.update(historical_restore_sha256="0" * 64)),
    )
    refused = []
    for label, change in controls:
        altered = copy.deepcopy(state)
        change(altered)
        try:
            admitted(altered)
        except (AssertionError, ValueError, KeyError):
            refused.append(label)
        else:
            raise AssertionError("source-admission mutation accepted: " + label)
    assert admitted(state) and len(refused) == 8
    entry = pin(raw(source, "tests/hia_native/public102_entry.py"))
    materializer = pin(raw(source, "tests/hia_native/historical_public58/materialize.py"))
    assert entry["sha256"] == EXPECTED["entry_sha256"] and materializer["sha256"] == EXPECTED["materializer_sha256"]
    return dict(status="INSTALLED_PUBLIC102_AND_GLOBAL_BATCH_SOURCE_CLOSURE_PASS",
        installed_source_files=installed, global_batch_source_files=global_actual,
        global_batch_actual_source_roles=global_roles, global_batch_qualification_root="explicit historical58 materialization",
        current_default_images=102, historical_images=58, historical_restore_unchanged=True,
        current_public_only_exclusions=75, retained_global_batch_proofs=list(KEEP),
        source_admission_refusals=refused, source_admission_admissions=2,
        complete_joint_profile=pin(master_raw), historical_profile=pin(profile_raw),
        global_profile=pin(global_raw), global_reader=pin(reader_raw),
        global_registry=pin(qualifier_raw), entry=entry, materializer=materializer,
        native_or_rust_executions=0, full_sdk_qualified=False, whole_runtime_replaced=False)
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--joint-source", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.source.resolve(strict=True), args.joint_source.resolve(strict=True)), sort_keys=True))
