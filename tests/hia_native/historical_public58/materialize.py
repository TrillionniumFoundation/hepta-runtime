"""Create an explicit historical58 qualification source root from current source.

The current default executable is never changed. Only the owned new output
directory receives the exact historical graph closure and excludes the exact
current-public-only additions. A separate fixed authority restores the complete original runtime and workdir
reference domains. An independent extension restores the complete original
production metadata domain. Every source outside the explicit restore sets is kept.
"""
from pathlib import Path
import argparse,ast,hashlib,importlib.util,json,shutil,stat,sys
sys.dont_write_bytecode=True
if not __debug__:raise RuntimeError("historical source materialization requires assertions enabled")
PREFIX=Path("tests/hia_native/historical_public58")
DIRECTORIES=("native","scripts","src","tests",".github","authoring","vendor","runtime_support")
ROOT_FILES=("Cargo.toml","Cargo.lock","rustfmt.toml","README.md","AGENTS.md")
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
def pin(raw):
    return dict(bytes=len(raw),sha256=SHA(raw),git_blob=hashlib.sha1(
        b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest())
def read(root,name):
    relative=Path(name);assert not relative.is_absolute() and ".." not in relative.parts
    path=root/relative;assert path.resolve(strict=True)==path and not path.is_symlink() and stat.S_ISREG(path.stat().st_mode)
    return path.read_bytes()

# Separate fixed reference authority. PROFILE.json remains the original v8 graph.
REFERENCE_PROFILE = PREFIX / "REFERENCE_PROFILE.json"
REFERENCE_SOURCE = PREFIX / "reference_source"
REFERENCE_PROFILE_PIN = {'bytes': 20051, 'sha256': 'aaad4c09937ba2c227a316e32ff0cd2beaa7de4f3c2358bf14c1533668c856ce', 'git_blob': '0659b11c6760d02bb63208348188d23d891b34c4'}

def reference_require(condition, reason):
    if not condition:
        raise ValueError(reason)

def reference_literal(raw, name):
    matches = [node for node in ast.parse(raw).body if isinstance(node, ast.Assign)
        and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == name]
    reference_require(len(matches) == 1, "historical reference authority definition differs: " + name)
    return ast.literal_eval(matches[0].value)

def reference_authority(source):
    captured = {}
    def capture(name):
        name = Path(name).as_posix()
        raw = read(source, name)
        reference_require(name not in captured or captured[name] == raw,
            "historical reference authority changed between captures: " + name)
        captured[name] = raw
        return raw
    raw = capture(REFERENCE_PROFILE)
    reference_require(pin(raw) == REFERENCE_PROFILE_PIN, "historical original reference profile changed")
    value = json.loads(raw)
    reference_require(value["schema"] == "hepta.historical-public58.reference-source-profile.v1",
        "historical original reference profile schema differs")
    inventory = value["inventory_authority"]
    inventory_raw = capture(inventory["path"])
    reference_require(pin(inventory_raw) == {key: inventory[key] for key in ("bytes", "sha256", "git_blob")},
        "the complete original runtime inventory authority changed")
    originals = reference_literal(inventory_raw, "ORIGINAL_RUNTIME_BLOBS")
    reference_require(reference_literal(inventory_raw, "RUNTIME_BASE_COMMIT") == value["original_commit"]
        and reference_literal(inventory_raw, "RUNTIME_BASE_TREE") == value["original_tree"],
        "historical runtime reference commit or tree changed")
    original_files = value["original_runtime_files"]
    reference_require(len(original_files) == len(originals) == 53
        and {name: identity["git_blob"] for name, identity in original_files.items()} == originals,
        "the complete 53-path original runtime reference domain changed")
    workdir = value["workdir_authority"]
    workdir_raw = capture(workdir["path"])
    reference_require(pin(workdir_raw) == {key: workdir[key] for key in ("bytes", "sha256", "git_blob")},
        "the complete workdir qualification source authority changed")
    inventory = value["native_inventory_authority"]
    inventory_raw = capture(inventory["path"])
    reference_require(pin(inventory_raw) == {key: inventory[key] for key in ("bytes", "sha256", "git_blob")},
        "the complete historical native inventory authority changed")
    components = json.loads(inventory_raw)["native_components"]
    reference_require(len(components) == value["historical_native_components"] == 195
        and len({row["source"] for row in components}) == 195,
        "the complete 195-path historical native source domain changed")
    reference_require(set(value["excluded_current_only_files"]) == {"native/context_protocol_policy.hepta"},
        "the additional current-only source exclusion changed")
    workdir_files = json.loads(workdir_raw)["files"]
    reference_require(len(workdir_files) == 84, "the complete 84-path workdir source domain changed")
    required = {name: {key: identity[key] for key in ("bytes", "sha256")}
        for name, identity in original_files.items()}
    for name, identity in workdir_files.items():
        reference_require(name not in required or required[name] == identity,
            "original runtime and workdir source authorities conflict: " + name)
        required[name] = identity
    reference_require(len(required) == value["complete_declared_source_count"] == 131,
        "the complete original reference source union changed")
    restore = value["restore"]
    reference_require(len(restore) == 18 and set(restore) == set(value["current_inputs"])
        and all(original_files.get(name) == identity for name, identity in restore.items()),
        "historical original reference restore scope changed")
    fixture = source / REFERENCE_SOURCE
    actual = {path.relative_to(fixture).as_posix() for path in fixture.rglob("*") if path.is_file()}
    reference_require(actual == set(restore), "historical original reference fixture inventory changed")
    for name, identity in restore.items():
        reference_require(pin(capture(REFERENCE_SOURCE / name)) == identity,
            "historical original reference fixture changed: " + name)
    for name, data in captured.items():
        reference_require(read(source, name) == data,
            "historical reference authority changed at terminal readback: " + name)
    terminal = {path.relative_to(fixture).as_posix() for path in fixture.rglob("*") if path.is_file()}
    reference_require(terminal == actual, "historical original reference fixture inventory changed at terminal readback")
    return value, required

def check_current_references(source, profile, reference, required):
    reference_require(not (set(reference["restore"]) & set(profile["restore"]))
        and not (set(required) & set(profile["remove_current_public_only"])),
        "original reference restoration overlaps the immutable historical graph transition")
    captured = {}
    exclusions = reference["excluded_current_only_files"]
    reference_require(not (set(exclusions) & (set(required) | set(profile["restore"])
        | set(profile["remove_current_public_only"]))),
        "the current-only reference addition overlaps the immutable historical source domain")
    for name, identity in exclusions.items():
        raw = read(source, name)
        reference_require(pin(raw) == identity, "current-only reference addition changed: " + name)
        captured[(source, name)] = raw
    for name, identity in required.items():
        if name in reference["restore"]:
            root, expected = source, reference["current_inputs"][name]
        elif name in profile["restore"]:
            root, expected = source / PREFIX / "source", identity
        else:
            root, expected = source, identity
        raw = read(root, name)
        actual = pin(raw)
        reference_require(all(actual[key] == digest for key, digest in expected.items()),
            "current historical qualification source differs from its fixed relation: " + name)
        captured[(root, name)] = raw
    for (root, name), raw in captured.items():
        reference_require(read(root, name) == raw,
            "current historical qualification source changed at terminal readback: " + name)

def verify_reference_domains(root, reference, required):
    captured = {}
    for name, identity in required.items():
        raw = read(root, name)
        actual = pin(raw)
        reference_require({key: actual[key] for key in ("bytes", "sha256")} == identity,
            "materialized original reference source differs: " + name)
        if name in reference["original_runtime_files"]:
            reference_require(actual == reference["original_runtime_files"][name],
                "materialized complete original Git blob differs: " + name)
        captured[name] = raw
    for name, raw in captured.items():
        reference_require(read(root, name) == raw,
            "materialized original reference changed at terminal readback: " + name)
    return {"original_runtime_paths": 53, "workdir_source_paths": 84,
        "complete_declared_source_paths": 131, "restored_reference_paths": 18}

def verify_native_reference_inventory(root, reference):
    authority = reference["native_inventory_authority"]
    raw = read(root, authority["path"])
    reference_require(pin(raw) == {key: authority[key] for key in ("bytes", "sha256", "git_blob")},
        "materialized historical native inventory authority changed")
    declared = {row["source"] for row in json.loads(raw)["native_components"]}
    actual = {path.relative_to(root).as_posix() for path in (root / "native").rglob("*.hepta")}
    reference_require(actual == declared and len(actual) == 195,
        "materialized complete historical native inventory changed")
    for name in reference["excluded_current_only_files"]:
        reference_require(not (root / name).exists(), "current-only reference addition remains: " + name)
    reference_require(read(root, authority["path"]) == raw,
        "historical native inventory authority changed at terminal readback")
    terminal = {path.relative_to(root).as_posix() for path in (root / "native").rglob("*.hepta")}
    reference_require(terminal == actual, "historical native inventory changed at terminal readback")
    return {"native_components": 195, "excluded_current_only_paths": 1}


# This extension is independent of the retained 131-path/195-component authority.
METADATA_REFERENCE_PROFILE = PREFIX / "METADATA_REFERENCE_PROFILE.json"
METADATA_REFERENCE_SOURCE = PREFIX / "metadata_source"
METADATA_REFERENCE_PROFILE_PIN = {"bytes":17577,"sha256":"69b1db7be27a1a7657c23902413745fccdac315dec64d7abb9b65d6b5d73cd91","git_blob":"b2d916e4ce6adeb7522742c3e96f27227d43bd93"}

def metadata_reference_authority(source):
    captured = {}
    def capture(name):
        name = Path(name).as_posix()
        raw = read(source, name)
        reference_require(name not in captured or captured[name] == raw,
            "production metadata authority changed between captures: " + name)
        captured[name] = raw
        return raw
    raw = capture(METADATA_REFERENCE_PROFILE)
    reference_require(pin(raw) == METADATA_REFERENCE_PROFILE_PIN,
        "historical production metadata profile changed")
    value = json.loads(raw)
    reference_require(value["schema"] == "hepta.historical-public58.production-metadata-source-profile.v1",
        "historical production metadata profile schema changed")
    reference_raw = capture(REFERENCE_PROFILE)
    reference_require(pin(reference_raw) == REFERENCE_PROFILE_PIN
        and value["retained_reference_profile"] == REFERENCE_PROFILE_PIN,
        "retained original reference authority changed")
    reference = json.loads(reference_raw)
    authority = value["original_source_authority"]
    source_raw = capture(authority["path"])
    reference_require(pin(source_raw) == {key: authority[key] for key in ("bytes", "sha256", "git_blob")},
        "complete original production metadata authority changed")
    manifest = json.loads(source_raw)
    reference_require(manifest["schema"] == "hepta.runtime.shell-process-original-source.v1"
        and manifest["source_commit"] == value["original_commit"]
        and manifest["source_tree"] == value["original_tree"],
        "original production metadata commit or tree changed")
    expected = {name: {"bytes": identity["bytes"], "sha256": identity["sha256"],
                      "git_blob": identity["git_blob_sha1"]}
                for name, identity in manifest["production_metadata_inputs"].items()}
    reference_require(value["original_metadata_files"] == expected
        and len(expected) == value["original_metadata_paths"] == 71,
        "complete original 71-path production metadata domain changed")
    workdir = reference["workdir_authority"]
    workdir_raw = capture(workdir["path"])
    reference_require(pin(workdir_raw) == {key: workdir[key] for key in ("bytes", "sha256", "git_blob")},
        "retained workdir authority changed during metadata composition")
    prior = {name: {key: identity[key] for key in ("bytes", "sha256")}
             for name, identity in reference["original_runtime_files"].items()}
    for name, identity in json.loads(workdir_raw)["files"].items():
        reference_require(name not in prior or prior[name] == identity,
            "retained original reference identities conflict")
        prior[name] = identity
    reference_require(len(prior) == 131 and len(set(prior) | set(expected))
        == value["complete_reference_and_metadata_paths"] == 199,
        "complete reference and production metadata union changed")
    for name in set(prior) & set(expected):
        reference_require(prior[name] == {key: expected[name][key] for key in ("bytes", "sha256")},
            "original reference and production metadata disagree: " + name)
    restore = value["restore"]
    reference_require(set(restore) == set(value["current_inputs"])
        == {"vendor/ruzstd/HEPTA_PATCH.md", "vendor/ruzstd/UPSTREAM_SOURCE.json"}
        and all(expected.get(name) == identity for name, identity in restore.items()),
        "production metadata restoration scope changed")
    fixture = source / METADATA_REFERENCE_SOURCE
    actual = {path.relative_to(fixture).as_posix() for path in fixture.rglob("*") if path.is_file()}
    reference_require(actual == set(restore), "production metadata fixture inventory changed")
    for name, identity in restore.items():
        reference_require(pin(capture(METADATA_REFERENCE_SOURCE / name)) == identity,
            "original production metadata fixture changed: " + name)
    for name, data in captured.items():
        reference_require(read(source, name) == data,
            "production metadata authority changed at terminal readback: " + name)
    terminal = {path.relative_to(fixture).as_posix() for path in fixture.rglob("*") if path.is_file()}
    reference_require(terminal == actual, "production metadata fixture inventory changed at terminal readback")
    return value

def check_current_metadata_references(source, profile, reference, metadata):
    reference_require(not (set(metadata["restore"]) & (set(profile["restore"])
        | set(reference["restore"]) | set(profile["remove_current_public_only"])
        | set(reference["excluded_current_only_files"]))),
        "production metadata restoration overlaps a retained source transition")
    captured = {}
    for name, identity in metadata["original_metadata_files"].items():
        if name in metadata["restore"]:
            root, expected = source, metadata["current_inputs"][name]
        elif name in reference["restore"]:
            root, expected = source / REFERENCE_SOURCE, identity
        elif name in profile["restore"]:
            root, expected = source / PREFIX / "source", identity
        else:
            root, expected = source, identity
        raw = read(root, name)
        reference_require(pin(raw) == expected,
            "current production metadata source differs from its fixed relation: " + name)
        captured[(root, name)] = raw
    for (root, name), raw in captured.items():
        reference_require(read(root, name) == raw,
            "current production metadata source changed at terminal readback: " + name)

def verify_metadata_reference_domains(root, metadata):
    captured = {}
    for name, identity in metadata["original_metadata_files"].items():
        raw = read(root, name)
        reference_require(pin(raw) == identity,
            "materialized original production metadata source differs: " + name)
        captured[name] = raw
    for name, raw in captured.items():
        reference_require(read(root, name) == raw,
            "materialized original production metadata changed at terminal readback: " + name)
    return {"original_production_metadata_paths": 71, "additional_restored_metadata_paths": 2,
            "complete_reference_and_metadata_paths": 199}

def check(source):
    raw=read(source,(PREFIX/"PROFILE.json").as_posix());profile=json.loads(raw)
    assert profile["schema"]=="hepta.historical-public58.source-profile.v8"
    assert profile["historical_images"]==58 and profile["current_default_images"]==126
    assert len(profile["current_graph_files"])==544 and len(profile["restore"])==120
    assert len(profile["remove_current_public_only"])==400
    assert len(profile["current_authority_profile_files"])==6
    assert profile["retained_global_batch_input_paths"]==["native/batch_plan_input_performance.json",
        "scripts/author_input_fixed.py","scripts/performance_baselines/batch_plan_input.hepta"]
    assert not set(profile["retained_global_batch_input_paths"]).intersection(profile["remove_current_public_only"])
    assert SHA(read(source,"native/batch_plan_input_sources.json"))==profile["global_batch_input_source_profile_sha256"]
    assert not set(profile["current_graph_files"]).intersection(profile["current_authority_profile_files"])
    assert len(profile["current_workflow_files"])==4
    workflow=".github/workflows/hia-local-text-body-native.yml"
    assert profile["historical_workflow_restore"]=={workflow:profile["restore"][workflow]}
    assert profile["historical_workflow_commit"]=="208ff61db1da78aadfeb8d7913af7ddf4b59d461"
    body=json.loads(read(source,"tests/hia_native/local_text_body/source_files.json"))
    assert {key:profile["restore"][workflow][key] for key in ("bytes","sha256")}==body["files"][workflow]
    bound={**profile["current_graph_files"],**profile["current_authority_profile_files"],
        **profile["current_workflow_files"]}
    for name,expected in bound.items():assert pin(read(source,name))==expected,name
    assert len(profile["historical_authority_restore"])==7
    for name,expected in profile["historical_authority_restore"].items():assert profile["restore"][name]==expected
    assert SHA(read(source,"native/runtime_mcp_sources.json"))==profile["current_default_graph_binding_sha256"]
    fixture=source/PREFIX/"source"
    actual={p.relative_to(fixture).as_posix() for p in fixture.rglob("*") if p.is_file()}
    assert actual==set(profile["restore"])
    for name,expected in profile["restore"].items():assert pin(read(fixture,name))==expected,name
    binding=read(fixture,"native/runtime_mcp_sources.json")
    assert SHA(binding)==profile["historical_graph_binding_sha256"]=="0b7730769d36a4851e2d56ab717f7ce07c27d43bb728290aa7b5b32d014e82f2"
    for name,expected in json.loads(binding)["sources"].items():
        value=pin(read(fixture,name));assert {key:value[key] for key in ("bytes","sha256")}==expected
    reference,required=reference_authority(source)
    check_current_references(source,profile,reference,required)
    metadata=metadata_reference_authority(source)
    check_current_metadata_references(source,profile,reference,metadata)
    return profile,SHA(raw)
def selected(source):
    paths={}
    for name in DIRECTORIES:
        folder=source/name
        if not folder.is_dir():continue
        for path in folder.rglob("*"):
            if "__pycache__" in path.parts or path.suffix==".pyc":continue
            assert not path.is_symlink(),str(path)
            if path.is_dir():continue
            assert stat.S_ISREG(path.stat().st_mode)
            paths[path.relative_to(source).as_posix()]=path
    for name in ROOT_FILES:
        path=source/name
        if path.is_file():assert not path.is_symlink();paths[name]=path
    return paths
def verify_materialized(root):
    receipt=json.loads(read(root,"HISTORICAL_PUBLIC_SOURCE.json"))
    profile_raw=read(root,(PREFIX/"PROFILE.json").as_posix());profile=json.loads(profile_raw)
    assert receipt["schema"]=="hepta.historical-public58.materialized-source.v3"
    assert receipt["status"]=="SOURCE_PROFILE_MATERIALIZED"
    reference,required=reference_authority(root)
    metadata=metadata_reference_authority(root)
    assert receipt["reference_profile"]==REFERENCE_PROFILE_PIN
    assert receipt["original_reference_restored_paths"]==sorted(reference["restore"])
    assert receipt["original_reference_domains"]==verify_reference_domains(root,reference,required)
    assert receipt["metadata_reference_profile"]==METADATA_REFERENCE_PROFILE_PIN
    assert receipt["metadata_reference_domains"]==verify_metadata_reference_domains(root,metadata)
    assert receipt["metadata_reference_restored_paths"]==sorted(metadata["restore"])
    assert receipt["native_reference_inventory"]==verify_native_reference_inventory(root,reference)
    assert receipt["additional_excluded_current_only_paths"]==sorted(reference["excluded_current_only_files"])
    assert receipt["output_source"]==str(root.resolve(strict=True))
    assert receipt["profile_sha256"]==SHA(profile_raw)
    assert receipt["historical_public_images"]==58 and receipt["current_default_images"]==126
    assert receipt["historical_graph_restored_paths"]==sorted(profile["restore"])
    assert receipt["restored_paths"]==sorted(set(profile["restore"])|set(reference["restore"])|set(metadata["restore"]))
    assert receipt["excluded_current_only_paths"]==profile["remove_current_public_only"]
    assert {name:pin(path.read_bytes()) for name,path in selected(root).items()}==receipt["files"]
    for name,identity in profile["restore"].items():assert pin(read(root,name))==identity,name
    for name in profile["remove_current_public_only"]:assert not (root/name).exists(),name
    return dict(status="HISTORICAL58_COMPLETE_SOURCE_PROFILE_VERIFIED",files=len(receipt["files"]),
        profile_sha256=SHA(profile_raw),reference_profile=REFERENCE_PROFILE_PIN,
        original_reference_domains=receipt["original_reference_domains"],
        metadata_reference_domains=receipt["metadata_reference_domains"],historical_images=58,current_default_images=126,
        native_or_rust_executed=False,historical_pass_relabelled=False)
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source",type=Path,required=True);p.add_argument("--output",type=Path)
    p.add_argument("--check-only",action="store_true");a=p.parse_args()
    source=a.source.resolve(strict=True);profile,profile_sha=check(source)
    reference,required=reference_authority(source)
    metadata=metadata_reference_authority(source)
    if a.check_only:
        print(json.dumps(dict(status="CURRENT126_AND_HISTORICAL58_AUTHORITY_SOURCE_IDENTITIES_PASS",
            current_graph_files=544,current_authority_profile_files=6,current_workflow_files=4,historical_files=120,profile_sha256=profile_sha,
            original_runtime_reference_paths=53,workdir_reference_paths=84,original_reference_restores=18,
            production_metadata_paths=71,additional_metadata_restores=2,complete_reference_and_metadata_paths=199,
            default_current_images=126,historical_images=58,native_or_rust_executed=False),sort_keys=True));return
    assert a.output is not None;output=a.output.absolute()
    assert not output.exists() and not output.is_relative_to(source)
    original=selected(source);expected={name:pin(path.read_bytes()) for name,path in original.items()}
    input_before=dict(expected)
    output.mkdir(parents=True)
    for name,path in sorted(original.items()):
        destination=output/name;destination.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(path,destination)
        destination.chmod(path.stat().st_mode&0o777)
    for name in profile["remove_current_public_only"]:
        assert name in expected and pin(read(output,name))==profile["current_graph_files"][name]
        (output/name).unlink();del expected[name]
    for name,identity in reference["excluded_current_only_files"].items():
        assert name in expected and pin(read(output,name))==identity,name
        (output/name).unlink();del expected[name]
    for name,identity in profile["restore"].items():
        raw=read(source/PREFIX/"source",name);destination=output/name
        destination.parent.mkdir(parents=True,exist_ok=True);destination.write_bytes(raw);expected[name]=identity
    for name,identity in reference["restore"].items():
        assert pin(read(output,name))==reference["current_inputs"][name],name
        raw=read(source/REFERENCE_SOURCE,name);destination=output/name
        destination.write_bytes(raw);expected[name]=identity
    for name,identity in metadata["restore"].items():
        assert pin(read(output,name))==metadata["current_inputs"][name],name
        raw=read(source/METADATA_REFERENCE_SOURCE,name);destination=output/name
        destination.write_bytes(raw);expected[name]=identity
    reference_domains=verify_reference_domains(output,reference,required)
    metadata_domains=verify_metadata_reference_domains(output,metadata)
    native_reference_inventory=verify_native_reference_inventory(output,reference)
    actual={name:pin(path.read_bytes()) for name,path in selected(output).items()}
    assert actual==expected
    assert {name:pin(path.read_bytes()) for name,path in selected(source).items()}==input_before
    for name in profile["remove_current_public_only"]:assert not (output/name).exists()
    assert SHA(read(output,"native/runtime_mcp_sources.json"))==profile["historical_graph_binding_sha256"]
    # This is a source identity check only; no graph, compiler or reference runs.
    parsed=ast.parse(read(output,"scripts/hia_native_runtime_mcp_build.py"))
    members=[node for node in parsed.body if isinstance(node,ast.Assign) and any(
        isinstance(target,ast.Name) and target.id=="MEMBERS" for target in node.targets)]
    assert len(members)==1 and len(ast.literal_eval(members[0].value))==58
    receipt=dict(schema="hepta.historical-public58.materialized-source.v3",status="SOURCE_PROFILE_MATERIALIZED",
        input_source=str(source),output_source=str(output),profile_sha256=profile_sha,
        files=expected,restored_paths=sorted(set(profile["restore"])|set(reference["restore"])|set(metadata["restore"])),
        historical_graph_restored_paths=sorted(profile["restore"]),
        original_reference_restored_paths=sorted(reference["restore"]),
        reference_profile=REFERENCE_PROFILE_PIN,original_reference_domains=reference_domains,
        metadata_reference_profile=METADATA_REFERENCE_PROFILE_PIN,metadata_reference_domains=metadata_domains,
        metadata_reference_restored_paths=sorted(metadata["restore"]),
        native_reference_inventory=native_reference_inventory,
        additional_excluded_current_only_paths=sorted(reference["excluded_current_only_files"]),
        excluded_current_only_paths=profile["remove_current_public_only"],
        all_other_qualification_bytes_preserved=True,default_main_source_unchanged=True,
        historical_public_images=58,current_default_images=126,
        native_or_rust_executed=False,historical_pass_relabelled=False,full_sdk_qualified=False,
        production_activated=False,old_path_removed=False)
    # The receipt is outside the code inventory consumed by the old pipeline.
    (output/"HISTORICAL_PUBLIC_SOURCE.json").write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
    print(json.dumps({key:value for key,value in receipt.items() if key!="files"},sort_keys=True))
if __name__=="__main__":main()
