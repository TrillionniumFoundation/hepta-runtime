"""Create an explicit historical58 qualification source root from current source.

The current default executable is never changed. Only the owned new output
directory receives the exact historical graph closure and excludes the exact
current-public-only additions. Every other qualification source byte is kept.
"""
from pathlib import Path
import argparse,ast,hashlib,importlib.util,json,shutil,stat,sys
sys.dont_write_bytecode=True
PREFIX=Path("tests/hia_native/historical_public58")
DIRECTORIES=("native","scripts","src","tests",".github","authoring","vendor","runtime_support")
ROOT_FILES=("Cargo.toml","Cargo.lock","rustfmt.toml","README.md","AGENTS.md")
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
def pin(raw):
    return dict(bytes=len(raw),sha256=SHA(raw),git_blob=hashlib.sha1(
        b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest())
def read(root,name):
    relative=Path(name);assert not relative.is_absolute() and ".." not in relative.parts
    path=root/relative;assert not path.is_symlink() and stat.S_ISREG(path.stat().st_mode)
    return path.read_bytes()
def check(source):
    raw=read(source,(PREFIX/"PROFILE.json").as_posix());profile=json.loads(raw)
    assert profile["schema"]=="hepta.historical-public58.source-profile.v6"
    assert profile["historical_images"]==58 and profile["current_default_images"]==123
    assert len(profile["current_graph_files"])==486 and len(profile["restore"])==120
    assert len(profile["remove_current_public_only"])==342
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
    assert receipt["status"]=="SOURCE_PROFILE_MATERIALIZED"
    assert receipt["output_source"]==str(root.resolve(strict=True))
    assert receipt["profile_sha256"]==SHA(profile_raw)
    assert receipt["historical_public_images"]==58 and receipt["current_default_images"]==123
    assert receipt["restored_paths"]==sorted(profile["restore"])
    assert receipt["excluded_current_only_paths"]==profile["remove_current_public_only"]
    assert {name:pin(path.read_bytes()) for name,path in selected(root).items()}==receipt["files"]
    for name,identity in profile["restore"].items():assert pin(read(root,name))==identity,name
    for name in profile["remove_current_public_only"]:assert not (root/name).exists(),name
    return dict(status="HISTORICAL58_COMPLETE_SOURCE_PROFILE_VERIFIED",files=len(receipt["files"]),
        profile_sha256=SHA(profile_raw),historical_images=58,current_default_images=123,
        native_or_rust_executed=False,historical_pass_relabelled=False)
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source",type=Path,required=True);p.add_argument("--output",type=Path)
    p.add_argument("--check-only",action="store_true");a=p.parse_args()
    source=a.source.resolve(strict=True);profile,profile_sha=check(source)
    if a.check_only:
        print(json.dumps(dict(status="CURRENT123_AND_HISTORICAL58_AUTHORITY_SOURCE_IDENTITIES_PASS",
            current_graph_files=486,current_authority_profile_files=6,current_workflow_files=4,historical_files=120,profile_sha256=profile_sha,
            default_current_images=123,historical_images=58,native_or_rust_executed=False),sort_keys=True));return
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
    for name,identity in profile["restore"].items():
        raw=read(source/PREFIX/"source",name);destination=output/name
        destination.parent.mkdir(parents=True,exist_ok=True);destination.write_bytes(raw);expected[name]=identity
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
    receipt=dict(schema="hepta.historical-public58.materialized-source.v1",status="SOURCE_PROFILE_MATERIALIZED",
        input_source=str(source),output_source=str(output),profile_sha256=profile_sha,
        files=expected,restored_paths=sorted(profile["restore"]),excluded_current_only_paths=profile["remove_current_public_only"],
        all_other_qualification_bytes_preserved=True,default_main_source_unchanged=True,
        historical_public_images=58,current_default_images=123,
        native_or_rust_executed=False,historical_pass_relabelled=False,full_sdk_qualified=False,
        production_activated=False,old_path_removed=False)
    # The receipt is outside the code inventory consumed by the old pipeline.
    (output/"HISTORICAL_PUBLIC_SOURCE.json").write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
    print(json.dumps({key:value for key,value in receipt.items() if key!="files"},sort_keys=True))
if __name__=="__main__":main()
