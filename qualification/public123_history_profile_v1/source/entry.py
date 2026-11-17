#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Materialize the complete historical profile without HIA or Rust execution."""
from pathlib import Path
import argparse, ast, hashlib, importlib.util, json, os, shutil, stat, subprocess, sys, time
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import canonical,decode,pin,require,source_evidence
import readonly
HERE=Path(__file__).resolve().parent
BEFORE="5a5a35b355b7b58a23da797acd0002a832fc919b"
BEFORE_TREE="a2b2049c94a02f1a5a9af35c7f287a6881a0a9a8"
AFTER="8fd1718de5b61c751d9e3c0716bc90b38afefff3"
AFTER_TREE="9f7312de4759174919f919dcbbb828107e54beb6"
PREFIX="tests/hia_native/historical_public58/"
DIRECTORIES=("native","scripts","src","tests",".github","authoring","vendor","runtime_support")
ROOT_FILES=("Cargo.toml","Cargo.lock","rustfmt.toml","README.md","AGENTS.md")
LAYOUTS=(
    ("native-and-original",["native","scripts","authoring","runtime_support","src","vendor","tests/hia_native","tests/oracles",".github"]),
    ("local-text",["native","scripts","authoring","runtime_support","tests/hia_native",".github/workflows"]),
    ("shell",["native","scripts","authoring","runtime_support","src","tests/hia_native",".github"]),
)
WORKFLOWS={
    ".github/workflows/hia-runtime-native.yml":0,
    ".github/workflows/hia-runtime-original-shard.yml":0,
    ".github/workflows/hia-local-text-body-native.yml":1,
    ".github/workflows/hia-runtime-shell.yml":2,
}
def inputs():
    result=source_evidence(HERE)
    for name in ("entry.py","read_uploaded.py","common.py","readonly.py","archive.py","callable_common.py"):
        ast.parse((HERE/name).read_bytes(),filename=name)
    return result
def identity(raw):
    return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),
        git_blob=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest())
def file_identity(path):
    raw=path.read_bytes()
    return {**identity(raw),"mode":path.stat().st_mode&0o777}
def selected_name(name):
    parts=name.split("/")
    return "__pycache__" not in parts and not name.endswith(".pyc") and (
        name in ROOT_FILES or any(name.startswith(d+"/") for d in DIRECTORIES))
def selected(root):
    rows={}
    for folder in DIRECTORIES:
        top=root/folder
        if not top.exists():continue
        require(top.is_dir() and not top.is_symlink(),"ordinary source directory")
        for path in sorted(top.rglob("*")):
            name=path.relative_to(root).as_posix()
            if not selected_name(name):continue
            info=path.lstat()
            require(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode),"ordinary complete source")
            if path.is_file():rows[name]=file_identity(path)
    for name in ROOT_FILES:
        path=root/name
        if path.exists():
            require(not path.is_symlink() and stat.S_ISREG(path.stat().st_mode),"ordinary root source")
            rows[name]=file_identity(path)
    return rows
def copy_selected(source,destination):
    require(not destination.exists(),"fresh selected source")
    rows=selected(source);destination.mkdir(parents=True)
    for name,row in sorted(rows.items()):
        path=destination/name;path.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(source/name,path);path.chmod(row["mode"])
    require(selected(destination)==rows,"complete source copy")
    return rows
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(canonical(value))
def run(capture,label,argv,*,input_bytes=None,expected=0):
    prefix=capture/"processes"/label
    prefix.parent.mkdir(parents=True,exist_ok=True)
    started=time.monotonic();timed_out=False
    try:
        value=subprocess.run(argv,input=input_bytes,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            timeout=180,check=False)
        status=value.returncode;out=value.stdout;err=value.stderr
    except subprocess.TimeoutExpired as error:
        status=None;out=error.stdout or b"";err=error.stderr or b"";timed_out=True
    (prefix.with_suffix(".stdout")).write_bytes(out);(prefix.with_suffix(".stderr")).write_bytes(err)
    receipt=dict(argv=list(map(str,argv)),exit_code=status,timed_out=timed_out,
        elapsed_seconds=time.monotonic()-started,stdout=pin(prefix.with_suffix(".stdout")),
        stderr=pin(prefix.with_suffix(".stderr")),input=identity(input_bytes) if input_bytes is not None else None)
    save(prefix.with_suffix(".json"),receipt)
    require(not timed_out and status==expected,"source process failed: "+label)
    return out
def git_tree(raw):
    entries={}
    for item in raw.split(b"\0"):
        if not item:continue
        head,name=item.split(b"\t",1);mode,kind,sha=head.decode().split(" ")
        path=name.decode();require(path not in entries and not path.startswith("/") and ".." not in path.split("/"),
            "canonical unique Git path")
        entries[path]=dict(mode=mode,type=kind,sha=sha)
    return entries
def root_sha(entries):
    dirs={""};table={name:dict(row) for name,row in entries.items()}
    for name in entries:
        parts=name.split("/")[:-1]
        while parts:dirs.add("/".join(parts));parts.pop()
    for folder in sorted(dirs,key=lambda n:(n.count("/"),len(n)),reverse=True):
        prefix=folder+"/" if folder else ""
        children=[(n[len(prefix):],v) for n,v in table.items() if n.startswith(prefix) and "/" not in n[len(prefix):]]
        children.sort(key=lambda r:(r[0]+("/" if r[1]["type"]=="tree" else "")).encode())
        body=b"".join((r["mode"].lstrip("0")+" "+name).encode()+b"\0"+bytes.fromhex(r["sha"]) for name,r in children)
        sha=hashlib.sha1(b"tree "+str(len(body)).encode()+b"\0"+body).hexdigest()
        if folder:table[folder]=dict(type="tree",mode="040000",sha=sha)
    return sha
def workflow_layout(raw):
    lines=raw.decode().splitlines();found=[]
    for i,line in enumerate(lines):
        if line.strip()!="sparse-checkout: |":continue
        indent=len(line)-len(line.lstrip());block=[]
        for value in lines[i+1:]:
            if len(value)-len(value.lstrip())<=indent:break
            block.append(value.strip())
        if "native" in block:found.append(block)
    require(found and all(row==found[0] for row in found),"one exact current native sparse layout")
    return found[0]
def in_cone(name,paths):
    parent=name.rpartition("/")[0];ancestors={""}
    for value in paths:
        parts=value.split("/")[:-1]
        while parts:ancestors.add("/".join(parts));parts.pop()
    return parent in ancestors or any(name.startswith(value+"/") for value in paths)
def profile(root):
    return decode((root/(PREFIX+"PROFILE.json")).read_bytes())
def process_ok(capture,label,expected):
    path=capture/"processes"/label;row=decode(path.with_suffix(".json").read_bytes())
    require(row["timed_out"] is False and row["exit_code"]==expected and 0<=row["elapsed_seconds"]<180,
        "complete bounded source process")
    require(pin(path.with_suffix(".stdout"))==row["stdout"] and pin(path.with_suffix(".stderr"))==row["stderr"],
        "complete process streams")
    return row
def source_from_git(capture,label,commit,tree):
    root=capture/(label+"-source");rows=selected(root)
    raw=(capture/"git"/(label+".ls-tree")).read_bytes();items=git_tree(raw)
    require(root_sha(items)==tree,"complete immutable Git tree")
    wanted={name:item for name,item in items.items() if selected_name(name)}
    require(set(rows)==set(wanted),"complete selected Git source")
    for name,row in rows.items():
        require(wanted[name]["type"]=="blob" and wanted[name]["sha"]==row["git_blob"]
            and int(wanted[name]["mode"],8)&0o777==row["mode"],"selected exact Git blob/mode: "+name)
    meta=decode((capture/"git"/(label+".json")).read_bytes())
    require(meta==dict(commit=commit,tree=tree),"exact source checkout")
    return rows
def materialized(capture,label,source_rows):
    source=capture/(label+"-source");root=capture/(label+"-historical")
    p=profile(source);actual=selected(root);expected=dict(source_rows)
    for name in p["remove_current_public_only"]:
        require(name in expected,"explicit current removal");del expected[name]
    for name,row in p["restore"].items():
        inherited=source_rows[PREFIX+"source/"+name]
        require({k:inherited[k] for k in ("bytes","sha256","git_blob")}==row,"complete immutable restore input")
        expected[name]=dict(inherited)
    require(actual==expected,"whole exact historical output")
    receipt=decode((root/"HISTORICAL_PUBLIC_SOURCE.json").read_bytes())
    require(receipt["status"]=="SOURCE_PROFILE_MATERIALIZED" and receipt["historical_public_images"]==58
        and receipt["current_default_images"]==p["current_default_images"]
        and receipt["profile_sha256"]==pin(source/(PREFIX+"PROFILE.json"))["sha256"]
        and receipt["restored_paths"]==sorted(p["restore"])
        and receipt["excluded_current_only_paths"]==p["remove_current_public_only"]
        and receipt["files"]=={name:{k:r[k] for k in ("bytes","sha256","git_blob")} for name,r in actual.items()},
        "complete materialization receipt")
    require(all(receipt[k] is False for k in ("native_or_rust_executed","historical_pass_relabelled",
        "full_sdk_qualified","production_activated","old_path_removed")),"source-only receipt boundary")
    return actual

def control_specs(after):
    p=profile(after)
    authority=sorted(p["current_authority_profile_files"])[0]
    runtime="runtime_support/bellman_port/BYTE_ACCESS_REBINDING.json"
    require(runtime in p["current_graph_files"],"actual retained runtime support input")
    return [
        ("current-owner","native/runtime_mcp.hepta","append"),
        ("current-binding","native/runtime_mcp_sources.json","append"),
        ("historical-owner",PREFIX+"source/native/runtime_mcp.hepta","append"),
        ("authority-profile",authority,"append"),
        ("current-workflow",".github/workflows/hia-local-text-body-native.yml","append"),
        ("missing-runtime-support",runtime,"missing"),
        ("incomplete-current-profile",PREFIX+"PROFILE.json","omit-current"),
        ("unbound-extra-removal",PREFIX+"PROFILE.json","extra-removal"),
    ]
def mutated(raw,kind):
    if kind=="append":return raw+b"\n# physical source mutation\n"
    if kind=="missing":return None
    p=decode(raw)
    if kind=="omit-current":del p["current_graph_files"]["native/extract_gateway.hepta"]
    elif kind=="extra-removal":p["remove_current_public_only"].append("native/directory_errno.hepta")
    else:raise ValueError("unknown physical mutation")
    return canonical(p)
def capture(before,after,output,work):
    inputs();require(not output.exists() and not work.exists(),"fresh source-only outputs")
    output.mkdir(parents=True);work.mkdir(parents=True)
    for label,source,commit,tree in (("before",before,BEFORE,BEFORE_TREE),("after",after,AFTER,AFTER_TREE)):
        got=run(output,"git-"+label+"-head",["git","-C",str(source),"rev-parse","HEAD"]).decode().strip()
        actual_tree=run(output,"git-"+label+"-tree",["git","-C",str(source),"rev-parse","HEAD^{tree}"]).decode().strip()
        require(got==commit and actual_tree==tree,"exact fixed checkout")
        raw=run(output,"git-"+label+"-listing",["git","-C",str(source),"ls-tree","-rz","HEAD"])
        require(root_sha(git_tree(raw))==tree,"actual complete Git listing")
        (output/"git").mkdir(exist_ok=True);(output/"git"/(label+".ls-tree")).write_bytes(raw)
        save(output/"git"/(label+".json"),dict(commit=commit,tree=tree))
        copy_selected(source,output/(label+"-source"))
        source=output/(label+"-source")
        run(output,label+"-check",[sys.executable,"-I","-B",str(source/(PREFIX+"materialize.py")),
            "--source",str(source),"--check-only"])
        run(output,label+"-materialize",[sys.executable,"-I","-B",str(source/(PREFIX+"materialize.py")),
            "--source",str(source),"--output",str(output/(label+"-historical"))])
    full=selected(output/"after-source")
    for name,number in WORKFLOWS.items():
        require(workflow_layout((output/"after-source"/name).read_bytes())==LAYOUTS[number][1],
            "current actual workflow sparse paths")
    for number,(name,paths) in enumerate(LAYOUTS):
        sparse=work/("sparse-"+str(number));historical=work/("historical-"+str(number))
        run(output,"sparse-"+str(number)+"-clone",["git","clone","--shared","--no-checkout","--",str(after),str(sparse)])
        run(output,"sparse-"+str(number)+"-init",["git","-C",str(sparse),"sparse-checkout","init","--cone"])
        run(output,"sparse-"+str(number)+"-set",["git","-C",str(sparse),"sparse-checkout","set","--stdin"],
            input_bytes=("\n".join(paths)+"\n").encode())
        run(output,"sparse-"+str(number)+"-checkout",["git","-C",str(sparse),"checkout","--detach",AFTER])
        actual=selected(sparse)
        require(actual=={path:row for path,row in full.items() if in_cone(path,paths)},
            "actual sparse cone selected bytes")
        run(output,"sparse-"+str(number)+"-check",[sys.executable,"-I","-B",str(sparse/(PREFIX+"materialize.py")),
            "--source",str(sparse),"--check-only"])
        run(output,"sparse-"+str(number)+"-materialize",[sys.executable,"-I","-B",str(sparse/(PREFIX+"materialize.py")),
            "--source",str(sparse),"--output",str(historical)])
        save(output/"sparse"/(str(number)+".json"),dict(name=name,paths=paths,source=actual,
            historical=selected(historical),receipt=decode((historical/"HISTORICAL_PUBLIC_SOURCE.json").read_bytes())))
    source=output/"after-source"
    for number,(name,path,kind) in enumerate(control_specs(source)):
        folder=output/"controls"/str(number);folder.mkdir(parents=True)
        target=source/path;raw=target.read_bytes();mode=target.stat().st_mode&0o777;changed=mutated(raw,kind)
        (folder/"before.bin").write_bytes(raw)
        if changed is not None:(folder/"changed.bin").write_bytes(changed)
        try:
            if changed is None:target.unlink()
            else:target.write_bytes(changed)
            run(output,"control-"+str(number),[sys.executable,"-I","-B",str(source/(PREFIX+"materialize.py")),
                "--source",str(source),"--check-only"],expected=1)
        finally:
            target.write_bytes(raw);target.chmod(mode)
        require(target.read_bytes()==raw and target.stat().st_mode&0o777==mode,"physical control fully restored")
        save(folder/"CONTROL.json",dict(name=name,path=path,kind=kind,base=identity(raw),
            changed=identity(changed) if changed is not None else None,rejected=True,restored=True))
    require(selected(source)==full,"all controls leave complete source intact")
    save(output/"CAPTURE.json",dict(status="SOURCE_MATERIALIZATIONS_CAPTURED",before=BEFORE,after=AFTER,
        sparse_layouts=len(LAYOUTS),physical_controls=8,hia_executed=False,rust_executed=False))
    result=read(output)
    save(output/"RESULT.json",result)
    return result
def read(capture):
    inputs();capture=Path(capture)
    before=source_from_git(capture,"before",BEFORE,BEFORE_TREE)
    after=source_from_git(capture,"after",AFTER,AFTER_TREE)
    rows=decode((HERE/"SOURCE_ROWS.json").read_bytes())
    require(len(rows)==486 and len({r["path"] for r in rows})==486,"exact current source closure")
    current={r["path"]:{k:r[k] for k in ("bytes","sha256","git_blob")} for r in rows}
    for name,row in current.items():
        require({k:after[name][k] for k in row}==row and after[name]["mode"]==0o644,
            "complete current production source")
    old=profile(capture/"before-source");new=profile(capture/"after-source")
    expected=json.loads(json.dumps(old))
    expected.update(schema="hepta.historical-public58.source-profile.v6",current_default_images=123,
        current_graph_files=current,current_default_graph_binding_sha256=current["native/runtime_mcp_sources.json"]["sha256"])
    added=sorted(name for name in current if name not in before)
    require(len(added)==95 and "native/directory_errno.hepta" in before,"exact new public path set")
    expected["remove_current_public_only"]=sorted(set(old["remove_current_public_only"])|set(added))
    require(new==expected and len(new["restore"])==120 and len(new["remove_current_public_only"])==342,
        "only current profile changes")
    require(len(old["current_graph_files"])==390 and old["current_default_images"]==111,
        "retained installed111 baseline")
    bookkeeping={PREFIX+"PROFILE.json",PREFIX+"materialize.py"}
    expected_source=dict(before)
    for name in set(current)|bookkeeping:expected_source[name]=after[name]
    require(after==expected_source,"candidate preserves every unrelated selected source")
    patch=decode((HERE/"PATCH.json").read_bytes())
    text=(capture/"after-source"/(PREFIX+"materialize.py")).read_text()
    for item in reversed(patch["materializer_transforms"]):
        require(text.count(item["new"])==item["occurrences"],"exact materializer inverse occurrence")
        text=text.replace(item["new"],item["old"])
    require(text.encode()==(capture/"before-source"/(PREFIX+"materialize.py")).read_bytes(),
        "whole materializer inverse")
    left=materialized(capture,"before",before);right=materialized(capture,"after",after)
    require(set(left)==set(right),"all historical file paths preserved")
    delta={name for name in left if left[name]!=right[name]}
    require(delta==bookkeeping,"all historical bytes/modes preserved apart from current profile bookkeeping")
    require(right["native/runtime_mcp_sources.json"]["sha256"]==
        "0b7730769d36a4851e2d56ab717f7ce07c27d43bb728290aa7b5b32d014e82f2","exact historical58 binding")
    program=ast.parse((capture/"after-historical/scripts/hia_native_runtime_mcp_build.py").read_bytes())
    members=[n for n in program.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name)
        and t.id=="MEMBERS" for t in n.targets)]
    require(len(members)==1 and len(ast.literal_eval(members[0].value))==58,"actual historical builder member count")
    for label in ("before","after"):
        for stage in ("git-"+label+"-head","git-"+label+"-tree","git-"+label+"-listing",
            label+"-check",label+"-materialize"):process_ok(capture,stage,0)
    for path,number in WORKFLOWS.items():
        require(workflow_layout((capture/"after-source"/path).read_bytes())==LAYOUTS[number][1],
            "exact four installed workflow layouts")
    sparse=[]
    for number,(name,paths) in enumerate(LAYOUTS):
        item=decode((capture/"sparse"/(str(number)+".json")).read_bytes())
        source={path:row for path,row in after.items() if in_cone(path,paths)}
        historical=dict(source)
        for path in new["remove_current_public_only"]:
            require(path in historical,"sparse includes every bound removable current path");del historical[path]
        for path in new["restore"]:historical[path]=right[path]
        require(item["name"]==name and item["paths"]==paths and item["source"]==source
            and item["historical"]==historical,"complete actual sparse materialization bytes")
        receipt=item["receipt"]
        require(receipt["status"]=="SOURCE_PROFILE_MATERIALIZED" and receipt["historical_public_images"]==58
            and receipt["current_default_images"]==123 and receipt["profile_sha256"]==after[PREFIX+"PROFILE.json"]["sha256"]
            and receipt["files"]=={n:{k:r[k] for k in ("bytes","sha256","git_blob")} for n,r in historical.items()}
            and receipt["restored_paths"]==sorted(new["restore"])
            and receipt["excluded_current_only_paths"]==new["remove_current_public_only"],"sparse exact source receipt")
        for stage in ("clone","init","set","checkout","check","materialize"):
            process_ok(capture,"sparse-"+str(number)+"-"+stage,0)
        sparse.append(dict(name=name,source_files=len(source),historical_files=len(historical)))
    specs=control_specs(capture/"after-source")
    require({p.name for p in (capture/"controls").iterdir()}==set(map(str,range(8))),"all eight physical controls")
    for number,(name,path,kind) in enumerate(specs):
        folder=capture/"controls"/str(number);raw=(folder/"before.bin").read_bytes()
        require(raw==(capture/"after-source"/path).read_bytes(),"control original bytes bound")
        changed=mutated(raw,kind)
        wanted={"before.bin","CONTROL.json"}
        if changed is not None:
            require((folder/"changed.bin").read_bytes()==changed,"complete physical mutation bytes")
            wanted.add("changed.bin")
        require({p.name for p in folder.iterdir()}==wanted,"exact control file set")
        require(decode((folder/"CONTROL.json").read_bytes())==dict(name=name,path=path,kind=kind,
            base=identity(raw),changed=identity(changed) if changed is not None else None,rejected=True,restored=True),
            "complete physical refusal receipt")
        process_ok(capture,"control-"+str(number),1)
    require(decode((capture/"CAPTURE.json").read_bytes())==dict(status="SOURCE_MATERIALIZATIONS_CAPTURED",
        before=BEFORE,after=AFTER,sparse_layouts=3,physical_controls=8,hia_executed=False,rust_executed=False),
        "complete source capture declaration")
    result=dict(status="COMPLETE_HISTORICAL58_CURRENT123_SOURCE_PASS",before=BEFORE,after=AFTER,
        before_tree=BEFORE_TREE,after_tree=AFTER_TREE,current_files=486,historical_images=58,current_images=123,
        restored_files=120,removed_current_files=342,preserved_historical_files=len(left)-2,
        historical_file_count=len(left),bookkeeping_changes=sorted(bookkeeping),sparse_layouts=sparse,
        physical_refusals=8,source=inputs(),hia_executed=False,rust_executed=False,public_wait_qualified=False,
        publisher_async_qualified=False,production_installed=False,full_sdk=False,all_136_handlers=False,old_stack_removed=False)
    if (capture/"RESULT.json").exists():
        require(decode((capture/"RESULT.json").read_bytes())==result,"complete prior result exact")
    return result
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode",choices=("capture","read"))
    p.add_argument("--before",type=Path);p.add_argument("--after",type=Path);p.add_argument("--work",type=Path)
    p.add_argument("--capture",type=Path,required=True);p.add_argument("--output",type=Path)
    a=p.parse_args()
    if a.mode=="capture":
        result=capture(a.before.resolve(strict=True),a.after.resolve(strict=True),a.capture.absolute(),a.work.absolute())
    else:
        require(a.output is not None and not a.output.exists(),"fresh pure-read result")
        started=time.monotonic()
        result=readonly.guarded(lambda:read(a.capture),roots=(HERE,a.capture))
        require(time.monotonic()-started<180,"source pure reader180-second budget")
        a.output.write_bytes(canonical(result))
    print(json.dumps({k:v for k,v in result.items() if k not in ("before","after")},sort_keys=True))
if __name__=="__main__":main()
