"""Qualify source installation and historical materialization; never run HIA/Rust."""
from pathlib import Path
import argparse,ast,hashlib,json,os,shutil,stat,subprocess,sys,time,types
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
PREFIX=Path("tests/hia_native/historical_public58")
def require(value,message):
    if not value:raise ValueError(message)
def pin(raw):
    return {"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),
        "git_blob":hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()}
def raw(root,name):
    rel=Path(name);require(not rel.is_absolute() and ".." not in rel.parts,"relative path")
    p=root/rel;require(not p.is_symlink() and stat.S_ISREG(p.stat().st_mode),"ordinary source "+name)
    return p.read_bytes()
def put(path,value):
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def source_manifest():
    m=json.loads(raw(HERE,"SOURCE_MANIFEST.json"))
    actual={p.relative_to(HERE).as_posix() for p in HERE.rglob("*") if p.is_file()}
    require(actual=={"SOURCE_MANIFEST.json",*(r["path"] for r in m["files"])},"whole recipe set")
    for r in m["files"]:
        require(pin(raw(HERE,r["path"]))=={k:r[k] for k in ("bytes","sha256","git_blob")},"recipe "+r["path"])
    return pin(raw(HERE,"SOURCE_MANIFEST.json"))
def inverse(new,edits):
    value=new
    for edit in reversed(edits):
        before,after,count=(edit["before"],edit["after"],edit["count"]) if isinstance(edit,dict) else (*edit,1)
        require(value.count(after)==count,"exact inverse count "+after)
        value=value.replace(after,before)
    return value
def member_value(tree,name):
    values=[node.value for node in tree.body if isinstance(node,ast.Assign)
        and any(isinstance(x,ast.Name) and x.id==name for x in node.targets)]
    require(len(values)==1,"one literal "+name)
    value=ast.literal_eval(values[0])
    for node in tree.body:
        if isinstance(node,ast.Expr) and isinstance(node.value,ast.Call):
            call=node.value
            if isinstance(call.func,ast.Attribute) and isinstance(call.func.value,ast.Name) and call.func.value.id==name:
                require(call.func.attr=="extend" and len(call.args)==1 and not call.keywords,"fixed literal extension "+name)
                value.extend(ast.literal_eval(call.args[0]))
    return value
def load_materializer(source):
    p=source/PREFIX/"materialize.py";m=types.ModuleType("installed124_historical_profile")
    m.__file__=str(p);exec(compile(p.read_bytes(),str(p),"exec"),m.__dict__);return m
def snapshot(root,m):
    return {name:{**pin(path.read_bytes()),"mode":stat.S_IMODE(path.stat().st_mode)}
        for name,path in sorted(m.selected(root).items())}
def run(output,label,command):
    start=time.monotonic_ns();record={"command":command,"started_monotonic_ns":start}
    try:
        with (output/(label+".stdout")).open("xb") as stdout,(output/(label+".stderr")).open("xb") as stderr:
            p=subprocess.run(command,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,timeout=180,check=False)
        record["returncode"]=p.returncode;require(p.returncode==0,label+" failed")
    finally:
        record["elapsed_ns"]=time.monotonic_ns()-start;put(output/(label+".json"),record)
    return record
def main():
    p=argparse.ArgumentParser();p.add_argument("--source",type=Path,required=True);p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    source=a.source.resolve(strict=True);out=a.output.absolute();require(not out.exists(),"fresh output");out.mkdir(parents=True)
    recipe=source_manifest();plan=json.loads(raw(HERE,"PLAN.json"));rows=json.loads(raw(HERE,"PRODUCTION_ROWS.json"))["rows"]
    install=json.loads(raw(HERE,"INSTALL_ROWS.json"));require(len(rows)==536,"fixed source count")
    actual={}
    for row in rows:
        value=pin(raw(source,row["path"]));require(value=={k:row[k] for k in value},"source "+row["path"]);actual[row["path"]]=value
        require(format(stat.S_IMODE((source/row["path"]).stat().st_mode)|0o100000,"o")==row["mode"],"mode "+row["path"])
        if row["path"].endswith(".py"):compile(raw(source,row["path"]),row["path"],"exec")
    require(pin(raw(source,"native/runtime_mcp_sources.json"))==plan["candidate_binding"],"new closure")
    bound=json.loads(raw(source,"native/runtime_mcp_sources.json"))["sources"]
    require(set(bound)==set(actual)-{"native/runtime_mcp_sources.json"},"complete runtime closure")
    for name,identity in bound.items():require(identity=={k:actual[name][k] for k in ("bytes","sha256")},"bound source "+name)
    builder=raw(source,"scripts/hia_native_runtime_mcp_build.py").decode()
    require(inverse(builder,plan["default_builder_repair"]["edits"])==raw(HERE,"retained/default_builder.py").decode(),"whole builder inverse")
    require(pin(builder.encode())==plan["default_builder_repair"]["after"],"builder pin")
    graph=ast.parse(raw(source,"scripts/public_nine_build.py"));members=member_value(graph,"MEMBERS");extra=member_value(graph,"EXTRA")
    require(len(members)==116 and len(extra)==69,"actual graph cardinality")
    require(sum(r[0]=="publisher_worker" for r in members)==1,"actual publisher worker")
    component=json.loads(raw(source,"native/publication_worker_component.json"))
    require([component[k] for k in ("direct_hia_images","packed_hia_images","runtime_hia_images","physical_images")]==[116,8,124,117],"component counts")
    profile=json.loads(raw(source,(PREFIX/"PROFILE.json").as_posix()));old=json.loads(raw(HERE,"retained/PROFILE.json"))
    for key in old:
        if key not in ("schema","current_default_images","current_default_graph_binding_sha256","current_graph_files","remove_current_public_only"):
            require(profile[key]==old[key],"unchanged historical field "+key)
    require(profile["current_graph_files"]==actual,"profile binds every current row")
    require(profile["remove_current_public_only"]==sorted(set(old["remove_current_public_only"])|set(plan["new_main_paths"])),"exact exclusions")
    require("native/directory_errno.hepta" not in profile["remove_current_public_only"],"main errno source survives")
    materializer=raw(source,(PREFIX/"materialize.py").as_posix()).decode()
    require(inverse(materializer,plan["materializer_repair"]["edits"])==raw(HERE,"retained/materialize.py").decode(),"whole materializer inverse")
    # Source-only Git comparison: no worktree reset or application executable.
    git=["git","-C",str(source)]
    head=subprocess.check_output(git+["rev-parse","HEAD"],text=True).strip()
    parent=subprocess.check_output(git+["rev-parse","HEAD^"],text=True).strip()
    require(parent==plan["base_commit"],"exact main parent")
    names=subprocess.check_output(git+["diff-tree","--no-commit-id","--name-only","-r","HEAD"],text=True).splitlines()
    expected={r["path"] for r in install["changes"]}|set(plan["source_package_paths"])
    require(set(names)==expected and len(names)==len(expected),"complete installation tree delta")
    m=load_materializer(source);m.check(source);before=snapshot(source,m);put(out/"source-before.json",before)
    run(out,"materialize",[sys.executable,"-I","-S","-B",str(source/PREFIX/"materialize.py"),"--source",str(source),"--output",str(out/"historical")])
    verified=m.verify_materialized(out/"historical")
    require(snapshot(source,m)==before,"input source unchanged")
    after=snapshot(out/"historical",m);put(out/"historical-files.json",after)
    for name,identity in profile["restore"].items():require(pin(raw(out/"historical",name))==identity,"exact restored bytes")
    require("native/directory_errno.hepta" in after and after["native/directory_errno.hepta"]==before["native/directory_errno.hepta"],"retain existing errno bytes")
    # Build the full admission closure in an owned ordinary clone. Each mutation
    # is retained as full before/after bytes, then restored before the next case.
    admission=out/"admission";admission.mkdir()
    required=set(profile["current_graph_files"])|set(profile["current_authority_profile_files"])|set(profile["current_workflow_files"])
    required|={"native/batch_plan_input_sources.json","tests/hia_native/local_text_body/source_files.json",(PREFIX/"PROFILE.json").as_posix(),(PREFIX/"materialize.py").as_posix()}
    required|={(PREFIX/"source"/name).as_posix() for name in profile["restore"]}
    for name in sorted(required):
        dest=admission/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source/name,dest)
    m.check(admission);initial=snapshot(admission,m);controls=out/"controls";controls.mkdir();results=[]
    support=next(name for name in sorted(profile["current_graph_files"]) if name.startswith("runtime_support/") and name.endswith(".py"))
    mutations=[("current-entry","scripts/hia_native_runtime_mcp_build.py",False),
        ("current-hia","native/runtime_mcp.hepta",False),("packed-source",support,False),
        ("missing-packed-source",support,True),
        ("historical-hia",(PREFIX/"source/native/runtime_mcp.hepta").as_posix(),False),
        ("current-workflow",".github/workflows/hia-local-text-body-native.yml",False),
        ("historical-workflow",(PREFIX/"source/.github/workflows/hia-local-text-body-native.yml").as_posix(),False),
        ("new-worker","native/publication_worker.hepta",False)]
    for label,name,remove in mutations:
        folder=controls/label;folder.mkdir();path=admission/name;original=path.read_bytes();changed=original+b"\n# physical source corruption\n"
        (folder/"before.bin").write_bytes(original)
        if remove:path.unlink()
        else:path.write_bytes(changed);(folder/"after.bin").write_bytes(changed)
        failure=None
        try:m.check(admission)
        except (ValueError,AssertionError,FileNotFoundError) as exc:failure={"type":type(exc).__name__,"message":str(exc)}
        finally:path.write_bytes(original)
        require(failure is not None,"physical mutation accepted "+label);m.check(admission)
        require(snapshot(admission,m)==initial,"physical clone not restored "+label)
        record={"label":label,"path":name,"removed":remove,"before":pin(original),"after":None if remove else pin(changed),"rejection":failure}
        put(folder/"RESULT.json",record);results.append(record)
    require(snapshot(source,m)==before,"final complete input bytes and modes")
    require(m.verify_materialized(out/"historical")==verified,"final historical verification")
    result={"status":"SOURCE_ONLY_INSTALLATION_AND_HISTORICAL58_MATERIALIZATION_PASS","head":head,"base":parent,
        "recipe":recipe,"production_files":536,"runtime_hia_images":124,"physical_images":117,
        "source_files":len(before),"historical_files":len(after),"restored_files":120,"excluded_files":392,
        "physical_refusals":results,"actual_materializer":verified,"all_runtime_hia_and_asm_unchanged":True,
        "default_command_executed":False,"native_or_rust_executed":False,"production_installed":False,"full_sdk_qualified":False}
    put(out/"RESULT.json",result);print(json.dumps({k:v for k,v in result.items() if k!="physical_refusals"},sort_keys=True))
if __name__=="__main__":main()
