"""Join the full configured catalog proofs without loading any native executable."""
from pathlib import Path
import gzip, json, os, stat, sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import catalog_ci_support as c
import read_graph,read_reference
PREPARED={}

def prepare(package):
    package=Path(package).absolute();key=str(package)
    if key in PREPARED:return PREPARED[key]
    c.source_check(package)
    read_graph.prepare(package)
    component,domain,shared,public,old=read_reference.prepare(package)
    configured=c.source_module("configured_complete_native_reader",package/"source/read_configured.py")
    guard=c.source_module("configured_retained_readonly_guard",package/"source/retained/read_only_guard.py")
    # All source modules and their stdlib/ctypes imports are admitted before guard activation.
    PREPARED[key]=(component,domain,public,configured,old,guard)
    return PREPARED[key]

def execution_gate(package,capture):
    c.source_check(package)
    r=c.Reader(capture);gate=r.document("EXECUTION.json")
    c.need(gate["schema"]=="hepta.runtime.configured-catalog-execution.v1" and gate["status"]=="COMPLETE",
        "complete actual semantic execution gate")
    c.need(gate["package"]==c.pin(c.regular(package/"PACKAGE.json")) and gate["target_commit"]==c.TARGET
        and gate["compiler_commit"]==c.COMPILER,"complete executed source identity")
    for key in ("pid","parent_pid","pgid"):c.need(type(gate[key])is int and gate[key]>0,"gate process identity")
    root=Path(gate["producer_root"]);origins=gate["origins"]
    c.need(root.is_absolute() and origins=={key:str(root/name) for key,name in
        (("source","s"),("component_build","b"),("component_native","n"),("graph","g"),("sdk","k"),
         ("public_native","pn"),("public_original","po"))}|{"original":str(root.parent/(root.name+"-original"))},
        "fixed complete producer layout")
    c.need(Path(gate["target_checkout"]).is_absolute() and Path(gate["compiler_checkout"]).is_absolute()
        and Path(gate["python"]).is_absolute(),"exact external checkout/interpreter origins")
    c.need(all(gate[key] is False for key in c.FALSE_FLAGS),"global claims remain false")
    python=[gate["python"],"-I","-B"];s=origins["source"]
    commands={
        "direct-original":(python+[s+"/source/retained/pipeline/policy_base/reference/capture.py",
            "--target",gate["target_checkout"],"--output",origins["original"]],3600),
        "component-build":(python+[s+"/source/build_configured.py","--hepta",gate["compiler_checkout"],
            "--output",origins["component_build"]],300),
        "component-native":(python+[s+"/source/capture_configured.py","--build",origins["component_build"],
            "--output",origins["component_native"]],180),
        "graph-build":(python+[s+"/graph/scripts/hia_native_runtime_mcp_build.py","--source",s+"/graph",
            "--hepta",gate["compiler_checkout"],"--output",origins["graph"],
            "--bootstrap",origins["component_build"]+"/bootstrap"],300),
        "sdk-observers":(python+[s+"/ci/build_reference.py","--package",s,"--target",gate["target_checkout"],
            "--original",origins["original"],"--output",origins["sdk"]],300),
        "public-native":(python+[s+"/public/capture_public_configured.py","--component",s+"/source",
            "--graph",s+"/graph","--manifest",origins["graph"]+"/build/public-authority-batch/manifest.json",
            "--output",origins["public_native"]],180),
        "public-original":(python+[s+"/ci/observe_public_reference.py","--package",s,
            "--binary",origins["sdk"]+"/hia_configured_public.elf","--output",origins["public_original"]],180)}
    c.need(gate["process_order"]==list(commands),"all and only actual semantic processes")
    actual={p.name[:-len(".process.json")] for p in (capture/"processes").glob("*.process.json")}
    c.need(actual==set(commands),"actual process receipt domain")
    processes={};streams={}
    for name,(command,limit) in commands.items():
        processes[name],streams[name]=c.process(r,name,command=command,cwd=s,timeout=limit,parent=gate)
    c.need(streams["direct-original"]["stdout"]==b"","direct reference stdout belongs to retained child streams")
    for name in ("component-build","component-native","graph-build","sdk-observers","public-native","public-original"):
        c.need(streams[name]["stderr"]==b"","qualified process diagnostics: "+name)
    rust_env={"RUSTUP_TOOLCHAIN":"1.95.0","CARGO_TARGET_DIR":origins["original"]+"/cargo-target",
        "CARGO_BUILD_JOBS":"2","CARGO_INCREMENTAL":"0","CARGO_PROFILE_DEV_DEBUG":"0","CARGO_ENCODED_RUSTFLAGS":"",
        "LC_ALL":"C","PYTHONDONTWRITEBYTECODE":"1"}
    for name in ("direct-original","sdk-observers","public-original"):
        c.need(processes[name]["controlled_environment"]==rust_env,"controlled original parent environment")
    retention=r.document("ORIGINAL_RETENTION.json")
    c.need(retention["schema"]=="hepta.runtime.configured-original-retention.v1"
        and retention["origin"]==origins["original"] and retention["retained"]=="r"
        and retention["excluded_exact_directory"]=="cargo-target"
        and retention["complete_original_sources_registry_binary_and_streams_retained"] is True
        and type(retention["semantic_executions_added"])is int and retention["semantic_executions_added"]==0,
        "exact independently retained original capture")
    inventory={}
    for folder,dirs,names in os.walk(capture/"r",followlinks=False):
        base=Path(folder)
        c.need(stat.S_ISDIR(base.lstat().st_mode),"physical retained original directory")
        for name in dirs:c.need(stat.S_ISDIR((base/name).lstat().st_mode),"no original directory aliases")
        for name in names:
            path=base/name;raw=c.regular(path)
            inventory[path.relative_to(capture/"r").as_posix()]={"mode":stat.S_IMODE(path.stat().st_mode),**c.pin(raw)}
    c.need(inventory==retention["files"],"every retained original file byte and mode")
    return gate,processes,streams,r

def verify_semantics(package,capture):
    component,domain,public,configured,old,guard=prepare(package)
    gate,processes,streams,outer=execution_gate(package,capture)
    component_result=configured.verify(package/"source",capture/"b",capture/"n")
    native_report=c.read_json(capture/"n/result.json")
    process=processes["component-native"]
    c.need(native_report["pid"]==process["pid"] and native_report["parent_pid"]==process["parent_pid"]
        and native_report["pgid"]==process["pgid"],"all 478 calls belong to the actual native child")
    c.need(c.read_json(capture/"n/verification.json")==component_result,"retained complete component readback")
    summary={k:v for k,v in component_result.items() if k not in ("source_files","build_files","native_files","case_rows")}
    c.need(c.parse(streams["component-native"]["stdout"])==summary,"native stdout/complete capture custody")
    build_report=c.read_json(capture/"b/configured-build.json")
    c.need(c.parse(streams["component-build"]["stdout"])==build_report
        and build_report["status"]=="FRESH_CONFIGURED_COMPONENT_BUILD_PASS"
        and build_report["copied_qualified_bootstrap"] is False,"actual fresh component build")
    dependency=c.read_json(package/"ci/COMPILER_INPUTS.json")
    c.need(c.read_json(capture/"b/bootstrap/bootstrap.json")["dependency"]==dependency,"component compiler full closure")
    for name in component.MODULES:
        c.need(c.read_json(capture/"b/modules"/name/"build.json")["compiler_dependency"]==dependency,"component source closure")
    graph=read_graph.verify(package,capture/"g",expected_origin=gate["origins"]["graph"],
        expected_source=gate["origins"]["source"]+"/graph",expected_manifest=gate["graph_manifest"])
    c.need(c.parse(streams["graph-build"]["stdout"])==c.read_json(capture/"g/BUILD.json"),"actual default build stdout")
    manifest=capture/"g"/graph["manifest_relative"]
    native=public.verify(package/"public",package/"source",package/"graph",manifest,capture/"pn",graph["elf"])
    public_report=c.read_json(capture/"pn/result.json");process=processes["public-native"]
    c.need(all(public_report[key]==process[key] for key in ("pid","parent_pid","pgid")),"all public native processes have actual parent")
    c.need(c.parse(streams["public-native"]["stdout"])=={
        k:v for k,v in public_report.items() if k not in ("observed","processes","source_binding")},"public native complete stdout")
    roots={"package":gate["origins"]["source"],"target":gate["target_checkout"],
        "original":gate["origins"]["original"],"output":gate["origins"]["sdk"]}
    sdk=read_reference.verify_build(package,capture/"r",capture/"k",expected_roots=roots,
        expected_parent=processes["sdk-observers"])
    original=sdk["direct_original"]
    sdk_report=c.read_json(capture/"k/result.json")
    c.need(c.parse(streams["sdk-observers"]["stdout"])=={
        k:v for k,v in sdk_report.items() if k not in ("build_process","replay_process")},"SDK build stdout custody")
    original_public=read_reference.verify_public(package,capture/"r",capture/"k",capture/"po",
        expected_parent=processes["public-original"],
        expected_origin=gate["origins"]["sdk"]+"/hia_configured_public.elf",
        expected_binary=sdk["binaries"]["hia_configured_public"]["pin"],native=capture/"pn")
    public_original_report=c.read_json(capture/"po/result.json")
    c.need(c.parse(streams["public-original"]["stdout"])=={
        k:v for k,v in public_original_report.items() if k not in ("observed","processes")},"complete original public stdout")
    # The installed declaration bytes are independently compared to all current original profiles.
    c.need(component_result["cases"]==391 and component_result["actual_native_calls"]==478
        and native["catalog_exchanges"]==216 and original_public["original_list_handler_calls"]==162,
        "complete retained domains")
    return {"status":"COMPLETE_CONFIGURED_CATALOG_SEMANTICS_READONLY_PASS",
        "package":c.pin(c.regular(package/"PACKAGE.json")),"component":component_result,"graph":graph,
        "direct_original":original,"sdk":sdk,"native_public":native,"original_public":original_public,
        "processes":processes,"process_files":outer.files,"process_launches":0,
        "native_execution":False,"rust_execution":False,
        "configuration_aware_catalog_on_installed102_compared":True,
        "all_installed_masks_typed_sdk_compared":True,**{key:False for key in c.FALSE_FLAGS}}
