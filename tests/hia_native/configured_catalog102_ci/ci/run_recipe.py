"""Fresh configured-catalog qualification and strictly read-only verification."""
from pathlib import Path
import argparse, json, os, shutil, stat, sys, time, traceback
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import catalog_ci_support as c
import read_all,evidence_controls

def copy_regular_tree(source,destination,excluded=()):
    destination.mkdir(parents=True,exist_ok=False)
    inventory={}
    for folder,dirs,names in os.walk(source,followlinks=False):
        relative=Path(folder).relative_to(source)
        dirs[:]=[name for name in dirs if (relative/name).as_posix() not in excluded]
        for name in dirs:
            p=Path(folder)/name;c.need(stat.S_ISDIR(p.lstat().st_mode),"owned source directory")
            d=destination/relative/name;d.mkdir();d.chmod(stat.S_IMODE(p.stat().st_mode))
        for name in names:
            p=Path(folder)/name;key=(relative/name).as_posix()
            raw=c.regular(p);c.put(destination/key,raw);(destination/key).chmod(stat.S_IMODE(p.stat().st_mode))
            inventory[key]={"mode":stat.S_IMODE(p.stat().st_mode),**c.pin(raw)}
    return inventory

def prepare(package,capture):
    read_all.prepare(package)
    # Import all fixed negative-control paths before enabling the read-only guard.
    evidence_controls.read_all.prepare(package)
    return read_all.PREPARED[str(Path(package).absolute())][-1]

def final_evidence(package,capture):
    semantics=read_all.verify_semantics(package,capture)
    controls=evidence_controls.verify(package,capture,capture/"controls")
    gate=c.read_json(capture/"EXECUTION.json")
    r=c.Reader(capture/"checks")
    row,streams=c.process(r,"evidence-controls",
        command=[gate["python"],"-I","-B",gate["origins"]["source"]+"/ci/evidence_controls.py",
            "--package",gate["origins"]["source"],"--capture",gate["producer_root"],
            "--output",gate["producer_root"]+"/controls"],
        cwd=gate["origins"]["source"],timeout=180,parent=gate,empty_stderr=True)
    report=c.read_json(capture/"controls/result.json")
    c.need(all(report[key]==row[key] for key in ("pid","parent_pid","pgid")),"actual evidence-control process")
    expected={key:value for key,value in report.items() if key!="controls"}|{"refusals":12}
    c.need(c.parse(streams["stdout"])==expected,"control stdout/full retained tree custody")
    summary={"status":"COMPLETE_CONFIGURED_CATALOG_QUALIFICATION_PASS",
        "target_commit":c.TARGET,"compiler_commit":c.COMPILER,"component_cases":391,"component_native_calls":478,
        "retained_component_cases":87,"retained_non_list_operations":18,"runtime_images":102,
        "fresh_compiled_images":108,"direct_original_contexts":216,"typed_sdk_projection_records":1728,
        "public_native_processes":9,"public_original_processes":9,"public_requests_each":216,
        "public_list_results_each":162,"sdk_rejections_each":54,"complete_public_responses_each":225,
        "physical_refusals":12,"exact_current_sdk":"3.9.0","actual_locked_tokio":"1.53.3",
        "installed_masks_compared":[0,1,2,3],"installed_public_mask":1,
        "configurations":[0,1,3,5,7,9,11,13,15],"actual_config_query_child":6,"actual_config_query_operation":3,
        "bellman_advertised_in_actual102":False,"tool_body_executions":0,
        "configuration_aware_catalog_on_installed102_compared":True,
        **{key:False for key in c.FALSE_FLAGS}}
    return {"summary":summary,"semantics":semantics,"controls":controls,"control_process":row,
        "control_process_files":r.files}

def retained_reports(package,capture,current):
    comparison=c.read_json(capture/"COMPARISON.json")
    c.need(current==comparison,"retained complete comparison matches current read-only proof")
    original_guard=c.read_json(capture/"READONLY.json")
    c.need(original_guard["evidence"]==current and original_guard["before"]==original_guard["after"]
        and original_guard["reader_writes"]==original_guard["native_or_rust_executions"]==0
        and len(original_guard["probes"])==12 and original_guard["source_bound_guard"] is True,
        "complete retained read-only proof")
    qualification=c.read_json(capture/"QUALIFICATION.json")
    c.need(qualification==current["summary"]|{
        "package":c.pin(c.regular(package/"PACKAGE.json")),"comparison":c.pin(c.regular(capture/"COMPARISON.json")),
        "readonly":c.pin(c.regular(capture/"READONLY.json")),"readonly_probes":12,
        "complete_readonly_entries":len(original_guard["before"]),
        "fresh_original_pending":False},"complete final qualification identity")

def guarded_read(package,capture,foreign,*,retained=False):
    guard=prepare(package,capture)
    def operation():
        current=final_evidence(package,capture)
        if retained:retained_reports(package,capture,current)
        return current
    result=guard.guarded(operation,roots=[capture],foreign_path=foreign)
    c.need(result["reader_writes"]==result["native_or_rust_executions"]==0
        and len(result["probes"])==12 and result["before"]==result["after"],"complete read-only regression guard")
    return result

def execute(package,target,hepta,output):
    c.need(os.environ.get("GITHUB_ACTIONS")=="true","new semantic qualification is CI-only")
    c.source_check(package)
    output=output.absolute();c.need(len(str(output))<=20,"short owned fixture root preserves the original Unix path limit")
    c.need(not output.exists(),"new capture root")
    output.mkdir(mode=0o700)
    source=output/"s";copy_regular_tree(package,source)
    origin=output.parent/(output.name+"-original")
    c.need(not origin.exists(),"fresh independent original capture")
    old_umask=os.umask(0o077)
    start=time.monotonic_ns()
    gate={"schema":"hepta.runtime.configured-catalog-execution.v1","status":"RUNNING",
        "target_commit":c.TARGET,"compiler_commit":c.COMPILER,"package":c.pin(c.regular(source/"PACKAGE.json")),
        "producer_root":str(output),"origins":{key:str(output/name) for key,name in
            (("source","s"),("component_build","b"),("component_native","n"),("graph","g"),
             ("sdk","k"),("public_native","pn"),("public_original","po"))}|{"original":str(origin)},
        "target_checkout":str(target),"compiler_checkout":str(hepta),"python":sys.executable,
        "pid":os.getpid(),"parent_pid":os.getppid(),"pgid":os.getpgrp(),"process_order":[],
        **{key:False for key in c.FALSE_FLAGS}}
    py=[sys.executable,"-I","-B"];rust=c.original_environment(origin/"cargo-target")
    original_copied=False
    def run(name,args,limit,env=None):
        row=c.record_process(output/"processes",name,py+[str(x) for x in args],source,limit,env=env)
        gate["process_order"].append(name)
        return row
    try:
        run("direct-original",[source/"source/retained/pipeline/policy_base/reference/capture.py",
            "--target",target,"--output",origin],3600,rust)
        run("component-build",[source/"source/build_configured.py","--hepta",hepta,"--output",output/"b"],300)
        run("component-native",[source/"source/capture_configured.py","--build",output/"b","--output",output/"n"],180)
        run("graph-build",[source/"graph/scripts/hia_native_runtime_mcp_build.py","--source",source/"graph",
            "--hepta",hepta,"--output",output/"g","--bootstrap",output/"b/bootstrap"],300)
        manifest=output/"g/build/public-authority-batch/manifest.json"
        gate["graph_manifest"]=c.pin(c.regular(manifest))
        run("sdk-observers",[source/"ci/build_reference.py","--package",source,"--target",target,
            "--original",origin,"--output",output/"k"],300,rust)
        run("public-native",[source/"public/capture_public_configured.py","--component",source/"source",
            "--graph",source/"graph","--manifest",manifest,"--output",output/"pn"],180)
        run("public-original",[source/"ci/observe_public_reference.py","--package",source,
            "--binary",output/"k/hia_configured_public.elf","--output",output/"po"],180,rust)
        original_inventory=copy_regular_tree(origin,output/"r",excluded=("cargo-target",))
        original_copied=True
        c.put(output/"ORIGINAL_RETENTION.json",{"schema":"hepta.runtime.configured-original-retention.v1",
            "origin":str(origin),"retained":"r","files":original_inventory,"excluded_exact_directory":"cargo-target",
            "complete_original_sources_registry_binary_and_streams_retained":True,"semantic_executions_added":0})
        gate["status"]="COMPLETE";gate["elapsed_ns"]=time.monotonic_ns()-start
        c.put(output/"EXECUTION.json",gate)
        prepare(source,output)
        read_all.verify_semantics(source,output)
        c.record_process(output/"checks/processes","evidence-controls",
            py+[str(source/"ci/evidence_controls.py"),"--package",str(source),"--capture",str(output),
                "--output",str(output/"controls")],source,180)
        foreign=output.parent/(output.name+"-foreign.txt")
        c.put(foreign,b"owned external read refusal fixture\n")
        before=final_evidence(source,output)
        c.put(output/"COMPARISON.json",before)
        guarded=guarded_read(source,output,foreign)
        c.need(guarded["evidence"]==before,"same complete result under read-only guard")
        c.put(output/"READONLY.json",guarded)
        c.put(output/"QUALIFICATION.json",before["summary"]|{
            "package":gate["package"],"comparison":c.pin(c.regular(output/"COMPARISON.json")),
            "readonly":c.pin(c.regular(output/"READONLY.json")),"readonly_probes":12,
            "complete_readonly_entries":len(guarded["before"]),"fresh_original_pending":False})
        print(c.encoded(c.read_json(output/"QUALIFICATION.json")).decode())
    except BaseException as error:
        c.put(output/"FAILURE.json",{"schema":"hepta.runtime.configured-catalog-failure.v1","error":repr(error),
            "traceback":traceback.format_exc(),"gate":gate,"elapsed_ns":time.monotonic_ns()-start,
            "complete_domain_pass_claimed":False})
        raise
    finally:
        try:
            if origin.exists() and not original_copied and not (output/"r").exists():
                copy_regular_tree(origin,output/"r",excluded=("cargo-target",))
        finally:os.umask(old_umask)

def verify(package,capture,foreign):
    return guarded_read(package,capture,foreign,retained=True)

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--phase",choices=("all","verify"),required=True)
    p.add_argument("--package",type=Path,default=HERE.parent)
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--target",type=Path);p.add_argument("--hepta",type=Path);p.add_argument("--foreign-path",type=Path)
    a=p.parse_args();package=a.package.resolve(strict=True)
    if a.phase=="all":
        c.need(a.target is not None and a.hepta is not None,"fresh target and compiler required")
        execute(package,a.target.resolve(strict=True),a.hepta.resolve(strict=True),a.output.absolute())
    else:
        c.need(a.foreign_path is not None,"owned foreign-read probe required")
        print(c.encoded(verify(package,a.output.resolve(strict=True),a.foreign_path.absolute())).decode())
