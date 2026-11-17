"""Read unchanged Batch domains against the newly installed default111 graph."""
from pathlib import Path
import argparse,copy,importlib,json,sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import require,pin
from domain_support import doc,load,isolated,selected,check_origin,record_process,graph_identity
import read_build
NAMES=("source_check","read_builds","read_public","read_stdio","receipt_support","lane_guard",
    "retire_fixture","qualify_public","qualify_stdio","public_cases","public_observations",
    "capture_common","capture_fixture","check_evidence","public_nine_build","hia_native_build","hia_native_loader")
DOMAINS={"typed-legacy":417,"typed-modern":417,"filesystem":926,"session":17}
STDIO={"legacy":15,"modern":13}
FLAGS=("full_sdk_qualified","full_async_runtime_qualified","production_activated","old_path_removed")
def import_batch(package):
    source=Path(package)/"joint/batch"
    with isolated(NAMES):
        sys.path.insert(0,str(source))
        batch=load("_public111_unchanged_batch_recipe",source/"run_recipe.py")
        batch.read_builds.load_builder(source/"native-source")
        controls=importlib.import_module("check_evidence")
        require(Path(controls.__file__).resolve()==(source/"check_evidence.py").resolve(),"wrong retained controls module")
        modules={k:v for k,v in sys.modules.items() if k in NAMES}
    return batch,modules
def prepare(package,baseline):
    read_build.prepare(package)
    batch,modules=import_batch(package)
    with selected(modules,NAMES):
        original=batch.read_public.capture.case_rows
        retained={}
        for domain,count in DOMAINS.items():
            left=doc(baseline/"public"/domain/"native/result.json")
            right=doc(baseline/"public"/domain/"original/result.json")
            require(left["fixture"]==right["fixture"],"retained fixture identity")
            fixture=Path(left["fixture"]);require(fixture.is_absolute(),"absolute original fixture")
            rows=original(domain,fixture);require(len(rows)==count,"complete unchanged input definition")
            retained[(domain,fixture)]=rows
        def rows(domain,fixture):
            key=(domain,Path(fixture));require(key in retained,"unadmitted case definition")
            return copy.deepcopy(retained[key])
        batch.read_public.capture.case_rows=rows
    sys.path.insert(0,str(package/"wire"))
    wire=importlib.import_module("read_wire_guarded")
    return {"batch":batch,"modules":modules,"wire":wire,"guard":wire.prepare(package/"port"),
        "input_shapes":[{"domain":d,"fixture":str(p),"rows":len(v)} for (d,p),v in retained.items()]}
def lane(folder,kind,domain,binary,fixture,producer,source,batch,owner_pid):
    row=doc(folder.parent/(folder.name+".lane.json"));report=doc(folder/"result.json")
    module="qualify_public.py" if kind=="private" else "qualify_stdio.py"
    relative=("public" if kind=="private" else "stdio")+"/"+domain+"/native"
    require(row["schema"]=="hepta.runtime.batch-public-lane-guard.v1" and row["status"]=="PASS"
        and row["execution_kind"]=="in_process_recording_driver" and row["kind"]==kind
        and row["role"]=="native" and row["domain"]==domain
        and row["fixture"]==report["fixture"]==str(fixture)
        and row["output"]==str(producer/relative)
        and row["binary"]==report["binary"]["path"]==str(binary)
        and row["driver"]==module and row["driver_pin"]==pin(source/module)
        and type(row["owner_pid"]) is int and row["owner_pid"]==owner_pid>0
        and row["outer_lane_deadline_seconds"]==180 and row["per_exchange_deadline_seconds"]==60
        and row["alarm_fired"] is False and row["cleanup_in_recording_driver"] is True
        and batch.read_public.number(row["elapsed_seconds"],180) and row["elapsed_seconds"]<180
        and report["elapsed_seconds"]<=row["elapsed_seconds"]
        and row["capture"]==pin(folder/"result.json"),"complete actual111 native lane custody")
    stdout=None
    for key in ("stdout","stderr"):
        name=folder.name+".lane."+key;raw=(folder.parent/name).read_bytes()
        require(row[key]=={"path":name,**batch.PIN(raw)},"complete native lane stream")
        if key=="stderr":require(raw==b"","native lane diagnostics")
        else:stdout=batch.read_public.decode(raw)
    keys=("status","role","domain","case_count","completed_cases","elapsed_seconds") if kind=="private" else \
        ("status","role","era","case_count","completed_cases")
    require(stdout=={k:report[k] for k in keys},"native recording driver complete output")
    batch.retire_fixture.verify(folder,report)
    return row
def verify(package,run,manifest_sha256,role,dependencies,prepared):
    origin=check_origin(package,run,manifest_sha256,role,dependencies)
    batch=prepared["batch"];source=package/"joint/batch"
    baseline=run/"baseline" if role=="batch-reference" else dependencies["batch-reference"]/"baseline"
    with selected(prepared["modules"],NAMES):
        reference=batch.verify(baseline)
        require(reference["status"]=="PASS" and reference["fresh_original_build"] is True
            and reference["actual_private_rows_per_provider"]==1777
            and reference["actual_stdio_exchanges_per_provider"]==28
            and reference["actual_runtime_root_processes"]==12,"complete retained current reference")
        oldsource=batch.source_check.check(source)
        require(batch.source_check.check(baseline/"source")==oldsource,"exact retained reference source")
        if role=="batch-reference":
            py=[origin["python"],"-I","-S","-B"]
            process=record_process(run,"fresh-complete-batch-reference",py+[
                str(Path(origin["package"])/"joint/batch/run_recipe.py"),"--phase","all",
                "--hepta",origin["hepta"],"--target",origin["target"],"--rust-bin",origin["rust_bin"],
                "--output",str(Path(origin["output"])/"baseline")])
            result={"status":"FRESH_UNCHANGED_BATCH1777_STDIO28_REFERENCE_PASS",
                "reference":reference,"process":process,"reference_native_graph_images":102,
                "reference_native_promoted_to111":False}
        else:
            build=dependencies["build"];graph=read_build.verify_build(package,build,manifest_sha256)
            require(graph["runtime_hia_images"]==111 and graph["fresh_direct_members"]==103
                and graph["actual_default_entry"] is True,"actual111 default graph")
            declared=doc(run/"CAPTURE.json")
            require(declared["schema"]=="hepta.runtime.public111.batch-capture.v1"
                and declared["status"]=="PASS" and declared["domains"]==DOMAINS and declared["stdio"]==STDIO
                and declared["source"]==pin(source/"source-profile.json")
                and declared["actual_new_native_processes"]==6 and declared["fresh_original_reused_from_same_ci"] is True
                and declared["outer_lane_seconds"]==180 and declared["exchange_seconds"]==60,
                "actual111 complete native domain")
            original=reference["original_build"]["binaries"]["hepta-batch-sdk-current-original-oracle"]
            original_pin={k:original[k] for k in ("bytes","sha256")}
            oldreport=doc(baseline/"result.json");fixture_root=Path(oldreport["producer_root"])/"workspaces"
            producer=Path(origin["output"]);graph_origin=Path(origin["dependencies"]["build"])
            results={"private":{},"stdio":{}}
            for kind,domains in (("private",DOMAINS),("stdio",STDIO)):
                label="instances" if kind=="private" else "production"
                relative="instances/task-pump/filesystem-fixture.elf" if kind=="private" else \
                    "production/build/public-task-batch/runtime-mcp.elf"
                native_pin={k:graph["entries"][label]["elf"][k] for k in ("bytes","sha256")}
                binary=graph_origin/relative
                for domain,count in domains.items():
                    parent="public" if kind=="private" else "stdio"
                    left=run/parent/domain/"native";right=baseline/parent/domain/"original"
                    fixture=fixture_root/(("private-" if kind=="private" else "stdio-")+domain)
                    require(doc(right/"result.json")["fixture"]==str(fixture),"original absolute fixture path")
                    lane(left,kind,domain,binary,fixture,producer,source,batch,origin["pid"])
                    if kind=="private":
                        value=batch.read_public.compare(left,right,source,native_binary=native_pin,
                            original_binary=original_pin)
                        require(value["actual_rows_per_provider"]==count,"all private cases")
                    else:
                        value=batch.read_stdio.compare(left,right,source,native_pin,original_pin)
                        require(value["actual_exchanges_per_provider"]==count,"all real stdio cases")
                    require(value==doc(run/parent/domain/"comparison.json"),"complete comparison retention")
                    require(not fixture.exists() and not fixture.is_symlink(),"completed owned fixture still live")
                    results[kind][domain]=value
            require(declared["graph"]==graph_identity(graph) and declared["binary"]=={
                k:{field:graph["entries"][k]["elf"][field] for field in ("bytes","sha256")} for k in ("production","instances")},"executed graph binding")
            result={"status":"ACTUAL_DEFAULT111_BATCH1777_STDIO28_PASS",
                "actual_graph":graph_identity(graph),"reference":reference,"native":results,"input_shapes":prepared["input_shapes"],
                "actual_new_native_processes":6,"actual_private_rows_per_provider":1777,
                "actual_stdio_exchanges_per_provider":28,"same_ci_current_original":True,
                "retained_21_reference_controls_rechecked":True,"complete_graph_reader_rechecked":True,
                "unchanged_reference_native_graph_promoted":False}
    result.update(source_manifest_sha256=manifest_sha256,
        ci={k:origin[k] for k in ("git_head","run_id","run_attempt")},**dict.fromkeys(FLAGS,False))
    if (run/"QUALIFICATION.json").exists():
        require(doc(run/"QUALIFICATION.json")==result,"complete retained qualification changed")
    return result
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--role",choices=("batch-reference","batch"),required=True)
    for name in ("package","run"):p.add_argument("--"+name,type=Path,required=True)
    for name in ("build","batch-reference"):p.add_argument("--"+name,type=Path)
    p.add_argument("--manifest-sha256",required=True);a=p.parse_args()
    package=a.package.resolve(strict=True);run=a.run.resolve(strict=True)
    deps={n:getattr(a,n.replace("-","_")).resolve(strict=True) for n in ("build","batch-reference")
        if getattr(a,n.replace("-","_")) is not None}
    baseline=run/"baseline" if a.role=="batch-reference" else deps["batch-reference"]/"baseline"
    prepared=prepare(package,baseline)
    guarded=prepared["wire"].guarded(lambda:verify(package,run,a.manifest_sha256,a.role,deps,prepared),
        roots=[package,run,*deps.values()],prepared=prepared["guard"])
    print(json.dumps({"status":guarded["evidence"]["status"],"qualification":guarded["evidence"],
        "read_only":guarded},sort_keys=True,allow_nan=False))
if __name__=="__main__":main()
