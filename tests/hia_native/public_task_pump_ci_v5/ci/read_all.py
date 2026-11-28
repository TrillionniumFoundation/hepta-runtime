"""One source-bound read-only join of fresh graph, current original, and serial1394."""
from pathlib import Path
import argparse
import importlib
import json
import sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import files, pin, require
from source_check import source
import read_build
import build_controls

def prepare(package):
    package=Path(package).resolve(strict=True)
    read_build.prepare(package)
    sys.path.insert(0,str(package/"wire"))
    wire=importlib.import_module("read_wire_guarded")
    require(Path(wire.__file__).resolve()==package/"wire/read_wire_guarded.py","foreign joined wire reader")
    return wire,wire.prepare(package/"port")

def inventory(root,expected_manifest=None):
    path=root/"artifact-manifest.json"
    value=json.loads(path.read_bytes())
    if expected_manifest is not None:
        require(pin(path)==expected_manifest,"dependency archive manifest changed")
    require(value["schema"]=="hepta.runtime.complete-ci-archive.v1","archive inventory schema")
    actual=files(root)
    require(set(actual)==set(value["files"])|{"artifact-manifest.json"},"complete archive file set changed")
    for name,row in value["files"].items():
        require(actual[name]=={"bytes":row["bytes"],"sha256":row["sha256"]}
                and (root/name).stat().st_mode & 0o777==row["mode"],
                "complete archived file changed: "+name)
    return {"manifest":pin(path),"files":len(actual),"bytes":sum(row["bytes"] for row in actual.values())}

def recorded_command(capture,label,argv,origin,*,pid=None):
    record=json.loads((capture/"processes"/(label+".json")).read_bytes())
    require(record["label"]==label and record["command"]==argv and record["cwd"]==origin,
            "actual orchestration command differs: "+label)
    require(record["new_outer_timeout"] is False and record["workflow_job_limit_minutes"]==15
        and record["started"] is True and record["exit_code"]==0
        and record["process_still_running"] is False and "failure" not in record,
        "actual orchestration process failed: "+label)
    require(type(record["pid"]) is int and record["pid"]>0 and type(record["elapsed_ns"]) is int
        and record["elapsed_ns"]>=0,"actual process custody differs")
    if pid is not None:
        require(record["pid"]==pid,"actual observer producer pid differs")
    require(record["stdout"]==pin(capture/"processes"/(label+".stdout"))
        and record["stderr"]==pin(capture/"processes"/(label+".stderr"))
        and (capture/"processes"/(label+".stderr")).read_bytes()==b"",
        "complete actual orchestration streams differ")
    return record

def verify(package,build,original,capture,manifest_sha256,wire,prepared):
    package,build,original,capture=map(Path,(package,build,original,capture))
    admitted=source(package,manifest_sha256)
    origin=json.loads((capture/"NATIVE_ORIGIN.json").read_bytes())
    require(origin["schema"]=="hepta.runtime.task-pump-public-ci.v1"
        and origin["manifest_sha256"]==manifest_sha256 and origin["source_admission"]==admitted,
        "public source admission differs")
    require(origin["records"]==1394 and origin["tool_cases"]==1366
        and origin["process_deadline_seconds"]==180 and origin["exchange_deadline_seconds"]==60
        and origin["workflow_job_limit_minutes"]==15,"public domain/deadline changed")
    dependencies=json.loads((capture/"DEPENDENCIES.json").read_bytes())
    require(set(dependencies)=={"build","original"},"dependency archive set differs")
    archived={}
    for label,root in (("build",build),("original",original)):
        row=dependencies[label]
        require(row["label"]==label and row["source_manifest_sha256"]==manifest_sha256
            and row["qualification_inferred_from_archive"] is False
            and row["captured_tree_modified_by_export"] is False,"dependency archive scope differs")
        for key in ("git_head","run_id","run_attempt"):
            require(type(row[key]) is str and row[key] and row[key]==origin[key],"dependency was not from the same CI attempt")
        archived[label]=inventory(root,row["manifest"])
        require(source(root/"ci-package",manifest_sha256)==admitted,"dependency complete source snapshot differs")
        declaration=json.loads((root/"CI_SOURCE_DECLARATION.json").read_bytes())
        require(declaration["manifest_sha256"]==manifest_sha256 and declaration["label"]==label
            and declaration["archive_is_qualification"] is False
            and declaration["captured_tree_modified_by_export"] is False,"archive source declaration differs")
        require(all(declaration[k]==origin[k] for k in ("git_head","run_id","run_attempt")),
                "archive declaration CI identity differs")
    graph=read_build.verify_build(package,build,manifest_sha256)
    graph_controls=build_controls.verify_controls(package,build,manifest_sha256)
    build_origin=json.loads((build/"BUILD_ORIGIN.json").read_bytes())
    require(all(build_origin[key]==origin[key] for key in ("git_head","run_id","run_attempt")),
            "fresh graph CI identity differs")
    original_run=json.loads((original/"run.json").read_bytes())
    require(original_run["status"]=="FRESH_BELLMAN_PUBLIC_ORIGINAL_REFERENCE_PASS"
        and original_run["complete_original_cases"]==683 and original_run["complete_public_cases"]==1366,
        "complete fresh original run did not succeed")
    require(original_run["git_head"]==origin["git_head"] and original_run["run_id"]==origin["run_id"]
            and original_run["attempt"]==origin["run_attempt"],"fresh original CI identity differs")
    for flag in ("public_handler_qualified","full_server_router_qualified","audit_qualified",
                 "async_pending_registry_qualified","whole_runtime_replaced","old_stack_removal_qualified"):
        require(original_run[flag] is False,"original scope was enlarged")
    binary={key:graph["entries"]["journal"]["elf"][key] for key in ("bytes","sha256")}
    joined=wire.verify(capture/"public",original,expected_binary=binary,prepared=prepared)
    controls=prepared["controls"].verify(capture/"public",original,joined,capture/"public-reader-controls",prepared=prepared)
    observer=prepared["controls"].verify_observer_process_controls(capture/"observer-controls",prepared=prepared)
    native_report=json.loads((capture/"public/CAPTURE.json").read_bytes())
    py=[origin["python"],"-I","-S","-B"]
    public_command=py+[str(Path(origin["package"])/"wire/observe_native.py"),
        "--native",str(Path(origin["build"])/"journal/task-pump/task-pump-fixture.elf"),
        "--binary-sha256",binary["sha256"],"--output",str(Path(origin["output"])/"public")]
    native_process=recorded_command(capture,"native1394",public_command,origin["output"],pid=native_report["producer_pid"])
    require(native_report["producer_parent_pid"]==origin["pid"]
        and native_report["command"]==[origin["python"],*public_command[4:]],
        "public observer command/parent differs")
    require(json.loads((capture/"processes/native1394.stdout").read_bytes())
        =={key:value for key,value in native_report.items() if key not in ("sources","sessions")},
        "complete actual observer stdout differs")
    observer_command=py+[str(Path(origin["package"])/"wire/observer_process_controls.py"),
        "--output",str(Path(origin["output"])/"observer-controls")]
    recorded_command(capture,"observer-controls",observer_command,origin["output"])
    require(json.loads((capture/"processes/observer-controls.stdout").read_bytes())
            ==json.loads((capture/"observer-controls/CONTROLS.json").read_bytes()),
            "complete observer-controls stdout differs")
    preflight=json.loads((capture/"observer-preflight-readonly.json").read_bytes())
    require(preflight["before"]==preflight["after"] and len(preflight["probes"])==11
        and preflight["reader_writes"]==preflight["native_or_rust_executions"]==0
        and preflight["source_bound_guard"] is True
        and preflight["evidence"]==observer,"observer-control preflight readback changed")
    require(joined["status"]=="COMPLETE_SERIAL1394_WIRE_AND_WORKER_EVIDENCE_PASS"
        and joined["wire"]["records"]==joined["journal"]["records"]==1394
        and joined["wire"]["public_cases"]==1366 and joined["wire"]["response_count"]==1393,
        "complete wire/journal join differs")
    require(len(controls["wire"]["refusals"])==7 and len(controls["physical_journal_refusals"])==2
        and observer["actual_python_cases"]==10 and graph_controls["refusals"]==4,
        "complete retained reader/control domains differ")
    qualification={"status":"FRESH_GRAPH_AND_CURRENT_SERIAL1394_PASS",
        "source_manifest_sha256":manifest_sha256,
        "ci":{"git_head":origin["git_head"],"run_id":origin["run_id"],"run_attempt":origin["run_attempt"]},
        "runtime_hia_images":100,"fresh_direct_members":92,"packed_hia_members":8,
        "entry_pins":{label:{kind:{key:row[kind][key] for key in ("bytes","sha256")}
            for kind in ("elf","manifest")} for label,row in graph["entries"].items()},
        "original_cases":683,"public_records":joined["wire"]["records"],
        "tool_cases":joined["wire"]["public_cases"],"complete_responses":joined["wire"]["response_count"],
        "native_processes":2,"native_sessions_per_process":1,"original_processes":1,
        "original_sessions_per_process":2,"process_deadline_seconds":180,"exchange_deadline_seconds":60,
        "graph_physical_refusals":graph_controls["refusals"],
        "journal_physical_refusals":len(controls["physical_journal_refusals"]),
        "wire_refusals":len(controls["wire"]["refusals"]),
        "observer_python_controls":observer["actual_python_cases"],
        "journal_pins":[row["journal"] for row in joined["journal"]["journals"]],
        "input":pin(capture/"public/inputs.bin"),"capture":pin(capture/"public/CAPTURE.json"),
        "only_normalized_field":"native_operation_wall_seconds",
        "full_sdk_qualified":False,"full_router_qualified":False,"async_pending_registry_qualified":False,
        "cross_session_pool_qualified":False,"production_activated":False,"old_stack_removed":False}
    if (capture/"artifact-manifest.json").is_file():
        inventory(capture)
        require(source(capture/"ci-package",manifest_sha256)==admitted,"native archived source differs")
    if (capture/"driver.stdout").is_file():
        previous=json.loads((capture/"driver.stdout").read_bytes())
        require(previous["status"]==qualification["status"] and previous["qualification"]==qualification,
                "previous complete qualification does not match the actual reread")
        prior=previous["read_only"]
        require(prior["before"]==prior["after"] and len(prior["probes"])==11
            and prior["source_bound_guard"] is True and prior["reader_writes"]==prior["native_or_rust_executions"]==0
            and prior["evidence"]["qualification"]==qualification,"previous guarded qualification differs")
        require((capture/"driver.stderr").read_bytes()==b"","complete native driver stderr differs")
    return {"qualification":qualification,"graph":graph,"graph_controls":graph_controls,
        "public":joined,"public_controls":controls,"observer_controls":observer,
        "dependency_archives":archived,"native_process":native_process}

def guarded_verify(package,build,original,capture,manifest_sha256,*,prepared_pair=None):
    package,build,original,capture=(Path(p).resolve(strict=True) for p in (package,build,original,capture))
    wire,prepared=prepared_pair or prepare(package)
    report=wire.guarded(lambda:verify(package,build,original,capture,manifest_sha256,wire,prepared),
        roots=[package,build,original,capture],prepared=prepared)
    qualification=report["evidence"]["qualification"]
    return {"status":qualification["status"],"qualification":qualification,"read_only":report}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("package","build","original","capture"):
        p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--manifest-sha256",required=True)
    a=p.parse_args()
    print(json.dumps(guarded_verify(a.package,a.build,a.original,a.capture,a.manifest_sha256),sort_keys=True))

if __name__=="__main__":
    main()
