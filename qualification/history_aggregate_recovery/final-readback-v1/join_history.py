#!/usr/bin/env python3
"""Join independently guarded historical readbacks without importing captured code."""
from __future__ import annotations
import argparse,gzip,hashlib,io,json,os,stat,sys,time,zipfile
from pathlib import Path,PurePosixPath
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
import read_only_guard as guard
REPORT={"bytes":94614535,"sha256":"6159169d8c0763d2418c8f625e5cd67099a06179f69927f7a1e62972a1eafa41"}
PROBES=["python-file-write","descriptor-open","descriptor-write","metadata-mode","metadata-time",
 "directory-create","subprocess","shell","native-dlopen","native-mmap","producer-or-foreign-read","unadmitted-file-descriptor"]
def need(v,s):
    if not v:raise ValueError(s)
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+"\n").encode()
def pin(p):
    before=p.lstat();need(stat.S_ISREG(before.st_mode) and p.resolve()==p.absolute(),"ordinary final input")
    with p.open("rb") as f:h=hashlib.file_digest(f,"sha256").hexdigest()
    after=p.lstat()
    need(all(getattr(before,k)==getattr(after,k) for k in ("st_mode","st_dev","st_ino","st_size","st_mtime_ns","st_ctime_ns")),
         "entire final input stable")
    return {"bytes":before.st_size,"sha256":h}
def read_json(p):return json.loads(p.read_bytes())
def open_bundle(inputs,label,expected):
    path=inputs/(label+".zip");need(pin(path)==expected["artifact"]["zip"],"exact complete independent ZIP")
    metadata=read_json(inputs/(label+"-artifact.json"))
    need(metadata["id"]==expected["artifact"]["id"] and metadata["size_in_bytes"]==expected["artifact"]["zip"]["bytes"]
         and metadata["digest"]=="sha256:"+expected["artifact"]["zip"]["sha256"] and metadata["expired"] is False
         and metadata["workflow_run"]["id"]==expected["run"] and metadata["workflow_run"]["head_sha"]==expected["head"],
         "immutable independent workflow artifact")
    jobs=read_json(inputs/(label+"-jobs.json"))["jobs"]
    actual=[j for j in jobs if j["id"]==expected["job"]]
    need(len(actual)==1 and actual[0]["run_id"]==expected["run"] and actual[0]["status"]=="completed"
         and actual[0]["conclusion"]=="success","actual final independent job terminal")
    need(all(step["conclusion"] in ("success","skipped") for step in actual[0]["steps"]),"no failed executed independent step")
    files={};rows=[]
    with zipfile.ZipFile(path) as z:
        need(len(z.namelist())==len(set(z.namelist())),"no duplicate ZIP member")
        for item in z.infolist():
            name=item.filename;p=PurePosixPath(name)
            need(p.as_posix()==name and not p.is_absolute() and name and ".." not in p.parts
                 and not item.is_dir() and stat.S_IFMT(item.external_attr>>16) in (0,stat.S_IFREG),"ordinary complete ZIP member")
            with z.open(item) as f:raw=f.read()
            need(len(raw)==item.file_size,"complete ZIP member extent")
            files[name]=raw;rows.append({"path":name,"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),
                                        "mode":stat.S_IMODE(item.external_attr>>16)})
    actual_sources={name.removeprefix("source/"):raw for name,raw in files.items() if name.startswith("source/")}
    source_manifest=expected["source_manifest"];raw=actual_sources.get("SOURCE_MANIFEST.json")
    need(raw is not None and {"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}==
         {k:source_manifest[k] for k in ("bytes","sha256")},"exact independent source manifest")
    manifest=json.loads(raw)
    need(manifest["files"]==expected["source_files"] and set(actual_sources)==set(manifest["files"])|{"SOURCE_MANIFEST.json"},"entire independent source closure")
    for name,row in manifest["files"].items():
        raw=actual_sources[name]
        need(len(raw)==row["bytes"] and hashlib.sha256(raw).hexdigest()==row["sha256"]
             and hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()==row["git_blob"],"every independent Git source byte")
    result=json.loads(files["guarded/READBACK.json"]);diagnostics=json.loads(files["guarded/DIAGNOSTICS.json"])
    before=json.loads(gzip.decompress(files["guarded/before.json.gz"]))
    after=json.loads(gzip.decompress(files["guarded/after.json.gz"]))
    external_before=json.loads(gzip.decompress(files["guarded/external_before.json.gz"]))
    external_after=json.loads(gzip.decompress(files["guarded/external_after.json.gz"]))
    need(before==after and external_before==external_after and before,"complete actual guarded snapshots unchanged")
    need(result["source_bound_guard"] is True and result["native_or_rust_executions"]==result["reader_writes"]==0
         and [p["name"] for p in result["probes"]]==PROBES and len(result["probes"])==12,
         "unchanged complete no-write/no-execution guard")
    need(len(diagnostics)==12 and all(d["phase"]=="probes" and d["frames"] for d in diagnostics)
         and [d["kind"] for d in diagnostics]==[p["guard_event"] for p in result["probes"]],"no swallowed reader refusal")
    need(type(result["elapsed_ns"])is int and 0<result["elapsed_ns"]<=180000000000,"unchanged independent reader budget")
    need(files["logs/reader.stderr"]==b"","actual empty independent reader stderr")
    stdout=json.loads(files["logs/reader.stdout"])
    evidence=result["evidence"];need(stdout["status"]==evidence["status"]==expected["status"]
         and stdout["native_or_rust_executions"]==evidence["native_or_rust_executions"]==0,"whole actual independent result")
    need(evidence["original_report"]==REPORT and evidence["original_failure_reclassified_as_pass"] is False,"same original failed aggregate")
    archive=json.loads(files["COMPLETE_ARCHIVE_READBACK.json"])
    need(archive["status"]=="COMPLETE_ARCHIVE_BYTES_AND_GIT_SOURCES_PASS" and archive["zip"]==expected["producer_zip"]
         and archive["native_or_rust_executions"]==0 and archive["input_zip_unchanged"] is True,"full producer archive admission")
    members=json.loads(gzip.decompress(files["COMPLETE_MEMBER_PINS.json.gz"]))
    need(len(members)==archive["members"] and len({m["path"] for m in members})==len(members)
         and sum(m["type"]=="file" for m in members)==archive["files"]
         and sum(m.get("bytes",0) for m in members)==archive["logical_bytes"],"complete producer member accounting")
    need(evidence["archive"]==archive["zip"] if label=="aggregate" else evidence["archive"]==archive,
         "actual proof joins admitted complete producer")
    return {"label":label,"artifact":metadata,"source_manifest":source_manifest,
            "readback_files":rows,"full_guard_snapshot_entries":len(before),
            "full_guard_snapshot_bytes":sum(r["bytes"] for r in before.values() if stat.S_ISREG(r["mode"])),
            "guard_elapsed_ns":result["elapsed_ns"],"guards":12,"evidence":evidence}
def verify(inputs,plan):
    results={k:open_bundle(inputs,k,row) for k,row in plan["inputs"].items()}
    need(set(results)=={"aggregate","filesystem","regex"},"three exact closed readback domains")
    a=results["aggregate"]["evidence"];f=results["filesystem"]["evidence"];r=results["regex"]["evidence"]
    need(a["retained_actual_checks"]==405 and a["retained_recipes"]==81 and a["registered_modules"]==87
         and a["source_pins"]==2111 and a["retained_materialized_source_files"]==2877
         and a["original_index_entries"]==178275 and a["original_logical_bytes"]==26910012457
         and a["original_status"]=="FAIL" and a["v10_overall_status"]=="FAILURE"
         and a["v10_control_timeout"]["timed_out"] is True and a["v10_control_timeout"]["exit_code"]==-9
         and a["original_full_metadata_equal"] is True and a["new_executable_mappings"]==0
         and a["current_kernel_mapping_and_seals_retested"] is False and a["global_flags_raised"] is False,
         "full retained aggregate completed with exact limited reader scope")
    need(a["retained_completed_controls"]==["result-values-evidence-controls","public-registry-evidence-controls",
         "result-storage-evidence-controls"],"all previously completed controls preserved")
    need(f["source_files"]==r["source_files"]==2877 and f["sealed_artifacts"]==901
         and f["full_refusals"]==11 and f["physical_relocations"]==2 and f["foreign_path_refusals"]==12
         and f["actual_reader_calls"]==80 and f["guard_equivalence_cases"]>0
         and f["all_input_metadata_unchanged"] is f["all_copied_bytes_restored"] is True,
         "complete filesystem domain retained")
    need(r["original_refusals"]==14 and r["complete_admissions"]==6
         and r["all_input_bytes_modes_restored"] is True
         and r["original_index_entries"]==178275 and r["original_logical_bytes"]==26910012457
         and len(r["actual_metadata_changes"]["source"])==1 and len(r["actual_metadata_changes"]["capture"])==8,
         "complete original config/regex domain retained")
    for name,e in (("filesystem",f),("regex",r)):
        p=e["process"]
        need(p["kind"]==name and type(p["timeout_seconds"])is int and p["timeout_seconds"]==180
             and type(p["elapsed_ns"])is int and 0<p["elapsed_ns"]<=180000000000
             and p["exit_code"]==0 and p["timed_out"] is False and p["start_error"] is None
             and type(p["pid"])is int and p["pid"]==p["pgid"]>0 and type(p["parent_pid"])is int
             and p["parent_pid"]>0 and p["pid"]!=p["parent_pid"],"both actual unchanged child process budgets")
    return {"schema":"hepta.history.final-retained-recovery.v1","status":"RETAINED_AGGREGATE_AND_PENDING_CONTROLS_CLOSED",
      "original_status":"FAILURE","original_report":REPORT,"original_run":43944061609,
      "original_aggregate_job":133605973125,"original_artifact":14274528318,
      "original_failure_reclassified_as_pass":False,"original_source_pins_rebound":False,
      "actual_checks_retained":405,"original_recipes_retained":81,"source_pins_retained":2111,"modules_retained":87,
      "original_capture_entries":178275,"original_capture_logical_bytes":26910012457,
      "completed_controls_replayed":False,"filesystem_refusals":11,"filesystem_relocations":2,
      "filesystem_foreign_path_refusals":12,"configuration_regex_refusals":14,"configuration_regex_complete_admissions":6,
      "independent_readbacks":results,"native_or_rust_executions":0,"new_executable_mappings":0,
      "current_kernel_mapping_and_seals_retested":False,"main_branch_changed":False,
      "whole_runtime_replaced":False,"production_activated":False,"old_stack_removal_qualified":False}
def main():
    p=argparse.ArgumentParser();p.add_argument("--inputs",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();out=a.output.absolute();out.mkdir(mode=0o700,parents=True,exist_ok=False);start=time.monotonic_ns()
    package=Path(__file__).resolve().parent;plan=read_json(package/"JOIN_PLAN.json")
    gzip.decompress(gzip.compress(b"preload",mtime=0))
    for label in plan["inputs"]:
        with zipfile.ZipFile(a.inputs/(label+".zip")) as z:z.read("guarded/READBACK.json")
    diagnostics=[];result=guard.guarded(lambda:verify(a.inputs,plan),roots=[a.inputs.absolute(),package],
        foreign_path="/home/runner/work/_temp/hia-runtime-native/forbidden-original",diagnostics=diagnostics)
    need(not [d for d in diagnostics if d["phase"]=="reader"],"zero final forbidden read")
    for name in ("before","after","external_before","external_after"):
        rows=result.pop(name)
        with gzip.open(out/(name+".json.gz"),"xb",compresslevel=1) as f:f.write(encoded(rows))
    result["elapsed_ns"]=time.monotonic_ns()-start;result["reader_source"]=pin(Path(__file__))
    with (out/"FINAL_READBACK.json").open("xb") as f:f.write(encoded(result))
    with (out/"DIAGNOSTICS.json").open("xb") as f:f.write(encoded(diagnostics))
    print(json.dumps({"status":result["evidence"]["status"],"actual_checks":405,"recipes":81,"modules":87,
       "filesystem_refusals":11,"regex_refusals":14,"guards":len(result["probes"]),
       "elapsed_ns":result["elapsed_ns"],"native_or_rust_executions":0},sort_keys=True))
if __name__=="__main__":main()
