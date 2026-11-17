#!/usr/bin/env python3
"""Bind completed readback and skipped controls to the unchanged old evidence."""
from __future__ import annotations
import argparse,gzip,hashlib,json,os,stat,sys,time,zipfile
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import read_only_guard as guard
from read_recovered import SOURCE,CAPTURE,COMPILER,REPORT_SHA,need,pin,put,sha,encoded
from restore_archive import INDEX_MEMBER,INDEX_MEMBER_SHA,INDEX_BYTES,INDEX_SHA,FILES,DIRECTORIES,LOGICAL_BYTES
from run_skipped import FS_LABELS,REGEX_LABELS
def read_json(path):return json.loads(path.read_bytes())
def semantic_snapshot(value):
 result={}
 for key,row in value.items():
  result[key]={"mode":row["mode"],"sha256":row["sha256"]}
  if row["sha256"] is not None:result[key]["bytes"]=row["bytes"]
 return result
def main():
 p=argparse.ArgumentParser();p.add_argument("--output",type=Path,required=True);p.add_argument("--index-zip",type=Path,required=True);a=p.parse_args()
 out=a.output.absolute();started=time.monotonic_ns()
 restoration=read_json(out/"RESTORATION.json");readback=read_json(out/"reader/READBACK.json")
 skipped=read_json(out/"skipped/SKIPPED_CONTROLS.json");preflight=read_json(out/"PREFLIGHT.json")
 need(restoration["status"]=="COMPLETE_RESTORED_BYTES_AND_MODES_PASS" and restoration["files"]==FILES
  and restoration["directories"]==DIRECTORIES and restoration["logical_bytes"]==LOGICAL_BYTES,"complete restoration proof")
 need(readback["evidence"]["status"]=="COMPLETE_RETAINED_AGGREGATE_READBACK_PASS"
  and readback["evidence"]["original_status"]=="FAIL" and readback["evidence"]["actual_checks"]==405
  and readback["evidence"]["recipes"]==81 and readback["evidence"]["source_pins_rebound"] is False
  and readback["reader_writes"]==readback["native_or_rust_executions"]==0
  and len(readback["probes"])==12,"complete unchanged aggregate reader proof")
 with gzip.open(out/"reader/before.json.gz","rb") as f:before=json.load(f)
 with gzip.open(out/"reader/after.json.gz","rb") as f:after=json.load(f)
 need(before==after and len(before)==readback["full_snapshot_entries"],"full actual read-only snapshots")
 with gzip.open(out/"reader/external_before.json.gz","rb") as f:external_before=json.load(f)
 with gzip.open(out/"reader/external_after.json.gz","rb") as f:external_after=json.load(f)
 need(external_before==external_after and len(external_before)==readback["external_snapshot_entries"],"complete external read pins")
 need(skipped["status"]=="PASS" and skipped["original_completed_controls_rerun"] is False
  and skipped["native_or_rust_executions"]==0,"only previously skipped controls")
 for kind in ("filesystem","regex"):
  item=skipped[kind];process=read_json(out/"skipped"/(kind+".process.json"))
  audit=read_json(out/"skipped"/(kind+".audit.json"))
  stdout=(out/"skipped"/(kind+".stdout")).read_bytes();stderr=(out/"skipped"/(kind+".stderr")).read_bytes()
  need(process==item["process"] and audit==item["audit"]
   and json.loads(stdout)==item["original_summary"] and stderr==b""
   and pin(out/"skipped"/(kind+".stdout"))==process["stdout"]
   and pin(out/"skipped"/(kind+".stderr"))==process["stderr"],"full actual control streams and receipts")
  need(type(process["pid"]) is int and process["pid"]>0 and process["pgid"]==process["pid"]
   and type(process["elapsed_ns"]) is int and 0<process["elapsed_ns"]<=180000000000
   and process["timeout_seconds"]==180 and process["exit_code"]==0 and process["timed_out"] is False
   and process["start_error"] is None and audit["status"]=="PASS"
   and audit["pid"]==process["pid"] and audit["parent_pid"]==process["parent_pid"]
   and audit["pgid"]==process["pgid"] and audit["argv"]==process["command"][9:]
   and audit["native_or_rust_executions"]==0,"actual unchanged 180-second control custody")
 fs=skipped["filesystem"]["original_summary"];re=skipped["regex"]["original_summary"]
 need(fs["controls"]==11 and [x["name"] for x in fs["events"]]==FS_LABELS
  and fs["actual_foreign_path_refusals"]==12 and fs["physical_relocations"]==2,"all filesystem control domains")
 need(re["negative_control_count"]==14 and [x["name"] for x in re["negative_controls"]]==REGEX_LABELS
  and re["actual_baseline_admissions"]==6,"all configuration/regex control domains")
 need(preflight["status"]=="PASS" and preflight["prefix_regressions"]==8
  and len(preflight["mechanical_refusals"])==6 and len(preflight["guard_refusals"])==12
  and preflight["descriptor_complete_reads"]==2 and [row["name"] for row in preflight["descriptor_refusals"]]==[
   "directory-no-follow-required","foreign-directory","preexisting-directory-descriptor",
   "relative-parent-escape","replaced-directory-descriptor","relative-descriptor-write"],"frozen source controls")
 need(pin(CAPTURE/"result.json")["sha256"]==REPORT_SHA,"original failed report bytes")
 report=read_json(CAPTURE/"result.json")
 need(report["status"]=="FAIL" and len(report["checks"])==405 and len(report["original_rust_comparisons"])==81,"old failure and complete process set retained")
 code=read_json(out/"reader/STATIC_CODE_ADMISSION.json")
 code_controls=preflight["static_code_controls"]
 need(pin(out/"reader/STATIC_CODE_ADMISSION.json")==readback["static_code_admission"]
  and code["source"]==str(SOURCE) and code["output"]==str(CAPTURE)
  and code["prefix"]==code_controls["prefix"]
  and code["prefix"]["loader_sha256"]=="58e2fe0492379340d7471a7857e1aa5de1a9a5d1e37a118852278b131bb1fe06"
  and code["execution_attempts"]==[] and code["new_executable_mappings"]==0
  and code["native_or_rust_executions"]==0 and code["kernel_mapping_and_seals_retested"] is False
  and code_controls["status"]=="PASS" and len(code_controls["refusals"])==25
  and code_controls["complete_static_admissions"]==1
  and code_controls["early_and_late_alias_restoration"] is True,"exact static loader admission and controls")
 table=[]
 for key,row in sorted(report["modules"].items()):
  actual=before["0:"+row["manifest"]]
  need(actual["sha256"]==row["sha256"],"registered module snapshot identity")
  table.append({"key":key,"manifest":row["manifest"],"bytes":actual["bytes"],"sha256":actual["sha256"]})
 need(len(table)==87 and table==code["registered_modules"]
  and len(code["admissions"])==readback["evidence"]["static_code_admissions"]>0,
  "all registered modules and actual static constructor admissions")
 for row in code["admissions"]:
  need(row["new_executable_mapping"] is False,"no new executable mapping")
  for field in ("manifest","source","image"):
   actual=before["0:"+row[field]]
   need(actual["bytes"]==row[field+"_bytes"] and actual["sha256"]==row[field+"_sha256"],
    "complete admitted module byte span: "+field)
  need(row["source_sha256"]==row["metadata"]["source_sha256"]
   and row["image_sha256"]==row["metadata"]["image_sha256"],"retained source and image identities")
 # Original negative controls restore bytes/modes; their expected ctime/mtime
 # changes are explicitly distinct from the earlier strictly read-only phase.
 final=guard.snapshot([CAPTURE,SOURCE,COMPILER])
 need(semantic_snapshot(final)==semantic_snapshot(before),"complete source/capture bytes or modes not restored")
 with gzip.open(out/"POST_CONTROLS_COMPLETE_SNAPSHOT.json.gz","xb",compresslevel=1) as f:f.write(encoded(final))
 need(pin(a.index_zip)=={"bytes":INDEX_BYTES,"sha256":INDEX_SHA},"retained complete index ZIP")
 with zipfile.ZipFile(a.index_zip) as archive:
  packed=archive.read(INDEX_MEMBER);need(sha(packed)==INDEX_MEMBER_SHA,"complete frozen member index")
  count=0;total=0
  for line in gzip.decompress(packed).splitlines():
   row=json.loads(line);observed=final["0:"+row["path"]]
   need(stat.S_IMODE(observed["mode"])==row["mode"],"original restored mode after controls")
   if row["type"]=="0":
    need(observed["bytes"]==row["data"]["bytes"] and observed["sha256"]==row["data"]["sha256"],"original entire file after controls")
    total+=row["data"]["bytes"]
   else:need(row["type"]=="5" and stat.S_ISDIR(observed["mode"]),"original directory after controls")
   count+=1
 need(count==FILES+DIRECTORIES and total==LOGICAL_BYTES,"every original indexed member remained")
 changed=[k for k in before if final[k]!=before[k]]
 files={}
 for path in sorted(out.rglob("*")):
  if path.is_file():files[path.relative_to(out).as_posix()]=pin(path)
 result={"schema":"hepta.history.aggregate-recovery.v1","status":"RETAINED_AGGREGATE_AND_SKIPPED_CONTROLS_PASS",
  "original_run":43944061609,"original_head":"08ce7b6fdfda64aa382e3238a1547c5e379f156a",
  "original_artifact":14274528318,"original_aggregate_status":"FAILURE",
  "original_failure_reclassified_as_pass":False,"source_pins_rebound":False,
  "retained_actual_checks":405,"retained_original_recipes":81,"retained_source_pins":len(report["source_sha256"]),
  "retained_aggregate_controls_rerun":False,"previously_skipped_control_processes":2,
  "filesystem_control_refusals":11,"filesystem_foreign_path_refusals":12,"filesystem_physical_relocations":2,
  "configuration_regex_refusals":14,"configuration_regex_complete_admissions":6,
  "native_or_rust_executions":0,"all_original_bytes_and_modes_unchanged":True,
  "static_code_admissions":len(code["admissions"]),"registered_module_bindings":87,
  "static_code_refusals":25,"new_executable_mappings":0,
  "current_kernel_mapping_and_seals_retested":False,
  "original_report_sha256":REPORT_SHA,"read_only_phase_full_metadata_unchanged":True,
  "negative_control_phase_metadata_differences":changed,"source":pin(HERE/"SOURCE_MANIFEST.json"),
  "proof_files":files,"elapsed_ns":time.monotonic_ns()-started,
  "whole_runtime_replaced":False,"production_activated":False,"old_stack_removal_qualified":False}
 put(out/"FINAL.json",result)
 print(json.dumps({k:v for k,v in result.items() if k not in ("proof_files","negative_control_phase_metadata_differences")},sort_keys=True))
if __name__=="__main__":main()
