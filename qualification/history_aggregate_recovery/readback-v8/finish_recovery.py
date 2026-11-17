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
from source_reconstruction import FILES as REBUILT_FILES,DIRECTORIES as REBUILT_DIRECTORIES,OPERATIONS as REBUILT_OPERATIONS,PINS as REBUILT_PINS,CALLERS as REBUILT_CALLERS
from source_reconstruction_controls import NAMES as REBUILT_CONTROL_NAMES
import retained_writebacks as schema_writes
from retained_writeback_controls import NAMES as SCHEMA_CONTROL_NAMES
import runtime_library_reads as libraries
from runtime_library_controls import NAMES as LIBRARY_CONTROL_NAMES
import reference_environment_reads as environment_reads
from reference_environment_controls import NAMES as ENVIRONMENT_CONTROL_NAMES
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
 rebuilt=read_json(out/"reader/SOURCE_RECONSTRUCTION.json")
 rebuild_controls=preflight["source_reconstruction_controls"]
 need(pin(out/"reader/SOURCE_RECONSTRUCTION.json")==readback["source_reconstruction"]
  and rebuilt["source"]==str(SOURCE) and rebuilt["output"]==str(CAPTURE)
  and rebuilt["crate"]==str(CAPTURE/"view-call-original/crate")
  and rebuilt["expected_files"]==list(REBUILT_FILES) and rebuilt["expected_directories"]==list(REBUILT_DIRECTORIES)
  and rebuilt["expected_callers"]==[list(row) for row in REBUILT_CALLERS]
  and rebuilt["violations"]==[] and rebuilt["active_reconstruction"] is False
  and rebuilt["new_file_writes"]==rebuilt["native_or_rust_executions"]==0
  and rebuilt["original_materialize_function_modified"] is False and rebuilt["materialization_summary_cached"] is False,
  "exact complete read-only source regeneration")
 for name,identity in rebuilt["source_files"].items():
  expected=before["1:"+name]
  need(name in REBUILT_PINS and identity=={"bytes":expected["bytes"],"sha256":expected["sha256"]}
   and (identity["bytes"],identity["sha256"])==REBUILT_PINS[name],"unchanged original materializer/caller bytes")
 need(set(rebuilt["source_files"])==set(REBUILT_PINS),"complete materializer source bindings")
 for name,identity in rebuilt["initial_inventory"].items():
  suffix="" if name=="." else "/"+name
  need(identity==before["0:view-call-original/crate"+suffix],"complete captured crate bytes and metadata")
 need(set(rebuilt["initial_inventory"])==set(REBUILT_FILES)|set(REBUILT_DIRECTORIES)
  and len(rebuilt["records"])==readback["evidence"]["source_reconstructions"]>0,"all source reconstructions recorded")
 need({(row["caller_source"],row["caller_function"],row["temporary_prefix"]) for row in rebuilt["records"]}==set(REBUILT_CALLERS),
  "both complete original source-reconstruction callers actually ran")
 for row in rebuilt["records"]:
  need(row["status"]=="PASS" and row["error"] is None and row["crate"]==rebuilt["crate"]
   and row["temporary_path"]==str(CAPTURE/"view-call-original")
   and (row["caller_source"],row["caller_function"],row["temporary_prefix"]) in REBUILT_CALLERS
   and [(item["operation"],item["path"]) for item in row["operations"]]==list(REBUILT_OPERATIONS),
   "every original materialize operation preserved")
  for item in row["operations"]:
   need(item["physical_writes"]==0,"no materializer filesystem write")
   if item["operation"]!="mkdir":
    expected=before["0:view-call-original/crate/"+item["path"]]
    need(item["complete_bytes"]=={"bytes":expected["bytes"],"sha256":expected["sha256"]},"entire regenerated original file")
    if item["operation"]=="copyfile":
     name="tests/hia_native/view_call_oracle/"+item["path"];source=before["1:"+name]
     need(item["source"]==str(SOURCE/name) and item["complete_bytes"]=={"bytes":source["bytes"],"sha256":source["sha256"]},"original Cargo copy source")
 need(rebuild_controls["status"]=="PASS" and rebuild_controls["complete_generator_admissions"]==4
  and rebuild_controls["exact_caller_prefix_pairs"]==[list(row) for row in REBUILT_CALLERS]
  and rebuild_controls["generated_files_per_admission"]==7 and rebuild_controls["operations_per_admission"]==10
  and [row["name"] for row in rebuild_controls["refusals"]]==REBUILT_CONTROL_NAMES
  and rebuild_controls["early_and_late_alias_restoration"] is True
  and rebuild_controls["native_or_rust_executions"]==0 and rebuild_controls["execution_attempts"]==[]
  and rebuild_controls["original_materialize_function_modified"] is False,"all complete source reconstruction controls")
 schemas=read_json(out/"reader/RETAINED_SCHEMA_WRITES.json");schema_controls=preflight["retained_schema_controls"]
 need(pin(out/"reader/RETAINED_SCHEMA_WRITES.json")==readback["retained_schema_writes"]
  and schemas["source"]==str(SOURCE) and schemas["output"]==str(CAPTURE)
  and schemas["folder"]==str(CAPTURE/"view-call-original")
  and schemas["input_name"]==schema_writes.INPUT and schemas["output_names"]==list(schema_writes.OUTPUTS)
  and schemas["physical_writes"]==schemas["native_or_rust_executions"]==0
  and schemas["pending_operations"]==[] and schemas["pending_frame"] is False and schemas["violations"]==[]
  and schemas["original_summary_function_modified"] is False and schemas["summary_result_cached"] is False,
  "complete unchanged summary with only retained schema comparisons")
 need(set(schemas["source_files"])==set(schema_writes.PINS),"all retained summary source bindings")
 for name,row in schemas["source_files"].items():
  expected=before["1:"+name]
  need(row=={"bytes":expected["bytes"],"sha256":expected["sha256"]}
   and (row["bytes"],row["sha256"])==schema_writes.PINS[name],"exact unchanged summary source")
 need(set(schemas["initial_inventory"])=={schema_writes.INPUT,*schema_writes.OUTPUTS},"complete schema input/output inventory")
 for name,row in schemas["initial_inventory"].items():
  need(row==before["0:view-call-original/"+name],"complete schema input/output bytes and metadata")
 need(len(schemas["records"])==readback["evidence"]["retained_schema_pairs"]>0,"actual retained schema comparison pairs")
 for row in schemas["records"]:
  need(row["status"]=="PASS" and row["folder"]==schemas["folder"]
   and (row["caller_source"],row["caller_function"])==schema_writes.CALLER
   and (row["parent_source"],row["parent_function"])==schema_writes.PARENT
   and [item["path"] for item in row["operations"]]==list(schema_writes.OUTPUTS),"exact original summary write order/callers")
  for item in row["operations"]:
   expected=before["0:view-call-original/"+item["path"]];incoming=before["0:view-call-original/"+schema_writes.INPUT]
   need(item["operation"]=="write_bytes" and item["physical_writes"]==0
    and item["complete_bytes"]=={"bytes":expected["bytes"],"sha256":expected["sha256"]}
    and item["input_stream"]=={"bytes":incoming["bytes"],"sha256":incoming["sha256"]},"full original schema input/output spans")
 need(schema_controls["status"]=="PASS" and schema_controls["complete_pair_admissions"]==2
  and schema_controls["complete_files_per_pair"]==2 and [row["name"] for row in schema_controls["refusals"]]==SCHEMA_CONTROL_NAMES
  and schema_controls["early_and_late_alias_restoration"] is True and schema_controls["execution_attempts"]==[]
  and schema_controls["native_or_rust_executions"]==0 and schema_controls["original_summary_function_modified"] is False,
  "all retained schema comparison controls")
 binding=readback["runtime_libraries"];library_controls=preflight["runtime_library_controls"]
 need(binding["schema"]=="hepta.history.runtime-library-admission.v1" and binding["status"]=="PASS"
  and binding["source"]==str(SOURCE) and binding["output"]==str(CAPTURE)
  and binding["manifest_path"]==libraries.MANIFEST
  and binding["manifest_identity"]==before["0:"+libraries.MANIFEST]
  and binding["current_files_read_completely"]==binding["retained_files_read_completely"]==2
  and binding["paths_rewritten"] is False and binding["library_loads"]==binding["native_or_rust_executions"]==0
  and binding["original_build_reader_modified"] is False,"two original complete runtime library admissions")
 need(binding==libraries.admit(SOURCE,CAPTURE,report),"same two actual libraries after skipped controls")
 need(binding["source_files"]=={name:{"bytes":value[0],"sha256":value[1]} for name,value in libraries.PINS.items()},
  "exact original library reader source")
 need([row["role"] for row in binding["files"]]==[row[0] for row in libraries.ROLES],"exact library roles")
 for row in binding["files"]:
  expected=before["0:"+row["retained_path"]];external=external_before[row["path"]]
  need(row["retained_identity"]==expected and row["pin"]=={"size":expected["bytes"],"sha256":expected["sha256"]},
   "complete retained library bytes and metadata")
  need(external["absent"] is False and external["resolved"]==row["path"]
   and external["sha256"]==row["pin"]["sha256"]
   and {key:external["target"][key] for key in row["current_identity"] if key!="sha256"}==
       {key:value for key,value in row["current_identity"].items() if key!="sha256"}
   and row["current_identity"]["sha256"]==external["sha256"],"complete current library external snapshot")
 need(library_controls["schema"]=="hepta.history.runtime-library-controls.v1" and library_controls["status"]=="PASS"
  and [row["name"] for row in library_controls["refusals"]]==LIBRARY_CONTROL_NAMES
  and library_controls["complete_admissions"]==len(library_controls["admissions"])==2
  and library_controls["complete_library_files_per_admission"]==2
  and library_controls["test_owned_library_bytes_not_executed"] is True
  and library_controls["library_loads"]==library_controls["native_or_rust_executions"]==0
  and library_controls["execution_attempts"]==[],"all runtime library controls")
 for row in library_controls["admissions"]:
  controlled=row["guard"]
  need(controlled["before"]==controlled["after"] and controlled["external_before"]==controlled["external_after"]
   and controlled["evidence"]==row["binding"] and len(controlled["probes"])==12
   and controlled["reader_writes"]==controlled["native_or_rust_executions"]==0,
   "complete guarded runtime library control admission")
 environment=readback["reference_environment"];environment_controls=preflight["reference_environment_controls"]
 need(environment==environment_reads.admit(SOURCE,CAPTURE,report),"all original reference environment bytes and identities unchanged")
 need(environment["schema"]=="hepta.history.reference-environment-admission.v1" and environment["status"]=="PASS"
  and environment["source"]==str(SOURCE) and environment["output"]==str(CAPTURE)
  and environment["source_files"]=={name:{"bytes":source_row[0],"sha256":source_row[1]} for name,source_row in environment_reads.SOURCES.items()}
  and [row["key"] for row in environment["reports"]]==list(environment_reads.KEYS)
  and environment["paths_rewritten"] is False and environment["library_loads"]==environment["native_or_rust_executions"]==0
  and environment["original_reference_readers_modified"] is False and environment["qualification_summary_cached"] is False,
  "exact source-bound reference dependency admission")
 need(environment["external_files"]==[row["path"] for row in environment["files"]]
  and len(set(environment["external_files"]))==len(environment["files"]),"complete exact external dependency path set")
 for row in environment["files"]:
  actual=external_before[row["path"]]
  need(actual["absent"] is False and actual["resolved"]==row["resolved_path"]
   and actual["logical"]==row["logical"] and actual["target"]==row["target"]
   and row["pin"]=={"bytes":actual["target"]["bytes"],"sha256":actual["sha256"]},
   "every external dependency complete bytes and metadata match both read-only snapshots")
 for row in environment["retained_files"]:
  saved=before["0:"+row["path"]]
  need(row["pin"]=={"bytes":saved["bytes"],"sha256":saved["sha256"]},"all retained dynamic library/config bytes")
 expected_reports={libraries.MANIFEST}|{row["path"] for row in environment["reports"]}
 need(set(readback["retained_dependency_reports"])==expected_reports,"exact five full original dependency reports")
 for relative,row in readback["retained_dependency_reports"].items():
  need(row["path"]=="retained-input-reports/"+relative,"fixed copied original dependency report path")
  raw=(out/"reader"/row["path"]).read_bytes();saved=before["0:"+relative]
  need(row["pin"]==pin(out/"reader"/row["path"])=={"bytes":saved["bytes"],"sha256":saved["sha256"]}
   and raw==(CAPTURE/relative).read_bytes(),"entire original dependency report copy")
 need(environment_controls["schema"]=="hepta.history.reference-environment-controls.v1"
  and environment_controls["status"]=="PASS"
  and environment_controls["complete_admissions"]==len(environment_controls["admissions"])==2
  and environment_controls["complete_reference_reports_per_admission"]==4
  and [row["name"] for row in environment_controls["refusals"]]==ENVIRONMENT_CONTROL_NAMES
  and environment_controls["test_owned_dependency_bytes_not_executed"] is True
  and environment_controls["library_loads"]==environment_controls["native_or_rust_executions"]==0,
  "complete exact reference dependency controls")
 for row in environment_controls["admissions"]:
  g=row["guard"]
  need(g["before"]==g["after"] and g["external_before"]==g["external_after"]
   and g["evidence"]==row["binding"] and len(g["probes"])==12
   and g["reader_writes"]==g["native_or_rust_executions"]==0,"complete guarded reference dependency admission")
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
  "source_reconstructions":len(rebuilt["records"]),"source_reconstruction_refusals":18,
  "source_reconstruction_file_writes":0,"original_materialize_function_modified":False,
  "retained_schema_pairs":len(schemas["records"]),"retained_schema_refusals":10,
  "retained_schema_physical_writes":0,"original_summary_function_modified":False,
  "current_runtime_library_files":2,"runtime_library_refusals":13,"library_loads":0,
  "reference_environment_files":len(environment["files"]),"reference_environment_reports":4,
  "reference_environment_refusals":16,"reference_environment_report_copies":5,
  "original_report_sha256":REPORT_SHA,"read_only_phase_full_metadata_unchanged":True,
  "negative_control_phase_metadata_differences":changed,"source":pin(HERE/"SOURCE_MANIFEST.json"),
  "proof_files":files,"elapsed_ns":time.monotonic_ns()-started,
  "whole_runtime_replaced":False,"production_activated":False,"old_stack_removal_qualified":False}
 put(out/"FINAL.json",result)
 print(json.dumps({k:v for k,v in result.items() if k not in ("proof_files","negative_control_phase_metadata_differences")},sort_keys=True))
if __name__=="__main__":main()
