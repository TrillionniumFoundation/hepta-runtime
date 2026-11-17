#!/usr/bin/env python3
"""Read the complete filesystem continuation under a fixed no-write/no-execution guard."""
from __future__ import annotations
import argparse,ast,copy,gzip,hashlib,json,os,stat,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
import filesystem_fast_guard as fast
import read_only_guard as guard
SOURCE="/home/runner/work/_temp/hia-historical-public58"
CAPTURE="/home/runner/work/_temp/hia-runtime-native"
RUN="/home/runner/work/_temp/history-filesystem-proof/run"
REPORT={"bytes":94614535,"sha256":"6159169d8c0763d2418c8f625e5cd67099a06179f69927f7a1e62972a1eafa41"}
LABELS=["native_deadline_not_180","native_claimed_as_original_phase","original_claimed_as_native_phase",
 "duplicate_private_summary_field","resigned_private_return_mismatch","resigned_private_refusal_mutation",
 "retirement_binds_other_native_evidence","reintroduced_live_fixture","another_declared_compiler_than_actual_build",
 "unchanged_original_module_changed","missing_original_retirement"]
def need(v,s):
    if not v:raise ValueError(s)
def read(p):return json.loads(p.read_bytes())
def gz(p):
    with gzip.open(p,"rb") as f:return json.loads(f.read())
def pin(p):
    before=p.lstat();need(stat.S_ISREG(before.st_mode) and p.resolve()==p.absolute(),"ordinary retained file")
    with p.open("rb") as f:h=hashlib.file_digest(f,"sha256").hexdigest()
    after=p.lstat()
    need(all(getattr(before,k)==getattr(after,k) for k in
             ("st_mode","st_dev","st_ino","st_size","st_mtime_ns","st_ctime_ns")),"file stable through complete read")
    return {"bytes":before.st_size,"sha256":h}
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+"\n").encode()
def put(p,v):
    with p.open("xb") as f:f.write(encoded(v))
def file_table(root):
    return {p.relative_to(root).as_posix():{**pin(p),"mode":stat.S_IMODE(p.lstat().st_mode)}
            for p in root.rglob("*") if p.is_file()}
def plain_snapshot(table):
    return {k:{"bytes":v["bytes"],"sha256":v["sha256"],"mode":stat.S_IMODE(v["mode"])}
            for k,v in table.items() if stat.S_ISREG(v["mode"])}
def verify(home,prepared):
    complete=read(home/"COMPLETE_READBACK.json");members=read(home/"COMPLETE_MEMBER_PINS.json")
    need(complete["status"]=="COMPLETE_ARCHIVE_BYTES_AND_GIT_SOURCES_PASS"
         and complete["kind"]=="filesystem" and complete["continuation_status"]=="PASS"
         and complete["zip"]=={"bytes":210134590,"sha256":"fa523a6a9fcf2420253dd186754669fbb973160b585aee8ae38d06013eecb9cb"}
         and complete["inner_archive"]=={"bytes":208579480,"sha256":"e8c34b749969209b6c4aaea36367365c9d99f6d303607735bfe70de11414141f"},
         "exact actual complete continuation archive")
    extracted=home/"proof"
    actual={p.relative_to(extracted).as_posix() for p in extracted.rglob("*")}
    need(actual=={r["path"] for r in members},"entire physical extraction set")
    for row in members:
        p=extracted/row["path"];info=p.lstat()
        need(stat.S_IMODE(info.st_mode)==row["mode"],"complete extracted mode")
        if row["type"]=="file":need(pin(p)=={k:row[k] for k in ("bytes","sha256")},"complete extracted bytes")
        else:need(row["type"]=="directory" and stat.S_ISDIR(info.st_mode),"complete extracted type")
    source=extracted/"source";proof=extracted/"proof";run=proof/"run"
    manifest=read(source/"SOURCE_MANIFEST.json")
    need(pin(source/"SOURCE_MANIFEST.json")=={"bytes":3967,"sha256":"e855b02db15994d3bd015d33e246f993e249bb992baa72f9041d2785a19b9421"},
         "original executed continuation source closure")
    need(len(manifest["files"])==17 and set(file_table(source))==set(manifest["files"])|{"SOURCE_MANIFEST.json"},"whole source set")
    for name,row in manifest["files"].items():
        raw=(source/name).read_bytes()
        need(pin(source/name)=={k:row[k] for k in ("bytes","sha256")}
             and hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()==row["git_blob"],"whole Git source")
    prep=read(proof/"PREPARATION.json");result=read(run/"CONTINUATION.json")
    need(prep["status"]=="COMPLETE_SEALED_INPUT_SUBSET_PASS" and prep["source"]==SOURCE and prep["capture"]==CAPTURE
         and prep["subset_only"] is True and prep["full_aggregate_reexecuted"] is False
         and prep["source_pins_rebound"] is False and prep["native_or_rust_executions"]==0,"retained exact subset scope")
    need(prep["original_report"]==REPORT and prep["retained_full_aggregate"]==
         {"bytes":505974,"sha256":"bb7242428349b0d741a10ff67a22fcc0da49127bfe4100046b61c4d6b25b88f6"},"unchanged original evidence boundary")
    need(result["status"]=="PASS" and result["error"] is None and result["preparation"]==pin(proof/"PREPARATION.json")
         and result["source_manifest"]==pin(source/"SOURCE_MANIFEST.json")
         and result["original_aggregate_reexecuted"] is False and result["original_failure_reclassified_as_pass"] is False
         and result["native_or_rust_executions"]==0,"actual continuation completion")
    before=gz(run/"before.json.gz");after=gz(run/"after.json.gz")
    need(before==after and result["full_input_metadata_unchanged"] is True,"complete original inputs including metadata unchanged")
    hs=extracted/"historical-source";cap=extracted/"filesystem-input"
    for role,folder,key in (("source",hs,"source_files"),("capture",cap,"output_files")):
        need(file_table(folder)==prep[key]==plain_snapshot(before[role]),"entire relocated immutable input")
    need(len(prep["source_files"])==2877 and len(prep["output_files"])==902,"full materialized source and complete sealed filesystem domain")
    need(pin(cap/"result.json")==REPORT,"all original failed report bytes")
    original=read(cap/"result.json")
    need(original["status"]=="FAIL" and len(original["checks"])==405 and len(original["original_rust_comparisons"])==81,"original FAIL not relabeled")
    base={"native":original["filesystem_parity_evidence"],"retirement":original["filesystem_parity_fixture_retirement"],
          "original":original["original_rust_comparisons"]["filesystem_parity"]}
    sp=base["native"]["source_sha256"]
    ap={**base["native"]["artifact_sha256"],**base["retirement"]["artifact_sha256"],**base["original"]["artifact_sha256"]}
    need(sp==prep["sealed_source_subset"] and ap==prep["sealed_artifact_subset"] and len(sp)==30 and len(ap)==901,"all original seals")
    for label in ("moved-one","moved-two"):
        for role,pins,original_rows in (("source",sp,prep["source_files"]),("output",ap,prep["output_files"])):
            rows=file_table(run/"filesystem-controls"/label/role)
            need(set(rows)==set(pins),"exact physical relocation set")
            for name,digest in pins.items():
                need(rows[name]["sha256"]==digest and rows[name]["bytes"]==original_rows[name]["bytes"],"all physical copy bytes restored")
    process=read(run/"filesystem.process.json");audit=read(run/"filesystem.audit.json")
    output=read(run/"filesystem.stdout")
    need(result["actual_filesystem_control"]=={"process":process,"audit":audit,"original_summary":output},"actual receipts fully bound")
    need(process["schema"]=="hepta.history.skipped-control-process.v1" and process["kind"]=="filesystem"
         and process["cwd"]==SOURCE and process["original_failed_report_sha256"]==REPORT["sha256"],"control identity")
    for key in ("pid","pgid","parent_pid","parent_pgid","elapsed_ns","timeout_seconds","exit_code"):
        need(type(process[key]) is int,"integer process field")
    need(process["pid"]==process["pgid"]>0 and process["parent_pid"]>0 and process["parent_pgid"]>0
         and process["pid"]!=process["parent_pid"] and process["exit_code"]==0
         and process["timed_out"] is False and process["start_error"] is None
         and process["timeout_seconds"]==180 and 0<process["elapsed_ns"]<=180000000000,"real original deadline and reaped child")
    expected=[SOURCE+"/tests/hia_native/filesystem_parity/qualify_pipeline.py","--repo",SOURCE,"--output",CAPTURE,
              "--report",CAPTURE+"/result.json","--controls",RUN+"/filesystem-controls"]
    need(process["command"]==["/home/runner/work/_temp/hia-native-python/bin/python3","-I","-B",
          "/home/runner/work/hepta-runtime/hepta-runtime/qualification/history_aggregate_recovery/filesystem-controls-v1/run_control.py",
          "--kind","filesystem","--audit-receipt",RUN+"/filesystem.audit.json","--",*expected],"fixed actual wrapper and argv")
    need(process["original_source"]==pin(hs/"tests/hia_native/filesystem_parity/qualify_pipeline.py")
         and process["wrapper_source"]==pin(source/"run_control.py"),"both complete executed sources")
    for name in ("stdout","stderr"):
        need(process[name]==pin(run/("filesystem."+name)),"whole child stream")
    need((run/"filesystem.stderr").read_bytes()==b"" and output==read(run/"filesystem-controls/RESULT.json"),"actual stdout/empty stderr/summary")
    need(audit["status"]=="PASS" and audit["error"] is None and audit["kind"]=="filesystem" and audit["argv"]==expected
         and audit["pid"]==process["pid"] and audit["parent_pid"]==process["parent_pid"] and audit["pgid"]==process["pgid"]
         and audit["native_or_rust_executions"]==0 and audit["guard_probes"]==["process","native-map","native-library"]
         and audit["execution_attempts"]==[{"event":"subprocess.Popen","probe":True},{"event":"mmap.__new__","probe":True},
                                          {"event":"ctypes.dlopen","probe":True}],"actual no-execution audit")
    need(output["status"]=="PASS" and output["controls"]==11 and [r["name"] for r in output["events"]]==LABELS
         and all(r["status"]=="REJECTED" and r["message"] and r["elapsed_seconds"]>=0 for r in output["events"])
         and output["physical_relocations"]==2 and output["actual_foreign_path_refusals"]==12
         and output["all_source_and_artifacts_unchanged"] is True and output["copied_live_fixtures"] is False
         and output["source_files"]==30 and output["artifacts"]==901
         and output["producer_paths_blocked_during_relocation"] is True
         and output["new_native_calls"]==output["new_rust_processes"]==output["new_processes"]==0
         and output["whole_runtime_replaced"] is output["public_filesystem_handlers_complete"] is False,"all original controls retained")
    baseline_raw=json.dumps(base,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode()
    need(output["baseline_sha256"]==hashlib.sha256(baseline_raw).hexdigest(),"complete original native/original/retirement seal")
    probes=output["foreign_path_refusals"];expected_probes=[]
    for label,other in (("moved-one","moved-two"),("moved-two","moved-one")):
        targets=[SOURCE+"/"+sorted(sp)[0],CAPTURE+"/"+sorted(ap)[0],
                 RUN+"/filesystem-controls/"+other+"/output/"+sorted(ap)[0]]
        for target in targets:
            for operation in ("open","stat"):expected_probes.append({"path":target,"operation":operation,"status":"REJECTED"})
    need(probes==expected_probes,"all 12 exact producer/other-copy refusals")
    changed,binding,eq=prepared
    need((run/"filesystem-control-adapted.py").read_bytes()==changed
         and read(run/"FILESYSTEM_GUARD_BINDING.json")==binding,"only declared guard AST was replaced")
    observed=read(run/"GUARD_EQUIVALENCE.json")
    need(result["guard_equivalence"]==pin(run/"GUARD_EQUIVALENCE.json"),"complete guard-equivalence evidence")
    need({k:v for k,v in observed.items() if k not in ("old_guard_ns","new_guard_ns")}==eq,"every independent guard equivalence row")
    adapter=audit["filesystem_guard_adapter"]
    need({k:adapter[k] for k in binding}==binding and adapter["coarse_call_observer_only"] is True
         and adapter["qualifier_source_sha256"]==fast.QUALIFIER_SHA
         and adapter["journal"]==pin(run/"filesystem-reader-calls.jsonl"),"fixed timing observer")
    stack=[];begins={};ends={};events=[json.loads(line) for line in (run/"filesystem-reader-calls.jsonl").read_bytes().splitlines()]
    for row in events:
        seq=row["sequence"];need(type(seq)is int and seq>0 and row["pid"]==process["pid"],"journal PID/sequence")
        if row["event"]=="begin":
            need(seq==len(begins)+1 and row["parent_sequence"]==(stack[-1] if stack else None)
                 and row["name"] in fast.TIMED and row["module_sha256"]==fast.QUALIFIER_SHA,"exact FIFO begin")
            home=SOURCE if row["module"].startswith(SOURCE+"/") else row["module"].split("/source/")[0]+"/source"
            need(home in (SOURCE,RUN+"/filesystem-controls/moved-one/source",RUN+"/filesystem-controls/moved-two/source")
                 and row["module"]==home+"/scripts/hia_native_filesystem_parity_qualification.py","bound qualifier location")
            begins[seq]=row;stack.append(seq)
        else:
            need(row["event"]=="end" and stack and stack.pop()==seq and row["name"]==begins[seq]["name"]
                 and row["parent_sequence"]==begins[seq]["parent_sequence"] and type(row["elapsed_ns"])is int
                 and row["elapsed_ns"]>=0 and seq not in ends,"complete nested end")
            ends[seq]=row
    need(not stack and len(begins)==len(ends)==adapter["actual_reader_calls"]==80,"every actual original reader call completed")
    need(result["input_entries"]==sum(map(len,before.values()))
         and result["input_files"]==sum(len(plain_snapshot(t)) for t in before.values())
         and result["input_bytes"]==sum(r["bytes"] for t in before.values() for r in t.values() if stat.S_ISREG(r["mode"])),"entire immutable input extent")
    return {"schema":"hepta.history.filesystem-continuation-independent.v1","status":"COMPLETE_FILESYSTEM_CONTINUATION_READBACK_PASS",
            "archive":complete,"original_report":REPORT,"source_files":2877,"sealed_artifacts":901,
            "full_refusals":11,"physical_relocations":2,"foreign_path_refusals":12,
            "guard_equivalence_cases":observed["cases"],"actual_reader_calls":len(begins),
            "process":process,"all_input_metadata_unchanged":True,"all_copied_bytes_restored":True,
            "original_failure_reclassified_as_pass":False,"native_or_rust_executions":0}
def main():
    parser=argparse.ArgumentParser();parser.add_argument("--readback",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True);args=parser.parse_args()
    out=args.output.absolute();out.mkdir(mode=0o700,parents=True,exist_ok=False)
    home=args.readback.absolute();historical=home/"proof/historical-source/tests/hia_native/filesystem_parity/qualify_pipeline.py"
    changed,binding,_=fast.transformed(historical);eq=fast.equivalence(historical)
    eq={k:v for k,v in eq.items() if k not in ("old_guard_ns","new_guard_ns")}
    eq=json.loads(encoded(eq))
    prepared=(changed.encode(),binding,eq)
    gzip.decompress(gzip.compress(b"preload",mtime=0))
    diagnostics=[];start=time.monotonic_ns()
    result=guard.guarded(lambda:verify(home,prepared),roots=[home,Path(__file__).resolve().parent],
                          foreign_path="/home/runner/work/_temp/hia-historical-public58/unadmitted",diagnostics=diagnostics)
    need(not [r for r in diagnostics if r["phase"]=="reader"],"zero swallowed guarded refusal")
    for name in ("before","after","external_before","external_after"):
        value=result.pop(name)
        with gzip.open(out/(name+".json.gz"),"xb",compresslevel=1) as stream:stream.write(encoded(value))
    result["elapsed_ns"]=time.monotonic_ns()-start;result["guard_source"]=pin(Path(guard.__file__))
    put(out/"READBACK.json",result);put(out/"DIAGNOSTICS.json",diagnostics)
    print(json.dumps({"status":result["evidence"]["status"],"guards":len(result["probes"]),
         "elapsed_ns":result["elapsed_ns"],"full_refusals":11,"relocations":2,"foreign_paths":12,
         "native_or_rust_executions":0},sort_keys=True))
if __name__=="__main__":main()
