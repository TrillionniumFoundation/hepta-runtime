"""Pure final proof over unchanged original captures and the first physical controls."""
from pathlib import Path
from evidence_common import decode,encoded,owned,pin,require,source_evidence
from read_build_evidence import tree,saved_guard
from read_controls import controls
import read_origin,read_capture
NAMES=["source-check","semantic-fetch","semantic-unpack","build-fetch","build-unpack","origin-read","full-read","physical-controls"]
LIMITS=[60,60,180,60,180,180,180,180]
def argument(row,name):return row["argv"][row["argv"].index("--"+name)+1]
def process_rows(folder,names,limits):
    rows=decode(owned(folder,"processes.json").read_bytes())
    require([r["name"] for r in rows]==names,"exact frozen pure process prefix")
    values={};files={"processes.json"}
    for row,limit in zip(rows,limits):
        require(row["pid"]==row["pgid"] and row["pid"]>0 and row["parent_pid"]>0
            and row["exit_code"]==0 and row["timed_out"] is False and row["completed"] is True
            and row["timeout_seconds"]==limit and 0<=row["elapsed_seconds"]<limit and row["stdin"] is None,
            "actual natural bounded pure process")
        for suffix in ("stdout","stderr"):
            name=row["name"]+"."+suffix;files.add(name);part=row[suffix]
            require(part["file"]==name and pin(owned(folder,name))=={k:part[k] for k in ("bytes","sha256")},
                "all pure process streams")
        require(row["stderr"]["bytes"]==0,"no hidden pure process error")
        values[row["name"]]=decode((folder/row["stdout"]["file"]).read_bytes())
    require({p.name for p in folder.iterdir()}==files,"complete frozen pure process stream set")
    return rows,values
def verify(reader,semantic,reuse,frozen,group):
    reader,semantic,reuse,frozen=map(Path,(reader,semantic,reuse,frozen))
    identity=source_evidence(reader);prefix=frozen/"proof_inputs";rows,values=process_rows(prefix/"processes",NAMES,LIMITS)
    decode(owned(prefix,"ENVIRONMENT.json").read_bytes())
    require({p.name for p in prefix.iterdir()}=={"processes","ENVIRONMENT.json"},"immutable proof input inventory")
    require(values["source-check"]["status"]=="PURE_FILESYSTEM_RECOVERY_SOURCE_PASS"
        and values["source-check"]["source"]==identity and values["source-check"]["new_original_or_native_applications"]==0,
        "complete recovery source admission")
    for name in ("semantic-fetch","semantic-unpack","build-fetch","build-unpack"):
        require(values[name]["status"]=="PASS" and values[name]["native_or_rust_executions"]==0,"pure complete archive stage")
    origin=read_origin.verify(reader,semantic,reuse,group)
    source=semantic/"original/restored/source";capture=semantic/"original/restored/run";data=capture/"application"
    origin_guard=values["origin-read"];require(origin_guard["evidence"]==origin,"full original custody result")
    source_origin=argument(rows[5],"reader");semantic_origin=Path(argument(rows[5],"semantic"));reuse_origin=Path(argument(rows[5],"reuse"))
    guard_files=saved_guard(origin_guard,{source_origin:tree(reader),
        str(semantic_origin/"original"):tree(semantic/"original"),str(semantic_origin/"download"):tree(semantic/"download"),
        str(reuse_origin/"original"):tree(reuse/"original"),str(reuse_origin/"download"):tree(reuse/"download")})
    actual=read_capture.verify(source,data,group)
    primary=decode(owned(frozen,"READONLY.json").read_bytes())
    require(primary==values["full-read"] and primary["evidence"]==actual,"same completed applications full reader")
    guard_files+=saved_guard(primary,{argument(rows[6],"source"):tree(source),argument(rows[6],"data"):tree(data)})
    physical,control_files=controls(source,data,frozen,actual,values["physical-controls"],argument(rows[7],"output"),argument(rows[7],"source"));guard_files+=control_files
    require(physical==values["physical-controls"],"all complete physical-control returned values")
    require(actual["cases"]==origin["completed_original"]["cases"]==origin["completed_native"]["cases"]
        and actual["original"]["entry_invocations"]==origin["completed_original"]["calls"]
        and actual["native"]["entry_invocations"]==origin["completed_native"]["calls"],"zero application replay")
    require({p.name for p in frozen.iterdir()}=={"READONLY.json","controls","proof_inputs"},"complete frozen recovery evidence")
    return dict(status="COMPLETE_SAME_CAPTURE_FILESYSTEM_RECOVERY_PASS",group=group,reader_source=identity,
        original_custody=origin,actual=actual,physical_refusals=8,full_relocations=2,
        retained_recovery_guard_invocations=12,retained_recovery_guard_probes=132,
        retained_full_guard_file_references=guard_files,source_change=pin(reader/"READER_CHANGE.json"),
        original_failure_preserved=True,new_original_or_native_applications=0,public_routes_qualified=False,whole_runtime_replaced=False)
def completed(reader,semantic,reuse,capture,group):
    reader,semantic,reuse,capture=map(Path,(reader,semantic,reuse,capture))
    actual=verify(reader,semantic,reuse,capture/"frozen",group)
    rows,values=process_rows(capture/"processes",NAMES+["final-read"],LIMITS+[180])
    prefix=decode((capture/"frozen/proof_inputs/processes/processes.json").read_bytes())
    require(rows[:8]==prefix,"immutable pre-final process prefix retained")
    for row in rows[:8]:
        for suffix in ("stdout","stderr"):
            name=row[suffix]["file"]
            require((capture/"processes"/name).read_bytes()==(capture/"frozen/proof_inputs/processes"/name).read_bytes(),
                "exact complete prefix stream retention")
    final=decode(owned(capture,"FINAL_READONLY.json").read_bytes())
    require(values["final-read"]==final and final["evidence"]==actual,"full actual final guarded read")
    last=rows[-1];origin_reader=argument(last,"reader");origin_semantic=Path(argument(last,"semantic"))
    origin_reuse=Path(argument(last,"reuse"));origin_frozen=argument(last,"frozen")
    files=saved_guard(final,{origin_reader:tree(reader),str(origin_semantic/"original"):tree(semantic/"original"),
        str(origin_semantic/"download"):tree(semantic/"download"),str(origin_reuse/"original"):tree(reuse/"original"),
        str(origin_reuse/"download"):tree(reuse/"download"),origin_frozen:tree(capture/"frozen")})
    gate=decode(owned(capture,"GATE.json").read_bytes())
    require(gate["status"]=="PASS" and gate["group"]==group and gate["source"]==source_evidence(reader)
        and gate["processes"]==rows and gate["evidence"]==actual and gate["new_original_or_native_applications"]==0
        and gate["original_failure_preserved"] is True,"complete recovery gate")
    require((capture/"ENVIRONMENT.json").read_bytes()==(capture/"frozen/proof_inputs/ENVIRONMENT.json").read_bytes(),
        "complete original pure environment custody")
    require({p.name for p in capture.iterdir()}=={"processes","frozen","GATE.json","FINAL_READONLY.json","ENVIRONMENT.json"},
        "complete recovered capture root")
    return dict(status="COMPLETE_UPLOADED_FILESYSTEM_RECOVERY_AND_ALL_GUARDS_PASS",group=group,evidence=actual,
        final_guard_files=files,final_guard_probes=11,pure_processes=9,new_original_or_native_applications=0)
