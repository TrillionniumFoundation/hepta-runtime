"""Independent full uploaded recovery, including all unchanged original and control bytes."""
from pathlib import Path
from evidence_common import decode,pin,require,source_evidence
from read_build_evidence import tree,saved_guard
from physical_controls import CASES,files
import recover_read
def process_values(folder,rows,expected):
    require(decode((folder/"processes.json").read_bytes())==rows
        and[(r["name"],r["timeout_seconds"])for r in rows]==expected,"complete exact recovery process list")
    result={}
    for row in rows:
        require(row["pid"]==row["pgid"]and row["parent_pid"]>0 and row["exit_code"]==0
            and row["completed"]is True and row["timed_out"]is False and row["stdin"]is None
            and 0<=row["elapsed_seconds"]<row["timeout_seconds"],"natural bounded pure recovery process")
        for suffix in("stdout","stderr"):
            item=row[suffix];require(item["file"]==row["name"]+"."+suffix
                and pin(folder/item["file"])=={k:item[k]for k in("bytes","sha256")},"all recovery process bytes")
        require(row["stderr"]["bytes"]==0,"hidden recovery process error")
        result[row["name"]]=decode((folder/row["stdout"]["file"]).read_bytes())
    return result
def verify(source,work,old_module):
    identity=source_evidence(source);gate=decode((work/"GATE.json").read_bytes())
    require(gate["status"]=="PASS"and gate["schema"]=="hepta.runtime.binary-entropy.recovery-gate.v1"
        and gate["source"]==identity and gate["new_original_application_calls"]==gate["new_native_application_calls"]==0
        and gate["original_terminal_status"]=="FAIL"and gate["whole_runtime_replaced"]is False,"exact pure recovery terminal status")
    require(gate["original_capture"]==decode((source/"CAPTURE_INPUT.json").read_bytes()),"one immutable original capture")
    rows=gate["processes"];values=process_values(work/"processes",rows,[("source-check",60),
        ("capture-fetch",60),("capture-unpack",180),("complete-recovery-read",180),("physical-controls",180)])
    require(values["source-check"]==gate["source_check"]and values["source-check"]["status"]=="RECOVERY_SOURCE_ONLY_PASS"
        and values["source-check"]["original_or_native_application_calls"]==0
        and values["capture-fetch"]==gate["capture_fetch"]and values["capture-unpack"]==gate["capture_restore"],
        "all exact source and complete archive stages")
    input_work=work/"input";actual=recover_read.verify(source,input_work,old_module)
    primary=decode((work/"READONLY.json").read_bytes())
    require(primary==values["complete-recovery-read"]and primary["evidence"]==gate["recovered"]==actual,
        "complete unchanged actual and diagnostic recovery")
    source_origin=rows[0]["cwd"];work_origin=rows[0]["argv"][rows[0]["argv"].index("--work")+1]
    references=saved_guard(primary,{source_origin:tree(source),work_origin+"/input/original":tree(input_work/"original"),
        work_origin+"/input/download":tree(input_work/"download")})
    controls=decode((work/"controls/CONTROLS.json").read_bytes())
    require(controls==gate["controls"]==values["physical-controls"]
        and controls["status"]=="SEVEN_PHYSICAL_REFUSALS_TWO_RELOCATIONS_PASS"
        and controls["source"]==actual["original_source"]and controls["guard_probes"]==99
        and controls["application_executions"]==0 and controls["all_expanded_copies_retained"]is True,
        "all actual physical refusal and relocation controls")
    returns=process_values(work/"controls/processes",controls["processes"],[(n,180)for n,_ in CASES])
    old=input_work/"original/restored";original_files={}
    for label,folder in(("source",old/"source"),("application",old/"run/application"),("runtime",old/"run/runtime")):
        original_files.update({label+"/"+name:value for name,value in files(folder).items()})
    require(len(controls["cases"])==len(CASES),"exact physical control count")
    for row,(name,message)in zip(controls["cases"],CASES):
        folder=work/"controls"/name;working=folder/"working";guard=decode((folder/"READONLY.json").read_bytes())
        process=next(p for p in controls["processes"]if p["name"]==name)
        require(row["name"]==name and row["process"]==process and process["parent_pid"]==rows[4]["pid"]
            and row["guard"]==pin(folder/"READONLY.json")and returns[name]==guard
            and guard["evidence"]==row["result"],"every actual physical guard and bounded process")
        observed=files(working)
        require(set(observed)==set(original_files)and len(observed)==row["retained_complete_files"],"whole physical input file set")
        differences={path:dict(before=original_files[path],after=observed[path])
            for path in observed if observed[path]!=original_files[path]}
        require(differences==row["changes"]and bool(differences)==(message is not None),
            "every actual physical mutation byte and mode")
        if message is None:
            require(row["result"]==dict(status="COMPLETE_RELOCATED_ENTROPY_PASS",name=name,qualification=actual["actual"]),
                "complete actual evidence survives relocation")
        else:
            require(row["result"]["status"]=="TARGETED_PHYSICAL_REFUSAL"and row["result"]["name"]==name
                and message in row["result"]["message"],"actual targeted refusal")
        labels=row["origins"]
        require(set(labels)=={"source","application","runtime"}and row["original_source"]==source_origin
            and all(Path(value).name==key and Path(value).parent.name=="working"
                and Path(value).parent.parent.name==name for key,value in labels.items()),"exact historical physical roots")
        roots={source_origin:tree(source)}
        roots.update({value:tree(working/key)for key,value in labels.items()})
        references+=saved_guard(guard,roots)
    return dict(status="COMPLETE_UPLOADED_ENTROPY_RECOVERY_AND_CONTROLS_PASS",recovered=actual,
        retained_guard_full_file_references=references,retained_guards=10,retained_guard_probes=110,
        physical_refusals=7,complete_relocations=2,new_native_or_original_applications=0,whole_runtime_replaced=False)
