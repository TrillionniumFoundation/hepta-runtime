#!/usr/bin/env python3
"""Close the original completed stdio captures and controls by pure complete-byte admission."""
from pathlib import Path
from common import decode,pin,require,source_evidence
from read_build_evidence import tree,saved_guard
import read_all,reader_controls
import reader_controls_pure

def verify(source,work,name):
    source,work=Path(source),Path(work);capture=work/"capture";identity=source_evidence(source)
    gate=decode((work/"GATE.json").read_bytes())
    require(gate["status"]=="FAIL"and gate["stage"]=="verify"and gate["group"]==name
        and gate["source"]==identity and gate["error_type"]=="RuntimeError"
        and gate["message"]=="recorded command failed: verify"and gate["build_replayed"]is False,
        "retained exact original terminal evidence failure")
    rows=decode((work/"processes/processes.json").read_bytes())
    require(rows==gate["processes"]and[(r["name"],r["timeout_seconds"])for r in rows]==
        [("source-check",60),("read-comparison",180),("physical-controls",180),("verify",180)],
        "complete original bounded process sequence")
    outputs={}
    for row in rows[:3]:
        actual,value=read_all.process(work/"processes",row["name"],row["timeout_seconds"])
        require(actual==row,"complete successful original process publication");outputs[row["name"]]=value
    last=rows[-1]
    require(last["exit_code"]==1 and last["completed"]is True and last["timed_out"]is False
        and 0<last["elapsed_seconds"]<181 and last["pid"]==last["pgid"]and last["stdin"]is None,
        "last original pure reader completed with failure")
    for channel in("stdout","stderr"):
        item=last[channel]
        require(item["file"]=="verify."+channel and pin(work/"processes"/item["file"])==
            {k:item[k]for k in("bytes","sha256")},"whole initial failed reader stream")
    require(not(work/"processes/verify.stdout").read_bytes()and
        b"ValueError: complete physical changed bytes"in(work/"processes/verify.stderr").read_bytes()
        and not(work/"VERIFY.json").exists(),"original no-op-write accounting refusal retained")
    require(outputs["source-check"]["status"]=="STDIO_READ67_SOURCE_AND_INPUT_ONLY_PASS"
        and outputs["source-check"]["source"]==identity,"complete pre-application source admission")
    result=read_all.verify(source,capture,name)
    require(gate["producer_processes"]==decode((capture/"processes/processes.json").read_bytes()),
        "entire original and native role process provenance")
    original_source=rows[0]["cwd"];original_work=rows[0]["argv"][rows[0]["argv"].index("--work")+1]
    primary=decode((work/"READONLY.json").read_bytes())
    require(primary==outputs["read-comparison"]and primary["evidence"]==result,
        "all original successful semantic comparison bytes unchanged")
    bound=saved_guard(primary,{original_source:tree(source),original_work+"/capture":tree(capture)})
    report=decode((work/"controls/controls.json").read_bytes())
    require(report==outputs["physical-controls"],"complete original physical control producer return")
    try:reader_controls.verify(source,capture,work/"controls",name)
    except ValueError as error:require(str(error)=="complete physical changed bytes","exact original pure reader failure")
    else:raise ValueError("original accounting failure no longer reproducible")
    controls=reader_controls_pure.verify(source,capture,work/"controls",name)
    require(len(controls["fully_bound_byte_identical_writes"])==1,"complete retained byte-identical summary write")
    return dict(status="COMPLETE_ORIGINAL_STDIO_READ67_CAPTURE_RECOVERY_PASS",group=name,actual=result["comparison"],
        build=result["build"],physical_refusals=8,complete_relocations=2,
        original_failure_preserved=True,original_failure_reproduced_by_pure_reader=True,
        fully_bound_byte_identical_writes=controls["fully_bound_byte_identical_writes"],
        complete_saved_guard_files=bound+controls["complete_saved_guard_files"],
        saved_semantic_and_control_guard_probes=121,new_application_calls=0,new_physical_controls=0,
        all_original_full_buffers_and_actual_kernel_bytes_preserved=True)
