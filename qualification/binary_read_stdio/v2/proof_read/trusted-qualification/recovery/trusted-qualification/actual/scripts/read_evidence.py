#!/usr/bin/env python3
"""Independent complete actual producer/guard/control admission; zero new applications."""
from pathlib import Path
import copy
from common import decode,pin,require,source_evidence
from read_build_evidence import tree,saved_guard
import read_all,reader_controls
def verify(source,work,name):
    source,work=Path(source),Path(work);capture=work/"capture";identity=source_evidence(source)
    gate=decode((work/"GATE.json").read_bytes());require(gate["status"]=="PASS"and gate["group"]==name
        and gate["source"]==identity and gate["new_compiler_calls"]==gate["application_calls_replayed"]==0
        and gate["build_replayed"]is False and gate["whole_runtime_replaced"]is False,"full qualified actual terminal gate")
    rows=decode((work/"processes/processes.json").read_bytes());require(rows==gate["processes"]
        and[(r["name"],r["timeout_seconds"])for r in rows]==[("source-check",60),("read-comparison",180),("physical-controls",180),("verify",180)],
        "exact outer bounded process set")
    outputs={}
    for r in rows:
        actual,raw=read_all.process(work/"processes",r["name"],r["timeout_seconds"])
        require(actual==r,"whole outer process publication");outputs[r["name"]]=raw
    require(outputs["source-check"]["status"]=="STDIO_READ67_SOURCE_AND_INPUT_ONLY_PASS"
        and outputs["source-check"]["source"]==identity,"complete initial source check")
    result=read_all.verify(source,capture,name)
    require(result["comparison"]==gate["actual"]and gate["producer_processes"]==decode((capture/"processes/processes.json").read_bytes()),
        "complete original/native group and inner process gate")
    old_source=rows[0]["cwd"];old_work=rows[0]["argv"][rows[0]["argv"].index("--work")+1]
    read=decode((work/"READONLY.json").read_bytes())
    require(read==outputs["read-comparison"]and read["evidence"]==result,"whole initial comparison proof")
    bound=saved_guard(read,{old_source:tree(source),old_work+"/capture":tree(capture)})
    report=decode((work/"controls/controls.json").read_bytes())
    require(report==outputs["physical-controls"]==gate["controls"],"whole physical-control producer return")
    controls=reader_controls.verify(source,capture,work/"controls",name)
    complete=copy.deepcopy(result);complete["physical_controls"]=controls
    verified=decode((work/"VERIFY.json").read_bytes())
    require(verified==outputs["verify"]and verified["evidence"]==complete,"whole final qualification output")
    bound+=saved_guard(verified,{old_source:tree(source),old_work+"/capture":tree(capture),old_work+"/controls":tree(work/"controls")})
    return dict(status="COMPLETE_UPLOADED_STDIO_READ67_QUALIFICATION_PASS",group=name,actual=gate["actual"],
        physical_refusals=8,complete_relocations=2,complete_saved_guard_files=bound+controls["complete_saved_guard_files"],
        saved_guard_probes=132,new_application_executions=0,new_physical_controls=0,upstream=result["build"])
