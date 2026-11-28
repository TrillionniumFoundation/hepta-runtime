#!/usr/bin/env python3
"""Admit the exact pure reader correction before opening any retained application."""
from pathlib import Path
import ast,struct,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import decode,encoded,pin,require,source_evidence
from cases import domain,groups
import read_origin,read_recovery,read_controls
def main():
    identity=source_evidence(ROOT);count=0
    for path in sorted(ROOT.rglob("*.py")):
        node=ast.parse(path.read_bytes(),str(path));compile(node,str(path),"exec");count+=1
        if path.parent==ROOT/"scripts":
            names=[n.name for n in node.body if isinstance(n,(ast.FunctionDef,ast.ClassDef,ast.AsyncFunctionDef))]
            require(len(names)==len(set(names)),"no shadowed source-owned reader definition")
    binding=decode((ROOT/"ORIGIN_BINDING.json").read_bytes())
    require(set(binding["groups"])==set(groups()) and len(groups())==27,"all original groups frozen")
    failed=[];passed=[]
    for group,value in binding["groups"].items():
        require(value["commit"]=="d50401175486f3dc64ae1179a0689b488799b2c4" and value["run_id"]==44174569617
            and value["manifest_sha256"]==pin(ROOT/"ORIGINAL_SOURCE_MANIFEST.json")["sha256"],
            "complete original source and terminal job binding")
        if value["gate_status"]=="FAIL":
            require(value["conclusion"]=="failure" and value["retained_first_failure"]==
                "struct.error: pack expected 11 items for packing (got 10)","exact first pure reader failure")
            failed.append(group)
        else:
            require(value["gate_status"]=="PASS" and value["conclusion"]=="success"
                and value["retained_first_failure"] is None,"original success remains success")
            passed.append(group)
    require(len(failed)==22 and set(passed)=={"validate-a","validate-b","validate-c","validate-d","observer-off"},
        "no successful group is replayed or relabeled")
    change=decode((ROOT/"READER_CHANGE.json").read_bytes())
    before=(ROOT/"reference/read_trace_before.py").read_text();after=(ROOT/"scripts/read_trace.py").read_text()
    expected=dict(old='struct.pack("<11Q",3,U(prior["work"],16),0,0,0,0,0,0,0,0)',
        new='struct.pack("<11Q",3,U(prior["work"],16),0,0,0,0,0,0,0,0,0)',occurrences=1)
    require(change["edits"]==[expected] and before.count(expected["old"])==1
        and before.replace(expected["old"],expected["new"])==after,"one exact missing reserved parent-close word")
    require(len(b"HPRDQ001"+struct.pack("<11Q",3,17,0,0,0,0,0,0,0,0,0))==96,"actual fixed parent-close header extent")
    require(pin(ROOT/"reference/read_trace_before.py")=={k:change["before"][k] for k in ("bytes","sha256")}
        and pin(ROOT/"scripts/read_trace.py")=={k:change["after"][k] for k in ("bytes","sha256")},"complete reader edit pins")
    proof=decode((ROOT/"CONTROLS_DERIVATION.json").read_bytes())
    old=(ROOT/"reference/read_qualification_before.py").read_text()
    block=old[old.index(proof["start"]):old.index(proof["end"])]
    for edit in proof["edits"]:
        require(block.count(edit["old"])==edit["occurrences"],"exact complete physical reader preimage")
        block=block.replace(edit["old"],edit["new"])
    head=old[:old.index("def verify(")]
    generated=head+'def controls(source,data,frozen,actual,returned,controls_origin,original_source):\n    source,data,capture=map(Path,(source,data,frozen))\n    guarded_files=0\n'+block+'    require({p.name for p in (capture/"controls").iterdir()}==set(names)|{"relocated-1","relocated-2","RESULT.json"},\n        "complete physical control root inventory")\n    return controls,guarded_files\n'
    require(generated==(ROOT/"scripts/read_controls.py").read_text()
        and pin(ROOT/"reference/read_qualification_before.py")=={k:proof["before"][k] for k in ("bytes","sha256")}
        and pin(ROOT/"scripts/read_controls.py")==proof["after"],"all former full mutation and relocation checks preserved")
    frozen=decode((ROOT/"DOMAIN.json").read_bytes())
    require(frozen["cases"]==domain() and frozen["groups"]==groups() and len(domain())==84
        and sum(q["attempts"] for q in domain())==89,"unchanged complete original filesystem input domain")
    require(source_evidence(ROOT)==identity,"source admission changed its source")
    result=dict(status="PURE_FILESYSTEM_RECOVERY_SOURCE_PASS",source=identity,syntax_files=count,
        failed_lanes_to_recover=failed,passed_lanes_retained=passed,original_inputs=84,original_invocations=89,
        new_original_or_native_applications=0)
    print(encoded(result).decode(),end="")
if __name__=="__main__":main()
