#!/usr/bin/env python3
"""Freeze complete source, copied build and input-only original fault domain."""
from pathlib import Path
import ast,sys
sys.dont_write_bytecode=True
SOURCE=Path(__file__).resolve().parents[1];sys.path.insert(0,str(SOURCE/"scripts"))
from evidence_common import source_evidence,require,encoded,pin,decode,sha
from cases import cases,actual_query
from protocol import wire,U
def main():
    identity=source_evidence(SOURCE);files=[]
    for path in sorted(SOURCE.rglob("*.py")):
        raw=path.read_bytes();ast.parse(raw,filename=str(path));compile(raw,str(path),"exec")
        files.append(dict(path=path.relative_to(SOURCE).as_posix(),**pin(path)))
    require(pin(SOURCE/"target/binary_file.py")["sha256"]=="c15e8900b0ab867b221ff08d5a10401c8b656c87676f57b478b9a21219f7fe12"
        and pin(SOURCE/"target/file_metadata.py")["sha256"]=="24b9df89816536db16dd35a74d6460b1a215981a00798393a00853da6077f5d3","complete exact original targets")
    import read_capture,read_journal
    queries=cases();require(len(queries)==45 and[q["id"]for q in queries]==list(range(1,46)),"frozen complete input extent")
    groups={};observed=off=0
    for q in queries:
        require(q["expected_result"]is None and not q["actions"]and(q["observer"]or q["arm"]is None),"input-only immutable domain")
        require(q["attempts"]in(1,2)and(q["attempts"]==1 or q["arm"]=="first"and q["cleanup"]=="explicit"),"fixed generation/context inputs")
        require(q["entry"]in("path","at")and(q["entry"]=="path"or q["mode"]in("fingerprint","private")),"exact admitted entry")
        require(not q["fd_limit"]or q["entry"]=="at"and q["control_fd0"]is None,"fixed one-free-FD domain")
        groups.setdefault(q["group"],[]).append(dict(id=q["id"],name=q["name"],input_sha256=sha(encoded(q))))
        if q["observer"]:observed+=1
        else:off+=1
        packet=wire(actual_query(q,Path("/fixed-owned-fixture")))
        require(packet[:8]==(b"HBRDFD01"if q["entry"]=="at"else b"HBRDQ001")
            and U(packet,88)==len(packet)-96 and(q["entry"]=="path"or U(packet,32)==0),"complete fixed ABI input")
        require(decode(encoded(q))==q,"exact input roundtrip")
    require(observed==40 and off==5 and len(groups)==13 and sum(q["attempts"]for q in queries)==49,"fixed input/call/group counts")
    require(sum(q["attempts"]for q in queries if q["arm"]=="first")==25
        and sum(q["arm"]in("second","last")for q in queries)==10
        and sum(q["cleanup"]!="explicit"for q in queries)==4,"fixed actual fault/lifetime domain")
    derivation=decode((SOURCE/"authoring/read_journal_derivation.json").read_bytes())
    old=(SOURCE/derivation["before"]).read_text();new=old
    for item in derivation["changes"]:
        require(new.count(item["before"])==1,"retained reader preimage");new=new.replace(item["before"],item["after"])
    require(new==(SOURCE/derivation["after"]).read_text(),"all retained full-buffer reader checks")
    reference=(SOURCE/"reference/file_info_original_before.py").read_text()
    start,end="class Filter(","class ObservedFile:"
    fixed=reference[reference.index(start):reference.index(end)]
    require((SOURCE/"scripts/reference_worker.py").read_text().count(fixed)==1,"exact real-kernel fault filter")
    require((SOURCE/"target/binary_file.py").read_bytes()==(SOURCE/"trusted-build/target/binary_file.py").read_bytes(),"native author targets original")
    report=dict(status="READ_ORPHANS_SOURCE_AND_INPUT_ONLY_PASS",source=identity,python_sources=files,groups=groups,
        observed_inputs=observed,observer_off_inputs=off,entry_invocations=49,inputs=queries,
        original_function_calls=0,hia_calls=0,rust_calls=0,fixture_effects=0,original_binding=read_capture.reference_binding(SOURCE))
    print(encoded(report).decode(),end="")
if __name__=="__main__":main()
