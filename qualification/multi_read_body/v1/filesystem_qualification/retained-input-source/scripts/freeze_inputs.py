#!/usr/bin/env python3
"""Author only concrete input records and verify all existing Python syntax."""
from pathlib import Path
import argparse,ast,base64,json,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import decode,encoded,pin,require,source_evidence
from process import Recorder
from cases import domain,groups,actual_query
from protocol import wire,U
def main():
    p=argparse.ArgumentParser();p.add_argument("--output",type=Path);p.add_argument("--author-output",type=Path)
    a=p.parse_args();identity=source_evidence(ROOT)
    if a.author_output is not None:
        out=a.author_output;require(not out.exists(),"fresh concrete input output")
        for path in ROOT.rglob("*.py"):ast.parse(path.read_bytes(),filename=str(path))
        rows=domain();names=groups()
        require([q["id"]for q in rows]==list(range(len(rows)))and len(names)==len(set(names)),"fixed input order")
        for q in rows:
            query=actual_query(q,"/fixed-input-fixture");packet=wire(query)
            require(packet[:8]==b"HMRDQ001"and len(packet)<1048576 and U(packet,88)==len(packet)-96,"input frame bound")
            require(q["attempts"]in(1,2) and q["cleanup"]in("explicit","eof-borrow","eof-idle"),"input ownership profile")
            require(all(a["attempt"]<=q["attempts"]for a in q["actions"]),"actor input attempt")
        out.mkdir()
        (out/"DOMAIN.json").write_bytes(encoded(dict(schema="hepta.runtime.multi-read-body.actual-inputs.v1",
            expected_outputs=False,application_executions=0,groups=names,cases=rows)))
        report=dict(status="INPUT_AUTHOR_ONLY_PASS",source=identity,groups=len(names),inputs=len(rows),
            requested_original_calls=sum(q["attempts"]for q in rows),
            requested_native_calls=sum(q["attempts"]for q in rows),observer_off_inputs=sum(not q["observer"]for q in rows),
            real_mutation_inputs=sum(bool(q["actions"])for q in rows),
            real_fstat_fault_inputs=sum(q["fault"]is not None for q in rows),
            shared_pool_inputs=sum(q["attempts"]==2 for q in rows),
            original_applications=0,native_applications=0,rust_applications=0)
        require(source_evidence(ROOT)==identity,"input author source changed")
        (out/"INPUT_AUTHOR.json").write_bytes(encoded(report));print(encoded(report).decode(),end="");return
    out=a.output;require(out is not None and not out.exists(),"fresh source-only receipt")
    out.mkdir(parents=True);rec=Recorder(ROOT,out/"processes")
    raw,row=rec.run("input-author",[sys.executable,"-I","-S","-B",Path(__file__).resolve(),
        "--author-output",out/"generated"],timeout=60)
    require(decode(raw)["status"]=="INPUT_AUTHOR_ONLY_PASS","input author succeeded")
    require(source_evidence(ROOT)==identity,"source changed during source-only process")
    members={}
    for path in sorted(out.rglob("*")):
        if not path.is_file():continue
        raw=path.read_bytes();name=path.relative_to(out).as_posix();value=pin(path)
        members[name]=dict(**value,mode=path.stat().st_mode&0o777)
        data=base64.b64encode(raw).decode("ascii");pieces=[data[i:i+16384]for i in range(0,len(data),16384)]or[""]
        for i,part in enumerate(pieces):
            print("INPUT_BYTES "+json.dumps(dict(path=name,index=i,count=len(pieces),data=part,**value),sort_keys=True))
    print("INPUT_COMPLETE "+json.dumps(dict(files=len(members),members=members),sort_keys=True))
if __name__=="__main__":main()
