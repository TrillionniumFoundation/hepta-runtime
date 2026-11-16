"""Read all engineering FD4 records and compare every retained response byte."""
from pathlib import Path
import argparse
import collections
import hashlib
import json
import struct

def pin(p):
    with p.open("rb") as f:d=hashlib.file_digest(f,"sha256").hexdigest()
    return {"bytes":p.stat().st_size,"sha256":d}

def read(capture,manifest,source,inputs,row):
    receipt=json.loads((capture/"PROCESS.json").read_bytes())
    assert receipt["exit_code"]==0 and receipt["timed_out"] is False and receipt["timeout_seconds"]==60
    for name,expected in receipt["artifacts"].items():assert pin(capture/name)==expected
    assert (capture/"stderr.bin").read_bytes()==b""
    assert pin(capture/"stdin.bin")==row["input"]
    assert (capture/"stdin.bin").read_bytes()==(inputs/(row["name"]+".stdin")).read_bytes()
    expected=(inputs/(row["name"]+".stdout")).read_bytes().splitlines(keepends=True)
    actual=(capture/"stdout.bin").read_bytes().splitlines(keepends=True)
    assert len(expected)==len(actual)==row["response_count"]==2
    compare=source/"wire_compare.py";scope={"__name__":"_frozen_wire_compare","__file__":str(compare)}
    exec(compile(compare.read_bytes(),str(compare),"exec"),scope)
    assert actual[0]==expected[0]
    old_wall=new_wall=None
    if row["normalize_solver_clock"]:
        before,old_wall=scope["checked_clock_wire"](expected[1]);after,new_wall=scope["checked_clock_wire"](actual[1])
        assert before==after
    else:assert actual[1]==expected[1]
    data=(capture/"trace.bin").read_bytes();at=sequence=0;stack=[];polls={}
    totals=collections.defaultdict(collections.Counter);slot_rows=[];poll_rows=[];host=[]
    while at<len(data):
        assert len(data)-at>=16
        n=struct.unpack_from("<Q",data,at+8)[0];assert 16<=n<=len(data)-at
        raw=data[at:at+n]
        if raw[:8]==b"HPHASE01":
            assert n==112
            seq,event,engine,slot,now,inp,result,wcap,ocap,phase,ds,desc=struct.unpack("<14Q",raw)[2:]
            sequence+=1;assert seq==sequence
            if event==1:stack.append([slot,now,0,inp,engine,desc])
            elif event==2:
                start=stack.pop();assert start[0]==slot and start[4:]==[engine,desc] and now>=start[1]
                elapsed=now-start[1];own=elapsed-start[2];assert own>=0
                totals[slot].update(inclusive_ns=elapsed,self_ns=own,calls=1)
                slot_rows.append({"slot":slot,"parent_slot":stack[-1][0] if stack else None,"start_ns":start[1],"end_ns":now,"input_bytes":start[3],"inclusive_ns":elapsed,"self_ns":own})
                if stack:stack[-1][2]+=elapsed
            elif event==3:
                assert slot not in polls;polls[slot]=(now,inp,phase,wcap,ocap,engine,desc)
            elif event==4:
                start,size,old_phase,bw,bo,old_engine,old_desc=polls.pop(slot)
                assert now>=start and engine==old_engine and desc==old_desc
                elapsed=now-start;totals[slot].update(direct_hia_ns=elapsed,polls=1)
                poll_rows.append({"slot":slot,"start_ns":start,"end_ns":now,"nanoseconds":elapsed,"input_bytes":size,"workspace_capacity":bw,"output_capacity":bo,"phase_before":old_phase,"phase_after":phase,"actual_return":result})
            else:raise AssertionError(event)
        else:
            assert raw[:8]==b"HPTREV01" and n>=128
            w=struct.unpack("<16Q",raw[:128]);assert n==128+sum(w[9:12])
            host.append({"event_sequence":w[2],"event":w[3],"host_generation":w[4],"sdk_generation":w[5],"monotonic_ns":w[8],"phase":w[12]})
        at+=n
    assert not stack and not polls and [r["event_sequence"] for r in host]==list(range(1,len(host)+1))
    m=json.loads(manifest.read_bytes());assert m["elf_sha256"]==receipt["elf"]["sha256"]
    return {"schema":"hepta.runtime.public111.engineering-profile.v1","status":"COMPLETE_ENGINEERING_CAPTURE_READ_ONLY_PASS",
        "sequence":row["sequence"],"actual_response_count":len(actual),"whole_wire_equal_except_original_solver_clock":True,
        "timing_is_monotonic_wall_not_cpu":True,"process_seconds":(receipt["finished_ns"]-receipt["started_ns"])/1e9,
        "solver_wire_wall_seconds":new_wall,"retained_solver_wire_wall_seconds":old_wall,
        "elf":receipt["elf"],"manifest":pin(manifest),"process":pin(capture/"PROCESS.json"),"trace":pin(capture/"trace.bin"),
        "engine_events":sequence,"host_events":len(host),"slots":[{"slot":s,**dict(v)} for s,v in sorted(totals.items(),key=lambda x:-x[1]["self_ns"])],
        "slot_turns":slot_rows,"direct_polls":poll_rows,"host_turns":host,"full_public_domain_qualified":False,"async_qualified":False,
        "reader_native_executions":0,"reader_rust_executions":0}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for k in ("source","capture","manifest","inputs"):p.add_argument("--"+k,type=Path,required=True)
    p.add_argument("--name",required=True);a=p.parse_args()
    corpus=json.loads((a.source/"CORPUS.json").read_bytes());row=next(r for r in corpus["rows"] if r["name"]==a.name)
    print(json.dumps(read(a.capture,a.manifest,a.source,a.inputs,row),sort_keys=True,indent=2))

if __name__=="__main__":main()
