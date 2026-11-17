#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Whole retained first direct failures; never replay a native process."""
from pathlib import Path
import argparse,collections,gzip,hashlib,json,struct,sys,time
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
U=lambda b,n:struct.unpack_from("<Q",b,n)[0]
def main():
    p=argparse.ArgumentParser()
    for name in ("retained","build-recipe","output","restored"):p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    sys.path.insert(0,str(a.retained))
    from common import canonical,decode,pin,require,sha,source_evidence
    from buffer_store import Reader
    import readonly
    source_evidence(HERE);source_evidence(a.retained)
    for q in HERE.glob("*.py"):compile(q.read_bytes(),str(q),"exec")
    sys.path.insert(0,str(a.build_recipe/"current"))
    from restore_full import restore
    inputs=decode((HERE/"INPUTS.json").read_bytes())
    archives={k:restore(a.restored/k,v) for k,v in inputs.items()}
    def operation():
        results={}
        for key,(archive,receipt) in archives.items():
            root=archive/"capture/native";plan=decode((root/"PLAN.json").read_bytes())
            cases=[]
            for case in sorted((root/"cases").iterdir()):
                process=decode((case/"process/PROCESS.json").read_bytes())
                failure=decode((case/"FAILURE.json").read_bytes()) if (case/"FAILURE.json").exists() else None
                streams={};control_in=None
                for name,expected in process["files"].items():
                    path=case/"process"/(name+".gz");require(pin(path)==expected["gzip"],"full gzip bytes")
                    digest=hashlib.sha256();n=0;small=bytearray()
                    with gzip.open(path,"rb") as src:
                        while b:=src.read(1<<20):
                            digest.update(b);n+=len(b)
                            if name in ("control.stdin","process.stdout","process.stderr"):small.extend(b)
                    require(dict(bytes=n,sha256=digest.hexdigest())==expected["raw"],"entire raw stream")
                    streams[name]=dict(bytes=n,sha256=digest.hexdigest())
                    if name=="control.stdin":control_in=bytes(small)
                    if name in ("process.stdout","process.stderr"):streams[name]["hex"]=bytes(small).hex()
                controls=[];at=0
                while at<len(control_in):
                    h=control_in[at:at+64];require(len(h)==64 and h[:8]==b"HAPFQ001","whole attempted private request")
                    n=U(h,32);body=control_in[at+64:at+64+n];require(len(body)==n,"entire attempted payload")
                    controls.append(dict(offset=at,sequence=U(h,8),operation=U(h,16),session=U(h,24),
                        length=n,arg0=U(h,40),arg1=U(h,48),payload_sha256=sha(body),
                        payload_hex=body.hex() if len(body)<2048 else body[:256].hex()))
                    at+=64+n
                tail=collections.deque(maxlen=40);counts=collections.Counter();total=0;digest=hashlib.sha256()
                with gzip.open(case/"process/host-trace.gz","rb") as stream:
                    def read(n):
                        nonlocal total
                        b=stream.read(n);require(len(b)==n,"whole recorded host frame");total+=n;digest.update(b);return b
                    while magic:=stream.read(8):
                        require(len(magic)==8,"whole trace magic");total+=8;digest.update(magic)
                        if magic in (b"HRGTR002",b"HRCNAK02"):
                            h=magic+read(216 if magic==b"HRGTR002" else 120)
                            tail.append(dict(magic=magic.decode(),words=[U(h,n) for n in range(8,len(h),8)]));counts[magic.decode()]+=1
                        else:
                            require(magic==b"HPTREV01","actual host frame magic");h=magic+read(120)
                            spans=[read(U(h,x)) for x in (72,80,88)]
                            require(U(h,8)==128+sum(map(len,spans)),"full private trace extent")
                            tail.append(dict(magic="HPTREV01",words=[U(h,n) for n in range(8,128,8)],
                                spans=[dict(bytes=len(b),sha256=sha(b),prefix=b[:256].hex()) for b in spans]))
                            counts["event"+str(U(h,24))]+=1
                require(dict(bytes=total,sha256=digest.hexdigest())==process["files"]["host-trace"]["raw"],"entire parsed actual trace")
                store=Reader(case/"buffers");commands=[]
                for row in decode((case/"COMMANDS.json").read_bytes()):
                    commands.append(dict(number=row["number"],source_step=row["source_step"],
                        request=decode(store.get(row["request"])),result=row["result"]))
                cases.append(dict(case=case.name,process=process,failure=failure,streams=streams,
                    attempted_controls=controls[-8:],completed_commands=commands,trace_counts=dict(counts),trace_tail=list(tail)))
            results[key]=dict(archive=receipt,plan=plan,cases=cases)
        return dict(status="COMPLETE_FIRST_DIRECT_FAILURE_BYTES_READ",partitions=results,
            native_executed=False,rust_executed=False,qualification=False)
    start=time.monotonic()
    proof=readonly.guarded(operation,roots=[HERE,a.retained,*[v[0] for v in archives.values()]])
    require(time.monotonic()-start<180,"pure diagnostic180s")
    (a.output/"READONLY.json").write_bytes(canonical(proof));(a.output/"DIAGNOSTIC.json").write_bytes(canonical(proof["evidence"]))
    print("DIRECT_FAILURE_DIAGNOSTIC "+json.dumps(proof["evidence"],sort_keys=True),flush=True)
if __name__=="__main__":main()
