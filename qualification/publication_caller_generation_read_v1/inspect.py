#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Read exact saved caller mappings at each actual worker observation boundary."""
from pathlib import Path
import argparse,gzip,hashlib,json,struct,sys,time
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
def main():
    p=argparse.ArgumentParser()
    for name in ("retained","build-recipe","output","restored"):p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    sys.path.insert(0,str(a.retained))
    from common import canonical,decode,pin,require,sha,source_evidence
    import readonly
    source_evidence(HERE);source_evidence(a.retained)
    sys.path.insert(0,str(a.build_recipe/"current"))
    from restore_full import restore
    inputs=decode((HERE/"INPUTS.json").read_bytes())
    archives={k:restore(a.restored/k,v) for k,v in inputs.items()}
    def operation():
        root=archives["native"][0]/"capture/native/cases/000"
        process=decode((root/"process/PROCESS.json").read_bytes());path=root/"process/host-trace.gz"
        require(pin(path)==process["files"]["host-trace"]["gzip"],"exact entire trace gzip")
        U=lambda b,n:struct.unpack_from("<Q",b,n)[0]
        digest=hashlib.sha256();total=0;counts={};group=None;boundary={};rows={}
        with gzip.open(path,"rb") as stream:
            def read(n):
                nonlocal total
                b=stream.read(n);require(len(b)==n,"full actual trace");digest.update(b);total+=n;return b
            while magic:=stream.read(8):
                require(len(magic)==8,"full magic");digest.update(magic);total+=8
                if magic==b"HRGTR002":read(216);continue
                if magic==b"HRCNAK02":read(120);continue
                require(magic==b"HPTREV01","full host magic");h=magic+read(120)
                e=U(h,24);spans=[read(U(h,x)) for x in (72,80,88)];counts[str(e)]=counts.get(str(e),0)+1
                require(U(h,8)==128+sum(map(len,spans)),"full extent")
                node=(U(h,56),U(h,48),U(h,32))
                if e in (3,4,7):boundary[node]=e
                if e==19:
                    n,c,_=spans
                    require(len(n)==len(c)==4096,"full node/context")
                    group=dict(engine=node[0],node=node[1],host_generation=node[2],sdk_generation=U(n,32),
                        boundary=boundary[node],sequence=U(h,16),pool=U(c,32),job=U(c,40),tag=U(c,48),
                        stage=U(c,56),active=U(n,1184),ownership=U(n,216),context_sha256=sha(c))
                if e==23:
                    d,w,o=spans;require(len(d)==64,"full descriptor")
                    row=dict(group=group,descriptor_hex=d.hex(),workspace=dict(bytes=len(w),sha256=sha(w)),
                        output=dict(bytes=len(o),sha256=sha(o)),caller_descriptor_generation=U(d,24))
                    if len(w)>=4096:
                        off,n=U(w,288),U(w,296)
                        row["caller"]=dict(magic=w[:8].hex(),phase=U(w,8),generation=U(w,16),
                            child=U(w,48),action_generation=U(w,264),input_offset=off,input_length=n,
                            active=U(w,416),substate=U(w,440))
                        require(off+n<=len(w),"whole actual caller loan")
                        row["input_hex"]=w[off:off+n].hex()
                    key=json.dumps([group["job"],group["stage"],group["boundary"],row["caller_descriptor_generation"],
                        row.get("caller",{})],sort_keys=True)
                    if key not in rows:rows[key]=dict(count=0,first=row,last_sequence=U(h,16))
                    rows[key]["count"]+=1;rows[key]["last_sequence"]=U(h,16)
        require(dict(bytes=total,sha256=digest.hexdigest())==process["files"]["host-trace"]["raw"],"all trace bytes")
        failure=archives["failure"][0]
        stderr=(failure/"driver.stderr").read_text()
        require("ValueError: actual admitted caller generation" in stderr,"retained exact first reader failure")
        return dict(status="COMPLETE_ACTUAL_CALLER_GENERATION_DIAGNOSTIC_ONLY",counts=counts,trace=process["files"]["host-trace"],
            rows=list(rows.values()),failure_stderr=stderr,failure_pin=pin(failure/"driver.stderr"),
            archives={k:v[1] for k,v in archives.items()},native_executed=False,rust_executed=False,
            qualification=False)
    begin=time.monotonic()
    proof=readonly.guarded(operation,roots=[HERE,a.retained,*[v[0] for v in archives.values()]])
    require(time.monotonic()-begin<180,"complete pure diagnostic original180s")
    (a.output/"READONLY.json").write_bytes(canonical(proof))
    (a.output/"DIAGNOSTIC.json").write_bytes(canonical(proof["evidence"]))
    print("CALLER_GENERATION_DIAGNOSTIC "+json.dumps(proof["evidence"],sort_keys=True),flush=True)
if __name__=="__main__":main()
