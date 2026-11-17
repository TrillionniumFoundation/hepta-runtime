#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Full immutable failure read. No native, Rust, or fixture replay."""
from pathlib import Path
import argparse,collections,json,struct,sys
sys.dont_write_bytecode=True;HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/"build-reference"))
from async_build_common import require,pin,put,doc
import restore_full,read_only_guard as guard
U=lambda b,n:struct.unpack_from("<Q",b,n)[0]
def summary_span(b):
    return dict(bytes=len(b),prefix_hex=b[:128].hex())
def inspect(target):
    p=target/"capture/probes/00-legacy-complete/process"
    report=dict(process=doc(p/"PROCESS.json"),events=doc(p/"EVENTS.json"),
        responses=doc(p/"RESPONSES.json"),failure=doc(p.parent/"FAILURE.json"),
        stdout=(p/"stdout").read_bytes().hex(),stderr=(p/"stderr").read_bytes().hex())
    for n,row in report["process"]["files"].items():require(pin(p/n)==row,"whole stream identity")
    raw=(p/"host-trace").read_bytes();at=0;rows=[];counts=collections.Counter()
    while at<len(raw):
        require(len(raw)-at>=128 and raw[at:at+8]==b"HPTREV01","complete host trace header")
        h=raw[at:at+128];length=U(h,8);lengths=[U(h,n) for n in (72,80,88)]
        require(length==128+sum(lengths) and at+length<=len(raw),"complete trace extent")
        payload=raw[at+128:at+length];spans=[];off=0
        for n in lengths:spans.append(payload[off:off+n]);off+=n
        event=U(h,24);counts[event]+=1
        r=dict(offset=at,extent=length,sequence=U(h,16),event=event,host_generation=U(h,32),
            sdk_generation=U(h,40),node=U(h,48),engine=U(h,56),time=U(h,64),phase=U(h,96),
            spans=list(map(summary_span,spans)))
        if event==1:r["input"]=spans[0].decode("utf-8")
        if event==2:r["request_words"]=[U(spans[0],i) for i in range(8,64,8)];r["reply_words"]=[U(spans[1],i) for i in range(8,192,8)]
        if event in (19,20):r["node_words"]=[U(spans[0],i) for i in range(0,min(len(spans[0]),4096),8)]
        rows.append(r);at+=length
    report["host_trace"]=dict(bytes=at,frames=len(rows),events=dict(counts),last=rows[-30:])
    raw=(p/"publication-journal").read_bytes();at=0;rows=[];counts=collections.Counter()
    while at<len(raw):
        require(len(raw)-at>=64 and raw[at:at+8]==b"HPTWJR01","complete publication trace header")
        h=raw[at:at+64];length=U(h,24);require(at+64+length<=len(raw),"complete publication trace payload")
        v=raw[at+64:at+64+length];event=U(h,8);counts[event]+=1
        r=dict(offset=at,event=event,sequence=U(h,16),extent=length,context=U(h,32),context_size=U(h,40),pid=U(h,48),payload=summary_span(v))
        if event in (1,2,4,5,6,7):r["words"]=[U(v,i) for i in range(0,min(len(v),320),8)]
        rows.append(r);at+=64+length
    report["publication_trace"]=dict(bytes=at,frames=len(rows),events=dict(counts),last=rows[-20:])
    report.update(status="COMPLETE_FAILURE_EVIDENCE_READ_ONLY",application_replayed=False,producer_status="failure")
    return report
def main():
    p=argparse.ArgumentParser();p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    target,archive=restore_full.restore(a.output,doc(HERE/"INPUT.json"))
    result=guard.guarded(lambda:inspect(target),roots=[target,HERE],foreign_path=Path("/dev/null"))
    put(a.output/"READ_ONLY.json",result);put(a.output/"DIAGNOSTIC.json",result["evidence"])
    print(json.dumps(dict(archive=archive,diagnostic=result["evidence"],guards=len(result["probes"]),
        snapshot_entries=len(result["before"]),application_replayed=False),sort_keys=True),flush=True)
if __name__=="__main__":main()
