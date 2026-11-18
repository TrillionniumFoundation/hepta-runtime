#!/usr/bin/env python3
"""Read complete actual original depth captures; no JSON operation is replayed."""
from pathlib import Path
import argparse,gzip,hashlib,struct,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from legacy_common import canonical,decode,owned,pin,require,sha,source_evidence
import legacy_cases as cases
import legacy_read_runtime as read_runtime
from readonly import guarded
def take(stream,n):
    require(type(n)is int and n>=0,"ordinary complete profile span")
    value=stream.read(n);require(len(value)==n,"short complete original profile record");return value
def observation(raw,case):
    require(len(raw)>=8,"full observed original tree")
    n=struct.unpack_from("<Q",raw)[0];shape=bytes(2 if case["shape"]=="object"or(case["shape"]=="alternating"and i%2)else 1 for i in range(case["depth"]))
    require(n==len(shape)and raw[8:8+n]==shape,"whole actual original nesting")
    expected={"zero":("int","0"),"large":("int","257"),"none":("NoneType",None),"true":("bool","true"),
        "char":("str","78000000"),"string":("str","76000000610000006c0000007500000065000000"),
        "half":("float","000000000000e03f"),"nan":("float","000000000000f87f"),
        "inf":("float","000000000000f07f"),"overflow":("float","000000000000f07f"),
        "emptylist":("list",[]),"emptydict":("dict",[])}
    kind,data=expected[case["leaf"]]
    require(raw[8+n:]==canonical(dict(type=kind,data=data)),"whole actual original terminal value")
def process(folder,row,name,limit):
    require(row["name"]==name and row["timeout_seconds"]==limit and row["pid"]==row["pgid"]and row["parent_pid"]>0
        and row["completed"]is True and row["timed_out"]is False and row["exit_code"]==0 and row["stdin"]is None
        and 0<=row["elapsed_seconds"]<limit,"naturally completed bounded original profile process")
    for key in("stdout","stderr"):
        value=row[key];require(value["file"]==name+"."+key and pin(owned(folder,value["file"]))==
            {k:value[k]for k in("bytes","sha256")},"complete process output bytes")
    require(row["stderr"]["bytes"]==0,"no hidden original profile error")
    return decode(owned(folder,row["stdout"]["file"]).read_bytes())
def verify(source,work,group):
    identity=source_evidence(source);runtime=read_runtime.verify(source,work/"runtime")
    origin=decode(owned(work/"admission","ORIGIN.json").read_bytes());folder=work/"capture"
    meta=decode(owned(folder,"CAPTURE.json").read_bytes());rows=decode(owned(folder,"records.json").read_bytes())
    require(meta["schema"]=="hepta.runtime.python-json-value.original-depth-capture.v1"and meta["status"]=="PASS"
        and meta["group"]==str(group)and meta["source"]==identity and meta["runtime"]==runtime
        and meta["native_applications"]==meta["application_replays"]==0,"whole original profile capture identity")
    require(meta["compressed"]==pin(owned(folder,"records.bin.gz"))and meta["records"]==pin(owned(folder,"records.json")),
        "whole original profile retained stream")
    proc=decode(owned(work/"admission","processes/processes.json").read_bytes())
    require([(p["name"],p["timeout_seconds"])for p in proc]==[("source-check",60),("runtime-source",60),("original-profile",60)],
        "complete bounded pre-read process table")
    values={p["name"]:process(work/"admission/processes",p,p["name"],p["timeout_seconds"])for p in proc}
    domain=cases.domain();planned=next(r["cases"]for r in domain["groups"]if r["group"]==int(group))
    require(values["source-check"]==dict(status="ORIGINAL_JSON_PROFILE_SOURCE_PASS",source=identity,domain=domain,
        group=str(group),planned_original_calls=planned,native_applications=0),"complete original profile source admission")
    require(values["runtime-source"]==runtime and values["original-profile"]==meta and meta["pid"]==proc[2]["pid"],
        "exact original runtime and actual child stdout")
    command=[origin["python"],"-I","-S","-B",str(Path(origin["source"])/"scripts/original_capture.py"),
        "--group",str(group),"--runtime",str(Path(origin["work"])/"runtime"),"--output",str(Path(origin["work"])/"capture")]
    require(proc[2]["argv"]==command and all(p["cwd"]==origin["source"]for p in proc),"actual single original profile command")
    whole=hashlib.sha256();offset=0;count=0;profiles={}
    with gzip.open(owned(folder,"records.bin.gz"),"rb")as stream:
        for number,case in enumerate(cases.cases(group),1):
            require(number<=len(rows),"present frozen original profile");row=rows[number-1]
            header=take(stream,80);cid,wi,pa,me,ordinal,bl,br,al,ar,zero=struct.unpack("<10Q",header)
            require(cid==case["case_id"]and ordinal==number and zero==0 and me<=65536,"complete original profile frame")
            wire,payload,metadata,before_left,before_right,after_left,after_right=[take(stream,n)for n in(wi,pa,me,bl,br,al,ar)]
            value=decode(metadata);require(metadata==canonical(value),"canonical original metadata")
            expected_wire=cases.text(case["shape"],case["depth"],case["leaf"]).encode("utf-32-le","surrogatepass")
            digest=hashlib.sha256();size=0
            for span in(header,wire,payload,metadata,before_left,before_right,after_left,after_right):
                digest.update(span);whole.update(span);size+=len(span)
            expected=dict(**case,offset=offset,bytes=size,input_bytes=len(wire),input_sha256=sha(wire),
                payload_bytes=len(payload),payload_sha256=sha(payload),metadata=value,
                observed_before=[sha(before_left),sha(before_right)],observed_after=[sha(after_left),sha(after_right)],
                record_sha256=digest.hexdigest())
            require(row==expected and wire==expected_wire,"entire original recipe/request/outcome bytes")
            require(before_left==after_left and before_right==after_right and value["identity_before"]==value["identity_after"],
                "complete actual operand trees and identities unchanged")
            if case["mode"]=="parse":
                require(not before_left and not before_right and not value["identity_before"],"parse has no constructed operands")
            else:
                observation(before_left,case)
                if case["mode"]=="equal":
                    observation(before_right,case)
                    identities=bytes.fromhex(value["identity_before"])
                    require(len(identities)==case["depth"]+1 and identities[:-1]==b"\0"*case["depth"]
                        and identities[-1]in(0,1),"complete actual equality identity path")
                else:require(not before_right and not value["identity_before"],"dump has one operand")
            if value["status"]=="RAISED":
                require(type(value["exception_class"])is str and payload==(value["exception_class"]+": "+value["message"]).encode(),
                    "whole original exception class and text")
            else:
                require(value["status"]=="RETURNED"and value["exception_class"]is value["message"]is None,"actual returned value")
                if case["mode"]=="equal":require(value["type"]=="bool"and payload==b"1","actual reference equality")
                elif case["mode"]=="dump":
                    require(value["type"]=="str"and len(payload)==4*value["length"],"complete actual dumps text")
                elif case["depth"]>0 or case["leaf"]in("emptylist","emptydict"):observation(payload,case)
                else:require(case["leaf"]=="zero"and value["type"]=="int"and payload==b"0","actual scalar baseline")
            key=":".join(case[k]for k in("mode","shape","leaf"))
            profiles.setdefault(key,[]).append(dict(depth=case["depth"],status=value["status"],
                exception_class=value["exception_class"],message=value["message"],
                leaf_identity=(int(bytes.fromhex(value["identity_before"])[-1])if value["identity_before"]else None)))
            offset+=size;count=number
        require(stream.read()==b""and count==len(rows)==meta["cases"],"entire declared original profile record set")
    require(meta["raw"]==dict(bytes=offset,sha256=whole.hexdigest()),"all original profile raw bytes")
    reduced={}
    for key,entries in profiles.items():
        good=[e["depth"]for e in entries if e["status"]=="RETURNED"];bad=[e for e in entries if e["status"]=="RAISED"]
        transitions=[]
        for e in entries:
            signature=[e["status"],e["exception_class"],e["message"]if e["exception_class"]=="RecursionError"else None,e["leaf_identity"]]
            if not transitions or transitions[-1]["signature"]!=signature:transitions.append(dict(depth=e["depth"],signature=signature))
        reduced[key]=dict(cases=len(entries),minimum_depth=entries[0]["depth"],maximum_depth=entries[-1]["depth"],
            returned=len(good),last_returned=max(good)if good else None,first_raised=bad[0]if bad else None,transitions=transitions)
    return dict(status="COMPLETE_ORIGINAL_JSON_DEPTH_PROFILE_PASS",group=str(group),source=identity,actual_calls=count,
        full_original_bytes=offset,profiles=reduced,new_application_calls=0,native_applications=0,application_replays=0)
def main():
    p=argparse.ArgumentParser();p.add_argument("--source",type=Path,required=True);p.add_argument("--work",type=Path,required=True)
    p.add_argument("--group",required=True);a=p.parse_args();source,work=a.source.resolve(strict=True),a.work.resolve(strict=True)
    "".encode("utf-32-le","surrogatepass")
    result=guarded(lambda:verify(source,work,a.group),roots=[source,work/"capture",work/"runtime",work/"admission"])
    print(canonical(result).decode(),end="")
if __name__=="__main__":main()
