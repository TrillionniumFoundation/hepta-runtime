# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual native audit Record comparisons against unchanged original Rust blocks."""
from pathlib import Path
import argparse, hashlib, itertools, json, os, random, struct, subprocess, sys, time
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
SOURCE_NAMES=(
 "scripts/author_durable_common.py","scripts/author_durable_audit_record.py",
 "scripts/durable_audit_record_source.py.txt","native/durable_audit_record.hepta",
 "native/durable_audit_record_composition.json","native/request_storage_json.hepta",
 "scripts/hia_native_build.py","scripts/hia_native_loader.py",
 "scripts/prepare_durable_audit_record_reference.py",
 "scripts/qualify_durable_audit_record.py","src/mcp/runtime/request_audit.rs")
def pins(root):
    return {name:dict(bytes=len(raw),sha256=SHA(raw)) for name in SOURCE_NAMES for raw in [(root/name).read_bytes()]}
def packet(raw,op=1,filename=None):
    filename=(b"a"*64+b".json") if filename is None else filename
    name=filename if op==2 else b""
    return struct.pack("<4Q",int.from_bytes(b"HRAJQ001","little"),op,len(raw),len(name))+name+raw
def corpus():
    base={"request_id":"a"*64,"owner":"b"*64,"tool_name":"host_list","state":"unknown","accepted_unix_ms":0,"elapsed_ms":None}
    canonical=lambda value:json.dumps(value,ensure_ascii=False,separators=(",",":")).encode()
    cases=[];seen=set()
    def add(label,raw):
        if raw not in seen:cases.append((label,raw));seen.add(raw)
    add("base",canonical(base))
    for state in ["unknown","completed","failed"]:
        for tagged in [False,True]:
            for elapsed in [None,0,1,(1<<64)-1]:
                row=dict(base,state={state:None}if tagged else state,elapsed_ms=elapsed)
                add("state-form",canonical(row))
    for order in itertools.permutations(base):
        add("field-permutation",canonical({name:base[name] for name in order}))
    for timestamp in [0,1,(1<<32)-1,1<<32,(1<<64)-1,1<<64,(1<<127)-1,1<<127,(1<<128)-1,1<<128,-1,-0.0,0.0,1.5]:
        row=dict(base,accepted_unix_ms=timestamp);add("u128-edge-map",canonical(row));add("u128-edge-sequence",canonical(list(row.values())))
    rng=random.Random(0xD012AB1E)
    for i in range(512):
        row=dict(base,accepted_unix_ms=rng.getrandbits(128),elapsed_ms=rng.getrandbits(64)if i%2 else None)
        add("u128-random-map",canonical(row));add("u128-random-sequence",canonical(list(row.values())))
    for name in base:
        row=dict(base);del row[name];add("missing-"+name,canonical(row))
        raw=canonical(base)
        for value in [None,False,True,{},[],0,"",1.5]:
            row=dict(base);row[name]=value;add("wrong-type-"+name,canonical(row))
        for literal in [name, "".join("\\u%04x"%ord(ch)for ch in name)]:
            raw=canonical(base)[:-1]+b',"' +literal.encode()+b'":null}'
            add("duplicate-"+name,raw)
    for field in ["request_id","owner","tool_name"]:
        for value in ["", "\0", "😃", "\ud800", "A"*64,"x"*64,"a"*63,"a"*65,"_","a_b","host-list", "a"*1900]:
            row=dict(base);row[field]=value
            add("string-"+field,json.dumps(row,ensure_ascii=True,separators=(",",":")).encode())
    raw=canonical(base)
    for name in base:
        escaped='"'+"".join("\\u%04x"%ord(ch)for ch in name)+'"'
        add("escaped-field",raw.replace(json.dumps(name).encode(),escaped.encode()))
    for name in ["request_id","owner","tool_name","state"]:
        row=dict(base);value=row[name];raw2=canonical(row)
        escaped='"'+"".join("\\u%04x"%ord(ch)for ch in value)+'"'
        add("escaped-value",raw2.replace(json.dumps(value).encode(),escaped.encode()))
    for state in ["unknown","completed","failed"]:
        for value in [0,False,[],{},"null",1]:
            add("bad-unit-enum",canonical(dict(base,state={state:value})))
        add("enum-extra",canonical(dict(base,state={state:None,"other":None})))
    sequence=list(base.values())
    for size in range(8):
        add("sequence-length",canonical(sequence[:size]+([None]*(size-6)if size>6 else[])))
    for token in [b"01",b"00",b"-0",b"-1",b"+1",b"1e0",b"1.0",b"1e999",b"NaN",b"Infinity",b"null",b"true",b'"1"',b"340282366920938463463374607431768211455",b"340282366920938463463374607431768211456"]:
        add("number-grammar",raw.replace(b'"accepted_unix_ms":0',b'"accepted_unix_ms":'+token))
    for token in [b"18446744073709551615",b"18446744073709551616",b"-0",b"0.0",b"1e0",b"true",b'"0"',b"null"]:
        add("optional-number",raw.replace(b'"elapsed_ms":null',b'"elapsed_ms":'+token))
    for ending in [b"",b" ",b"\t\r\n",b"null",b"\0",b"{}",b"[]"]:
        add("trailing",raw+ending)
    for n in [0,1,16,512,2048-len(raw),2049-len(raw)]:
        add("whitespace-size",b" "*n+raw)
    for n in range(len(raw)+1):
        add("truncated",raw[:n])
        if n<len(raw):
            for c in [0,0xFF,ord('"'),ord(':'),ord(',')]:
                add("byte-mutation",raw[:n]+bytes([c])+raw[n+1:])
    for literal in [b'"\\ud800"',b'"\\udc00"',b'"\\ud800\\ud800"',b'"\\u0000"',b'"\\ud83d\\ude03"',b'"\xc0\x80"',b'"\xf4\x90\x80\x80"']:
        add("unicode",raw.replace(b'"host_list"',literal))
    out=[]
    for label,value in cases:
        for op in (1,2):out.append((label+"/op"+str(op),packet(value,op)))
    for fname in [b"A"*64+b".json",b"a"*64+b".JSON",b"/"*64+b".json",b"0"*64+b".json"]:
        for value in [raw,b"{}",b" "*2049]:
            out.append(("filename-error-priority",packet(value,2,fname)))
    return out
def stream(frames):
    return b"".join(struct.pack("<I",len(raw))+raw for raw in frames)
def split(raw):
    out=[];at=0
    while at<len(raw):
        if len(raw)-at<4:raise ValueError("truncated oracle frame")
        size=struct.unpack_from("<I",raw,at)[0];at+=4
        if size>8192 or len(raw)-at<size:raise ValueError("invalid oracle response")
        out.append(raw[at:at+size]);at+=size
    return out
def main():
    p=argparse.ArgumentParser();p.add_argument("--source",type=Path,required=True);p.add_argument("--manifest",type=Path,required=True);p.add_argument("--oracle",type=Path,required=True);p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    os.umask(0o022);a.output.mkdir(parents=True,exist_ok=False);before=pins(a.source)
    oracle_raw=a.oracle.read_bytes();manifest_raw=a.manifest.read_bytes()
    rows=corpus();frames=[v for _,v in rows];input_raw=stream(frames)
    (a.output/"input.bin").write_bytes(input_raw)
    (a.output/"cases.json").write_text(json.dumps([dict(ordinal=i,label=k,bytes=len(v),sha256=SHA(v))for i,(k,v)in enumerate(rows)],sort_keys=True,indent=2)+"\n")
    (a.output/"source-before.json").write_text(json.dumps(before,sort_keys=True,indent=2)+"\n")
    command=[str(a.oracle.resolve())];started=time.monotonic()
    proc=subprocess.run(command,input=input_raw,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=180)
    (a.output/"original.stdout").write_bytes(proc.stdout);(a.output/"original.stderr").write_bytes(proc.stderr)
    original=dict(argv=command,exit_code=proc.returncode,elapsed_seconds=time.monotonic()-started,
                  binary_sha256=SHA(oracle_raw),input_sha256=SHA(input_raw),stdout_sha256=SHA(proc.stdout),stderr_sha256=SHA(proc.stderr))
    (a.output/"original-terminal.json").write_text(json.dumps(original,sort_keys=True,indent=2)+"\n")
    if proc.returncode or proc.stderr:raise ValueError("original reference failed")
    expected=split(proc.stdout)
    if len(expected)!=len(rows):raise ValueError("original count differs")
    sys.path.insert(0,str(a.source/"scripts"))
    from hia_native_loader import NativeModule
    actual=[];failures=[];categories={}
    started=time.monotonic()
    with NativeModule(a.manifest,manifest_sha256=SHA(manifest_raw)) as native:
        with native.session(output_capacity=8192,workspace_capacity=16384) as session:
            for i,((label,wire),want)in enumerate(zip(rows,expected)):
                got=session.invoke(wire);actual.append(got)
                diagnostic=struct.unpack_from("<Q",got,8)[0];categories[str(diagnostic)]=categories.get(str(diagnostic),0)+1
                if got!=want:failures.append(dict(ordinal=i,label=label,wire_sha256=SHA(wire),expected_sha256=SHA(want),actual_sha256=SHA(got)))
        controls=[]
        valid=frames[0];want=expected[0]
        invalid=[b"",valid[:31],b"X"+valid[1:],valid[:8]+struct.pack("<Q",0)+valid[16:],valid[:24]+struct.pack("<Q",1)+valid[32:],valid+b"x"]
        for wire in invalid:
            result,out,_=native.invoke_raw(wire,output_capacity=8192,workspace_capacity=16384,output_fill=0x6d,workspace_fill=0x3c)
            if result!=0xffffffff or out!=b"\x6d"*8192:raise AssertionError("invalid frame published or was accepted")
            controls.append(dict(kind="frame",sha256=SHA(wire),result=result))
        for oc,wc in [(0,16384),(31,16384),(32,16384),(len(want)-1,16384),(8192,0),(8192,16383)]:
            result,out,_=native.invoke_raw(valid,output_capacity=oc,workspace_capacity=wc,output_fill=0x6d,workspace_fill=0x3c)
            if result!=0xfffffffe or out!=b"\x6d"*oc:raise AssertionError("capacity published or was accepted")
            controls.append(dict(kind="capacity",output_capacity=oc,workspace_capacity=wc,result=result))
    actual_raw=stream(actual);(a.output/"native.stdout").write_bytes(actual_raw)
    after=pins(a.source);(a.output/"source-after.json").write_text(json.dumps(after,sort_keys=True,indent=2)+"\n")
    report=dict(schema="hepta.runtime.durable-audit-record-qualification.v1",
        source=before,source_unchanged=before==after,compiler_profile="d3e2-development-fixed-point",
        original=original,native_elapsed_seconds=time.monotonic()-started,cases=len(rows),
        native_entries=len(rows)+len(controls),controls=controls,categories=categories,failures=failures,
        input_sha256=SHA(input_raw),actual_stdout_sha256=SHA(actual_raw),
        manifest_sha256=SHA(manifest_raw),public_gateway_qualified=False,filesystem_qualified=False,
        whole_runtime_replaced=False)
    report["passed"]=not failures and before==after and a.oracle.read_bytes()==oracle_raw and a.manifest.read_bytes()==manifest_raw
    (a.output/"report.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
    print(json.dumps({k:v for k,v in report.items()if k not in ("source","controls","original")},sort_keys=True))
    if not report["passed"]:raise SystemExit(1)
if __name__=="__main__":main()
