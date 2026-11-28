#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Frozen input-only diagnostic domain; no reference/native result is read."""
from pathlib import Path
import struct
from common import canonical,decode,require,sha
ROOT=Path(__file__).resolve().parents[1]
MAX=(1<<64)-1
INVALID,CAPACITY=0xffffffff,0xfffffffe
WORK=12288
CLASSES=("ValueError","PermissionError","OSError","FileNotFoundError","NotADirectoryError",
    "IsADirectoryError","FileExistsError","InterruptedError","BlockingIOError","BrokenPipeError",
    "TimeoutError","ConnectionResetError","ConnectionAbortedError","ConnectionRefusedError")
NAMED_ERRNOS=(1,2,3,10,13,17,20,21,22,32,80,110,133,134,4095)
FILENAMES=("", "plain.bin", "quote'.bin", 'double".bin', 'both\'".bin', "back\\slash.bin",
    "line\ncarriage\rtab\t.bin", "nul\0.byte", "\u6c49\u5b57/\u6587\u4ef6.bin", "emoji-\U0001f600.bin",
    "\x01\x07\x0b\x0c\x1b\x7f\x85\xa0", "\u200b\u2028\u2029\ufeff", "'", '"', "x"*4097,
    "\U00010000last\U0010ffff")
LITERALS=("", "literal error", "nul\0byte", "\u6c49\u5b57\U0001f600", "'\"\\both", "\n\r\t",
    "x"*4097, "z"*65537)
def domain():return decode((ROOT/"DOMAIN.json").read_bytes())
def wire_class(number):
    return {1:2,13:2,2:4,20:5,21:6,17:7,4:8,11:9,114:9,115:9,32:10,108:10,
        110:11,104:12,103:13,111:14}.get(number,3)
def packet(kind,number,payload=b"",named=False,sequence=0):
    return b"HBRDS001"+struct.pack("<7Q",3,sequence,kind,number,len(payload)if number==0 else 0,int(named),len(payload))+payload
def row(cid,label,kind,number,payload,named=False):
    sequences=(0,(1<<63)-1,1<<63,MAX)
    return dict(case_id=cid,label=label,kind=kind,errno=number,payload=payload,named=bool(named),
        sequence=sequences[(cid-1)%4])
def cases(group):
    selected=next(r for r in domain()["groups"]if r["name"]==group);kind=selected["kind"]
    if kind=="errno":
        for number in range(selected["first"],selected["last"]+1):
            yield row(number,"errno-"+str(number),wire_class(number),number,b"")
    elif kind=="named":
        index=selected["index"];number=NAMED_ERRNOS[index]
        for j,name in enumerate(FILENAMES):
            yield row(4096+index*len(FILENAMES)+j,"named-"+str(number)+"-"+str(j),
                wire_class(number),number,name.encode(),True)
    elif kind=="unicode":
        plane=selected["plane"]
        name="".join(chr(cp)for cp in range(plane<<16,(plane+1)<<16)if not 0xd800<=cp<=0xdfff)
        yield row(4336+plane,"unicode-plane-"+str(plane),4,2,name.encode(),True)
    elif kind=="literal":
        cls=selected["class_id"]
        for j,message in enumerate(LITERALS):
            yield row(4353+(cls-1)*len(LITERALS)+j,"literal-"+str(cls)+"-"+str(j),cls,0,message.encode())
    else:raise ValueError("unknown frozen group")
def frame(value):
    return packet(value["kind"],value["errno"],value["payload"],value["named"],value["sequence"])
def capacity(value):
    return len(value["payload"])*(10 if value["named"]else 1)+1024
def public_row(value):
    return {k:v for k,v in value.items()if k!="payload"}|dict(payload_bytes=len(value["payload"]),
        payload_sha256=sha(value["payload"]),input_bytes=len(frame(value)),input_sha256=sha(frame(value)))
def controls():
    result=[]
    def add(label,wire,out,work,expect,**extra):
        result.append(dict(case_id=100000+len(result),label=label,wire=wire,output_capacity=out,
            workspace_capacity=work,expected=expect,**extra))
    message="capacity\0\u6c49\u5b57'\"\\".encode()
    for cls in range(1,15):
        wire=packet(cls,0,message,sequence=MAX-cls);needed=len(CLASSES[cls-1])+2+len(message)
        for cap in(0,1,needed-1,needed,needed+17):
            add("output-"+str(cls)+"-"+str(cap),wire,cap,WORK+31,CAPACITY if cap<needed else needed,
                mutation="installed",required=needed,reference_class=cls,message_hex=message.hex())
        for size in(0,1,WORK-1):
            add("workspace-"+str(cls)+"-"+str(size),wire,needed+17,size,CAPACITY,mutation="unchanged")
        for repeat in range(3):
            add("reuse-"+str(cls)+"-"+str(repeat),wire,needed+17,WORK+31,needed,
                mutation="installed",reuse=repeat>0,required=needed,reference_class=cls,message_hex=message.hex())
    good=packet(1,0,b"sample",sequence=MAX)
    def change(raw,at,value):return raw[:at]+struct.pack("<Q",value)+raw[at+8:]
    bad=[]
    for size in range(64):bad.append(("short-"+str(size),good[:size]))
    for at in range(8):bad.append(("magic-"+str(at),good[:at]+bytes([good[at]^1])+good[at+1:]))
    for value in(0,1,2,4,MAX):bad.append(("response-kind-"+str(value),change(good,8,value)))
    for value in(5,7,MAX):bad.append(("extent-"+str(value),change(good,56,value)))
    for value in(0,15,16,MAX):bad.append(("class-"+str(value),change(good,24,value)))
    for value in(4096,MAX):bad.append(("errno-"+str(value),change(good,32,value)))
    for value in(2,MAX):bad.append(("named-"+str(value),change(good,48,value)))
    bad.append(("literal-with-filename",change(good,48,1)))
    for value in(5,7):bad.append(("literal-count-"+str(value),change(good,40,value)))
    osframe=packet(4,2,b"file",True)
    bad.append(("errno-with-literal-count",change(osframe,40,1)))
    bad.append(("unnamed-with-payload",change(osframe,48,0)))
    for number in NAMED_ERRNOS:
        bad.append(("wrong-class-"+str(number),packet(wire_class(number)%14+1,number)))
    invalid_utf8=(b"\x80",b"\xbf",b"\xc0\x80",b"\xc1\xbf",b"\xc2",b"\xc2A",
        b"\xe0\x80\x80",b"\xed\xa0\x80",b"\xed\xbf\xbf",b"\xe1\x80",b"\xe1A\x80",
        b"\xf0\x80\x80\x80",b"\xf4\x90\x80\x80",b"\xf5\x80\x80\x80",b"\xff",
        b"\xf1\x80\x80",b"\xf1\x80A\x80",b"valid\xf1\x80\x80\x80\x80")
    for i,raw in enumerate(invalid_utf8):bad.append(("utf8-"+str(i),packet(1,0,raw)))
    for label,wire in bad:add(label,wire,512,WORK+31,INVALID,mutation="unchanged")
    require(len(bad)==126 and len(result)==280,"frozen boundary count")
    return result
def validate():
    d=domain();all_rows=[r for g in d["groups"]for r in cases(g["name"])]
    require(len(d["groups"])==62 and len(all_rows)==4464 and
        [r["case_id"]for r in all_rows]==list(range(1,4465)),"frozen complete diagnostic domain")
    require(sum(len(r["payload"].decode())for r in all_rows if r["label"].startswith("unicode-plane-"))==1112064,
        "complete Unicode scalar count")
    require(len(controls())==280 and d["semantic_cases"]==4464 and d["controls"]==280,
        "frozen domain totals")
    return dict(groups=62,semantic_cases=4464,controls=280,unicode_scalars=1112064,
        domain_sha256=sha(canonical(d)))
