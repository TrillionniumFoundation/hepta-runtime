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

# Successor definitions. The complete legacy domain and its wire bytes above are retained.
_legacy_cases=cases
_legacy_frame=frame
_legacy_controls=controls
FD_ERRNOS=(9,1,2,3,10,13,17,20,21,22,32,80,110,133,134,4095)
def fd_values():return tuple(int(s)for s in domain()["integer_values_decimal"])
def metadata_packet(kind,number,payload=b"",filename_kind=0,sequence=0):
    return b"HMDSR001"+struct.pack("<7Q",3,sequence,kind,number,len(payload)if number==0 else 0,filename_kind,len(payload))+payload
def metadata_row(cid,label,kind,number,payload,filename_kind=0):
    return row(cid,label,kind,number,payload,filename_kind!=0)|dict(protocol="metadata",filename_kind=filename_kind)
def cases(group):
    selected=next(r for r in domain()["groups"]if r["name"]==group);kind=selected["kind"];fds=fd_values()
    if not kind.startswith("metadata_"):
        yield from _legacy_cases(group);return
    if kind=="metadata_errno":
        for number in range(selected["first"],selected["last"]+1):
            fd=fds[(number-1)%len(fds)]
            yield metadata_row(10000+number,"metadata-errno-"+str(number),wire_class(number),number,struct.pack("<Q",fd),2)
    elif kind=="metadata_fd":
        index=selected["index"];number=FD_ERRNOS[index]
        for j,fd in enumerate(fds):
            yield metadata_row(50000+index*len(fds)+j,"metadata-fd-"+str(number)+"-"+str(fd),wire_class(number),number,struct.pack("<Q",fd),2)
    elif kind=="metadata_nameless":
        for j,number in enumerate(FD_ERRNOS):
            yield metadata_row(59000+j,"metadata-nameless-"+str(number),wire_class(number),number,b"")
    elif kind=="metadata_literal":
        cls=selected["class_id"]
        for j,message in enumerate(LITERALS):
            yield metadata_row(60000+(cls-1)*len(LITERALS)+j,"metadata-literal-"+str(cls)+"-"+str(j),cls,0,message.encode())
    else:raise ValueError("unknown metadata group")
def frame(value):
    if value.get("protocol")=="metadata":
        return metadata_packet(value["kind"],value["errno"],value["payload"],value["filename_kind"],value["sequence"])
    return _legacy_frame(value)
def controls():
    legacy=_legacy_controls();result=list(legacy)
    old_magic=b"HBRDS001";new_magic=b"HMDSR001"
    for index,value in enumerate(legacy):
        wire=value["wire"]
        changed=bytes(wire[i]^old_magic[i]^new_magic[i]for i in range(min(8,len(wire))))+wire[8:]
        result.append(dict(value,case_id=200000+index,label="metadata-"+value["label"],wire=changed))
    def add(label,wire,out,work,expect,**extra):
        result.append(dict(case_id=300000+len(result),label=label,wire=wire,output_capacity=out,
            workspace_capacity=work,expected=expect,**extra))
    fds=fd_values()
    for fd in(0,9,10,2147483647,10000000000000000000,18446744073709551615):
        wire=metadata_packet(3,9,struct.pack("<Q",fd),2,MAX)
        needed=len(b"OSError: [Errno 9] Bad file descriptor: ")+len(str(fd))
        reference=50000+fds.index(fd)
        for cap in(0,1,needed-1,needed,needed+17):
            add("fd-output-"+str(fd)+"-"+str(cap),wire,cap,WORK+31,CAPACITY if cap<needed else needed,
                mutation="installed",required=needed,reference_case_id=reference)
        for size in(0,1,WORK-1):
            add("fd-workspace-"+str(fd)+"-"+str(size),wire,needed+17,size,CAPACITY,mutation="unchanged")
        for repeat in range(3):
            add("fd-reuse-"+str(fd)+"-"+str(repeat),wire,needed+17,WORK+31,needed,
                mutation="installed",reuse=repeat>0,required=needed,reference_case_id=reference)
    def change(raw,at,value):return raw[:at]+struct.pack("<Q",value)+raw[at+8:]
    good=metadata_packet(3,9,struct.pack("<Q",MAX),2,MAX)
    bad=[]
    for size in(*range(8),9,16):bad.append(("fd-extent-"+str(size),metadata_packet(3,9,b"x"*size,2)))
    for kind in(0,1,3,MAX):bad.append(("fd-filename-kind-"+str(kind),change(good,48,kind)))
    bad.extend([
        ("fd-with-literal",metadata_packet(1,0,struct.pack("<Q",MAX),2)),
        ("fd-with-literal-count",change(good,40,1)),
        ("fd-with-wrong-class",change(good,24,4)),
        ("legacy-integer-fd",b"HBRDS001"+good[8:]),
        ("metadata-quoted-filename",metadata_packet(3,9,b"file",1)),
        ("metadata-response-kind",change(good,8,2)),
        ("metadata-incomplete-extent",change(good,56,7)),
    ])
    require(len(bad)==21,"metadata malformed boundary count")
    for label,wire in bad:add(label,wire,512,WORK+31,INVALID,mutation="unchanged")
    require(len(result)==647,"complete successor boundary count")
    return result
def validate():
    d=domain();all_rows=[r for g in d["groups"]for r in cases(g["name"])];ids=[r["case_id"]for r in all_rows]
    require(len(d["groups"])==109 and len(all_rows)==d["semantic_cases"] and len(set(ids))==len(ids),
        "complete dual-envelope diagnostic domain")
    legacy=[r for r in all_rows if r.get("protocol")!="metadata"]
    require(len(legacy)==4464 and [r["case_id"]for r in legacy]==list(range(1,4465)),"retained legacy domain")
    require(sum(len(r["payload"].decode())for r in legacy if r["label"].startswith("unicode-plane-"))==1112064,
        "complete retained Unicode scalar count")
    fds=fd_values();require(len(fds)==d["integer_values_count"]and tuple(sorted(set(fds)))==fds
        and fds[0]==0 and fds[-1]==MAX,"frozen exact integer data domain")
    boundary=controls()
    counts=dict(invalid=sum(r["expected"]==INVALID for r in boundary),capacity=sum(r["expected"]==CAPACITY for r in boundary),
        success=sum(r["expected"]not in(INVALID,CAPACITY)for r in boundary))
    require(len(boundary)==d["controls"]and counts==dict(invalid=d["malformed_controls"],
        capacity=d["capacity_controls"],success=d["successful_dirty_controls"]),"complete successor control classes")
    return dict(groups=len(d["groups"]),semantic_cases=len(all_rows),legacy_cases=len(legacy),metadata_cases=len(all_rows)-len(legacy),
        controls=len(boundary),control_counts=counts,unicode_scalars=1112064,integer_values=len(fds),domain_sha256=sha(canonical(d)))
