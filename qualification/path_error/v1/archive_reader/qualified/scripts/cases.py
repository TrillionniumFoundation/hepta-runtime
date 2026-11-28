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
FD_ERRNOS=(9,1,2,3,10,13,17,20,21,22,32,80,110,133,134,4095,11,114,115)
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
    blocking_text={11:b"BlockingIOError: [Errno 11] Resource temporarily unavailable",
        114:b"BlockingIOError: [Errno 114] Operation already in progress",
        115:b"BlockingIOError: [Errno 115] Operation now in progress"}
    for number in(11,114,115):
        for fd in(0,9223372036854775807,9223372036854775808,18446744073709551615):
            wire=metadata_packet(9,number,struct.pack("<Q",fd),2,MAX)
            text=blocking_text[number]if fd<=9223372036854775807 else b"ValueError: cannot fit 'int' into an index-sized integer"
            needed=len(text);reference=50000+FD_ERRNOS.index(number)*len(fds)+fds.index(fd)
            for cap in(0,1,needed-1,needed,needed+17):
                add("blocking-output-"+str(number)+"-"+str(fd)+"-"+str(cap),wire,cap,WORK+31,CAPACITY if cap<needed else needed,
                    mutation="installed",required=needed,reference_case_id=reference)
            for size in(0,1,WORK-1):
                add("blocking-workspace-"+str(number)+"-"+str(fd)+"-"+str(size),wire,needed+17,size,CAPACITY,mutation="unchanged")
            for repeat in range(3):
                add("blocking-reuse-"+str(number)+"-"+str(fd)+"-"+str(repeat),wire,needed+17,WORK+31,needed,
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
    require(len(result)==779,"complete successor boundary count")
    return result
def validate():
    d=domain();all_rows=[r for g in d["groups"]for r in cases(g["name"])];ids=[r["case_id"]for r in all_rows]
    require(len(d["groups"])==112 and len(all_rows)==d["semantic_cases"] and len(set(ids))==len(ids),
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

# New two-string protocol. All preceding 12,908 cases and 779 controls retain
# their exact source definitions; only the new candidate is being qualified.
_previous_cases=cases
_previous_frame=frame
_previous_controls=controls
def dual_packet(kind,number,first,second,sequence=0):
    payload=first+second
    return b"HOSER001"+struct.pack("<7Q",3,sequence,kind,number,len(first),3,len(payload))+payload
def dual_row(cid,label,number,first,second):
    return row(cid,label,wire_class(number),number,first+second,True)|dict(protocol="dual",first_size=len(first),filename_kind=3)
def cases(group):
    selected=next(r for r in domain()["groups"]if r["name"]==group);kind=selected["kind"]
    if not kind.startswith("dual_"):
        yield from _previous_cases(group);return
    if kind=="dual_errno":
        for number in range(selected["first"],selected["last"]+1):
            first=FILENAMES[(number-1)%16].encode();second=FILENAMES[(number*7+3)%16].encode()
            yield dual_row(70000+number,"dual-errno-"+str(number),number,first,second)
    elif kind=="dual_named":
        index=selected["index"];number=FD_ERRNOS[index]
        for i,first in enumerate(FILENAMES):
            for j,second in enumerate(FILENAMES):
                yield dual_row(80000+index*256+i*16+j,"dual-named-"+str(number)+"-"+str(i)+"-"+str(j),number,first.encode(),second.encode())
    elif kind=="dual_unicode":
        plane=selected["plane"];raw="".join(chr(cp)for cp in range(plane<<16,(plane+1)<<16)if not 0xd800<=cp<=0xdfff).encode()
        yield dual_row(90000+plane*2,"dual-unicode-first-"+str(plane),2,raw,b"paired")
        yield dual_row(90001+plane*2,"dual-unicode-second-"+str(plane),2,b"paired",raw)
    else:raise ValueError("undeclared dual-filename group")
def frame(value):
    if value.get("protocol")=="dual":
        n=value["first_size"];return dual_packet(value["kind"],value["errno"],value["payload"][:n],value["payload"][n:],value["sequence"])
    return _previous_frame(value)
def controls():
    result=list(_previous_controls())
    def add(label,wire,out,work,expect,**extra):
        result.append(dict(case_id=400000+len(result),label=label,wire=wire,output_capacity=out,
            workspace_capacity=work,expected=expect,**extra))
    prefixes={2:b"FileNotFoundError: [Errno 2] No such file or directory: ",
        11:b"BlockingIOError: [Errno 11] Resource temporarily unavailable: ",
        4095:b"OSError: [Errno 4095] Unknown error 4095: "}
    pairs=((0,0),(1,1),(2,3),(7,8),(10,11),(14,15))
    for number in(2,11,4095):
        for i,j in pairs:
            first,second=FILENAMES[i],FILENAMES[j]
            wire=dual_packet(wire_class(number),number,first.encode(),second.encode(),MAX)
            needed=len(prefixes[number])+len(repr(first).encode())+4+len(repr(second).encode())
            reference=80000+FD_ERRNOS.index(number)*256+i*16+j
            label=str(number)+"-"+str(i)+"-"+str(j)
            for cap in(0,1,needed-1,needed,needed+17):
                add("dual-output-"+label+"-"+str(cap),wire,cap,WORK+31,CAPACITY if cap<needed else needed,
                    mutation="installed",required=needed,reference_case_id=reference)
            for size in(0,1,WORK-1):
                add("dual-workspace-"+label+"-"+str(size),wire,needed+17,size,CAPACITY,mutation="unchanged")
            for repeat in range(3):
                add("dual-reuse-"+label+"-"+str(repeat),wire,needed+17,WORK+31,needed,
                    mutation="installed",reuse=repeat>0,required=needed,reference_case_id=reference)
    def change(raw,at,value):return raw[:at]+struct.pack("<Q",value)+raw[at+8:]
    good=dual_packet(4,2,b"a",b"b",MAX);bad=[]
    for size in(0,7,8,63):bad.append(("dual-short-"+str(size),good[:size]))
    for at in range(8):bad.append(("dual-magic-"+str(at),good[:at]+bytes([good[at]^1])+good[at+1:]))
    for value in(0,1,2,4,MAX):bad.append(("dual-kind-"+str(value),change(good,8,value)))
    for value in(0,3,MAX):bad.append(("dual-extent-"+str(value),change(good,56,value)))
    for value in(0,15,16,MAX):bad.append(("dual-class-"+str(value),change(good,24,value)))
    for value in(0,4096,MAX):bad.append(("dual-errno-"+str(value),change(good,32,value)))
    for value in(0,1,2,4,MAX):bad.append(("dual-filename-kind-"+str(value),change(good,48,value)))
    for value in(3,MAX):bad.append(("dual-first-size-"+str(value),change(good,40,value)))
    for number in FD_ERRNOS:bad.append(("dual-wrong-class-"+str(number),dual_packet(wire_class(number)%14+1,number,b"a",b"b")))
    invalid_utf8=(b"\x80",b"\xbf",b"\xc0\x80",b"\xc1\xbf",b"\xc2",b"\xc2A",
        b"\xe0\x80\x80",b"\xed\xa0\x80",b"\xed\xbf\xbf",b"\xe1\x80",b"\xe1A\x80",
        b"\xf0\x80\x80\x80",b"\xf4\x90\x80\x80",b"\xf5\x80\x80\x80",b"\xff",
        b"\xf1\x80\x80",b"\xf1\x80A\x80",b"valid\xf1\x80\x80\x80\x80")
    for i,raw in enumerate(invalid_utf8):
        bad.append(("dual-first-utf8-"+str(i),dual_packet(4,2,raw,b"valid")))
        bad.append(("dual-second-utf8-"+str(i),dual_packet(4,2,b"valid",raw)))
    for raw in(b"\xc2\xa2",b"\xe4\xb8\xad",b"\xf0\x9f\x98\x80"):
        for n in range(1,len(raw)):bad.append(("dual-split-"+str(len(raw))+"-"+str(n),dual_packet(4,2,raw[:n],raw[n:])))
    for magic in(b"HBRDS001",b"HMDSR001"):bad.append(("dual-old-envelope-"+magic.decode(),magic+good[8:]))
    require(len(bad)==97,"frozen dual malformed count")
    for label,wire in bad:add(label,wire,512,WORK+31,INVALID,mutation="unchanged")
    require(len(result)==1074,"complete three-protocol controls")
    return result
def validate():
    d=domain();all_rows=[r for g in d["groups"]for r in cases(g["name"])];ids=[r["case_id"]for r in all_rows]
    require(len(d["groups"])==164 and len(all_rows)==d["semantic_cases"]==21901 and len(set(ids))==len(ids),"three-protocol complete domain")
    legacy=[r for r in all_rows if r.get("protocol")not in("metadata","dual")]
    metadata=[r for r in all_rows if r.get("protocol")=="metadata"];dual=[r for r in all_rows if r.get("protocol")=="dual"]
    require(len(legacy)==4464 and len(metadata)==8444 and len(dual)==8993,"exact retained and dual domains")
    require([r["case_id"]for r in legacy]==list(range(1,4465)),"legacy case identities")
    scalar_counts=[sum(len(r["payload"].decode())-6 for r in dual if r["label"].startswith("dual-unicode-"+position+"-"))for position in("first","second")]
    require(scalar_counts==[1112064,1112064],"both complete Unicode filename positions")
    fds=fd_values();require(len(fds)==222 and tuple(sorted(set(fds)))==fds and fds[0]==0 and fds[-1]==MAX,"exact integer domain")
    boundary=controls();counts=dict(invalid=sum(r["expected"]==INVALID for r in boundary),
        capacity=sum(r["expected"]==CAPACITY for r in boundary),success=sum(r["expected"]not in(INVALID,CAPACITY)for r in boundary))
    require(counts==dict(invalid=370,capacity=384,success=320)and len(boundary)==d["controls"]==1074,"three-protocol boundary domain")
    return dict(groups=164,semantic_cases=21901,legacy_cases=4464,metadata_cases=8444,dual_filename_cases=8993,
        controls=1074,control_counts=counts,unicode_scalars=1112064,unicode_scalars_per_position=1112064,
        integer_values=222,domain_sha256=sha(canonical(d)))
