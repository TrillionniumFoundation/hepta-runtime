#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Frozen input materialization; never calls json.loads, detect_encoding or HIA."""
import itertools
ENCODINGS=(("utf-8",b""),("utf-8",b"\xef\xbb\xbf"),
    ("utf-16-le",b""),("utf-16-le",b"\xff\xfe"),("utf-16-be",b""),("utf-16-be",b"\xfe\xff"),
    ("utf-32-le",b""),("utf-32-le",b"\xff\xfe\0\0"),("utf-32-be",b""),("utf-32-be",b"\0\0\xfe\xff"))
LIMIT=6*1024*1024
def groups():
    return [dict(id=i,name=("pairs-"+str(i)if i<16 else
        {16:"empty-single",17:"utf8-boundaries",18:"unit-truncation",19:"surrogate-pairs",
         20:"full-bound-ascii",21:"full-bound-utf16",22:"full-bound-utf32",23:"full-bound-error"}.get(i,"unicode-"+str(i-24))))for i in range(34)]
def values(group):
    group=int(group)
    if 0<=group<16:
        for v in range(group*4096,(group+1)*4096):yield bytes((v>>8,v&255))
    elif group==16:
        yield b""
        for v in range(256):yield bytes([v])
        yield b"\xff\xfeA"
        yield b"\0\0\xfe\xff\0\x11\0\0"
        yield b"\xef\xbb\xbf\xff"
    elif group==17:
        for prefix in(b"[]",b"\xef\xbb\xbf[]"):
            for lead in(0xc2,0xdf,0xe0,0xed,0xef,0xf0,0xf4,0xf5):
                for second in range(256):
                    for tail in(b"",b"\x80",b"\x80\x80",b"A",b"\xbfA"):
                        yield prefix+bytes((lead,second))+tail
            for suffix in(b"\xc0",b"\xc1",b"\xe0\xa0",b"\xed\xa0",b"\xf0\x90\x80",b"\xf4\x8f\xbf"):
                yield prefix+suffix
    elif group==18:
        for codec,bom in ENCODINGS[2:]:
            prefix=bom+"[]".encode(codec)
            width=2 if "16"in codec else 4
            for length in range(1,width):
                for v in range(256):yield prefix+bytes([v])*length
            if width==4:
                order="little"if codec.endswith("le")else"big"
                for v in(0x10ffff,0x110000,0x110001,0x1fffff,0x7fffffff,0x80000000,0xffffffff):
                    yield prefix+v.to_bytes(4,order)
    elif group==19:
        units=(0,0x41,0xd7ff,0xd800,0xdbff,0xdc00,0xdfff,0xe000,0xffff)
        for codec,bom in ENCODINGS[2:6]:
            prefix=bom+"[]".encode(codec);order="little"if codec.endswith("le")else"big"
            for a,b in itertools.product(units,repeat=2):yield prefix+a.to_bytes(2,order)+b.to_bytes(2,order)
            yield prefix+"".join(chr(v)+"|"for v in range(0xd800,0xe000)).encode(codec,"surrogatepass")
            for unit in units:
                for trailing in range(256):yield prefix+unit.to_bytes(2,order)+bytes([trailing])
    elif group==20:
        yield b"[]" + b"A"*(LIMIT-2)
    elif group==21:
        yield "[]".encode("utf-16-le")+b"A\0"*((LIMIT-4)//2)
    elif group==22:
        yield "[]".encode("utf-32-be")+b"\0\0\0A"*((LIMIT-8)//4)
    elif group==23:
        yield b"\xef\xbb\xbf[]"+b"A"*(LIMIT-7)+b"\xf0\x90"
    elif 24<=group<34:
        codec,bom=ENCODINGS[group-24]
        for start in range(0,0x110000,16384):
            text="[]"+"".join(map(chr,range(start,min(start+16384,0x110000))))
            yield bom+text.encode(codec,"surrogatepass")
    else:raise ValueError("undeclared group")
def cases(group):
    for i,wire in enumerate(values(group)):
        yield dict(case_id=int(group)*1000000+i,label=str(group)+":"+str(i),wire=wire,
            output_capacity=max(512,64+len(wire)*4+37),workspace_capacity=1055,
            output_fill=0xa5,workspace_fill=0x7b,control=False)
def controls():
    rows=[]
    for wire in(b"",b"{}",b"\xe0",b"\xff\xfeA",b"\0\0\xfe\xff\0\x11\0\0"):
        for out,work in((0,0),(63,1024),(512,0),(512,1023),(512,1024)):
            rows.append(dict(wire=wire,output_capacity=out,workspace_capacity=work))
    for wire in(b"",b"[]",b"\xef\xbb\xbf\xff",b"\xff\xfeA"):
        rows.append(dict(wire=wire,output_capacity=64,workspace_capacity=1055))
    rows.append(dict(wire=b"A"*(LIMIT+1),output_capacity=512,workspace_capacity=1055))
    for i,row in enumerate(rows):
        yield dict(case_id=34000000+i,label="control:"+str(i),output_fill=0x6d,workspace_fill=0x3c,control=True,**row)
def domain():
    rows=[dict(**g,cases=sum(1 for _ in values(g["id"])))for g in groups()]
    return dict(schema="hepta.runtime.python-json-bytes.domain.v1",groups=rows,controls=30,
        semantic_cases=sum(g["cases"]for g in rows),input_limit=LIMIT,unicode_codepoints_per_encoding=0x110000,
        encodings=[dict(codec=c,bom=b.hex())for c,b in ENCODINGS],all_two_byte_inputs=65536,
        original_calls_per_case=1,native_calls_per_case=1,application_replay=False)

SHARDS={0:list(range(10))+[16],1:list(range(10,16))+[17,18],2:list(range(19,24)),3:list(range(24,34))}
def plan(shard):
    require_shard=int(shard)
    if require_shard not in SHARDS:raise ValueError("undeclared shard")
    return [(role,str(group))for group in SHARDS[require_shard]for role in("original","native")]+([("native","controls")]if require_shard==0 else [])
def shard_domain(shard):
    d=domain();selected=SHARDS[int(shard)];rows=[r for r in d["groups"]if r["id"]in selected]
    return dict(shard=int(shard),groups=rows,semantic_cases=sum(r["cases"]for r in rows),private_native_calls=30 if int(shard)==0 else 0)
