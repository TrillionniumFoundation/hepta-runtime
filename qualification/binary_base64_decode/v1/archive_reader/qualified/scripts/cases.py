#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Frozen input recipes only; no decoding, semantic oracle or native execution."""
from pathlib import Path
from functools import lru_cache
import hashlib,struct
from common import canonical,decode,require,sha
ROOT=Path(__file__).resolve().parents[1]
INVALID=0xffffffff
CAPACITY=0xfffffffe
WORK=0
ALPHABET=b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
@lru_cache(maxsize=1)
def domain():return decode((ROOT/"DOMAIN.json").read_bytes())
def encode_fixture(raw):
    # This creates valid encoded inputs, never expected decoded outputs.
    out=bytearray()
    for at in range(0,len(raw),3):
        chunk=raw[at:at+3];n=len(chunk)
        value=(chunk[0]<<16)|((chunk[1]if n>1 else 0)<<8)|(chunk[2]if n>2 else 0)
        out.extend((ALPHABET[(value>>18)&63],ALPHABET[(value>>12)&63],
            ALPHABET[(value>>6)&63]if n>1 else 61,ALPHABET[value&63]if n>2 else 61))
    return bytes(out)
def input_values(g):
    kind=g["kind"]
    if kind=="values":
        for v in g["values"]:yield v.encode("utf-8")
    elif kind=="alphabet":
        for at in range(4):
            for b in ALPHABET:
                v=bytearray(b"AAAA");v[at]=b;yield bytes(v)
    elif kind in("two","three"):
        for i in range(g["first"],g["last"]):
            for b in ALPHABET:
                yield bytes((ALPHABET[i],b,61,61))if kind=="two"else bytes((65,ALPHABET[i],b,61))
    elif kind=="ascii":
        for at in range(8):
            for b in range(128):
                v=bytearray(b"QUJDRA==");v[at]=b;yield bytes(v)
    elif kind=="padding":
        n=g["length"]
        for mask in range(1<<n):yield bytes(61 if mask&(1<<at)else 65 for at in range(n))
    elif kind=="unicode":
        for cp in g["scalars"]:
            ch=chr(cp).encode("utf-8")
            for prefix,suffix in((b"",b""),(b"!",b""),(b"",b"!"),(b"AA==",b""),
                (b"",b"AA=="),(b"AA=",b"!"),(b"=",b"A"),(b"A",b"="),
                (b"AAAA",b"AAAA"),(b"\x00",b""),(b"",b"\x00"),(b"AAA=",b"AAAA")):
                yield prefix+ch+suffix
    elif kind=="pad-suffix":
        for prefix in g["prefixes"]:
            for suffix in g["suffixes"]:yield (prefix+suffix).encode()
    elif kind=="binary":
        for n in g["sizes"]:yield encode_fixture(bytes((i*73+(i>>8)*19+11)&255 for i in range(n)))
    elif kind=="length":
        for n in g["sizes"]:yield b"A"*n
    else:raise ValueError("undeclared Base64 input family")
@lru_cache(maxsize=None)
def cases(group):
    g=next(g for g in domain()["groups"]if g["name"]==group)
    values=tuple(dict(case_id=g["first_case_id"]+i,label=group+"-"+str(i),
        payload=raw,kind=g["kind"])for i,raw in enumerate(input_values(g)))
    require(len(values)==g["count"],"frozen input recipe count")
    return values
def frame(value):return b"HRCODEC1"+struct.pack("<QQ",4,0)+value["payload"]
def capacity(value):
    # Upper bound and tail only; this never predicts whether a string decodes.
    return 256 if value["kind"]=="length"else max(256,64+len(value["payload"])+31)
def public_row(value):
    return dict(case_id=value["case_id"],label=value["label"],family=value["kind"],
        input_bytes=len(frame(value)),input_sha256=sha(frame(value)))
@lru_cache(maxsize=1)
def controls():
    result=[];spec=domain()["private_controls"];basic=cases("basic")
    def add(label,wire,out,work,expected,**extra):
        result.append(dict(case_id=10000000+len(result),label=label,wire=wire,
            output_capacity=out,workspace_capacity=work,expected=expected,**extra))
    for index in spec["reference_basic_indices"]:
        v=basic[index];wire=frame(v)
        for cap in spec["output_capacities"]:
            add("output-"+str(index)+"-"+str(cap),wire,cap,31,"reference",reference_case_id=v["case_id"])
        for cap in spec["workspace_capacities"]:
            add("workspace-"+str(index)+"-"+str(cap),wire,512,cap,"reference",reference_case_id=v["case_id"])
        for repeat in range(spec["repeat_dirty_workspace"]):
            add("reuse-"+str(index)+"-"+str(repeat),wire,512,31,"reference",
                reference_case_id=v["case_id"],reuse=repeat>0)
    good=frame(basic[0]);bad=[]
    for n in range(24):bad.append(("short-"+str(n),good[:n]))
    for i in range(8):bad.append(("magic-"+str(i),good[:i]+bytes([good[i]^1])+good[i+1:]))
    def word(raw,at,n):return raw[:at]+struct.pack("<Q",n)+raw[at+8:]
    for n in(0,1,2,3,5,0xffffffff,0xffffffffffffffff):bad.append(("command-"+str(n),word(good,8,n)))
    for n in(1,0xffffffff,0xffffffffffffffff):bad.append(("reserved-"+str(n),word(good,16,n)))
    malformed=(b"\x80",b"\xbf",b"\xc0\x80",b"\xc1\xbf",b"\xc2",b"\xc2A",
        b"\xe0\x80\x80",b"\xed\xa0\x80",b"\xed\xbf\xbf",b"\xe1\x80",b"\xe1A\x80",
        b"\xf0\x80\x80\x80",b"\xf4\x90\x80\x80",b"\xf5\x80\x80\x80",b"\xff",
        b"\xf1\x80\x80",b"\xf1\x80A\x80",b"valid\xf1\x80\x80\x80\x80")
    for i,raw in enumerate(malformed):
        for position,(prefix,suffix)in enumerate(((b"",b""),(b"!",b""),(b"",b"="),(b"AAAA",b"AAAA"))):
            bad.append(("utf8-"+str(i)+"-"+str(position),good[:24]+prefix+raw+suffix))
    for label,wire in bad:
        for cap in(0,512):add(label+"-out-"+str(cap),wire,cap,31,INVALID)
    return tuple(result)
@lru_cache(maxsize=1)
def validate():
    d=domain();all_rows=[v for g in d["groups"]for v in cases(g["name"])]
    ids=[r["case_id"]for r in all_rows]
    require(len(d["groups"])==59 and len(all_rows)==d["semantic_cases"]==11918
        and len(set(ids))==len(ids),"complete semantic input domain")
    digest=hashlib.sha256();total=0
    for row in all_rows:
        raw=frame(row);row["payload"].decode("utf-8")
        require(len(raw)<=8<<20 and capacity(row)<=8<<20,"declared native buffer profile")
        digest.update(struct.pack("<QQ",row["case_id"],len(raw)));digest.update(raw);total+=len(raw)
    private=controls()
    require(len({r["case_id"]for r in private})==len(private)
        and not set(ids)&{r["case_id"]for r in private},"unique private input identities")
    invalid=sum(r["expected"]==INVALID for r in private)
    require(invalid==228 and len(private)==503,"frozen private boundary extent")
    return dict(groups=59,semantic_cases=len(all_rows),controls=len(private),
        private_invalid=invalid,private_reference=len(private)-invalid,
        input_bytes=total,input_sha256=digest.hexdigest(),domain_sha256=sha(canonical(d)),
        expected_semantics_generated=False,base64_decoder_executed=False)
