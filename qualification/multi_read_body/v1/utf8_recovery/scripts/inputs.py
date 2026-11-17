#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Input-only exhaustive UTF-8 boundary corpus. No decoder or expected outputs."""
import struct

GROUPS=tuple("pairs-"+format(i,"x") for i in range(16))+(
    "singles","scalars","multi-0","multi-1","multi-2","tails","abi")
def frame(raw):
    return b"HUTFQ001"+struct.pack("<Q",len(raw))+raw
def semantic(name,raw):
    return dict(id=name,kind="semantic",wire=frame(raw),data=raw,
        out_capacity=256,work_capacity=512,out_seed=165,work_seed=199)
def inputs(group):
    if group not in GROUPS:raise ValueError("unknown frozen input group")
    if group.startswith("pairs-"):
        lane=int(group[6:],16)
        for n in range(lane*4096,(lane+1)*4096):
            yield semantic("pair-"+format(n,"04x"),n.to_bytes(2,"big"))
    elif group=="singles":
        for n in range(256):yield semantic("single-"+format(n,"02x"),bytes([n]))
        for name,raw in (("empty",b""),("ascii",bytes(range(128))),
            ("nul",b"\0"*1024),("ascii-long",b"A"*4096),
            ("bom",b"\xef\xbb\xbf"),("max-scalar",b"\xf4\x8f\xbf\xbf")):
            yield semantic(name,raw)
    elif group=="scalars":
        for first in range(0,0x110000,65536):
            raw="".join(chr(n) for n in range(first,min(first+65536,0x110000))
                if not 0xd800<=n<=0xdfff).encode("utf-8")
            yield semantic("scalar-block-"+format(first,"06x"),raw)
        for n in (0,1,127,128,255,256,2047,2048,55295,57344,65535,65536,1114111):
            yield semantic("position-"+format(n,"06x"),
                b"a"*65535+chr(n).encode("utf-8")+b"\xff")
        for index,tail in enumerate((b"\xc2",b"\xe0\xa0",b"\xf0\x90\x80",
            b"\xf4\x8f\xbf",b"\xe0\x80",b"\xed\xa0\x80",b"\xf4\x90\x80\x80")):
            yield semantic("long-prefix-"+str(index),b"x"*65536+tail)
    elif group.startswith("multi-"):
        prefix=(b"",b"a",b"\xe4\xb8\xad\xf0\x9f\x99\x82")[int(group[-1])]
        tails=(b"",b"\x80",b"\xbf",b"\x80\x80",b"\xbf\xbf",b"\x7f",b"\xc0",b"\xff",b"\x80x")
        ordinal=0
        for first in (0xe0,0xe1,0xec,0xed,0xee,0xef,0xf0,0xf1,0xf3,0xf4):
            for second in (0,0x7f,0x80,0x8f,0x90,0x9f,0xa0,0xaf,0xb0,0xbf,0xc0,0xff):
                for tail in tails:
                    for suffix in (b"",b"Z"):
                        yield semantic(group+"-"+str(ordinal),prefix+bytes([first,second])+tail+suffix)
                        ordinal+=1
    elif group=="tails":
        leads=(b"\xe0\xa0",b"\xe1\x80",b"\xed\x9f",b"\xef\xbf",
            b"\xf0\x90\x80",b"\xf0\xbf\xbf",b"\xf1\x80\x80",b"\xf4\x8f\xbf")
        ordinal=0
        for lead in leads:
            for n in range(256):
                for suffix in (b"",b"Z"):
                    yield semantic("tail-"+str(ordinal),lead+bytes([n])+suffix)
                    ordinal+=1
    else:
        raws=(b"",b"hello",b"\xed\xa0\x80")
        for i,raw in enumerate(raws):yield semantic("abi-semantic-"+str(i),raw)
        ordinal=0
        for i,raw in enumerate(raws):
            for oc in (0,1,63,64,255,256,257,4096):
                for wc in (0,1,255,256,511,512,513,4096):
                    row=semantic("capacity-"+str(ordinal),raw)
                    row.update(kind="capacity",reference="abi-semantic-"+str(i),
                        out_capacity=oc,work_capacity=wc,out_seed=(ordinal*73+19)%256,
                        work_seed=(ordinal*101+7)%256)
                    yield row;ordinal+=1
        base=frame(b"abc")
        malformed=[base[:i] for i in range(16)]
        malformed += [base[:i]+bytes([base[i]^1])+base[i+1:] for i in range(8)]
        malformed += [base[:8]+struct.pack("<Q",n)+base[16:] for n in (0,2,4,(1<<64)-1)]
        for i,wire in enumerate(malformed):
            for oc,wc in ((256,512),(0,0)):
                yield dict(id="framing-"+str(i)+"-"+str(oc),kind="framing",
                    wire=wire,data=None,out_capacity=oc,work_capacity=wc,
                    out_seed=(i*11+3)%256,work_seed=(i*31+5)%256)
def public_input(row):
    return {k:v.hex() if type(v) is bytes else v for k,v in row.items()}
