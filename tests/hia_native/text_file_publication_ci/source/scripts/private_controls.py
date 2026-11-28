#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Private framing controls retain complete buffers and do not execute effects."""
import struct
from common import canonical, require
word=lambda raw,at:struct.unpack_from("<Q",raw,at)[0]

def definitions():
    path=b"/qualification-owned-name";content=b"x";expected=b"absent"
    base=b"HTPBQ001"+struct.pack("<7Q",1,0,1,len(path),1,6,len(path)+7)+path+content+expected
    rows=[]
    def add(name,wire,ocap=64,wcap=4096,code=0xffffffff,kind=None):
        rows.append(dict(name=name,wire=wire.hex(),ocap=ocap,wcap=wcap,code=code,kind=kind))
    add("empty-input",b"")
    add("short-tag",base[:7])
    add("short-header",base[:63])
    add("wrong-tag",b"X"+base[1:])
    for name,at,value in (("command-zero",8,0),("command-three",8,3),("start-sequence",16,1),
        ("mode-zero",24,0),("mode-four",24,4),("wrong-payload-size",56,0),
        ("oversized-path",32,16*1024*1024+1),("wrong-field-sum",40,0)):
        raw=bytearray(base);struct.pack_into("<Q",raw,at,value);add(name,bytes(raw))
    for cap in (1,7,63):
        add("short-output-"+str(cap),base,ocap=cap,code=0xfffffffe)
    for cap in (1,64,4095,4096):
        add("workspace-growth-"+str(cap),base,wcap=cap,code=64,kind=4)
    add("empty-resume",b"HTPBQ001"+struct.pack("<7Q",2,1,0,0,0,0,0))
    return rows

def capture(actor,store,output):
    rows=[]
    module=actor.modules["text-file-publication"]
    for index,case in enumerate(definitions()):
        with module.session(output_capacity=case["ocap"],workspace_capacity=case["wcap"]) as session:
            code,out,after=actor.invoke(session,bytes.fromhex(case["wire"]),-index-1,"body")
        require(code==case["code"],"private framing control return: "+case["name"])
        require(after==bytes(case["wcap"]),"private framing control changed workspace")
        if case["kind"] is None:
            require(out==b"\xa5"*case["ocap"],"private refusal changed output")
        else:
            require(out[:8]==b"HTPBS001" and word(out,8)==case["kind"],"private growth framing")
        rows.append(dict(name=case["name"],call=actor.ordinal,definition=case))
    output.write_bytes(canonical(rows))
    return rows
