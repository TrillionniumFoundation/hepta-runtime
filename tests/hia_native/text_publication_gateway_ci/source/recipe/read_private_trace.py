#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Read the two exact frozen private trace records; never execute a component."""
from pathlib import Path
import struct
from common import require,sha
U=lambda b,n:struct.unpack_from("<Q",b,n)[0]
CANONICAL_SOURCE="f5cc41ee6dfab55f43913907fd0f67c8fecf1b725835e2fe5e4a3cee5989f285"
def read(raw):
    source=Path(__file__).resolve().parents[1]/"retained/runtime_mcp_canonical_bridge.S"
    require(sha(source.read_bytes())==CANONICAL_SOURCE,"frozen canonical ACK source differs")
    require(raw,"empty private engine diagnostic")
    at=0;engine=0;canonical=0;forget=0
    while at<len(raw):
        tag=raw[at:at+8]
        if tag==b"HRGTR002":
            f=raw[at:at+224]
            require(len(f)==224 and U(f,8)>0 and U(f,16)<69 and U(f,24) in (1,2,3,4),
                "private engine trace framing")
            # Values are exact actual engine observations. Semantic responses and
            # full workspace-derived snapshots are compared separately.
            if U(f,16)==68:
                require(U(f,24)==1 and U(f,32)==96 and U(f,48)==96 and U(f,72)==96
                    and f[192:200]==b"HRSCR001","actual fixed Forget capability return")
                forget+=1
            engine+=1;at+=224
        elif tag==b"HRCNAK02":
            f=raw[at:at+128]
            require(len(f)==128 and U(f,8)>0 and U(f,120)==U(f,8),"complete canonical ACK sequence")
            state,kind=U(f,16),U(f,24)
            require(1<=kind<=8 and state==({4:20,5:21}.get(kind,kind)),"canonical action/state")
            offset,count,rc,errno,result_length=tuple(U(f,n) for n in (32,40,48,56,64))
            capacity=U(f,104)
            require(capacity>=4096,"canonical workspace extent")
            if kind in (2,7):
                require(offset==count==0,"canonical null probe span")
            else:
                require(4096<=offset<capacity and 0<count<capacity-offset,
                    "canonical complete path span")
                require(offset==U(f,80 if kind in (4,5) else 72),"canonical owned row selection")
            if kind==4:
                require(4096<=U(f,88)<capacity and 0<U(f,96)<=capacity-U(f,88),
                    "canonical readlink output span")
            signed=rc-(1<<64) if rc>=(1<<63) else rc
            if signed<0:
                require(-4095<=signed<=-1 and errno==-signed and result_length==0,
                    "canonical syscall error observation")
            elif kind==4:
                require(errno==0 and result_length==rc and rc<=U(f,96),"canonical readlink success")
            else:
                require(rc==errno==result_length==0,"canonical zero-result syscall")
            canonical+=1;at+=128
        else:raise ValueError("unknown or partial private diagnostic record at "+str(at))
    require(at==len(raw) and engine>0,"full private diagnostic coverage")
    return dict(bytes=len(raw),sha256=sha(raw),engine_frames=engine,canonical_acks=canonical,
        fixed_forget_returns=forget)
