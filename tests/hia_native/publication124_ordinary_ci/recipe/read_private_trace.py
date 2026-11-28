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
    for name,digest in {"view_call_key_bridge.S":"d917a1a4497ab219519057c5d8345af2fc99c2469c94a11b9f735b51d4a56110","view_call_read_bridge.S":"d992bf48ac2d836e067e2b6f9938dea305bc861257ecd9e8068907d71c1ab682"}.items():
        require(sha((source.parent/name).read_bytes())==digest,"frozen view effect source differs")
    at=0;engine=0;canonical=0;forget=0;key_effects=0;read_effects=0
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
        elif tag==b"HFLKEYFX":
            f=raw[at:at+128]
            require(len(f)==128 and U(f,8)>0 and 1<=U(f,16)<=13 and U(f,96)==1
                and U(f,112)==U(f,120)==0,"complete canonical-key effect ACK")
            kind,value,errno=U(f,16),U(f,56),U(f,64)
            require(errno<=4095,"canonical-key errno")
            stats=tuple(U(f,n) for n in (72,80,88,104))
            if errno:
                require(value==0 and stats==(0,0,0,0),"canonical-key error fields")
            else:
                if kind in (5,6,8):
                    require(value==0 and U(f,88)<(1<<32),"canonical-key stat fields")
                else:require(stats==(0,0,0,0),"canonical-key non-stat fields")
                if kind in (3,4,9,11,13):require(value==0,"canonical-key zero completion")
                if kind==1:require(0<value<=U(f,32),"canonical-key getcwd count")
                if kind==2:require(value<=U(f,48),"canonical-key readlink count")
                if kind==7:require(value==U(f,24) and value in (1,2),"canonical-key logical descriptor")
                if kind==12:require(value<=U(f,40),"canonical-key directory count")
            key_effects+=1;at+=128
        elif tag==b"HVRDACK1":
            f=raw[at:at+128]
            require(len(f)==128 and U(f,8)>0 and U(f,16)>0 and U(f,120)==U(f,8)
                and 1<=U(f,24)<=4,"complete file-read effect ACK")
            kind,raw_result,translated,errno=U(f,24),U(f,64),U(f,72),U(f,80)
            before_fd,after_fd=U(f,104),U(f,112)
            signed=raw_result-(1<<64) if raw_result>=(1<<63) else raw_result
            if signed<0:
                require(-4095<=signed<=-1 and errno==-signed and translated==raw_result
                    and U(f,88)==U(f,96)==0,"file-read syscall error")
            else:
                require(errno==0 and translated==(0 if kind==2 else raw_result),"file-read syscall result")
                if kind in (1,4):require(raw_result==0,"file-read zero result")
                if kind==3:require(raw_result<=65536,"file-read count")
                if kind!=1:require(U(f,88)==U(f,96)==0,"file-read non-stat fields")
                else:require(U(f,88)<(1<<32),"file-read stat mode")
            if kind==1:
                require(before_fd==after_fd==(1<<64)-1 and U(f,32)==4096 and U(f,48)==1024
                    and U(f,56)==144,"file-read stat arguments")
            elif kind==2:
                require(before_fd==(1<<64)-1 and after_fd==(raw_result if signed>=0 else (1<<64)-1)
                    and U(f,32)==4096 and U(f,48)==524288 and U(f,56)==0,"file-read open arguments")
            elif kind==3:
                require(before_fd==after_fd and before_fd<(1<<63) and U(f,32)==0 and U(f,48)==65536
                    and U(f,56)==0,"file-read data arguments")
            else:
                require(before_fd<(1<<63) and after_fd==(1<<64)-1
                    and all(U(f,n)==0 for n in (32,40,48,56)),"file-read close arguments")
            read_effects+=1;at+=128
        else:raise ValueError("unknown or partial private diagnostic record at "+str(at))
    require(at==len(raw) and engine>0,"full private diagnostic coverage")
    return dict(bytes=len(raw),sha256=sha(raw),engine_frames=engine,canonical_acks=canonical,
        fixed_forget_returns=forget,key_effect_acks=key_effects,file_read_acks=read_effects)
