#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Project every byte of the actual fixed two-session snapshot mappings."""
from pathlib import Path
import hashlib,struct,sys
from common import require
sys.path.insert(0,str(Path(__file__).resolve().parent/"retained-state"))
import observations,wait_observations
U=lambda b,n:struct.unpack_from("<Q",b,n)[0]
def original(value):
    parsed={}
    for key,field,reader in (("locks","lock_snapshot_hex",observations.locks),
        ("history","history_snapshot_hex",observations.history)):
        parsed[key]=wait_observations.logical(reader(bytes.fromhex(value[field])))
    require(len(value["cache_snapshots_hex"])==len(value["sessions"])==2 and value["scope_unbound_after_exchange"] is True,
        "two actual original session snapshots")
    caches=[wait_observations.logical(observations.cache(bytes.fromhex(raw))) for raw in value["cache_snapshots_hex"]]
    sessions=[]
    for row in value["sessions"]:
        require(set(row)=={"root","current","effective","session_applied","poisoned"},"whole original session fields")
        sessions.append(dict(root_hex=row["root"].encode().hex(),
            current_hex=None if row["current"] is None else row["current"].encode().hex(),
            effective_hex=row["effective"].encode().hex(),session_applied=row["session_applied"],poisoned=row["poisoned"]))
    return [dict(parsed,cache=caches[i],session=sessions[i]) for i in (0,1)]
def native(header,body,co,pm,sid,sequence,operation):
    require(len(header)==64 and header[:8]==b"HXLTR001","complete fixed snapshot header")
    require(tuple(U(header,n) for n in (8,16,24,32,40,48,56))==
        (sequence,operation,sid,0,0,len(body),U(pm,328)),"actual snapshot/current PM identity")
    require(len(body)>=32 and body[:8]==b"HXLTS001" and U(body,8)==0 and U(body,16)==27
        and U(body,24) in (0,1),"all27 native mappings")
    at=32;rows={};pins=[]
    for _ in range(27):
        require(at+32<=len(body),"complete mapping descriptor")
        kind,owner,address,extent=struct.unpack_from("<4Q",body,at);at+=32
        require((kind,owner) not in rows and ((address==extent==0) or (address>0 and 0<extent<=256<<20))
            and extent<=len(body)-at,"exact mapping identity/extent")
        data=body[at:at+extent];at+=extent
        rows[kind,owner]=dict(address=address,data=data)
        pins.append(dict(kind=kind,owner=owner,address=address,bytes=extent,sha256=hashlib.sha256(data).hexdigest()))
    require(at==len(body) and bool(U(body,24))==bool(rows[9,0]["address"]),"no omitted native mapping bytes")
    require(rows[1,0]["address"]==U(pm,224)==U(co,32) and rows[2,0]["address"]==U(pm,240),
        "actual PM references the same engine and shared hub being observed")
    require(len(rows[1,0]["data"])==4096 and rows[13,0]["address"]==U(pm,1200),"actual full borrowed hub/fixture")
    # The retained state parser's phase90/91 are its old fixture's control
    # operations, not these PM service phases. Its complete structural decoder
    # is unchanged. Real phase4 closure is checked explicitly below.
    logical,private=wait_observations.native_state(rows,0,sequence)
    phase=U(pm,328);require(phase in (0,1,2,3,4),"actual SDK service phase")
    if phase==4:
        context=rows[11,10]["data"];scope=rows[11,6]["data"]
        if context and any(context):require(tuple(U(context,n) for n in (24,32,40))==(64,0,0),"closed request context")
        if scope and any(scope):require(U(scope,24)==U(scope,64)==0,"closed operation Scope")
        require(U(pm,296)==U(pm,304)==U(pm,312)==U(pm,320)==U(pm,816)==0,
            "service closure retained a request/response node")
        require(U(pm,1256)==1 and U(pm,832)==0,"actual closed pipes and restored OFD flags")
    hub=rows[1,0]["data"]
    if U(co,136):
        require(phase==4 and U(hub,192)==U(hub,208)==U(hub,216)==0
            and U(pm,272)==0,"process runtime is actually retired after both services")
    return dict(state=logical,private=private,mappings=pins,phase=phase,
        worker_pool=U(hub,216),engine=U(pm,240),shared_hub=U(pm,224))
