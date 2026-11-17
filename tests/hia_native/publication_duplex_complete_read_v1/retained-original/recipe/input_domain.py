#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Input-only lifecycle domain; no expected wire or publication result."""
from pathlib import Path
import json,struct
PUBLIC=("complete","cancel_pending","cancel_unknown","cancel_after_complete",
    "reuse_id_pending","reuse_id_cancel_new","two_same_session","two_sessions",
    "eof_pending","close_transport_pending","eof_after_complete")
DIRECT=("unpolled_drop","started_drop","started_complete","queued_drop","queued_complete",
    "two_started_drop_first","started_drop_then_second","queued_drop_then_second")

def declaration():
    return dict(schema="hepta.runtime.publisher.async.inputs.v1",
        public=[dict(name=name,era=era) for era in ("legacy","modern") for name in PUBLIC],
        direct=[dict(name=name,mode="queued" if name.startswith("queued") else "direct") for name in DIRECT],
        cases=30,public_cases=22,direct_cases=8,
        process_timeout_seconds=180,exchange_timeout_seconds=60,job_timeout_minutes=15,
        original_target="d3d75c30719db966b004756f610007a7c723729e",
        expected_wire_supplied=False,expected_file_effect_supplied=False,
        full_async=False,full_sdk=False,production_installed=False)

def metadata():
    return {"io.modelcontextprotocol/protocolVersion":"2026-07-28",
        "io.modelcontextprotocol/clientInfo":{"name":"publisher-async-reference","version":"1"},
        "io.modelcontextprotocol/clientCapabilities":{}}

def raw(value):
    return (json.dumps(value,ensure_ascii=False,separators=(",",":"))+"\n").encode()

def params(root,name):
    return dict(path=str(Path(root)/name),mode="create",
        content="ordinary publication: "+name+"\n",expected_sha256="absent")

def cache_wire(key,value):
    key=key.encode();value=value.encode()
    return b"HVCACH01"+struct.pack("<5Q",2,0,len(key),len(value),0)+key+value

def seeds(root):
    return [dict(kind="cache",session=sid,wire_hex=cache_wire(str(Path(root)/path),
        "session-%d retained stale entry for %s\n"%(sid,path)).hex())
        for sid in (0,1) for path in ("held/a.txt","held/b.txt","free/c.txt")]

def request(era,method,identifier,parameters):
    if era=="modern":parameters=dict(parameters,_meta=metadata())
    return dict(jsonrpc="2.0",id=identifier,method=method,params=parameters)

def send(era,method,identifier,parameters,sid=0):
    return dict(kind="send",session=sid,wire_hex=raw(request(era,method,identifier,parameters)).hex())

def publish(root,era,name,identifier=10,sid=0):
    return send(era,"tools/call",identifier,dict(name="text_file_write",arguments=params(root,name)),sid)

def cancel(era,identifier,sid=0):
    p=dict(requestId=identifier,reason="owned ordinary cancellation observation")
    if era=="modern":p["_meta"]=metadata()
    return dict(kind="send",session=sid,
        wire_hex=raw(dict(jsonrpc="2.0",method="notifications/cancelled",params=p)).hex())

def startup(era):
    rows=[]
    for sid in (0,1):
        if era=="legacy":
            rows.append(dict(kind="send",session=sid,wire_hex=raw(dict(jsonrpc="2.0",id=1,
                method="initialize",params=dict(protocolVersion="2025-11-25",
                capabilities={},clientInfo=dict(name="publisher-async-reference",version="1")))).hex()))
            rows.append(dict(kind="read",session=sid))
            rows.append(dict(kind="send",session=sid,wire_hex=raw(
                dict(jsonrpc="2.0",method="notifications/initialized")).hex()))
        else:
            rows.append(send(era,"tools/list",1,{},sid))
            rows.append(dict(kind="read",session=sid))
    return rows

def public_case(root,name,era):
    rows=seeds(root)+startup(era)
    rows.append(publish(root,era,"held/a.txt"))
    rows.append(dict(kind="wait_blocked",session=0,path=str(Path(root)/"held"),count=1))
    rows.append(dict(local="filesystem_snapshot",name="first-worker-held"))
    count=1
    if name in ("cancel_pending","cancel_unknown"):
        rows.append(cancel(era,10 if name=="cancel_pending" else 999))
        rows.append(send(era,"ping",9000,{}))
        rows.append(dict(local="read_until_id",session=0,request_id=9000,max_lines=8))
    if name=="reuse_id_pending":
        rows.append(publish(root,era,"free/c.txt",10))
        rows.append(dict(kind="read",session=0))
        rows.append(dict(local="filesystem_snapshot",name="new-id-response-before-old-completion"))
        count=2
    if name in ("reuse_id_cancel_new","two_same_session","two_sessions"):
        second=10 if name=="reuse_id_cancel_new" else 11
        sid=1 if name=="two_sessions" else 0
        rows.append(publish(root,era,"held/b.txt",second,sid))
        rows.append(dict(kind="wait_blocked",session=0,path=str(Path(root)/"held"),count=2))
        count=2
        if name=="reuse_id_cancel_new":
            rows.append(cancel(era,10))
            rows.append(send(era,"ping",9000,{}))
            rows.append(dict(local="read_until_id",session=0,request_id=9000,max_lines=8))
    if name=="eof_pending":
        rows.append(dict(kind="eof",session=0))
        rows.append(dict(kind="drive",session=0,milliseconds=50))
        rows.append(dict(kind="observe",session=0))
    elif name=="close_transport_pending":
        rows.append(dict(kind="close_transport",session=0))
        rows.append(dict(kind="drive",session=0,milliseconds=50))
        rows.append(dict(kind="observe",session=0))
    rows.append(dict(local="unlock"))
    if name not in ("eof_pending","close_transport_pending"):
        rows.append(dict(kind="wait_events",session=0,event="returned",count=count))
    if name=="cancel_after_complete":
        rows.append(dict(kind="read",session=0))
        rows.append(cancel(era,10))
        rows.append(send(era,"ping",9000,{}))
        rows.append(dict(local="read_until_id",session=0,request_id=9000,max_lines=8))
    if name=="eof_after_complete":
        rows.append(dict(kind="read",session=0))
    for sid in (0,1):
        if sid!=0 or name not in ("eof_pending","close_transport_pending"):
            rows.append(dict(kind="eof",session=sid))
        rows.append(dict(kind="drain",session=sid))
    rows.append(dict(kind="finalize",session=0))
    rows.append(dict(local="filesystem_snapshot",name="after-runtime-drop"))
    return dict(name=name,era=era,mode="public",steps=rows)

def direct_case(root,name):
    rows=seeds(root)
    def start(path="held/a.txt",tag=10,sid=0,kind="direct_start"):
        return dict(kind=kind,session=sid,tag=tag,parameters=params(root,path),metadata=None)
    mode="queued" if name.startswith("queued") else "direct"
    if name=="unpolled_drop":
        rows.append(start(kind="direct_unpolled_drop"))
        rows.append(dict(local="unlock"))
    else:
        rows.append(start())
        rows.append(dict(kind="wait_events",session=0,event="entered",count=1))
        if mode=="queued":
            rows.append(dict(kind="blocked_snapshot",session=0,path=str(Path(root)/"held")))
        else:
            rows.append(dict(kind="wait_blocked",session=0,path=str(Path(root)/"held"),count=1))
        rows.append(dict(local="filesystem_snapshot",name="original-future-suspended"))
        if name=="two_started_drop_first":
            rows.append(start("held/b.txt",11,1))
            rows.append(dict(kind="wait_blocked",session=0,path=str(Path(root)/"held"),count=2))
        dropped=name in ("started_drop","queued_drop","two_started_drop_first",
            "started_drop_then_second","queued_drop_then_second")
        if dropped:
            rows.append(dict(kind="direct_drop",session=0,tag=10))
            rows.append(dict(kind="wait_events",session=0,event="dropped",count=1,after_return=False))
        if mode=="queued":
            rows.append(dict(kind="release_blocker",session=0))
            rows.append(dict(kind="wait_blocked",session=0,path=str(Path(root)/"held"),count=1))
        rows.append(dict(local="unlock"))
        if not dropped:rows.append(dict(kind="direct_join",session=0,tag=10))
        if name=="two_started_drop_first":rows.append(dict(kind="direct_join",session=1,tag=11))
        if name in ("started_drop_then_second","queued_drop_then_second"):
            rows.append(start("free/c.txt",11,1))
            rows.append(dict(kind="direct_join",session=1,tag=11))
    rows.append(dict(kind="finalize",session=0))
    rows.append(dict(local="filesystem_snapshot",name="after-runtime-drop"))
    return dict(name=name,era="direct",mode=mode,steps=rows)

def cases(root):
    root=Path(root)
    result=[]
    for era in ("legacy","modern"):
        for name in PUBLIC:
            case_root=root/(era+"-"+name)
            result.append(dict(root=str(case_root),**public_case(case_root,name,era)))
    for name in DIRECT:
        case_root=root/("direct-"+name)
        result.append(dict(root=str(case_root),**direct_case(case_root,name)))
    assert len(result)==30
    for number,row in enumerate(result):row["case"]=number
    return result
