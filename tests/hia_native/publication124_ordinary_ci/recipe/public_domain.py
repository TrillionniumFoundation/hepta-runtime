#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Owned public request inputs only; no expected wire or filesystem result."""
from pathlib import Path
import hashlib
import importlib.util
import json
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("retained_publisher_gateway_inputs",ROOT/"retained/gateway_input_domain.py")
old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
ERAS=("legacy","modern")
PROFILES=old.PROFILES+("typed","catalog")
encode=lambda v:json.dumps(v,ensure_ascii=False,separators=(",",":")).encode()
sha=lambda b:hashlib.sha256(b).hexdigest()
def inline_meta(metadata=None):
    result={"io.modelcontextprotocol/protocolVersion":"2026-07-28",
        "io.modelcontextprotocol/clientInfo":{"name":"publisher-public","version":"1"},
        "io.modelcontextprotocol/clientCapabilities":{}}
    if metadata is not None:result.update(metadata)
    return result
def wire_row(name,sid,request,response=True,**extra):
    return dict(id=name,kind="wire",session=sid,fixture=".",wire_hex=(encode(request)+b"\n").hex(),
        response=response,**extra)
def startup(sessions=(0,1)):
    result=[]
    for sid in sessions:
        result.append(wire_row("initialize-"+str(sid),sid,{"jsonrpc":"2.0","id":"init-"+str(sid),
            "method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},
                "clientInfo":{"name":"publisher-public","version":"1"}}}))
        result.append(wire_row("initialized-"+str(sid),sid,
            {"jsonrpc":"2.0","method":"notifications/initialized"},False))
    return result
def tool(row,index,era):
    params={"name":row["tool"],"arguments":row["parameters"]}
    if era=="modern":params["_meta"]=inline_meta(row.get("metadata"))
    elif row.get("metadata") is not None:params["_meta"]=row["metadata"]
    request={"jsonrpc":"2.0","id":index+1000,"method":"tools/call","params":params}
    result=wire_row(row["id"],row["session"],request,tool=row["tool"],parameters=row["parameters"],
        metadata=row.get("metadata"),original_input=row)
    result["fixture"]=row["fixture"]
    return result
def ping(name,index,era,sid=0):
    request={"jsonrpc":"2.0","id":index,"method":"ping"}
    if era=="modern":request["params"]={"_meta":inline_meta()}
    return wire_row(name,sid,request)
def rows(profile,root,era):
    assert profile in PROFILES and era in ERAS
    root=Path(root);result=startup()
    if profile in old.PROFILES:
        for index,row in enumerate(old.rows(profile,root)):
            result.append(tool(row,index,era) if row["kind"]=="call" else dict(row,original_input=row))
        return result
    if profile=="catalog":
        for index,value in enumerate([None,{},{"cursor":None},{"cursor":""},{"cursor":"opaque"},
                {"cursor":"λ\u0000cursor"},{"unknown":{"ordinary":True}}]):
            request={"jsonrpc":"2.0","id":"list-"+str(index),"method":"tools/list"}
            if value is not None:request["params"]=dict(value)
            if era=="modern":request.setdefault("params",{})["_meta"]=inline_meta()
            result.append(wire_row("catalog-"+str(index),index%2,request))
        return result
    ordinary={"path":"typed-file","mode":"create","content":"normal\n","expected_sha256":"absent"}
    values=[]
    values.append(("empty-arguments",{}))
    for field in ordinary:
        value=dict(ordinary);del value[field];values.append(("missing-"+field,value))
        for number,replacement in enumerate([None,False,0,1.25,[],{},["value"]]):
            value=dict(ordinary);value[field]=replacement
            values.append((field+"-type-"+str(number),value))
    for index,mode in enumerate(["","Create","replace ","0"]):
        values.append(("mode-value-"+str(index),dict(ordinary,mode=mode)))
    for index,digest in enumerate(["","ABSENT","0"*63,"g"*64,"0"*65]):
        values.append(("expectation-value-"+str(index),dict(ordinary,expected_sha256=digest)))
    values.append(("unknown-field",dict(ordinary,extra=True)))
    for index,value in enumerate([None,[],False,0,1.25,"ordinary"]):
        values.append(("root-arguments-"+str(index),value))
    for index,(name,value) in enumerate(values):
        row=dict(id=name,kind="call",session=index%2,tool="text_file_write",parameters=value,
            metadata=None,fixture=".")
        result.append(tool(row,index,era))
    for n,identifier in enumerate([17.0,"escaped\"id\\λ",-1,9007199254740993]):
        params=dict(ordinary,path="id-"+str(n),content="id\n")
        req={"jsonrpc":"2.0","id":identifier,"method":"tools/call",
            "params":{"name":"text_file_write","arguments":params}}
        if era=="modern":req["params"]["_meta"]=inline_meta()
        result.append(wire_row("id-domain-"+str(n),n%2,req,tool="text_file_write",parameters=params))
    notify={"jsonrpc":"2.0","method":"tools/call","params":{"name":"text_file_write",
        "arguments":dict(ordinary,path="notification-input")}}
    if era=="modern":notify["params"]["_meta"]=inline_meta()
    result.append(wire_row("ordinary-notification",0,notify,False))
    result.append(ping("notification-barrier",8001,era))
    recovery=dict(id="ordinary-recovery",kind="call",session=0,tool="text_file_write",
        parameters=dict(ordinary,path="recovery"),metadata=None,fixture=".")
    result.append(tool(recovery,len(result),era))
    result.append(ping("final-barrier",8002,era,1))
    return result
def stdio_rows(root,era):
    assert era in ERAS
    result=startup((0,))
    operations=[
        ("create","create","first\n","absent"),
        ("replace","replace","second\n",sha(b"first\n")),
        ("append","append","third\n",sha(b"second\n")),
        ("stale","replace","unchanged",sha(b"first\n")),
    ]
    for index,(name,mode,content,expected) in enumerate(operations):
        result.append(tool(dict(id=name,kind="call",session=0,tool="text_file_write",
            parameters=dict(path="stdio-file",mode=mode,content=content,expected_sha256=expected),
            metadata=None,fixture="."),index,era))
    for index,value in enumerate([{},{"path":None,"mode":"create","content":"","expected_sha256":"absent"}]):
        result.append(tool(dict(id="typed-"+str(index),kind="call",session=0,tool="text_file_write",
            parameters=value,metadata=None,fixture="."),20+index,era))
    result.append(tool(dict(id="text-create",kind="call",session=0,tool="text_editor",
        parameters=dict(command="create",path="stdio-history",content="before\n"),
        metadata=None,fixture="."),30,era))
    result.append(tool(dict(id="text-replace",kind="call",session=0,tool="text_editor",
        parameters=dict(command="str_replace",path="stdio-history",old_text="before",new_text="after"),
        metadata=None,fixture="."),31,era))
    result.append(tool(dict(id="publish-preserves-history",kind="call",session=0,tool="text_file_write",
        parameters=dict(path="stdio-history",mode="append",content="tail\n",expected_sha256=sha(b"after\n")),
        metadata=None,fixture="."),32,era))
    result.append(tool(dict(id="text-undo",kind="call",session=0,tool="text_editor",
        parameters=dict(command="undo_edit",path="stdio-history"),
        metadata=None,fixture="."),33,era))
    request={"jsonrpc":"2.0","id":"catalog","method":"tools/list","params":{"cursor":"ordinary"}}
    if era=="modern":request["params"]["_meta"]=inline_meta()
    result.append(wire_row("stdio-catalog",0,request))
    result.append(ping("stdio-barrier",9000,era))
    return result
def declaration():
    return dict(schema="hepta.runtime.publisher.public-domain.v1",profiles=list(PROFILES),eras=list(ERAS),
        retained_private_inputs=191,input_only=True,expected_wire_embedded=False,
        initial_sessions="two actual legacy handshakes; modern requests carry full actual SDK metadata",
        original_dispatch="unchanged target methods through actual serve/ToolCallContext/AsyncMethodAdapter",
        complete_files_cache_history_locks_and_sessions=True,
        per_exchange_seconds=60,per_process_seconds=180,ci_job_minutes=15,
        retained_private_rows_unchanged=True,full_async=False,full_sdk=False)
