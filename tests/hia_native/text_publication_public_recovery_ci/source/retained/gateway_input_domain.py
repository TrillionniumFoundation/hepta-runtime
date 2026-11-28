#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Normal owned input sequences only. No expected response or filesystem result."""
from pathlib import Path
import hashlib
import struct
from body_cases import cases as body_cases, request as body_request
Q=lambda *v:struct.pack("<"+"Q"*len(v),*v)
sha=lambda b:hashlib.sha256(b).hexdigest()
PROFILES=("configured","absent","denied","fence_required","capabilities","body")
def cache(op,key="",value=""):
    k,v=key.encode(),value.encode()
    return (b"HVCACH01"+Q(op,0,len(k),len(v),0)+k+v).hex()
def rows(profile,root):
    root=Path(root);out=[]
    def call(name,path="file",mode="create",content="new\n",expected="absent",sid=0,tool="text_file_write",metadata=None,parameters=None):
        params=parameters if parameters is not None else dict(path=path,mode=mode,content=content,expected_sha256=expected)
        row=dict(id=name,kind="call",session=sid,tool=tool,parameters=params,metadata=metadata,fixture=".")
        out.append(row)
    def c(name,sid,op,path,value=""):
        out.append(dict(id=name,kind="cache",session=sid,wire_hex=cache(op,str(root/path),value),fixture="."))
    if profile=="body":
        for case in body_cases():
            fixture="fixtures/case-%03d"%case["id"]
            params=body_request(case,root/fixture);params.pop("id")
            if case["path_form"]=="relative":params["path"]=fixture+"/"+case["path"]
            out.append(dict(id="body-"+case["name"],kind="call",session=case["id"]%2,
                tool="text_file_write",parameters=params,metadata=None,fixture=fixture,body_id=case["id"]))
        return out
    if profile=="capabilities":
        first={"io.modelcontextprotocol/clientCapabilities":{"experimental":{"session":{"workdir":str(root/"session-a")}}}}
        second={"io.modelcontextprotocol/clientCapabilities":{"experimental":{"session":{"workdir":str(root/"session-b")}}}}
        call("first-session-workdir",metadata=first)
        call("later-metadata-ignored",path="later",metadata=second)
        call("second-session-workdir",sid=1,metadata=second)
        call("first-append-after-other-session",mode="append",content="tail",expected=sha(b"new\n"))
        call("second-replace",mode="replace",content="other",expected=sha(b"new\n"),sid=1)
        return out
    invalid=[{},dict(path="file"),dict(path=None,mode="create",content="",expected_sha256="absent"),
        dict(path="file",mode="unknown",content="",expected_sha256="absent"),
        dict(path="file",mode="create",content=None,expected_sha256="absent"),
        dict(path="file",mode="create",content="",expected_sha256=0),
        dict(path="file",mode="create",content="",expected_sha256="absent",extra=1)]
    for n,params in enumerate(invalid):call("typed-%d"%n,parameters=params,sid=n%2)
    c("seed-own",0,2,"file","stale");c("seed-other",1,2,"file","foreign")
    call("create")
    c("own-cache-after-create",0,1,"file");c("other-cache-after-create",1,1,"file")
    call("replace",mode="replace",content="replacement\n",expected=sha(b"new\n"),sid=1)
    call("append",mode="append",content="tail\n",expected=sha(b"replacement\n"))
    call("stale-digest",mode="replace",content="not-written",expected="0"*64)
    call("duplicate-create")
    call("content-validation",path="large",content="a"*65537)
    call("expectation-before-content",path="large",mode="replace",content="a"*65537,expected="absent")
    call("missing-parent",path="missing/file")
    call("empty-text",path="empty",content="")
    call("unicode",path="λ.txt",content="中文\r\n🦀\n")
    call("text-create-history",tool="text_editor",parameters=dict(command="create",path="history",content="alpha\n"))
    call("text-replace-history",sid=1,tool="text_editor",parameters=dict(command="str_replace",path="history",old_text="alpha",new_text="beta"))
    call("publisher-preserves-text-history",path="history",mode="append",content="tail\n",expected=sha(b"beta\n"))
    call("text-undo-existing-history",tool="text_editor",parameters=dict(command="undo_edit",path="history"))
    call("publisher-create-does-not-add-history",tool="text_editor",parameters=dict(command="undo_edit",path="file"),sid=1)
    return out

def declaration():
    return dict(schema="hepta.runtime.publisher.gateway-domain.v1",profiles=list(PROFILES),
        body_cases=len(body_cases()),input_only=True,expected_wire_embedded=False,
        original_context="actual RequestContext<RoleServer> + actual client_capabilities + serve_directly",
        original_gateway="unchanged d3d75 text_file_write method and whole filesystem module",
        per_exchange_seconds=60,per_process_seconds=180,ci_job_minutes=15,
        retained_body_lift="only relative fixture paths are prefixed with their owned case directory",
        limits_unchanged=True,public_route=False,full_async=False,full_sdk=False)
