#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Only fixed private native observations; the installed source is immutable."""
from pathlib import Path
import hashlib,json,re
HERE=Path(__file__).resolve().parent
def require(ok,message):
    if not ok:raise ValueError(message)
def pin(value):return dict(bytes=len(value),sha256=hashlib.sha256(value).hexdigest())
def compose(source):
    original=source
    changes=[
        ("\npublic_span_start:\n","\nretained_single_public_span_start:\n"),
        ("    call pump_fixture_preflight\n.endif\n","    call pump_fixture_preflight\n    call duplex_fixture_preflight\n.endif\n"),
        ("pump_handle_frontend:\n    PM_SAVE\n    mov rbp,rdi\n",
         "pump_handle_frontend:\n    PM_SAVE\n    mov rbp,rdi\n    call duplex_observe_future\n"),
    ]
    for before,after in changes:
        require(source.count(before)==1,"unique fixture boundary")
        source=source.replace(before,after,1)
    inverse=source
    for before,after in reversed(changes):
        require(inverse.count(after)==1,"unique inverse fixture boundary")
        inverse=inverse.replace(after,before,1)
    require(inverse==original,"complete original prefix preserved")
    additions="\n"+(HERE/"retained_wait_fixture.S").read_text()+"\n"+(HERE/"duplex_fixture.S").read_text()
    result=source+additions
    for name in re.findall(r"^\.global ([A-Za-z_][A-Za-z_0-9]*)$",result,re.M):
        if name=="_start":continue
        alias=name+"_flat"
        if "\n"+alias+":" not in result:
            result=result.replace("\n"+name+":","\n"+name+":\n"+alias+":")
        result=re.sub(r"\b(call|jmp) "+re.escape(name)+r"\b",lambda m:m[1]+" "+alias,result)
        result=result.replace("[rip + "+name+"]","[rip + "+alias+"]")
    require(result.count("\npublic_span_start:\n")==1,"actual fixed fixture entry")
    return result
def install(builder):
    original=builder.adapter_source
    def adapter(root,images=None,**kwargs):
        require(kwargs==dict(private_fixture=False,private_pump_fixture=True,
            private_pump_trace=True,private_publication_trace=True),"only fixed FD3/4/6 fixture")
        return compose(original(root,images,**kwargs))
    builder.adapter_source=adapter
    return original
