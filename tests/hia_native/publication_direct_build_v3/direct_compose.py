#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Fixed private direct futures on the exact production and duplex boundary."""
from pathlib import Path
import hashlib,json,re
import retained_compose,capacity_repair,cancel_repair
HERE=Path(__file__).resolve().parent
def require(ok,message):
    if not ok:raise ValueError(message)
def pin(value):return dict(bytes=len(value),sha256=hashlib.sha256(value).hexdigest())
def evidence():
    capacity_repair.verify()
    cancel_repair.verify()
    rows={n:pin((HERE/n).read_bytes()) for n in ("direct_fixture.S","duplex_fixture.S",
        "retained_duplex_fixture.S","retained_wait_fixture.S","retained_compose.py",
        "direct_compose.py","FIXTURE_EDITS.json","DIRECT_ABI.md")}
    change=json.loads((HERE/"FIXTURE_EDITS.json").read_bytes())
    text=(HERE/"retained_duplex_fixture.S").read_text()
    require(pin(text.encode())=={k:change["base"][k] for k in ("bytes","sha256")},"whole original duplex")
    for edit in change["edits"]:
        require(text.count(edit["before"])==1,"unique fixed direct fixture splice")
        text=text.replace(edit["before"],edit["after"],1)
    require(text==(HERE/"duplex_fixture.S").read_text()
        and pin(text.encode())=={k:change["after"][k] for k in ("bytes","sha256")},"whole patched duplex")
    for edit in reversed(change["edits"]):
        require(text.count(edit["after"])==1,"unique inverse direct fixture splice")
        text=text.replace(edit["after"],edit["before"],1)
    require(text==(HERE/"retained_duplex_fixture.S").read_text(),"all other duplex bytes retained")
    return dict(schema="hepta.publication.direct-fixture.boundary.v1",files=rows,
        production=change["production"],production_changes=0,sessions=2,
        private_control_fd=5,direct_operations=[6,7,8,9,10,11],root_slot=64,
        shared_actual_publication_pool=True,actual_drop_command=3,actual_join_command=2,
        registry_pending_simulated=False,queued_auxiliary_body_is_not_original_condvar=True,
        application_executed=False,public_async_qualified=False,full_sdk=False)
def compose(text):
    evidence()
    result=retained_compose.compose(text)+"\n"+(HERE/"direct_fixture.S").read_text()
    for name in re.findall(r"^\.global ([A-Za-z_][A-Za-z_0-9]*)$",result,re.M):
        if name=="_start":continue
        alias=name+"_flat"
        if "\n"+alias+":" not in result:
            result=result.replace("\n"+name+":","\n"+name+":\n"+alias+":")
        result=re.sub(r"\b(call|jmp) "+re.escape(name)+r"\b",lambda m:m[1]+" "+alias,result)
        result=result.replace("[rip + "+name+"]","[rip + "+alias+"]")
    require(result.count("\npublic_span_start:\n")==1,"one real entry")
    return result
def install(builder):
    original=builder.adapter_source
    def adapter(root,images=None,**kwargs):
        require(kwargs==dict(private_fixture=False,private_pump_fixture=True,
            private_pump_trace=True,private_publication_trace=True),"only fixed direct observed entry")
        return compose(original(root,images,**kwargs))
    builder.adapter_source=adapter
    return original
