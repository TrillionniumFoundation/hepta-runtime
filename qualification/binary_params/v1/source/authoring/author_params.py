#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Author five HIA typed binary owners; this process never executes native code."""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from authoring_support import compile_delta, substitute
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
CANON=lambda value:json.dumps(value,sort_keys=True,separators=(",",":")).encode()
BASELINE="310368785b761a4c1dbde449f3ebba2cb20df9d0f91cc9264ec8b2afbc20a262"
INTEGER_BASELINE="f507e8658e3a3905f3d7a9da8c18a0d4863a327015800a649c85b99de739a830"

def render_literals(schema):
    names=[name for name,field,kind in schema["fields"]]
    expected=("expected "+(" or ".join("\x60"+x+"\x60" for x in names) if len(names)==2 else
        "one of "+", ".join("\x60"+x+"\x60" for x in names)))
    variants=", ".join("\x60"+x+"\x60" for x in schema["variants"])
    literals={1:b"missing field \x60host\x60",2:b"missing field \x60path\x60",3:b"invalid type: ",
        4:b", expected ",5:b"a string",6:b"a boolean",7:b"string or map",
        8:b"invalid value: map, expected map with a single key",9:b"unit",
        10:b"unknown variant \x60",11:("\x60, expected one of "+variants).encode(),
        14:b"unknown field \x60",15:("\x60, "+expected).encode(),16:b"invalid value: ",17:b"u64"}
    for name,field,kind in schema["fields"]:
        if kind in ("string","bool","enum"):
            literals[100+field]=("missing field \x60"+name+"\x60").encode()
    text="\ndef literal(w:mutbuf,o:mutbuf,code:u64) -> u64:\n"
    for code,raw in sorted(literals.items()):
        text+=f"    if code=={code}:\n"
        for byte in raw:text+=f"        emit(w,o,{byte})\n"
        text+="        return 0\n"
    return text+"    return 0\n"

def render_fields(schema):
    text="\ndef field_key(s:readbuf,start:u64,end:u64) -> u64:\n"
    for name,field,kind in schema["fields"]:
        raw=json.dumps(name,separators=(",",":")).encode()
        text+=f"    if end-start=={len(raw)}:\n        same=1\n"
        split=len(raw)//8*8
        for i in range(0,split,8):
            word=int.from_bytes(raw[i:i+8],"little")
            text+=f"        if load(s,start+{i})!={word}:\n            same=0\n"
        for i in range(split,len(raw)):
            text+=f"        if byte(s,start+{i})!={raw[i]}:\n            same=0\n"
        text+=f"        if same!=0:\n            return {field}\n"
    text+="    return 0\n\ndef field_type(field:u64) -> u64:\n"
    kinds={"string":1,"option_string":2,"option_u64":3,"bool":4,"default_bool":5,"enum":6}
    for name,field,kind in schema["fields"]:
        text+=f"    if field=={field}:\n        return {kinds[kind]}\n"
    text+="    return 0\n\ndef required(present:u64) -> u64:\n"
    for name,field,kind in schema["fields"]:
        if kind in ("string","bool","enum"):
            text+=f"    if (present&{1<<field})==0:\n        return {100+field}\n"
    return text+"    return 0\n"

def render_enum(schema):
    text="\ndef enum_byte(kind:u64,index:u64) -> u64:\n"
    for kind,variant in enumerate(schema["variants"],1):
        text+=f"    if kind=={kind}:\n"
        for i,byte in enumerate(variant.encode()):
            text+=f"        if index=={i}:\n            return {byte}\n"
    return text+"    return 256\n"

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for key in ("hepta","source","output"):p.add_argument("--"+key,required=True,type=Path)
    a=p.parse_args(); source=a.source.resolve(strict=True); output=a.output.absolute()
    if output.exists():raise ValueError("author output must be fresh")
    sys.path.insert(0,str(a.hepta.resolve(strict=True)))
    from hepta.hia_agent_assembly import assemble_program,render_assembly
    original=(source/"baseline/text_editor_params.hepta").read_bytes()
    integer_raw=(source/"baseline/view_params.hepta").read_bytes()
    assert SHA(original)==BASELINE and SHA(integer_raw)==INTEGER_BASELINE
    baseline=assemble_program(original).as_dict()
    before={f["name"]:copy.deepcopy(f) for f in baseline["functions"]}
    other=assemble_program(integer_raw).as_dict()
    integer=copy.deepcopy(next(f for f in other["functions"] if f["name"]=="f3"))
    assert {i["attrs"]["function"] for b in integer["blocks"] for i in b["ops"]
        if i["op"]=="call"}=={"f19"}
    integer["name"]="f43"
    for block in integer["blocks"]:
        for instruction in block["ops"]:
            if instruction["op"]=="call":
                instruction["attrs"]["function"]="f11"
    baseline["functions"].append(integer)
    original_with_integer=render_assembly(baseline).encode()
    composition=json.loads((source/"baseline/text_editor_params_composition.json").read_bytes())
    aliases=dict(composition["functions"]);aliases.update(integer="f43",retained_error="f44")
    schemas=json.loads((source/"SCHEMAS.json").read_bytes())["types"]
    output.mkdir(parents=True)
    receipts=[]
    for schema in schemas:
        constants=dict(INVALID=0xffffffff,CAPACITY=0xfffffffe,MAXIMUM=(1<<64)-1,
            REQUEST=int.from_bytes(b"HBPRQ001","little"),RESPONSE=int.from_bytes(b"HBPRR001","little"),
            META=65536,KIND=schema["id"],ENUM_COUNT=len(schema["variants"]))
        pseudo=(source/"authoring/params.pseudo").read_text()
        pseudo+=render_literals(schema)+render_fields(schema)+render_enum(schema)
        pseudo=substitute(pseudo,constants)
        replacements=dict(entry="f0",project="f1",enum_kind="f3",error="f4",header="f5",
            field_key="f6",enum_byte="f7",literal="f8")
        additions=dict(typed_field="f45",success="f46",field_type="f47",required="f48")
        raw,after,retained=compile_delta(a.hepta,original_with_integer,aliases,pseudo,
            replacements,additions,(("f4","f44"),))
        document=assemble_program(raw).as_dict();document["module"]=schema["name"]+"_typed_params"
        raw=render_assembly(document).encode()
        actual={f["name"]:f for f in assemble_program(raw).as_dict()["functions"]}
        for name,body in before.items():
            if name not in replacements.values():assert actual[name]==body,name
        assert actual["f43"]==integer
        restored=copy.deepcopy(actual["f44"]);restored["name"]="f4"
        assert restored==before["f4"]
        ops=sum(len(b["ops"]) for f in actual.values() for b in f["blocks"])
        assert ops<=8192
        name=schema["name"]+"_params"
        (output/(name+".hepta")).write_bytes(raw)
        (output/(name+".pseudo")).write_text(pseudo)
        receipt=dict(schema="hepta.runtime.binary-params.authored.v1",kind=schema["id"],
            target_commit="d3d75c30719db966b004756f610007a7c723729e",
            target_type=schema["type"],source_sha256=SHA(raw),source_bytes=len(raw),
            baseline_sha256=BASELINE,integer_source_sha256=INTEGER_BASELINE,
            integer_exact_relocation={"f3":"f43","call_f19":"f11"},
            retained_exact_functions=retained,relocated_exact_functions={"f4":"f44"},
            aliases={**aliases,**replacements,**additions},constants=constants,
            function_sha256={key:SHA(CANON(value)) for key,value in actual.items()},
            functions=len(actual),instructions=ops,
            typed_canonical_map=True,root_value_reentry=False,
            body_semantics=False,config_authority=False,syscalls=False,
            native_compiled=False,native_executed=False,original_compared=False,
            public_route_integrated=False,whole_runtime_qualified=False)
        (output/(name+"_composition.json")).write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
        receipts.append({key:receipt[key] for key in ("kind","source_sha256","source_bytes","functions","instructions")})
    print(json.dumps(dict(schema="hepta.runtime.binary-params.authoring-result.v1",owners=receipts),sort_keys=True))

if __name__=="__main__":main()
