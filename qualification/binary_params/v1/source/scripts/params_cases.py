#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Frozen input-only domain for five exact binary tool parameter declarations."""
from pathlib import Path
import json
ROOT=Path(__file__).resolve().parents[1]
def dumps(value):
    return json.dumps(value,ensure_ascii=False,separators=(",",":"),allow_nan=False)
def schemas():
    return json.loads((ROOT/"SCHEMAS.json").read_bytes())["types"]
def base(kind):
    return {
        1:dict(host="operator",path="/allowed/payload.bin"),
        2:dict(host="operator",path="/allowed/payload.bin",offset=13,limit=32768,expected_version="v1"),
        3:dict(host="operator",path="/allowed/payload.bin",data_base64="AA==",expected_version="absent"),
        4:dict(host="operator",path="/allowed/payload.bin",action="chunk",upload_id="upload-01",
               offset=0,data_base64="AA==",expected_version="absent",size=1,sha256="0"*64),
        5:dict(host="operator",path="/allowed/payload.bin",action="apply",transaction_id="txn-01",
               acknowledge_non_atomic=True,preserve_special_bits=False,offset=0,
               expected_version="v1",expected_sha256="0"*64,data_base64="AA=="),
    }[kind]
def cases():
    rows=[]
    def raw(kind,name,text):
        rows.append(dict(case_id=len(rows),kind=kind,name=str(kind)+"-"+name,raw_json=text))
    def add(kind,name,value):raw(kind,name,dumps(value))
    values=[None,False,True,0,-1,17,17.0,1.5,"",[],[1],{},{"a":1},
            {"chunk":None},{"apply":None},{"chunk":{}},{"apply":False},
            {"chunk":None,"commit":None}]
    for schema in schemas():
        kind=schema["id"]; value=base(kind); fields=schema["fields"]
        add(kind,"base",value)
        for name,field,typ in fields:
            missing=dict(value);missing.pop(name,None)
            add(kind,"missing-"+name,missing)
            for index,item in enumerate(values):
                add(kind,"type-"+name+"-"+str(index),{**value,name:item})
            if typ in ("string","option_string"):
                for index,item in enumerate(("",".","..","a/../b","a\u0000b","λ🙂中",
                    "\\\"\t\b\f\n\r","a\x60b","\u2028\u2029","/allowed//child/./item")):
                    add(kind,"string-"+name+"-"+str(index),{**value,name:item})
            if typ=="option_u64":
                for number in (0,1,32767,32768,65535,65536,65537,2**53-1,2**53,2**53+1,
                               2**63-1,2**63,2**64-1,-(2**63),2**64,2**64+1):
                    add(kind,"integer-"+name+"-"+str(number),{**value,name:number})
                for number in ("-0","-0.0","1e0","1e30","1.2345678901234567","18446744073709551616",
                               "-9223372036854775809"):
                    text="{"+",".join(dumps(key)+":"+(number if key==name else dumps(item))
                        for key,item in value.items())+"}"
                    raw(kind,"number-spelling-"+name+"-"+number,text)
        required=[name for name,field,typ in fields if typ in ("string","bool","enum")]
        for mask in range(1<<len(required)):
            add(kind,"required-presence-"+str(mask),
                {name:value[name] for index,name in enumerate(required) if mask&(1<<index)})
        optional=[name for name,field,typ in fields if typ.startswith("option") or typ=="default_bool"]
        for mask in range(1<<len(optional)):
            obj={name:value[name] for name in required}
            for index,name in enumerate(optional):
                if mask&(1<<index):obj[name]=value[name]
            add(kind,"optional-presence-"+str(mask),obj)
        for variant in schema["variants"]:
            add(kind,"enum-"+variant,{**value,"action":variant})
            add(kind,"enum-map-"+variant,{**value,"action":{variant:None}})
            add(kind,"enum-map-nonunit-"+variant,{**value,"action":{variant:False}})
        if schema["variants"]:
            for index,variant in enumerate(("","unknown","APPLY","λ🙂","a\x60b","a\n\u0000b")):
                add(kind,"unknown-enum-"+str(index),{**value,"action":variant})
                add(kind,"unknown-enum-map-"+str(index),{**value,"action":{variant:None}})
            add(kind,"enum-multiple-keys",{**value,"action":{x:None for x in schema["variants"]}})
        for index,name in enumerate(("root","ssh_target","sudo","command","_meta","aaa","zzz","λ","a\x60b","a\n\u0000b")):
            add(kind,"unknown-"+str(index),{**value,name:None})
            add(kind,"unknown-before-missing-"+str(index),{name:1})
            add(kind,"unknown-and-bad-host-"+str(index),{**value,"host":False,name:None})
        for index,root in enumerate((None,False,True,17,17.0,"text",[],[value])):
            add(kind,"root-"+str(index),root)
        raw(kind,"duplicate-host-last",'{"host":false,'+dumps(value)[1:])
        raw(kind,"duplicate-path-last",'{"path":null,'+dumps(value)[1:])
        raw(kind,"escaped-host-key",dumps(value).replace('"host":','"h\\u006fst":',1))
        raw(kind,"whitespace"," \n "+json.dumps(value,ensure_ascii=True,indent=2)+" \t")
        for index,text in enumerate(("", "{", "{} trailing", '{"host":}', '{"path":"unterminated}',
                                     '{"path":"\\uD800"}', "[1,]",'{"host":"\\uDC00"}')):
            raw(kind,"raw-json-refusal-"+str(index),text)
        for name in ("host","path"):
            for length in (4095,4096,4097):
                add(kind,"long-"+name+"-"+str(length),{**value,name:"a"*length})
    for kind in (3,4,5):
        for length in (87383,87384,87385,1398103,1398104,1398105):
            add(kind,"typed-string-body-boundary-"+str(length),{**base(kind),"data_base64":"A"*length})
    assert len({r["name"] for r in rows})==len(rows)
    assert {r["kind"] for r in rows}==set(range(1,6))
    return rows
def encoded():
    return b"".join((dumps(row)+"\n").encode() for row in cases())
def control_values(kind):
    good=base(kind)
    bad={**good,"host":False}
    return [json.dumps(item,ensure_ascii=False,sort_keys=True,separators=(",",":")).encode()
            for item in (good,bad)]
if __name__=="__main__":
    import sys
    sys.stdout.buffer.write(encoded())
