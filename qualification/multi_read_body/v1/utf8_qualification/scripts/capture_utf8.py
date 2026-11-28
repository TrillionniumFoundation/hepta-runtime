#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Capture one frozen UTF-8 lane once; original results never enter the native process."""
from pathlib import Path
import argparse,ast,gzip,hashlib,os,struct,sys,traceback
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import encoded,decode,pin,require,source_evidence,sha
from buffer_store import Writer
from inputs import GROUPS,inputs,public_input
PYTHON_PIN=dict(bytes=8020928,sha256="e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f")
def original_decoder(source):
    raw=(source/"trusted-build/target/multi_read_host.py").read_bytes()
    module=ast.parse(raw)
    function=next(n for n in module.body if isinstance(n,ast.FunctionDef) and n.name=="multi_read")
    calls=[n for n in ast.walk(function) if isinstance(n,ast.Call)
        and isinstance(n.func,ast.Attribute) and n.func.attr=="decode"]
    expected=ast.parse("data.decode('utf-8', errors='strict')",mode="eval").body
    require(len(calls)==1 and ast.dump(calls[0],include_attributes=False)==ast.dump(expected,include_attributes=False),
        "actual target strict decoder expression changed")
    expression=ast.Expression(body=calls[0]);ast.fix_missing_locations(expression)
    code=compile(expression,str(source/"trusted-build/target/multi_read_host.py"),"eval")
    identity=dict(target=pin(source/"trusted-build/target/multi_read_host.py"),
        expression=ast.dump(calls[0],include_attributes=False),
        descriptor_type=type(bytes.decode).__name__,descriptor_name=bytes.decode.__name__,
        descriptor_class=bytes.decode.__objclass__.__name__)
    require(identity["descriptor_type"]=="method_descriptor" and identity["descriptor_name"]=="decode"
        and identity["descriptor_class"]=="bytes","actual CPython bytes decoder identity")
    return code,identity
def main():
    p=argparse.ArgumentParser();p.add_argument("--role",choices=["original","native"],required=True)
    p.add_argument("--group",choices=GROUPS,required=True);p.add_argument("--output",type=Path,required=True)
    p.add_argument("--build",type=Path);a=p.parse_args()
    identity=source_evidence(ROOT)
    require(sys.implementation.name=="cpython" and tuple(sys.version_info[:3])==(3,12,3)
        and pin(Path(sys.executable).resolve())==PYTHON_PIN,"exact frozen CPython reference binary")
    output=a.output.absolute();output.mkdir(parents=True,exist_ok=False)
    store=Writer(output/"buffers");carrier=None;hooks=None;completed=0;current=None
    digest=hashlib.sha256();raw_bytes=0;line_hashes=[];counts={}
    actual_python=dict(executable=str(Path(sys.executable).resolve()),binary=pin(Path(sys.executable).resolve()),
        version=sys.version,implementation=sys.implementation.name,pid=os.getpid(),pgid=os.getpgrp())
    code=None;decoder_identity=None
    if a.role=="original":code,decoder_identity=original_decoder(ROOT)
    else:
        require(a.build is not None,"native build missing")
        from carrier import Carrier
        from utf8_hooks import EOFHooks
        binary=a.build.resolve(strict=True)/"multi-read-body-callable.elf"
        require(pin(binary)==decode((ROOT/"BUILD_REUSE.json").read_bytes())["elf"],"exact frozen native image")
        carrier=Carrier(binary,output,store);hooks=EOFHooks(carrier,store);carrier.hooks=hooks
    try:
        with (output/"cases.jsonl.gz").open("xb") as raw_file:
            with gzip.GzipFile(filename="",mode="wb",fileobj=raw_file,mtime=0,compresslevel=1) as rows:
                for item in inputs(a.group):
                    if a.role=="original" and item["kind"]!="semantic":continue
                    current=item["id"]
                    row=dict(id=current,input=public_input(item))
                    if a.role=="original":
                        data=item["data"];row["actual_input"]=store.put(data)
                        try:
                            value=eval(code,{"__builtins__":{}},{"data":data})
                        except UnicodeDecodeError as exc:
                            row["result"]=dict(kind="error",type=type(exc).__name__,encoding=exc.encoding,
                                start=exc.start,end=exc.end,reason=exc.reason,object=store.put(bytes(exc.object)),
                                message=str(exc),diagnostic=type(exc).__name__+": "+str(exc))
                        else:
                            row["result"]=dict(kind="valid",text_utf8=store.put(value.encode("utf-8")),
                                codepoints=len(value))
                    else:
                        payload=struct.pack("<4Q",item["out_capacity"],item["work_capacity"],
                            item["out_seed"],item["work_seed"])+item["wire"]
                        complete,exchange=carrier.exchange(21,0,payload)
                        row.update(packet=store.put(payload),complete_reply=store.put(complete),exchange=exchange)
                    line=encoded(row);rows.write(line);digest.update(line);raw_bytes+=len(line)
                    line_hashes.append(sha(line));completed+=1
                    counts[item["kind"]]=counts.get(item["kind"],0)+1
        receipt=None
        if carrier:
            receipt=carrier.finish()
            require(len(hooks.rows)==1 and carrier.journal_bytes==0,"no body execution and one final EOF")
        require(source_evidence(ROOT)==identity,"source changed during actual capture")
        report=dict(status="PASS",role=a.role,group=a.group,source=identity,actual_python=actual_python,
            original_decoder=decoder_identity,cases=completed,kinds=counts,
            case_stream=dict(raw=dict(bytes=raw_bytes,sha256=digest.hexdigest()),
                compressed=pin(output/"cases.jsonl.gz"),line_sha256=line_hashes),
            original_decode_calls=completed if a.role=="original" else 0,
            native_utf8_calls=completed if a.role=="native" else 0,
            body_or_parent_application_calls=0,
            buffers=dict(images=store.images,logical_bytes=store.logical_bytes,blocks=len(store.known)),
            native_receipt=receipt,eof=[] if hooks is None else hooks.rows,
            expected_outputs_supplied_to_native=False)
        (output/"CAPTURE.json").write_bytes(encoded(report))
        print(encoded(dict(status="PASS",role=a.role,group=a.group,cases=completed,
            original_decode_calls=report["original_decode_calls"],native_utf8_calls=report["native_utf8_calls"],
            body_or_parent_application_calls=0)).decode(),end="")
    except BaseException as exc:
        (output/"FAILURE.json").write_bytes(encoded(dict(status="FAIL",role=a.role,group=a.group,
            completed=completed,current=current,type=type(exc).__name__,message=str(exc),traceback=traceback.format_exc())))
        raise
    finally:
        if carrier is not None:carrier.cleanup()
if __name__=="__main__":main()
