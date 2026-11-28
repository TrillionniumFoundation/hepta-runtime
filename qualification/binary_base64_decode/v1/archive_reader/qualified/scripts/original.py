#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual CPython base64.b64decode(validate=True); no HIA result or loader."""
from pathlib import Path
import argparse,base64,binascii,gzip,hashlib,os,struct,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from common import canonical,require,source_evidence,pin,sha
import cases,runtime_binding
def main():
    p=argparse.ArgumentParser();p.add_argument("--group",required=True)
    p.add_argument("--capture",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();frozen=source_evidence(ROOT);runtime=runtime_binding.bound(a.capture)
    require(not a.output.exists(),"fresh original group");a.output.mkdir(parents=True)
    records=[];offset=0;whole=hashlib.sha256()
    with(a.output/"records.bin.gz").open("xb")as raw,gzip.GzipFile(filename="",mode="wb",fileobj=raw,compresslevel=1,mtime=0)as stream:
        for value in cases.cases(a.group):
            wire=cases.frame(value);text=value["payload"].decode("utf-8")
            try:
                data=base64.b64decode(text,validate=True)
            except(ValueError,binascii.Error)as error:
                actual_class=type(error).__name__
                require(actual_class in("ValueError","Error"),"unexpected actual exception class")
                payload=str(error).encode("utf-8");klass=1 if actual_class=="ValueError"else 15
                response=b"HBRDS001"+struct.pack("<7Q",3,0,klass,0,len(payload),0,len(payload))+payload
                actual=dict(kind="error",class_name=actual_class,message=payload.decode("utf-8"))
            else:
                require(type(data)is bytes,"actual base64 result type")
                response=b"HBRDS001"+struct.pack("<7Q",0,0,0,0,0,0,len(data))+data
                actual=dict(kind="bytes",bytes=len(data),sha256=sha(data))
            header=struct.pack("<3Q",value["case_id"],len(wire),len(response))
            block=header+wire+response;stream.write(block);whole.update(block)
            records.append(dict(**cases.public_row(value),offset=offset,bytes=len(block),
                response_bytes=len(response),response_sha256=sha(response),record_sha256=sha(block),actual=actual))
            offset+=len(block)
    (a.output/"records.json").write_bytes(canonical(records))
    result=dict(status="PASS",schema="hepta.runtime.binary-base64-decode.original.v1",
        group=a.group,cases=len(records),raw=dict(bytes=offset,sha256=whole.hexdigest()),
        compressed=pin(a.output/"records.bin.gz"),records=pin(a.output/"records.json"),
        source=frozen,pid=os.getpid(),python=sys.executable,environment=runtime,
        hia_executed=False,native_result_read=False)
    require(source_evidence(ROOT)==frozen,"source changed during original capture")
    (a.output/"CAPTURE.json").write_bytes(canonical(result));print(canonical(result).decode(),end="")
if __name__=="__main__":main()
