#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Execute the actual fixed CPython detect_encoding/surrogatepass expression once."""
import argparse,gzip,hashlib,json,os,struct,sys
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from common import canonical,decode,require,pin,sha,source_evidence
import cases
from runtime import verify_runtime
def main():
    p=argparse.ArgumentParser();p.add_argument("--group",required=True);p.add_argument("--runtime",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True);a=p.parse_args();identity=source_evidence(ROOT)
    runtime=verify_runtime(a.runtime);require(not a.output.exists(),"fresh original capture");a.output.mkdir(parents=True)
    records=[];whole=hashlib.sha256();offset=0;success=False
    raw=(a.output/"records.bin.gz").open("xb");stream=gzip.GzipFile(filename="",mode="wb",fileobj=raw,compresslevel=1,mtime=0)
    try:
        for value in cases.cases(int(a.group)):
            wire=value["wire"];detected=json.detect_encoding(wire)
            try:
                result=wire.decode(detected,"surrogatepass")
                payload=result.encode("utf-32-le","surrogatepass");obj=b""
                meta=dict(kind=0,detected=detected,codepoints=len(result),native_byteorder=sys.byteorder)
            except UnicodeDecodeError as error:
                payload=(type(error).__name__+": "+str(error)).encode("utf-8")
                obj=error.object
                meta=dict(kind=1,detected=detected,encoding=error.encoding,start=error.start,end=error.end,
                    reason=error.reason,native_byteorder=sys.byteorder)
            metadata=canonical(meta);header=struct.pack("<8Q",value["case_id"],len(wire),len(payload),len(obj),len(metadata),len(records)+1,0,0)
            digest=hashlib.sha256();size=0
            for span in(header,wire,payload,obj,metadata):
                stream.write(span);digest.update(span);whole.update(span);size+=len(span)
            records.append(dict(case_id=value["case_id"],label=value["label"],offset=offset,bytes=size,
                input_bytes=len(wire),input_sha256=sha(wire),payload_bytes=len(payload),payload_sha256=sha(payload),
                object_bytes=len(obj),object_sha256=sha(obj),metadata=meta,record_sha256=digest.hexdigest()))
            offset+=size
        success=True
    finally:
        stream.close();raw.close()
        require(verify_runtime(a.runtime)==runtime,"actual runtime bytes unchanged")
        (a.output/"records.json").write_bytes(canonical(records))
        result=dict(schema="hepta.runtime.python-json-bytes.original.v1",status="PASS"if success else"FAIL",
            group=a.group,cases=len(records),raw=dict(bytes=offset,sha256=whole.hexdigest()),compressed=pin(a.output/"records.bin.gz"),
            records=pin(a.output/"records.json"),source=identity,runtime=runtime,pid=os.getpid(),python=sys.executable,application_replay=False)
        require(source_evidence(ROOT)==identity,"source unchanged during original capture")
        (a.output/"CAPTURE.json").write_bytes(canonical(result));print(canonical(result).decode(),end="")
if __name__=="__main__":main()
