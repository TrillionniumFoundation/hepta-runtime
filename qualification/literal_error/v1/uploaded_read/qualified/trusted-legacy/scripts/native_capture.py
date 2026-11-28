#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""One actual HIA call per frozen case; full input and mutable spans retained."""
from pathlib import Path
import argparse,ctypes,gzip,hashlib,os,struct,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from common import canonical,decode,require,source_evidence,pin,sha
import cases
def main():
    from hia_native_loader import NativeModule
    p=argparse.ArgumentParser();p.add_argument("--group",required=True);p.add_argument("--capture",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True);a=p.parse_args();frozen=source_evidence(ROOT)
    require(not a.output.exists(),"fresh native group");a.output.mkdir(parents=True)
    build=decode((a.capture/"build/formatter.json").read_bytes());member=build["member"]
    manifest=a.capture/member["manifest"]
    module=NativeModule(manifest,manifest_sha256=member["manifest_sha256"])
    records=[];offset=0;whole=hashlib.sha256();success=False;previous=None
    artifacts={member["manifest"]:pin(manifest)}
    for name in("source","image"):artifacts[str((manifest.parent/module.metadata[name]).relative_to(a.capture))]=pin(manifest.parent/module.metadata[name])
    raw=(a.output/"records.bin.gz").open("xb")
    stream=gzip.GzipFile(filename="",mode="wb",fileobj=raw,compresslevel=1,mtime=0)
    try:
        values=cases.controls()if a.group=="controls"else list(cases.cases(a.group))
        for value in values:
            control=a.group=="controls"
            wire=value["wire"]if control else cases.frame(value)
            capacity=value["output_capacity"]if control else cases.capacity(value)
            work_size=value["workspace_capacity"]if control else cases.WORK+31
            before=previous if control and value.get("reuse")else b"\x7b"*work_size
            require(len(before)==work_size,"retained workspace size")
            old=b"\xa5"*capacity
            with module.session(workspace_capacity=work_size,output_capacity=capacity)as session:
                if before:ctypes.memmove(session._workspace,before,len(before))
                if old:ctypes.memmove(session._output,old,len(old))
                code,out,after=session.invoke_raw(wire)
            header=struct.pack("<8Q",value["case_id"],code,len(wire),capacity,work_size,len(records)+1,0,0)
            digest=hashlib.sha256();size=0
            for span in(header,wire,before,old,out,after):
                stream.write(span);digest.update(span);whole.update(span);size+=len(span)
            record=dict(case_id=value["case_id"],label=value["label"],offset=offset,bytes=size,
                return_code=code,input_bytes=len(wire),input_sha256=sha(wire),output_capacity=capacity,
                workspace_capacity=work_size,before_sha256=sha(before),output_before_sha256=sha(old),
                output_sha256=sha(out),after_sha256=sha(after),record_sha256=digest.hexdigest())
            records.append(record);offset+=size;previous=after
        success=True
    finally:
        stream.close();raw.close();module.close()
        require(artifacts=={p:pin(a.capture/p)for p in artifacts},"admitted image/source changed")
        (a.output/"records.json").write_bytes(canonical(records))
        result=dict(status="PASS"if success else"FAIL",schema="hepta.runtime.path-error.native.v1",
            group=a.group,cases=len(records),raw=dict(bytes=offset,sha256=whole.hexdigest()),
            compressed=pin(a.output/"records.bin.gz"),records=pin(a.output/"records.json"),
            source=frozen,artifacts=artifacts,pid=os.getpid(),python=sys.executable,
            original_result_read=False,semantic_replay=False)
        require(source_evidence(ROOT)==frozen,"source changed during native capture")
        (a.output/"CAPTURE.json").write_bytes(canonical(result));print(canonical(result).decode(),end="")
if __name__=="__main__":main()
