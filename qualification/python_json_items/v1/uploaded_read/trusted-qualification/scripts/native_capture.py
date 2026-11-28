#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""One actual admitted HIA call per case; snapshot every actual byte and guard."""
import argparse,ctypes,gzip,hashlib,os,struct,sys
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from common import canonical,decode,require,pin,sha,source_evidence
import cases
def main():
    from hia_native_loader import NativeModule
    p=argparse.ArgumentParser();p.add_argument("--group",required=True);p.add_argument("--capture",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True);a=p.parse_args();identity=source_evidence(ROOT)
    require(not a.output.exists(),"fresh native capture");a.output.mkdir(parents=True)
    build=decode((a.capture/"build/module.json").read_bytes());row=build["member"];manifest=a.capture/row["manifest"]
    module=NativeModule(manifest,manifest_sha256=row["manifest_sha256"]);records=[];whole=hashlib.sha256();offset=0;success=False
    image=(manifest.parent/module.metadata["image"]).read_bytes()
    require(ctypes.string_at(module._address,module._size)==image,"complete actual sealed code mapping before calls")
    artifacts={row["manifest"]:pin(manifest)}
    for name in("source","image"):artifacts[str((manifest.parent/module.metadata[name]).relative_to(a.capture))]=pin(manifest.parent/module.metadata[name])
    raw=(a.output/"records.bin.gz").open("xb");stream=gzip.GzipFile(filename="",mode="wb",fileobj=raw,compresslevel=1,mtime=0)
    try:
        values=cases.controls()if a.group=="controls"else cases.cases(int(a.group))
        for value in values:
            wire=value["wire"];capacity=value["output_capacity"];work_size=value["workspace_capacity"]
            source_bytes=(wire or b"\0")+b"\xb6"*16;output_bytes=bytes([value["output_fill"]])*capacity+b"\xa5"*16
            work_bytes=bytes([value["workspace_fill"]])*work_size+b"\x5a"*16
            inp=ctypes.create_string_buffer(source_bytes,len(source_bytes));out=ctypes.create_string_buffer(output_bytes,len(output_bytes))
            work=ctypes.create_string_buffer(work_bytes,len(work_bytes))
            before_input=inp.raw;before_output=out.raw;before_work=work.raw
            code=module._entry(inp,len(wire),out,capacity,work,work_size)
            after_input=inp.raw;after_output=out.raw;after_work=work.raw
            header=struct.pack("<10Q",value["case_id"],code,len(wire),len(source_bytes),capacity,work_size,len(records)+1,0,0,0)
            digest=hashlib.sha256();size=0
            for span in(header,before_input,after_input,before_output,after_output,before_work,after_work):
                stream.write(span);digest.update(span);whole.update(span);size+=len(span)
            records.append(dict(case_id=value["case_id"],label=value["label"],offset=offset,bytes=size,
                return_code=code,input_bytes=len(wire),input_sha256=sha(wire),output_capacity=capacity,workspace_capacity=work_size,
                record_sha256=digest.hexdigest(),before=[sha(before_input),sha(before_output),sha(before_work)],
                after=[sha(after_input),sha(after_output),sha(after_work)]))
            offset+=size
        success=True
    finally:
        stream.close();raw.close()
        mapped=ctypes.string_at(module._address,module._size);module.close()
        require(mapped==image and artifacts=={k:pin(a.capture/k)for k in artifacts},"all admitted source and actual code bytes remain exact")
        (a.output/"records.json").write_bytes(canonical(records))
        result=dict(schema="hepta.runtime.python-json-items.native.v2",status="PASS"if success else"FAIL",
            group=a.group,cases=len(records),raw=dict(bytes=offset,sha256=whole.hexdigest()),compressed=pin(a.output/"records.bin.gz"),
            records=pin(a.output/"records.json"),source=identity,artifacts=artifacts,pid=os.getpid(),python=sys.executable,
            code_mapping_before_after=sha(image),actual_guard_bytes_retained=True,original_results_read=False,application_replay=False)
        require(source_evidence(ROOT)==identity,"source unchanged during native capture")
        (a.output/"CAPTURE.json").write_bytes(canonical(result));print(canonical(result).decode(),end="")
if __name__=="__main__":main()
