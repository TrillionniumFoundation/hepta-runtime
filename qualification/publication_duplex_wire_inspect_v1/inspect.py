#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Read complete retained producer bytes; never execute either application."""
from pathlib import Path
import argparse,json,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
def main():
    p=argparse.ArgumentParser();p.add_argument("--retained",type=Path,required=True)
    p.add_argument("--build-recipe",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    sys.path.insert(0,str(a.retained));from common import canonical,decode,pin,require,source_evidence
    from buffer_store import Reader
    import readonly
    source=source_evidence(a.retained);own=decode((HERE/"SOURCE_MANIFEST.json").read_bytes())
    for r in own["files"]:require(pin(HERE/r["path"])=={k:r[k] for k in ("bytes","sha256")},"inspector source pin")
    sys.path.insert(0,str(a.build_recipe/"current"));from restore_full import restore
    inputs=decode((a.retained/"RETAINED_INPUTS.json").read_bytes())
    original,old_archive=restore(a.output/"original",inputs["original"])
    native,new_archive=restore(a.output/"native",dict(artifact=14339243128,
        zip=dict(bytes=4126054,sha256="3505b508966a12198c2235860c84186662f59628d64cf70a782da9e465880c1c"),
        archive=dict(bytes=4021796,sha256="53d1846429b20e2c52adaebf7e67d3415aa43ccd3a5a83a933b34daeb7fd5795")))
    def operation():
        n=native/"capture/native/cases/000";o=original/"capture/domain/cases/000"
        nr=Reader(n/"buffers");orr=Reader(o/"buffers")
        nc=decode((n/"COMMANDS.json").read_bytes());oc=decode((o/"COMMANDS.json").read_bytes())
        require(len(nc)==len(oc),"complete retained command sequence")
        rows=[]
        for i,(left,right) in enumerate(zip(nc,oc,strict=True)):
            nq=nr.get(left["request"]);oq=orr.get(right["request"])
            require(nq==oq and left["source_step"]==right["source_step"],"exact retained input")
            old=decode(orr.get(right["response"]));actual=left["result"];expected=old["result"]
            row=dict(number=i,request=decode(nq),actual=actual,expected=expected,
                equal=actual==expected,native_control=left["state_control"])
            if "wire_hex" in actual and "wire_hex" in expected:
                x=bytes.fromhex(actual["wire_hex"]);y=bytes.fromhex(expected["wire_hex"])
                row.update(actual_wire=x.decode("utf-8"),expected_wire=y.decode("utf-8"))
            rows.append(row)
        return dict(status="DIAGNOSTIC_COMPLETE_RETAINED_COMMAND_BYTES_READ",
            commands=rows,source=source,original_archive=old_archive,native_archive=new_archive,
            native_executed=False,rust_executed=False,semantic_replay=False,qualification=False)
    proof=readonly.guarded(operation,roots=[HERE,a.retained,native,original])
    (a.output/"READONLY.json").write_bytes(canonical(proof))
    (a.output/"DIAGNOSTIC.json").write_bytes(canonical(proof["evidence"]))
    print("RETAINED_WIRE_DIAGNOSTIC "+json.dumps(proof["evidence"],ensure_ascii=True,sort_keys=True),flush=True)
if __name__=="__main__":main()
