#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Test-only host for the actual HIA audit owner and syscall-only boundary.

No audit operation, filesystem decision, canonicalization, serialization or
namespace decision is implemented in this driver. JSON is only the comparison
transport. The public runtime calls these same SysV symbols from its assembly.
"""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import struct
import sys
import time
from hia_native_loader import NativeModule


class Audit:
    def __init__(self,library,manifests,*,secure=0,test_probes=False):
        self.modules=[];self.context=0
        self.test_probes=test_probes
        build=json.loads((Path(library).parent/"BUILD.json").read_text())
        if build.get("test_only_effect_probes",False)!=test_probes:
            raise ValueError("test probe use differs from carrier build")
        if hashlib.sha256(Path(library).read_bytes()).hexdigest()!=build["library_pin"]["sha256"]:
            raise ValueError("audit carrier identity differs")
        rows=json.loads(Path(manifests).read_text())
        ordered=[]
        for role in ("append","canonical","sha","namespace","errno"):
            matches=[r for r in rows if r["name"].startswith("jobs_audit_"+role+"_")]
            if len(matches)!=1:raise ValueError("fixed child manifest is ambiguous: "+role)
            path=Path(matches[0]["manifest"])
            module=NativeModule(path,manifest_sha256=hashlib.sha256(path.read_bytes()).hexdigest())
            if module.metadata["image_sha256"]!=matches[0]["image_sha256"]:
                raise ValueError("fixed child image identity changed")
            self.modules.append(module);ordered.append(module._address)
        self.lib=ctypes.CDLL(str(Path(library).resolve(strict=True)))
        signatures={"create":([ctypes.c_void_p]*5+[ctypes.c_uint64],ctypes.c_int64),
                    "invoke":([ctypes.c_void_p,ctypes.c_void_p,ctypes.c_uint64],ctypes.c_uint64),
                    "output":([ctypes.c_void_p],ctypes.c_void_p),
                    "release":([ctypes.c_void_p],ctypes.c_int64),
                    "destroy":([ctypes.c_void_p],ctypes.c_int64)}
        for name,(args,result) in signatures.items():
            fn=getattr(self.lib,"jobs_audit_"+name);fn.argtypes=args;fn.restype=result
        self.context=self.lib.jobs_audit_create(*ordered,secure)
        if self.context<=0:raise OSError(-self.context,"native audit context creation")

    @staticmethod
    def request(root,host,subject,operation="write"):
        fields=[text.encode("utf-8") for text in (root,host,subject,operation)]
        return b"HBAUQ001"+struct.pack("<7Q",1,*(len(part) for part in fields),0,0)+b"".join(fields)

    def configure_probe(self,opcode=0,ordinal=0,error=5):
        if not self.test_probes:raise ValueError("effect injection requires an explicit test carrier")
        if not 0<=opcode<=22 or not 0<=ordinal<1<<63 or not 1<=error<=4095:
            raise ValueError("invalid closed effect fault probe")
        if ctypes.c_uint64.from_address(self.context+64).value!=0:
            raise ValueError("cannot change a leased test carrier")
        ctypes.memset(self.context+768,0,176)
        ctypes.memmove(self.context+944,struct.pack("<3Q",opcode,ordinal,error),24)

    def invoke(self,wire):
        source=ctypes.create_string_buffer(wire,max(1,len(wire)))
        started=time.monotonic_ns()
        code=self.lib.jobs_audit_invoke(self.context,source,len(wire))
        elapsed=time.monotonic_ns()-started
        output=self.lib.jobs_audit_output(self.context)
        frame=ctypes.string_at(output,code) if output and code<0xffff0000 else b""
        if source.raw!=(wire or b"\0"):raise AssertionError("audit input bytes changed")
        state=self.diagnostic()
        if output:
            released=self.lib.jobs_audit_release(self.context)
            if released:raise OSError(-released,"audit result release")
        result={"code":code,"frame_hex":frame.hex(),"elapsed_ns":elapsed,"state":state}
        if self.test_probes:
            result["test_effect_counts"]=list(struct.unpack("<22Q",ctypes.string_at(self.context+768,176)))
        return result

    def diagnostic(self):
        words=struct.unpack("<34Q",ctypes.string_at(self.context,272))
        work=words[13]
        header=struct.unpack("<48Q",ctypes.string_at(work,384)) if work else [0]*48
        return {"lease":words[8],"workspace_capacity":words[14],"sequence":words[18],
                "next_handle":words[19],"live_handles":words[20],"poison":words[21],
                "native_errno":ctypes.c_int64(words[22]).value,
                "owner_phase":header[1],"ready":header[16],
                "last_effect":list(header[32:48])}

    def close(self):
        if self.context:
            code=self.lib.jobs_audit_destroy(self.context)
            if code:raise OSError(-code,"native audit destruction")
            self.context=0
        for module in self.modules:module.close()
        self.modules=[]

    def __enter__(self):return self
    def __exit__(self,*args):self.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library",type=Path,required=True)
    parser.add_argument("--manifests",type=Path,required=True)
    parser.add_argument("--test-probes",action="store_true")
    args=parser.parse_args()
    audit=Audit(args.library,args.manifests,test_probes=args.test_probes)
    try:
        for line in sys.stdin:
            value=json.loads(line)
            if value.get("reset"):
                audit.close();audit=Audit(args.library,args.manifests,test_probes=args.test_probes);result={"reset":True}
            else:
                if args.test_probes:
                    fail=value.get("fail_sync","")
                    if fail=="file":probe=(9,1,5)
                    elif fail.startswith("directory:"):probe=(10,int(fail.split(":")[1])+1,5)
                    else:probe=tuple(value.get("effect_probe",(0,0,5)))
                    audit.configure_probe(*probe)
                wire=(bytes.fromhex(value["wire_hex"]) if "wire_hex" in value else
                      Audit.request(value["root"],value["host"],value["subject"],value.get("operation","write")))
                result=audit.invoke(wire)
                frame=bytes.fromhex(result["frame_hex"])
                if len(frame)>=32:
                    result["ok"]=struct.unpack_from("<Q",frame,8)[0]==0
                    result["error"]=frame[32:].decode("utf-8","strict")
            print(json.dumps(result,sort_keys=True),flush=True)
    finally:audit.close()


if __name__=="__main__":main()
