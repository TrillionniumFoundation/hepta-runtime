#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Assemble the fixed audit boundary for native development comparisons.

The shared object is a test carrier, with no libc dependency. Public linking
must include these same audited assembly bytes and fixed HIA image entries.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def pin(path):
    raw=path.read_bytes()
    return {"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--test-probes",action="store_true",
                        help="test-only effect counters and injected errno; never a public image")
    args=parser.parse_args()
    source=args.source.resolve(strict=True);out=args.output.absolute()
    out.mkdir(parents=True,exist_ok=False)
    authored=out/"canonical-authored"
    subprocess.run([sys.executable,str(source/"scripts/jobs_audit_author_canonical.py"),
                    "--source",str(source),"--output",str(authored)],check=True,
                   stdout=subprocess.PIPE)
    for name in ("jobs_audit_canonical.S","jobs_audit_canonical.json"):
        if (source/"asm"/name).read_bytes()!=(authored/name).read_bytes():
            raise ValueError("canonical source does not reproduce: "+name)
    inputs=[source/"asm/jobs_audit_pump.S",source/"asm/jobs_audit_canonical.S"]
    assembly=out/"jobs-audit-combined.S"
    original=inputs[0].read_text();pump=original;edits=[]
    if args.test_probes:
        before="""    lea rdx, [rip + ja_effect_table]
    movsxd rax, dword ptr [rdx + rax * 4 - 4]
"""
        after="""    /* TEST CARRIER ONLY: complete inverse retained in BUILD.json. */
    inc qword ptr [r15 + rax * 8 + 760]
    cmp [r15 + 944], rax
    jne ja_test_effect_admitted
    mov rcx, [r15 + rax * 8 + 760]
    cmp [r15 + 952], rcx
    jne ja_test_effect_admitted
    mov rax, [r15 + 960]
    neg rax
    jmp ja_kernel_return
ja_test_effect_admitted:
    lea rdx, [rip + ja_effect_table]
    movsxd rax, dword ptr [rdx + rax * 4 - 4]
"""
        if pump.count(before)!=1:raise ValueError("effect-table probe anchor differs")
        pump=pump.replace(before,after);edits.append({"before":before,"after":after})
        if pump.replace(after,before)!=original:raise ValueError("test probe whole-source inverse differs")
    assembly.write_bytes(pump.encode()+b"\n"+inputs[1].read_bytes())
    obj=out/"jobs-audit-pump.o";library=out/"jobs-audit-pump.so"
    subprocess.run(["as","--64","-o",str(obj),str(assembly)],check=True)
    subprocess.run(["ld","-shared","-Bsymbolic","--no-undefined","--fatal-warnings",
                    "--build-id=none","-z","noexecstack","-o",str(library),str(obj)],check=True)
    dynamic=subprocess.run(["readelf","-d",str(library)],check=True,capture_output=True,text=True).stdout
    if "NEEDED" in dynamic:raise ValueError("audit boundary imports a runtime library")
    result={"schema":"hepta.runtime.jobs-audit.pump-build.v1",
            "sources":{str(path.relative_to(source)):pin(path) for path in inputs},
            "canonical_reproduced":True,"library":str(library),"library_pin":pin(library),
            "test_only_effect_probes":args.test_probes,"exact_test_edits":edits,
            "test_carrier_whole_source_inverse":True,
            "runtime_library_dependencies":[],"public_route_qualified":False}
    (out/"BUILD.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    print(json.dumps(result,sort_keys=True))


if __name__=="__main__":main()
