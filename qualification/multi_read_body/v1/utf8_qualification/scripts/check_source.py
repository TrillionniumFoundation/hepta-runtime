#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Complete source/AST/input admission; zero original decodes or native applications."""
from pathlib import Path
import ast,hashlib,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import source_evidence,encoded,decode,pin,require
from inputs import GROUPS,inputs,public_input
from read_utf8 import original_identity
def main():
    identity=source_evidence(ROOT);syntax=0
    for path in sorted(ROOT.rglob("*.py")):
        compile(path.read_bytes(),str(path),"exec");syntax+=1
    expected_counts={name:(4096,4096) for name in GROUPS if name.startswith("pairs-")}
    expected_counts.update(singles=(262,262),scalars=(37,37),tails=(4096,4096),abi=(3,251))
    expected_counts.update({name:(2160,2160) for name in ("multi-0","multi-1","multi-2")})
    rows=[];original=0;native=0
    for group in GROUPS:
        seen=set();digest=hashlib.sha256();count=semantic=0;total=0
        for item in inputs(group):
            require(item["id"] not in seen,"unique exact input ID");seen.add(item["id"])
            require(item["kind"] in ("semantic","capacity","framing"),"input kind")
            line=encoded(public_input(item));digest.update(line);total+=len(line);count+=1
            semantic+=item["kind"]=="semantic"
            require(type(item["wire"]) is bytes and len(item["wire"])+96<=1048640
                and 0<=item["out_capacity"]<=4096 and 0<=item["work_capacity"]<=4096
                and 0<=item["out_seed"]<=255 and 0<=item["work_seed"]<=255,"real fixture input bounds")
        require((semantic,count)==expected_counts[group],"frozen domain count "+group)
        rows.append(dict(group=group,original_inputs=semantic,native_inputs=count,
            complete_input_bytes=total,input_sha256=digest.hexdigest()))
        original+=semantic;native+=count
    require(original==76414 and native==76662 and native-original==248 and len(rows)==23,
        "complete frozen domain extent")
    require(not any(isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=="decode"
        for n in ast.walk(ast.parse((ROOT/"scripts/inputs.py").read_bytes()))),"input generator must not decode")
    for name,replacements in (
        ("carrier.py",(("HBRDFQ01","HMRDFQ01"),("HBRDFR01","HMRDFR01"))),
        ("build_reuse.py",(("binary-read-body-callable.elf","multi-read-body-callable.elf"),)),
        ("read_build_evidence.py",(("asm/binary_read_body_callable.S","asm/multi_read_body_callable.S"),
            ("COMPLETE_UPLOADED_READ_ORPHANS_BUILD_AND_SEVEN_GUARDS_PASS","COMPLETE_UPLOADED_MULTI_READ_BUILD_AND_SEVEN_GUARDS_PASS"),
            ("binary_read_orphans_application_qualified=False","multi_read_body_application_qualified=False")))):
        before=(ROOT/"reference"/name).read_text()
        for old,new in replacements:require(old in before,"derivation preimage");before=before.replace(old,new)
        require(before==(ROOT/"scripts"/name).read_text(),"complete mechanical derivative "+name)
    fixture=(ROOT/"trusted-build/asm/multi_read_body_fixture.S").read_text()
    require(".Lmmf_utf8_direct:\n    cmp r13, 32\n" in fixture and ".Lmmf_utf8_direct:\n    cmp r13, 48\n" not in fixture,
        "actual short packet admission fixture")
    bound=decode((ROOT/"BUILD_REUSE.json").read_bytes())
    require(bound["commit"]=="1473d9b72f51f79154014724a96f3769d32b61cc"
        and pin(ROOT/"trusted-build/SOURCE_MANIFEST.json")["sha256"]==bound["manifest_sha256"],
        "actual native frozen source binding")
    result=dict(status="MULTI_UTF8_SOURCE_AND_INPUT_ONLY_PASS",source=identity,python_sources_compiled=syntax,
        groups=rows,original_inputs=original,native_inputs=native,private_controls=native-original,
        original_AST=original_identity(ROOT),original_decode_calls=0,native_or_rust_calls=0,
        inputs_never_expected_outputs=True)
    print(encoded(result).decode(),end="")
if __name__=="__main__":main()
