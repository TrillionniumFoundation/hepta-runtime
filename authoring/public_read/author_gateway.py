#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Compose read ordering over the original owned continuation implementation."""
from pathlib import Path
import argparse
import json
import sys
sys.dont_write_bytecode = True

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--source",type=Path,required=True)
    parser.add_argument("--hepta",type=Path,required=True)
    args=parser.parse_args(); root=args.source.resolve(strict=True)
    sys.path.insert(0,str(root/"authoring/public_publication_v1"))
    import source_support as support
    api=support.tools(args.hepta.resolve(strict=True))
    baseline=(root/"native/extract_gateway.hepta").read_bytes()
    composition=json.loads((root/"native/extract_gateway_composition.json").read_bytes())
    replacements=dict(zip(("HEXWGQ02","HEXWGQ03","HEXWGS01","HEXWGA01"),
                          ("HRDIQ002","HRDRQ002","HRDWS001","HRDWGA01")))
    renamed,changes=support.renamed(api,baseline,replacements,"runtime_public_read_gateway")
    constants={"INVALID":0xffffffff,"MAXIMUM":(1<<64)-1,
       **{name:support.WORD(value) for name,value in {
         "INFO_REQUEST":"HRDIQ002","MULTI_REQUEST":"HRDMQ002",
         "MULTI_PARAMS_REQUEST":"HMRPQ001","MULTI_PARAMS_RESULT":"HMRPR001",
         "MULTI_PLAN_REQUEST":"HMRLQ001","MULTI_PLAN_RESULT":"HMRLR001",
         "TEXT_REQUEST":"HRTCRQ01","TEXT_RESULT":"HRTCRS01","PARAMS_REQUEST":"HBPRQ001","PARAMS_RESULT":"HBPRR001",
         "PLAN_REQUEST":"HBPLQ001","PLAN_RESULT":"HBPLR001","MESSAGE":"HRCFGM01",
         "CONFIG_REQUEST":"HRCFGQ01","SSH_REQUEST":"HRSSQ001","CAPTURE_RESULT":"HRSCAP01",
         "DIAGNOSTIC_REQUEST":"HSJERQ01","DIAGNOSTIC_RESULT":"HSJERR01",
         "VALUE_RESULT":"HJSVR002","TRANSPORT_REQUEST":"HRTRQ001","TRANSPORT_RESULT":"HRTRR001"}.items()}}
    # Retain the complete original arena allocator; add only the eighth region
    # for the owned SSH capture. The original extract gateway uses 0..6.
    reserve_id=composition["aliases"]["reserve"]
    marker=("fn "+reserve_id+"(").encode()
    begin=renamed.index(marker); end=renamed.index(b"\nend",begin)+4
    original_reserve=renamed[begin:end]
    old=b'  v57:u64 = const() {"value":6}'
    new=b'  v57:u64 = const() {"value":7}'
    if original_reserve.count(old)!=1:
        raise ValueError("original exact arena region bound differs")
    extended_reserve=original_reserve.replace(old,new)
    extended=renamed[:begin]+extended_reserve+renamed[end:]
    if extended[:begin]+extended_reserve.replace(new,old)+extended[end+len(extended_reserve)-len(original_reserve):]!=renamed:
        raise ValueError("arena region extension inverse differs")
    arena_proof={"original_regions":7,"current_regions":8,
        "original_function":support.identity(original_reserve),
        "current_function":support.identity(extended_reserve),
        "only_changed_constant":{"old":6,"new":7},"complete_function_inverse":True}
    renamed=extended
    # Admit exactly the third private request identity; retain the entire
    # original continuation/admission function and prove the whole inverse.
    begin=renamed.index(b"fn f0(");end=renamed.index(b"\nend",begin)+4
    old_entry=renamed[begin:end]
    old=b'  v57:bool = compare.ne(v55,v56)\n  jump b6(v44,v45,v46,v57)'
    new=(b'  v57:bool = compare.ne(v55,v56)\n'
      +('  v1103:u64 = const() {"value":'+str(support.WORD("HRDMQ002"))+'}\n').encode()
      +b'  v1104:bool = compare.ne(v55,v1103)\n'
      +b'  v1105:bool = bool.and(v57,v1104)\n'
      +b'  jump b6(v44,v45,v46,v1105)')
    if old_entry.count(old)!=1 or b"v1103" in old_entry:
        raise ValueError("original gateway request admission differs")
    current_entry=old_entry.replace(old,new)
    if current_entry.replace(new,old)!=old_entry:
        raise ValueError("complete gateway request admission inverse differs")
    renamed=renamed[:begin]+current_entry+renamed[end:]
    entry_proof={"baseline":support.identity(old_entry),"current":support.identity(current_entry),
      "additional_request":"HRDMQ002","complete_function_inverse":True}
    raw,names,proof=support.compile_delta(api,renamed,composition["aliases"],
        (root/"authoring/public_read/gateway.pseudo").read_text(),constants,"runtime_public_read_gateway")
    proof.update(schema="hepta.runtime.public-read.gateway-author.v1",baseline=support.identity(baseline),
       arena_region_extension=arena_proof,request_admission_extension=entry_proof,private_magic_changes=changes,aliases=names,child_slots=[71,72,70,11,74,77,10,81,75,76,46],
       ordered_operations=["typed","binary-plan","installed-root","binary-plan-resume","installed-target","ssh","transport-result","actual-Value","transport-result-resume"],
       write_fence_used=False,permission_owner="original config operations9/11/12",deadline_owner="ssh capture future",
       public_route_qualified=False,old_stack_removed=False)
    (root/"native/public_read_gateway.hepta").write_bytes(raw)
    (root/"native/public_read_gateway_composition.json").write_bytes(support.ENCODE(proof))
    print(json.dumps({"source_sha256":support.SHA(raw),"bytes":len(raw),"functions":len(names),
                      "public_route_qualified":False},sort_keys=True))
if __name__=="__main__":
    main()
