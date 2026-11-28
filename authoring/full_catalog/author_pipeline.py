#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Author the fixed HIA catalog pipeline without reading expected result wires."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,sys
sys.dont_write_bytecode=True
def sha(raw): return hashlib.sha256(raw).hexdigest()
def encoded(value): return (json.dumps(value,sort_keys=True,indent=2)+"\n").encode()
def require(value,message):
    if not value: raise ValueError(message)
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("source","hepta","output"):
        parser.add_argument("--"+name,required=True,type=Path)
    args=parser.parse_args();root=args.source.resolve(strict=True);out=args.output.absolute()
    require(not out.exists(),"author output must be fresh")
    support_path=root/"authoring/public_publication_v1/source_support.py"
    spec=importlib.util.spec_from_file_location("full_catalog_source_support",support_path)
    support=importlib.util.module_from_spec(spec);spec.loader.exec_module(support)
    api=support.tools(args.hepta)
    base=root/"tests/hia_native/catalog_policy_ci/source"
    profile_raw=(base/"source-profile.json").read_bytes()
    require(sha(profile_raw)=="4ac13e456d7e2ed6344a89fef73c19790dcc1c85546e2d5362de165e7d0aa6ed","complete fixed policy source profile differs")
    profile=json.loads(profile_raw);captured={}
    for name,pin in profile["files"].items():
        raw=(base/name).read_bytes()
        require(support.identity(raw)==pin,"complete policy source differs: "+name)
        captured[name]=raw
    declaration=captured["catalog-input.json"];tools=json.loads(declaration)
    require(len(tools)==136 and len({t["name"] for t in tools})==136,"complete raw declaration domain differs")
    old=(root/"native/runtime_mcp_catalog_ninth.hepta").read_bytes()
    require(sha(old)=="c555bec54b9f7affd6ea85b8db005e334fecc4388897433b7b03ed557aa585c8","retained catalog source differs")
    composition_raw=(root/"native/runtime_mcp_catalog_ninth_composition.json").read_bytes()
    comp=json.loads(composition_raw)
    require(comp["source_sha256"]==sha(old) and comp["source_bytes"]==len(old),"retained catalog composition differs")
    roots={name:comp["aliases"][name] for name in ("load","get","put","grow","finish")}
    constants={"INVALID":0xffffffff,"RESOURCE":0xfffffffe,"ACTION":0xffffffb1,"OLD":0xffffffb2,
        "FRAME":support.WORD("HFCAPQ01"),"QUERY":support.WORD("HRMCD002"),
        "POLICY_QUERY":support.WORD("HCATCQ01"),"POLICY_REPLY":support.WORD("HCATCR01"),
        "VALUE_QUERY":support.WORD("HSJVAL01"),"SDK_QUERY":support.WORD("HRRSP001"),
        "SDK_REPLY":support.WORD("HRRPO001"),"RESULT_PREFIX":support.WORD(',"result'),
        "DECLARATION_BYTES":len(declaration),"REQUEST":4096,"FRAME_CAP":2<<20,
        "REPLY":4096+(2<<20),"WORK":4096+(4<<20),"TOTAL":4096+(100<<20),
        "POLICY_WORK":32<<20,"VALUE_WORK":32<<20,"SDK_WORK":96<<20}
    pseudo_raw=(root/"authoring/full_catalog/pipeline.pseudo").read_bytes()
    raw,names,proof=support.compile_new(api,old,roots,pseudo_raw.decode(),constants,"runtime_full_catalog_pipeline")
    proof.update(schema="hepta.runtime.full-catalog-pipeline-source.v1",aliases=names,constants=constants,
        original_declaration_count=136,declaration=support.identity(declaration),
        policy_source_profile=support.identity(profile_raw),policy_source_files=profile["files"],
        retained_catalog=support.identity(old),retained_composition=support.identity(composition_raw),
        pseudo=support.identity(pseudo_raw),support=support.identity(support_path.read_bytes()),
        expected_wire_used_as_implementation=False,original_policy_serde_sdk_unchanged=True,
        runtime_executed=False,public_dispatch_qualified=False,whole_runtime_replaced=False)
    for name,raw_before in captured.items():
        require((base/name).read_bytes()==raw_before,"policy source changed during authoring: "+name)
    require((root/"native/runtime_mcp_catalog_ninth.hepta").read_bytes()==old,"retained catalog changed during authoring")
    out.mkdir(parents=True)
    (out/"full_catalog_pipeline.hepta").write_bytes(raw)
    (out/"full_catalog_pipeline_composition.json").write_bytes(encoded(proof))
    print(json.dumps({key:proof[key] for key in ("source","functions","blocks","operations","original_declaration_count")},sort_keys=True))
if __name__=="__main__":main()
