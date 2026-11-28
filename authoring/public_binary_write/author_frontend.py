#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Add one fixed name using the complete original public request preparation."""
from pathlib import Path
import argparse
import copy
import json
import sys

sys.dont_write_bytecode=True


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("source","hepta","output"):
        parser.add_argument("--"+name,type=Path,required=True)
    args=parser.parse_args();root=args.source.resolve(strict=True)
    sys.path.insert(0,str(root/"authoring/public_publication_v1"))
    import source_support as support
    api=support.tools(args.hepta.resolve(strict=True))
    original=(root/"native/runtime_mcp.hepta").read_bytes()
    composition=json.loads((root/"native/runtime_mcp_composition.json").read_bytes())
    before=api[3](original).as_dict();old={f["name"]:f for f in before["functions"]}
    support.require(composition["source_sha256"]==support.SHA(original),"complete original frontend identity differs")
    support.require(composition["function_sha256"]=={n:support.SHA(support.CANON(f)) for n,f in old.items()},
                    "complete original frontend AST identity differs")
    names=composition["functions"]
    constants={key:support.WORD(value) for key,value in {
        "INFO_WORD":"file_inf","READ_WORD":"binary_r","WRITE_WORD":"binary_w",
        "MULTI_WORD0":"read_mul","MULTI_WORD1":"tiple_fi","MULTI_REQUEST":"HRDMQ002",
        "READ_REQUEST":"HRDRQ002","WRITE_REQUEST":"HBWWQ002"}.items()}
    raw,names,proof=support.compile_delta(api,original,names,
        (root/"authoring/public_binary_write/frontend.pseudo").read_text(),constants,before["module"])
    after=api[3](raw).as_dict();current={f["name"]:f for f in after["functions"]}
    changed={names[alias] for alias in ("tool_kind","prepare","binary_request_magic")}
    support.require({name for name in old if old[name]!=current[name]}==changed,"unexpected frontend delta")
    inverse=copy.deepcopy(after)
    inverse["functions"]=[old[f["name"]] if f["name"] in changed else f for f in inverse["functions"]]
    support.require(api[4](inverse).encode()==original,"whole original frontend inverse differs")
    proof.update(schema="hepta.runtime.public-binary-write.frontend-author.v1",aliases=names,
                 baseline=support.identity(original),changed_functions=sorted(changed),
                 whole_original_inverse=True,complete_request_preparation_retained=True,
                 complete_entry_retained=True,complete_future_drop_retained=True,
                 new_tool_kind=17,new_tool="binary_write",local_child=17,global_descriptor=73,
                 private_request="HBWWQ002",catalog_changed=False,public_route_qualified=False)
    output=args.output.absolute();output.mkdir(parents=True,exist_ok=False)
    (output/"public_io_frontend.hepta").write_bytes(raw)
    (output/"public_io_frontend_composition.json").write_bytes(support.ENCODE(proof))
    print(json.dumps(dict(source=proof["source"],functions=proof["functions"],blocks=proof["blocks"],operations=proof["operations"]),sort_keys=True))


if __name__=="__main__":main()
