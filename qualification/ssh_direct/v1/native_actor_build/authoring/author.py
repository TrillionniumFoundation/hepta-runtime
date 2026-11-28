#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Generate exact target child, admission and shared-owner HIA policies."""
from pathlib import Path
import argparse, hashlib, json, sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from source_support import tools, compile_new, WORD
MODULES=(
 ("ssh_original_child","child",{"REQUEST_MAGIC":"HSDCCQ01","STATE_MAGIC":"HSDCST01","RESULT_MAGIC":"HSDCCR01"}),
 ("ssh_request_admission","admission",{"REQUEST_MAGIC":"HSDARQ01","STATE_MAGIC":"HSDARS01","RESULT_MAGIC":"HSDARR01"}),
 ("ssh_shared_owner","core",{"REQUEST_MAGIC":"HSDCPQ01","STATE_MAGIC":"HSDCPS01","RESULT_MAGIC":"HSDCPR01","GROW_MAGIC":"HGRWS002"}),
 ("ssh_capture_io","io",{"REQUEST_MAGIC":"HSDIOQ01","STATE_MAGIC":"HSDIOS01","RESULT_MAGIC":"HSDIOR01","COMMAND_MAGIC":"HSDCMD01","COMMAND_RESULT":"HSCMLY01"}))
def author(source,hepta,output):
    output.mkdir(parents=True,exist_ok=False)
    original=(source/"retained/publication_worker.hepta").read_bytes()
    api=tools(hepta);proofs={}
    for name,entry,constants in MODULES:
        pseudo=(source/("authoring/"+name+".pseudo")).read_text()
        raw,names,proof=compile_new(api,original,{"read64":"f10","get":"f11","put":"f12"},pseudo,
            {k:WORD(v) for k,v in constants.items()},name)
        if name=="ssh_original_child":
            if hashlib.sha256(raw).hexdigest()!="ab3049a0f71b5838cf0ffdaaf5f57366c49c3ad4a5ce62af25b41e38c6b0dbff":
                # Module label is part of the raw byte identity. Compare using
                # the original frozen label, without changing any function AST.
                raw,names,proof=compile_new(api,original,{"read64":"f10","get":"f11","put":"f12"},pseudo,
                    {k:WORD(v) for k,v in constants.items()},"ssh_original_child_custody")
                if hashlib.sha256(raw).hexdigest()!="ab3049a0f71b5838cf0ffdaaf5f57366c49c3ad4a5ce62af25b41e38c6b0dbff":
                    raise ValueError("frozen original-child HIA differs")
        (output/(name+".hepta")).write_bytes(raw)
        proof.update(entry=names[entry],names=names,pseudo_sha256=hashlib.sha256(pseudo.encode()).hexdigest())
        proofs[name]=proof
    result=dict(status="SSH_ACTOR_SOURCE_AUTHOR_PASS",modules=proofs,
        target="d3d75c30719db966b004756f610007a7c723729e",applications_executed=0,
        independent_native_actor=False,public_ssh_qualified=False)
    (output/"AUTHOR.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    return result
if __name__=="__main__":
    p=argparse.ArgumentParser()
    for name in ("source","hepta","output"):p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args();print(json.dumps(author(a.source.resolve(),a.hepta.resolve(),a.output.absolute()),sort_keys=True))
