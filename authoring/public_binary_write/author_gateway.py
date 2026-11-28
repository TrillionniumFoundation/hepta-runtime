#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Compose a write owner and exact retained read owner on their shared lifetime."""
from pathlib import Path
import argparse
import ast
import copy
import json
import sys

sys.dont_write_bytecode = True


class WriteReadProjection(ast.NodeTransformer):
    def visit_Call(self, node):
        node = self.generic_visit(node)
        if isinstance(node.func, ast.Name) and node.func.id == "read_kind":
            return ast.copy_location(ast.Constant(4), node)
        return node

    def visit_If(self, node):
        node = self.generic_visit(node)
        if all(isinstance(n, (ast.Expression, ast.Constant, ast.Compare, ast.Eq, ast.NotEq,
                              ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.BoolOp, ast.And, ast.Or,
                              ast.UnaryOp, ast.Not)) for n in ast.walk(node.test)):
            selected = eval(compile(ast.Expression(node.test), "<fixed-kind>", "eval"), {"__builtins__":{}})
            return node.body if selected else node.orelse
        return node


def relocate(document, offset):
    current = copy.deepcopy(document)
    mapping = {f["name"]:"f"+str(int(f["name"][1:])+offset) for f in current["functions"]}
    for function in current["functions"]:
        function["name"] = mapping[function["name"]]
        for block in function["blocks"]:
            for operation in block["ops"]:
                if operation["op"] == "call":
                    operation["attrs"]["function"] = mapping[operation["attrs"]["function"]]
    return current, mapping


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "hepta", "output"):
        parser.add_argument("--"+name,type=Path,required=True)
    args=parser.parse_args();root=args.source.resolve(strict=True)
    sys.path.insert(0,str(root/"authoring/public_publication_v1"))
    import source_support as support
    api=support.tools(args.hepta.resolve(strict=True))
    original=(root/"native/extract_gateway.hepta").read_bytes()
    aliases=json.loads((root/"native/extract_gateway_composition.json").read_bytes())["aliases"]
    renamed, changes=support.renamed(api,original,
        dict(zip(("HEXWGQ02","HEXWGQ03","HEXWGS01","HEXWGA01"),
                 ("HBWWQ002","HBWWQ003","HRDWS001","HRDWGA01"))),"runtime_public_write_gateway")
    reserve_id=aliases["reserve"]
    start=renamed.index(("fn "+reserve_id+"(").encode());end=renamed.index(b"\nend",start)+4
    prior=renamed[start:end]
    old=b'  v57:u64 = const() {"value":6}';new=b'  v57:u64 = const() {"value":7}'
    support.require(prior.count(old)==1,"original arena bound differs")
    updated=prior.replace(old,new)
    support.require(updated.replace(new,old)==prior,"whole arena extension inverse differs")
    renamed=renamed[:start]+updated+renamed[end:]
    constants={"INVALID":0xffffffff,"MAXIMUM":(1<<64)-1,
       **{name:support.WORD(value) for name,value in {
         "PARAMS_REQUEST":"HBPRQ001","PARAMS_RESULT":"HBPRR001",
         "PLAN_REQUEST":"HBPLQ001","PLAN_RESULT":"HBPLR001","MESSAGE":"HRCFGM01",
         "CONFIG_REQUEST":"HRCFGQ01","SSH_REQUEST":"HRSSQ001","CAPTURE_RESULT":"HRSCAP01",
         "DIAGNOSTIC_REQUEST":"HSJERQ01","DIAGNOSTIC_RESULT":"HSJERR01",
         "VALUE_RESULT":"HJSVR002","TRANSPORT_REQUEST":"HRTRQ001","TRANSPORT_RESULT":"HRTRR001",
         "AUDIT_REQUEST":"HBAUQ001"}.items()}}
    read_pseudo=ast.parse((root/"authoring/public_read/gateway.pseudo").read_text())
    selected={"after_context","after_resolve","after_policy","after_caller","after_client",
              "clear_words","after_json_diagnostic","after_transport_ready","prepare"}
    functions=[]
    for function in read_pseudo.body:
        if function.name not in selected:continue
        function=WriteReadProjection().visit(copy.deepcopy(function))
        if function.name=="prepare":
            count=0
            for node in function.body:
                if not isinstance(node,ast.If):continue
                if ast.dump(node.test)==ast.dump(ast.parse("phase == 1",mode="eval").body):
                    node.body=ast.parse("return prepare_typed_write(s,o,w,phase)").body;count+=1
                if ast.dump(node.test)==ast.dump(ast.parse("phase == 5",mode="eval").body):
                    node.body=ast.parse("return prepare_write_access(s,o,w,phase)").body;count+=1
            support.require(count==2,"exact typed/access phases differ")
        functions.append(function)
    support.require({f.name for f in functions}==selected,"complete selected continuation functions differ")
    inherited=ast.unparse(ast.fix_missing_locations(ast.Module(body=functions,type_ignores=[])))+"\n"
    pseudo=(root/"authoring/public_binary_write/gateway_write.pseudo").read_text()+"\n"+inherited
    writer,writer_names,writer_proof=support.compile_delta(api,renamed,aliases,pseudo,constants,"runtime_public_write_gateway")
    writer_proof.update(schema="hepta.runtime.public-binary-write.gateway-author.v1",aliases=writer_names,
       baseline=support.identity(original),private_magic_changes=changes,
       arena_extension=dict(original=support.identity(prior),current=support.identity(updated),whole_inverse=True),
       read_phase_projection=dict(source=support.identity((root/"authoring/public_read/gateway.pseudo").read_bytes()),
                                 fixed_transport_kind=4,selected_functions=sorted(selected)),
       child_slots=[71,72,70,11,74,77,10,81,75,76,46,82,69],
       ordered_operations=["typed-write","binary-plan","installed-write-root","binary-plan-resume",
                           "installed-state-root","jobs-audit-append","installed-target","owned-ssh",
                           "transport-result","actual-Value","transport-result-resume"],
       audit_success_required_before_ssh=True,shared_read_lifetime_slot=73,
       public_route_qualified=False,old_stack_removed=False)
    read=(root/"native/public_read_gateway.hepta").read_bytes()
    read_doc=api[3](read).as_dict();write_doc=api[3](writer).as_dict()
    read_shift,read_map=relocate(read_doc,1)
    write_shift,write_map=relocate(write_doc,1+len(read_doc["functions"]))
    stub=b"hia-asm.v1 hepta.hia.program.v8 runtime_public_io_gateway\nfn f0(v0:readbuf,v1:mutbuf,v2:mutbuf) -> (u32) effects(read,write,trap) entry(b0)\nblock b0(v0:readbuf,v1:mutbuf,v2:mutbuf)\n  v3:u32 = const() {\"value\":4294967295}\n  ret(v3)\nend\n"
    combined=api[3](stub).as_dict()
    combined["functions"]+=read_shift["functions"]+write_shift["functions"]
    read_names=json.loads((root/"native/public_read_gateway_composition.json").read_bytes())["aliases"]
    names={"entry":"f0","read_entry":read_map["f0"],"write_entry":write_map["f0"],"load":read_map[read_names["load"]]}
    wrapper="def entry(s:readbuf,o:mutbuf,w:mutbuf) -> u32:\n    if length(s)>=8:\n        magic=load(s,0)\n        if magic==WRITE_REQUEST or magic==WRITE_REQUEST_SECOND:\n            return write_entry(s,o,w)\n    return read_entry(s,o,w)\n"
    raw,names,proof=support.compile_delta(api,api[4](combined).encode(),names,wrapper,
        {"WRITE_REQUEST":support.WORD("HBWWQ002"),"WRITE_REQUEST_SECOND":support.WORD("HBWWQ003")},combined["module"])
    actual={f["name"]:f for f in api[3](raw).as_dict()["functions"]}
    for old_doc,mapping in ((read_doc,read_map),(write_doc,write_map)):
        restored=copy.deepcopy(old_doc);restored["functions"]=[];inverse={v:k for k,v in mapping.items()}
        for old_function in old_doc["functions"]:
            function=copy.deepcopy(actual[mapping[old_function["name"]]])
            function["name"]=inverse[function["name"]]
            for block in function["blocks"]:
                for operation in block["ops"]:
                    if operation["op"]=="call":operation["attrs"]["function"]=inverse[operation["attrs"]["function"]]
            restored["functions"].append(function)
        support.require(restored==old_doc,"complete retained gateway inverse differs")
    proof.update(schema="hepta.runtime.public-binary-write.shared-lifetime.v1",aliases=names,
                 complete_read_source=support.identity(read),complete_write_source=support.identity(writer),
                 read_function_relocation=read_map,write_function_relocation=write_map,
                 both_whole_source_inverses_exact=True,shared_global_slot=73,shared_async_ssh_slot=74,
                 original_async_detach_restore_retire_unchanged=True,public_route_qualified=False)
    output=args.output.absolute();output.mkdir(parents=True,exist_ok=False)
    (output/"public_binary_write_gateway.hepta").write_bytes(writer)
    (output/"public_binary_write_gateway_composition.json").write_bytes(support.ENCODE(writer_proof))
    (output/"public_binary_write_gateway.pseudo").write_text(pseudo)
    (output/"public_io_gateway.hepta").write_bytes(raw)
    (output/"public_io_gateway_composition.json").write_bytes(support.ENCODE(proof))
    print(json.dumps(dict(writer=writer_proof["source"],shared=proof["source"],functions=proof["functions"],operations=proof["operations"]),sort_keys=True))


if __name__=="__main__":main()
