#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Author fixed remote JSON-field projection and fixed SSH bootstrap text in HIA."""
import argparse,ast,copy,hashlib,json,re,sys
from pathlib import Path
sys.dont_write_bytecode=True
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
CANON=lambda v:json.dumps(v,sort_keys=True,separators=(",",":")).encode()
def fields_extra(spec):
    result="\ndef field_index(s:readbuf,at:u64,size:u64) -> u64:\n"
    for i,key in enumerate(spec["keys"]):result+=f"    if key_{i}(s,at,size)!=0:\n        return {i}\n"
    result+="    return 16\n"
    for i,key in enumerate(spec["keys"]):
        result+=f"\ndef key_{i}(s:readbuf,at:u64,size:u64) -> u64:\n    if size!={len(key)}:\n        return 0\n"
        for j,b in enumerate(key.encode()):result+=f"    if codepoint(s,at+{j*4})!={b}:\n        return 0\n"
        result+="    return 1\n"
    result+="\ndef operation(w:mutbuf,at:u64,size:u64) -> u64:\n"
    for i,op in enumerate(spec["operations"],1):result+=f"    if op_{i}(w,at,size)!=0:\n        return {i}\n"
    result+="    return 0\n"
    for i,op in enumerate(spec["operations"],1):
        result+=f"\ndef op_{i}(w:mutbuf,at:u64,size:u64) -> u64:\n    if size!={len(op)}:\n        return 0\n"
        for j,b in enumerate(op.encode()):result+=f"    if byte(w,at+{j})!={b}:\n        return 0\n"
        result+="    return 1\n"
    result+="\ndef field_mask(op:u64) -> u64:\n"
    for op,mask in spec["masks"].items():result+=f"    if op=={op}:\n        return {mask}\n"
    return result+"    return 0\n"
def bootstrap_extra(spec):
    result="\ndef literal(o:mutbuf,w:mutbuf,code:u64) -> u64:\n"
    for code,value in spec["bootstrap_literals"].items():
        raw=value.encode();result+=f"    if code=={code}:\n";end=len(raw)//8*8
        for j in range(0,end,8):result+=f"        emit_word(o,w,{int.from_bytes(raw[j:j+8],'little')})\n"
        for j in range(end,len(raw)):result+=f"        emit(o,w,{raw[j]})\n"
        result+="        return 0\n"
    result+="    return 0\n\ndef power10(index:u64) -> u64:\n"
    for index in range(10):result+=f"    if index=={index}:\n        return {10**(9-index)}\n"
    return result+"    return 1\n"
def main():
    p=argparse.ArgumentParser()
    for n in("source","hepta","output"):p.add_argument("--"+n,type=Path,required=True)
    a=p.parse_args();root=a.source.resolve(strict=True);out=a.output.absolute()
    assert not out.exists();sys.path.insert(0,str(a.hepta.resolve(strict=True)))
    from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program,render_assembly
    class NativeBuilder(Builder):
        def expr(self,node):
            if isinstance(node,ast.Call)and isinstance(node.func,ast.Name)and node.func.id=="copy_span":
                values=[self.expr(v)for v in node.args]
                assert len(values)==5 and values[0][1]=="mutbuf"and values[1][1]=="readbuf"
                return self.op("buffer.copy_range",[values[0],values[1],*(self.cast(v,"usize")for v in values[2:])])
            return super().expr(node)
    baseline=(root/"baseline/config_directory_owner_span.hepta").read_bytes()
    assert SHA(baseline)=="6a0e7817013c32bd7189864c91dc768764ae44988cabe4391446ceafea9b5d81"
    original=copy.deepcopy(next(f for f in assemble_program(baseline).as_dict()["functions"]if f["name"]=="f44"))
    assert original["returns"]==["u64"]and[p["type"]for p in original["params"]]==["readbuf","u64","u64"]
    assert not any(op["op"]=="call"for b in original["blocks"]for op in b["ops"])
    spec=json.loads((root/"WIRE.json").read_bytes());out.mkdir(parents=True)
    for name in("binary_remote_fields","ssh_native_bootstrap"):
        fields=name=="binary_remote_fields"
        constants=dict(INVALID=0xffffffff,OUTPUT_SHORT=0xfffffffe,WORK_SHORT=0xfffffffd,LIMIT=0xffff0000,MAXIMUM=0xffffffffffffffff)
        constants.update({k:int.from_bytes(v.encode(),"little")for k,v in(
            {"REQUEST":"HBRJP001","VALUE":"HPYJSR01","ITEMS":"HPYJIR01","ERROR":"HBRER001","FLAT":"HRBFQ001"}if fields else
            {"REQUEST":"HSSBQ001","RESPONSE":"HSSBR001"}).items()})
        pseudo=(root/("authoring/"+name+".pseudo")).read_text()+(fields_extra(spec)if fields else bootstrap_extra(spec))
        pseudo=re.sub(r"\b("+"|".join(constants)+r")\b",lambda m:str(constants[m[0]]),pseudo)
        nodes=ast.parse(pseudo).body;assert nodes[0].name=="entry"and all(isinstance(n,ast.FunctionDef)for n in nodes)
        names={n.name:"f"+str(i)for i,n in enumerate(nodes)}
        signatures={n.name:([p.annotation.id for p in n.args.args],n.returns.id)for n in nodes}
        if fields:names["utf8"]="f"+str(len(nodes));signatures["utf8"]=(["readbuf","u64","u64"],"u64")
        total=total_scalar_functions(nodes);functions=[]
        for node in nodes:
            b=NativeBuilder(node,names,signatures,total);b.statements(node.body)
            functions.append(dict(name=names[node.name],params=[b.param(p)for p in b.params],returns=[b.returns],effects=["read","write","trap"],entry="b0",blocks=b.blocks))
        if fields:
            retained=copy.deepcopy(original);retained["name"]=names["utf8"];functions.append(retained)
        doc=dict(schema="hepta.hia.program.v8",module=name,functions=functions);doc=compact_authoring_cfg(doc)
        if fields:doc["functions"][-1]=retained
        raw=render_assembly(doc).encode();actual=assemble_program(raw).as_dict();assert render_assembly(actual).encode()==raw
        if fields:assert actual["functions"][-1]==retained
        operations=sum(len(b["ops"])for f in actual["functions"]for b in f["blocks"]);blocks=sum(len(f["blocks"])for f in actual["functions"])
        assert len(actual["functions"])<=128 and operations<=8192 and blocks<=1536
        for f in actual["functions"]:
            assert len(f["blocks"])<=256 and max(len(b["params"])for b in f["blocks"])<=16,f["name"]
            assert len(set(re.findall(r'"(v[0-9]+)"',json.dumps(f,sort_keys=True))))<=2048,f["name"]
        receipt=dict(schema="hepta.remote-binary.fixed-module.source.v1",module=name,entry="f0",source_bytes=len(raw),source_sha256=SHA(raw),
            functions=len(actual["functions"]),instructions=operations,blocks=blocks,aliases=names,constants=constants,
            function_sha256={f["name"]:SHA(CANON(f))for f in actual["functions"]},wire_source_sha256=SHA((root/"WIRE.json").read_bytes()),
            retained_utf8=dict(source_sha256=SHA(baseline),original_function="f44",function_sha256=SHA(CANON(original)))if fields else None,
            source_author_only=True,native_compiled=False,native_executed=False,public_route=False)
        (out/(name+".hepta")).write_bytes(raw);(out/(name+"_composition.json")).write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
        (out/(name+".expanded.pseudo")).write_text(pseudo)
        print(json.dumps({k:receipt[k]for k in("module","source_bytes","source_sha256","functions","instructions","blocks")},sort_keys=True))
if __name__=="__main__":main()
