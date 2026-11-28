# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Development author for the REA HIA file actor and its HIA syscall emitter."""
from pathlib import Path
import argparse, ast, copy, hashlib, json, re, struct, subprocess, sys

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for n in ("hepta","policy","code","engine","output"):
        ap.add_argument("--"+n,type=Path,required=True)
    a=ap.parse_args();a.hepta=a.hepta.resolve(strict=True)
    a.output.mkdir(mode=0o700,exist_ok=False)
    assert subprocess.check_output(["git","rev-parse","HEAD"],cwd=a.hepta).decode().strip()=="d3e2c90173cf733e42b299d0c4274df4b593a12f"
    sys.dont_write_bytecode=True;sys.path.insert(0,str(a.hepta))
    from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program,render_assembly
    sha=lambda b:hashlib.sha256(b).hexdigest()
    body_path=Path(__file__).with_name("rea_file_actor_source.py.txt")
    inputs={str(p):p.read_bytes()for p in [Path(__file__),body_path,a.policy,a.code,a.engine]}
    policy=inputs[str(a.policy)]
    assert sha(policy)=="93c4841f65904ba025de02ee3bb0c79fdc9f014552c2b02f204eed6a17f39a8d"
    originals=assemble_program(policy).as_dict()["functions"]
    assert len(originals)==10 and originals[0]["name"]=="f0"
    class Bulk(Builder):
        def expr(self,node):
            if isinstance(node,ast.Call)and isinstance(node.func,ast.Name)and node.func.id=="path_policy":
                args=[self.expr(v)for v in node.args]
                result=self.op("call",args,"u32",function=self.names["path_policy"])
                return self.cast(result,"u64")
            if isinstance(node,ast.Call)and isinstance(node.func,ast.Name)and node.func.id=="copy_range":
                args=[self.expr(v)for v in node.args]
                if args[0]==args[1]:
                    return self.op("buffer.move_within",[args[0],*(self.cast(v,"usize")for v in args[2:])])
                source=args[1]
                if source[1]=="mutbuf":source=self.op("borrow.read",[source],"readbuf")
                value=self.op("buffer.copy_range",[args[0],source,*(self.cast(v,"usize")for v in args[2:])])
                if args[1][1]=="mutbuf":self.op("loan.end",[source])
                return value
            return super().expr(node)
    def compile_body(name,text,imports=()):
        nodes=ast.parse(text).body
        assert nodes and all(isinstance(n,ast.FunctionDef)for n in nodes)
        names={n.name:"f"+str(j)for j,n in enumerate(nodes)}
        signatures={n.name:([v.annotation.id for v in n.args.args],n.returns.id)for n in nodes}
        relocated=[]
        relocation={}
        if imports:
            relocation={f["name"]:"f"+str(len(nodes)+j)for j,f in enumerate(imports)}
            for original in imports:
                f=copy.deepcopy(original);f["name"]=relocation[f["name"]]
                for block in f["blocks"]:
                    for op in block["ops"]:
                        if op["op"]=="call":op["attrs"]["function"]=relocation[op["attrs"]["function"]]
                relocated.append(f)
            names["path_policy"]=relocation["f0"]
            signatures["path_policy"]=(["readbuf","mutbuf","mutbuf"],"u32")
        total=total_scalar_functions(nodes);authored=[]
        for node in nodes:
            b=Bulk(node,names,signatures,total);b.statements(node.body)
            authored.append({"name":names[node.name],"params":[b.param(v)for v in b.params],
                "returns":[b.returns],"effects":["read","write","trap"],"entry":"b0","blocks":b.blocks})
        doc=compact_authoring_cfg({"schema":"hepta.hia.program.v8","module":"hepta_runtime_"+name,"functions":authored+relocated})
        doc["functions"]=doc["functions"][:len(authored)]+relocated
        raw=render_assembly(doc).encode();assembled=assemble_program(raw).as_dict()
        assert assembled["functions"][len(authored):]==relocated
        count=sum(len(b["ops"])for f in assembled["functions"]for b in f["blocks"])
        assert count<=8192 and len(assembled["functions"])<=128 and len(raw)<1048576
        (a.output/(name+".hepta")).write_bytes(raw)
        (a.output/(name+".py.txt")).write_text(text)
        return {"source_bytes":len(raw),"source_sha256":sha(raw),"functions":len(assembled["functions"]),
                "instruction_count":count,"relocation":relocation}
    constants={k:int.from_bytes(v,"little")for k,v in {
        "PATH_REQUEST":b"HREAFPL1","PATH_RESPONSE":b"HRFPLAN1",
        "STATE_MAGIC":b"HRFDST01","ACTION_MAGIC":b"HRFDAC01","RESULT_MAGIC":b"HRFDRS01"}.items()}
    text=re.sub(r"\b("+"|".join(constants)+r")\b",lambda m:str(constants[m[0]]),inputs[str(body_path)].decode())
    actor=compile_body("rea_file_actor",text,originals)
    engine=inputs[str(a.engine)]
    assert sha(engine)=="053897dee530fc54ac9682ad251425f4199fe15b9a1a6a5c66af6a3f3853ea07"
    record=json.loads(inputs[str(a.code)])
    assert record["schema"]=="hepta.runtime.rea-descriptor-mechanical-code.v1"
    flat=bytes.fromhex(record["flat_hex"])
    assert len(flat)==record["flat_bytes"]==2051
    assert sha(flat)==record["flat_sha256"]=="14e65f19b70579d0f3d028687283209440dde7d52613385ed7038c8a8de39f2e"
    assert record["source_sha256"]==sha(engine)and record["source_bytes"]==len(engine)
    exports={"create":0,"step":154,"take":1744,"destroy":1831}
    assert record["exports"]==exports and record["relocations"]is False
    output=b"HREAPK01"+struct.pack("<7Q",64+len(flat),len(flat),*(exports[k]for k in exports),0)+flat
    chunks=[]
    for start in range(0,len(output),512):
        lines=["def part_"+str(len(chunks))+"(o:mutbuf) -> u64:"]
        end=min(start+512,len(output));at=start
        while at+8<=end:
            lines.append("    put(o, "+str(at)+", "+str(int.from_bytes(output[at:at+8],"little"))+")");at+=8
        while at<end:
            lines.append("    store(o, "+str(at)+", "+str(output[at])+")");at+=1
        lines.append("    return 0");chunks.append("\n".join(lines))
    entry="def entry(i:readbuf, o:mutbuf, w:mutbuf) -> u32:\n"
    entry+="    if length(i) != 24:\n        return 4294967295\n"
    entry+="    if read64(i, 0) != "+str(int.from_bytes(b"HREAPQ01","little"))+" or read64(i, 8) != 1 or read64(i, 16) != 0:\n        return 4294967295\n"
    entry+="    if length(o) < "+str(len(output))+":\n        return 4294967294\n"
    for j in range(len(chunks)):entry+="    part_"+str(j)+"(o)\n"
    entry+="    return "+str(len(output))+"\n"
    helpers=text[text.index("def read64("):]
    packer=compile_body("rea_descriptor_packer",entry+"\n\n"+"\n\n".join(chunks)+"\n\n"+helpers)
    (a.output/"expected-descriptor.engine").write_bytes(output)
    (a.output/"composition.json").write_text(json.dumps({
        "schema":"hepta.runtime.rea-file-native-components.v1","actor":actor,"packer":packer,
        "policy_source_sha256":sha(policy),"engine_source_sha256":sha(engine),
        "engine_flat_sha256":sha(flat),"engine_flat_bytes":len(flat),"exports":exports,
        "expected_engine_bytes":len(output),"expected_engine_sha256":sha(output),
        "request_hex":(b"HREAPQ01"+struct.pack("<QQ",1,0)).hex(),
        "authoring_inputs":{n:{"bytes":len(b),"sha256":sha(b)}for n,b in inputs.items()},
        "assembler_required_by_product":False,"public_route_qualified":False,
        "descriptor_lifecycle_qualified":False},sort_keys=True,indent=2)+"\n")
    for n,b in inputs.items():assert Path(n).read_bytes()==b
    print(json.dumps({"actor":actor,"packer":packer,"engine_bytes":len(output),
        "engine_sha256":sha(output),"descriptor_lifecycle_qualified":False},sort_keys=True))

if __name__=="__main__":
    main()

