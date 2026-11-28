"""Deterministic source-only author for the target archive-anchor publication."""
import argparse, ast, copy, hashlib, json, re, sys
from pathlib import Path
def pin(raw):
    return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),git_blob=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest())
def encoded(value):
    return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+"\n").encode()
def generate(root,hepta,output):
    sys.dont_write_bytecode=True
    sys.path.insert(0,str(hepta))
    from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program,render_assembly
    spans=json.loads((root/"reference/ORIGINAL_SPANS.json").read_bytes())
    for name,expected in spans["sources"].items():
        actual=pin((root/name).read_bytes())
        assert all(actual[k]==expected[k] for k in actual),name
    for row in spans["spans"]:
        raw=(root/row["source"]).read_bytes()[row["start_byte"]:row["end_byte"]]
        assert raw==(root/row["extraction"]).read_bytes()
        actual=pin(raw);assert all(actual[k]==row[k] for k in actual),row["name"]
    target=(root/"reference/request_audit.rs.txt").read_bytes()
    assert (root/"reference/constants.rs.txt").read_bytes()==("\n".join(spans["constants"])+"\n").encode()
    for constant in spans["constants"]:assert target.count(constant.encode())==1
    constants=dict(INVALID=0xffffffff,CAPACITY=0xfffffffe,AGAIN=0xfffffffd,
        REQUEST=int.from_bytes(b"HAPURQ01","little"),ACK=int.from_bytes(b"HAPUACK1","little"),
        RESPONSE=int.from_bytes(b"HAPURS01","little"),WORKSPACE=int.from_bytes(b"HAPUWS01","little"),
        PROJECTION=int.from_bytes(b"HAJPR001","little"),JSONREQUEST=int.from_bytes(b"HAJRQ001","little"))
    pseudo=(root/"authoring/audit_anchor_publish.pseudo").read_text()
    rewritten=re.sub(r"\b("+ "|".join(constants)+r")\b",lambda m:str(constants[m[0]]),pseudo)
    nodes=ast.parse(rewritten).body
    assert all(isinstance(n,ast.FunctionDef) for n in nodes)
    names={n.name:"f"+str(i) for i,n in enumerate(nodes)}
    signatures={n.name:([p.annotation.id for p in n.args.args],n.returns.id) for n in nodes}
    raw=(root/"imports/audit_record_io.hepta").read_bytes()
    assert pin(raw)["sha256"]=="6826f361511a1345b63a1604a92b89252f5405c549fe38337e88e3d8aa8338ea"
    original={f["name"]:f for f in assemble_program(raw).as_dict()["functions"]}
    aliases=dict(get="f40",put="f41",read64="f42")
    pending=list(aliases.values());closure=set()
    while pending:
        key=pending.pop()
        if key in closure:continue
        closure.add(key)
        pending.extend(op["attrs"]["function"] for b in original[key]["blocks"] for op in b["ops"] if op["op"]=="call")
    relocation={name:"f"+str(len(nodes)+i) for i,name in enumerate(sorted(closure,key=lambda x:int(x[1:])))}
    inverse={v:k for k,v in relocation.items()};imported={}
    for name,new in relocation.items():
        fn=copy.deepcopy(original[name]);fn["name"]=new
        for b in fn["blocks"]:
            for op in b["ops"]:
                if op["op"]=="call":op["attrs"]["function"]=relocation[op["attrs"]["function"]]
        restore=copy.deepcopy(fn);restore["name"]=name
        for b in restore["blocks"]:
            for op in b["ops"]:
                if op["op"]=="call":op["attrs"]["function"]=inverse[op["attrs"]["function"]]
        assert restore==original[name]
        imported[new]=fn
    for alias,name in aliases.items():
        names[alias]=relocation[name];fn=imported[names[alias]]
        signatures[alias]=([p["type"] for p in fn["params"]],fn["returns"][0])
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        b=Builder(node,names,signatures,total);b.statements(node.body)
        functions.append(dict(name=names[node.name],params=[b.param(v) for v in b.params],returns=[b.returns],
            effects=["read","write","trap"],entry="b0",blocks=b.blocks))
    program=compact_authoring_cfg(dict(schema="hepta.hia.program.v8",module="audit_anchor_publish",
                                      functions=functions+list(imported.values())))
    program["functions"]=[imported.get(fn["name"],fn) for fn in program["functions"]]
    raw=render_assembly(program).encode();checked=assemble_program(raw).as_dict()
    for fn in checked["functions"]:
        if fn["name"] in imported:assert fn==imported[fn["name"]]
        assert len(fn["blocks"])<=256
        assert all(len(b["params"])<=16 for b in fn["blocks"])
    shape=dict(functions=len(checked["functions"]),blocks=sum(len(fn["blocks"]) for fn in checked["functions"]),
        operations=sum(len(b["ops"]) for fn in checked["functions"] for b in fn["blocks"]))
    assert shape["operations"]<=8192,shape
    proof=dict(schema="hepta.audit-anchor-publish.composition.v1",target_commit=spans["target_commit"],
        original_spans=pin((root/"reference/ORIGINAL_SPANS.json").read_bytes()),source=pin(raw),shape=shape,
        function_names=names,constants=constants,imports=dict(path="imports/audit_record_io.hepta",
            source=pin((root/"imports/audit_record_io.hepta").read_bytes()),relocation=relocation,aliases=aliases,
            inverse_full_ast_equal=True),json_child=pin((root/"imports/audit_json.hepta").read_bytes()),
        pseudo=pin(pseudo.encode()),author=pin(Path(__file__).read_bytes()),
        native_or_rust_semantic_executions=0,public_handler_qualified=False,whole_runtime_replaced=False)
    output.mkdir(parents=True,exist_ok=False)
    for name,body in {"audit_anchor_publish.hepta":raw,"audit_anchor_publish.composition.json":encoded(proof)}.items():
        (output/name).write_bytes(body)
        print("GENERATED_FILE_BEGIN native/"+name);print(body.decode(),end="");print("GENERATED_FILE_END native/"+name)
    print("GENERATED_OWNER "+json.dumps(proof,sort_keys=True))
if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root",type=Path,required=True);p.add_argument("--hepta",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();generate(a.root.resolve(strict=True),a.hepta.resolve(strict=True),a.output.absolute())
