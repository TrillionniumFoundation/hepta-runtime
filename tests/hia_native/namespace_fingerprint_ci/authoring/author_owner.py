"""Source-only namespace fingerprint author; whole qualified SHA helper AST imports."""
import argparse,ast,copy,hashlib,json,re,sys
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
        assert all(pin(raw)[k]==row[k] for k in pin(raw)),row["name"]
    constants=dict(INVALID=0xffffffff,CAPACITY=0xfffffffe,
        REQUEST=int.from_bytes(b"HNFRQ001","little"),ACK=int.from_bytes(b"HNFACK01","little"),
        RESPONSE=int.from_bytes(b"HNFRS001","little"),WORKSPACE=int.from_bytes(b"HNFWK001","little"))
    pseudo=(root/"authoring/namespace_fingerprint.pseudo").read_text()
    rewritten=re.sub(r"\b("+ "|".join(constants)+r")\b",lambda m:str(constants[m[0]]),pseudo)
    nodes=ast.parse(rewritten).body
    assert all(isinstance(n,ast.FunctionDef) for n in nodes)
    names={n.name:"f"+str(i) for i,n in enumerate(nodes)}
    signatures={n.name:([p.annotation.id for p in n.args.args],n.returns.id) for n in nodes}
    specs=[
        dict(path="imports/bellman_commitment.hepta",sha256="18a810c251fa1c73764bb0968d8db969ac5fc6a922e4a692cd5ce5e3f960ae36",
             aliases=dict(sha_init="f42",sha_update="f43",sha_finish="f44",get="f45",put="f48")),
        dict(path="imports/binary_codec.hepta",sha256="f58ab824ecb47545f19cd1d0daded9e41fca5457110693677d84e393e3098f23",
             aliases=dict(read64="f13"))]
    imported={};import_proofs=[]
    for spec in specs:
        raw=(root/spec["path"]).read_bytes();assert pin(raw)["sha256"]==spec["sha256"]
        original={f["name"]:f for f in assemble_program(raw).as_dict()["functions"]}
        pending=list(spec["aliases"].values());closure=set()
        while pending:
            key=pending.pop()
            if key in closure:continue
            closure.add(key)
            pending.extend(op["attrs"]["function"] for b in original[key]["blocks"] for op in b["ops"] if op["op"]=="call")
        relocation={name:"f"+str(len(nodes)+len(imported)+i) for i,name in enumerate(sorted(closure,key=lambda x:int(x[1:])))}
        inverse={v:k for k,v in relocation.items()}
        for name,new in relocation.items():
            fn=copy.deepcopy(original[name]);fn["name"]=new
            for b in fn["blocks"]:
                for op in b["ops"]:
                    if op["op"]=="call":op["attrs"]["function"]=relocation[op["attrs"]["function"]]
            restored=copy.deepcopy(fn);restored["name"]=name
            for b in restored["blocks"]:
                for op in b["ops"]:
                    if op["op"]=="call":op["attrs"]["function"]=inverse[op["attrs"]["function"]]
            assert restored==original[name]
            imported[new]=fn
        for alias,name in spec["aliases"].items():
            names[alias]=relocation[name];fn=imported[names[alias]]
            signatures[alias]=([p["type"] for p in fn["params"]],fn["returns"][0])
        import_proofs.append(dict(path=spec["path"],source=pin(raw),aliases=spec["aliases"],relocation=relocation,inverse_full_ast_equal=True))
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        b=Builder(node,names,signatures,total);b.statements(node.body)
        functions.append(dict(name=names[node.name],params=[b.param(v) for v in b.params],returns=[b.returns],
            effects=["read","write","trap"],entry="b0",blocks=b.blocks))
    program=compact_authoring_cfg(dict(schema="hepta.hia.program.v8",module="namespace_fingerprint",functions=functions+list(imported.values())))
    program["functions"]=[imported.get(fn["name"],fn) for fn in program["functions"]]
    raw=render_assembly(program).encode();checked=assemble_program(raw).as_dict()
    for fn in checked["functions"]:
        if fn["name"] in imported:assert fn==imported[fn["name"]]
        assert len(fn["blocks"])<=256
        assert all(len(b["params"])<=16 for b in fn["blocks"])
    shape=dict(functions=len(checked["functions"]),blocks=sum(len(fn["blocks"]) for fn in checked["functions"]),
        operations=sum(len(b["ops"]) for fn in checked["functions"] for b in fn["blocks"]))
    assert shape["operations"]<=8192,shape
    proof=dict(schema="hepta.namespace-fingerprint.composition.v1",target_commit=spans["target_commit"],
        original_spans=pin((root/"reference/ORIGINAL_SPANS.json").read_bytes()),source=pin(raw),shape=shape,
        function_names=names,constants=constants,imports=import_proofs,
        pseudo=pin(pseudo.encode()),author=pin(Path(__file__).read_bytes()),
        sha_algorithm_unchanged=True,sha_workspace_shared_disjoint_input=True,
        native_or_rust_semantic_executions=0,namespace_watch_qualified=False,public_handler_qualified=False,whole_runtime_replaced=False)
    output.mkdir(parents=True,exist_ok=False)
    for name,body in {"namespace_fingerprint.hepta":raw,"namespace_fingerprint.composition.json":encoded(proof)}.items():
        (output/name).write_bytes(body)
        print("GENERATED_FILE_BEGIN native/"+name);print(body.decode(),end="");print("GENERATED_FILE_END native/"+name)
    print("GENERATED_OWNER "+json.dumps(proof,sort_keys=True))
if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--root",type=Path,required=True)
    p.add_argument("--hepta",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();generate(a.root.resolve(strict=True),a.hepta.resolve(strict=True),a.output.absolute())
