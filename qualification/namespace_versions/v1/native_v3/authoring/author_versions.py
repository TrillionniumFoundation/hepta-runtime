"""Author the complete original namespace global/set policy; no application execution."""
import argparse,ast,copy,hashlib,json,re,sys
from pathlib import Path
def encoded(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+"\n").encode()
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest(),git_blob=hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest())
def generate(root,hepta):
    sys.dont_write_bytecode=True;sys.path.insert(0,str(hepta))
    from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program,render_assembly
    original=(root/"reference/namespace_version.rs.txt").read_bytes()
    assert pin(original)==dict(bytes=12833,git_blob="4672d33a9ede7470a469f619da4dae91f89fcecd",
        sha256="7dd63c53bc1a85995a353bedc9643e7e4eb864cc7a5603dc331f0b4dd12576db")
    imported=(root/"imports/namespace_watcher.hepta").read_bytes()
    assert pin(imported)==dict(bytes=103757,git_blob="1bd550a917f15855ee3e772aff2a8e43d8ff4781",
        sha256="b7947d6c8922b28a25499fd8bf20f84879f5fe32e8a33f546d0fdb16ec38a06f")
    constants=dict(INVALID=0xffffffff,CAPACITY=0xfffffffe,HIGH=1<<63,
        REQUEST=int.from_bytes(b"HNVSQ001","little"),ACK=int.from_bytes(b"HNVSAK01","little"),
        RESPONSE=int.from_bytes(b"HNVSR001","little"),STATE=int.from_bytes(b"HNVSW001","little"),
        GLOBAL=int.from_bytes(b"HNVGS001","little"),
        WATCH_RESPONSE=int.from_bytes(b"HNWR0001","little"),WATCH_STATE=int.from_bytes(b"HNWST001","little"),
        FINGERPRINT_RESPONSE=int.from_bytes(b"HNFRS001","little"))
    pseudo=(root/"authoring/namespace_versions.pseudo").read_bytes()
    rewritten=re.sub(r"\b("+"|".join(constants)+r")\b",lambda m:str(constants[m[0]]),pseudo.decode())
    nodes=ast.parse(rewritten).body;assert all(isinstance(n,ast.FunctionDef)for n in nodes)
    names={n.name:"f"+str(i)for i,n in enumerate(nodes)}
    signatures={n.name:([p.annotation.id for p in n.args.args],n.returns.id)for n in nodes}
    all_imports={f["name"]:f for f in assemble_program(imported).as_dict()["functions"]}
    aliases=dict(get="f26",put="f27",read64="f28");relocation={f:"f"+str(len(nodes)+i)for i,f in enumerate(aliases.values())}
    moved=[]
    for old,new in relocation.items():
        original_fn=all_imports[old];assert len(original_fn["blocks"])==1
        assert all(op["op"]!="call"for b in original_fn["blocks"]for op in b["ops"])
        fn=copy.deepcopy(original_fn);fn["name"]=new
        restored=copy.deepcopy(fn);restored["name"]=old;assert restored==original_fn
        moved.append(fn)
    for alias,old in aliases.items():
        fn=all_imports[old];names[alias]=relocation[old]
        signatures[alias]=([p["type"]for p in fn["params"]],fn["returns"][0])
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        b=Builder(node,names,signatures,total);b.statements(node.body)
        functions.append(dict(name=names[node.name],params=[b.param(v)for v in b.params],returns=[b.returns],
            effects=["read","write","trap"],entry="b0",blocks=b.blocks))
    program=compact_authoring_cfg(dict(schema="hepta.hia.program.v8",module="namespace_versions",functions=functions+moved))
    exact={f["name"]:f for f in moved};program["functions"]=[exact.get(f["name"],f)for f in program["functions"]]
    raw=render_assembly(program).encode();checked=assemble_program(raw).as_dict()
    for fn in checked["functions"]:
        if fn["name"]in exact:assert fn==exact[fn["name"]]
        assert len(fn["blocks"])<=256 and all(len(b["params"])<=16 for b in fn["blocks"])
    shape=dict(functions=len(checked["functions"]),blocks=sum(len(f["blocks"])for f in checked["functions"]),
        operations=sum(len(b["ops"])for f in checked["functions"]for b in f["blocks"]))
    assert shape["functions"]<=128 and shape["blocks"]<=1536 and shape["operations"]<=8192
    proof=dict(schema="hepta.namespace-versions.composition.v1",target_commit="d3d75c30719db966b004756f610007a7c723729e",
        original=pin(original),pseudo=pin(pseudo),author=pin(Path(__file__).read_bytes()),source=pin(raw),
        constants=constants,function_names=names,shape=shape,
        imports=[dict(path="imports/namespace_watcher.hepta",source=pin(imported),aliases=aliases,
            relocation=relocation,inverse_full_ast_equal=True,entire_fixed_eight_access_functions=True)],
        global_policy_owner=True,content_watch_set_policy_owner=True,
        native_application_calls=0,original_application_calls=0,namespace_version_qualified=False,public_handler_qualified=False)
    return raw,encoded(proof)
def run(root,hepta,output):
    raw,proof=generate(root,hepta);output.mkdir(parents=True,exist_ok=False)
    for name,body in (("namespace_versions.hepta",raw),("namespace_versions.composition.json",proof)):
        (output/name).write_bytes(body)
        print("GENERATED_FILE_BEGIN native/"+name);print(body.decode(),end="");print("GENERATED_FILE_END native/"+name)
    print("NAMESPACE_VERSIONS_AUTHOR "+json.dumps(json.loads(proof),sort_keys=True))
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--root",type=Path,required=True)
    p.add_argument("--hepta",type=Path,required=True);p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    run(a.root.resolve(strict=True),a.hepta.resolve(strict=True),a.output.absolute())
