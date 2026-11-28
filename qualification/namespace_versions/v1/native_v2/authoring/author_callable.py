"""Assemble native custody and author a three-member HIA packer, zero applications."""
import argparse,ast,json,re,subprocess,sys
from pathlib import Path
sys.dont_write_bytecode=True
def pin(raw):
    import hashlib
    return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+"\n").encode()
EXPORTS={name:"namespace_versions_"+name for name in("entry","initialize","set_allocate","set_dispose","owner","watcher","fingerprint","end")}
def generate(root,hepta,stub,offsets,images):
    assert tuple(images)==("namespace-versions","namespace-watcher","namespace-fingerprint")
    lengths=[len(images[n])for n in images];size=len(stub)+sum(lengths)
    assert offsets["entry"]==0 and offsets["owner"]==len(stub)and offsets["owner"]%16==0
    assert offsets["watcher"]==len(stub)+lengths[0]and offsets["fingerprint"]==len(stub)+sum(lengths[:2])and offsets["end"]==size
    magic=int.from_bytes(b"HNVPK001","little")
    pseudo=f"""def namespace_versions_callable(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!={40+sum(lengths)} or read64(s,0)!={magic} or read64(s,8)!=1 or read64(s,16)!={lengths[0]} or read64(s,24)!={lengths[1]} or read64(s,32)!={lengths[2]}:
        return 4294967295
    if length(o)<{size}:
        return 4294967294
"""
    literals=[]
    for start in range(0,len(stub),512):
        name="literal_"+str(start);pseudo+="    "+name+"(o)\n";body="def "+name+"(o:mutbuf) -> u64:\n"
        for at in range(start,min(start+512,len(stub)),8):
            assert len(stub[at:at+8])==8
            body+=f"    put64(o,{at},{int.from_bytes(stub[at:at+8],'little')})\n"
        literals.append(body+"    return 0\n")
    pseudo+=f"""    at=0
    while at<{sum(lengths)}:
        store(o,{len(stub)}+at,byte(s,40+at))
        at=at+1
    return {size}

"""
    pseudo+="\n".join(literals)+"\n"
    pseudo+="def read64(s:readbuf,at:u64) -> u64:\n    return "+"|".join(f"(byte(s,at+{i})<<{8*i})"for i in range(8))+"\n\n"
    pseudo+="def put64(o:mutbuf,at:u64,value:u64) -> u64:\n"+"".join(f"    store(o,at+{i},(value>>{8*i})&255)\n"for i in range(8))+"    return 0\n"
    sys.path.insert(0,str(hepta))
    from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program,render_assembly
    nodes=ast.parse(pseudo).body;names={n.name:"f"+str(i)for i,n in enumerate(nodes)}
    signatures={n.name:([p.annotation.id for p in n.args.args],n.returns.id)for n in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for n in nodes:
        b=Builder(n,names,signatures,total);b.statements(n.body)
        functions.append(dict(name=names[n.name],params=[b.param(v)for v in b.params],returns=[b.returns],
            effects=["read","write","trap"],entry="b0",blocks=b.blocks))
    program=compact_authoring_cfg(dict(schema="hepta.hia.program.v8",module="namespace_versions_callable",functions=functions))
    hia=render_assembly(program).encode();checked=assemble_program(hia).as_dict()
    shape=dict(functions=len(checked["functions"]),blocks=sum(len(f["blocks"])for f in checked["functions"]),
        operations=sum(len(b["ops"])for f in checked["functions"]for b in f["blocks"]))
    assert shape["functions"]<=128 and shape["blocks"]<=1536 and shape["operations"]<=8192
    template=(root/"authoring/namespace_versions_callable.S.in").read_bytes()
    asm=template.replace(b"@POLICY_BYTES@",str(lengths[0]).encode())
    proof=dict(schema="hepta.namespace-versions.callable-source.v1",adapter_template=pin(template),adapter_source=pin(asm),
        author=pin(Path(__file__).read_bytes()),adapter=pin(stub),adapter_hex=stub.hex(),offsets=offsets,
        members={name:pin(raw)for name,raw in images.items()},image_bytes=size,packer_source=pin(hia),
        pseudo=pin(pseudo.encode()),shape=shape,relocations=0,unresolved_symbols=0,
        namespace_policy_source=pin((root/"native/namespace_versions.hepta").read_bytes()),
        dependency_production_sources={name:pin((root/name).read_bytes())for name in(
            "imports/namespace_watcher.hepta","imports/namespace_watcher_callable.hepta","imports/namespace_watcher_callable.composition.json",
            "imports/namespace_fingerprint.hepta","imports/namespace_fingerprint_callable.hepta","imports/namespace_fingerprint_callable.composition.json")},
        environment_bytes=4096,set_bytes=4096,invocation_bytes=131072,policy_workspace_bytes=8192,
        actual_native_syscalls=["getpid","mmap","munmap"],actual_native_mutex="pthread_mutex_t",
        actual_shared_atomic="aligned u64 load and lock cmpxchg",observer_optional=True,
        native_policy_or_hash_algorithm=False,python_or_rust_required_in_production=False,
        native_application_calls=0,original_application_calls=0,namespace_version_qualified=False,public_handler_qualified=False)
    return asm,hia,encoded(proof),pseudo.encode()
def run(root,hepta,build,output):
    output.mkdir(parents=True,exist_ok=False);(output/"generated/native").mkdir(parents=True);(output/"generated/authoring").mkdir()
    images={"namespace-versions":(build/"modules/namespace-versions/module.image.bin").read_bytes(),
        "namespace-watcher":(build/"dependencies/namespace-watcher/callable.image.bin").read_bytes(),
        "namespace-fingerprint":(build/"dependencies/namespace-fingerprint/callable.image.bin").read_bytes()}
    template=(root/"authoring/namespace_versions_callable.S.in").read_bytes();assert template.count(b"@POLICY_BYTES@")==1
    asm=template.replace(b"@POLICY_BYTES@",str(len(images["namespace-versions"])).encode())
    source=output/"namespace_versions_callable.S";source.write_bytes(asm)
    commands=[
        ["/usr/bin/as","--64","--fatal-warnings","-o",str(output/"adapter.o"),str(source)],
        ["/usr/bin/objcopy","-O","binary","--only-section=.text",str(output/"adapter.o"),str(output/"template.bin")],
        ["/usr/bin/readelf","--wide","--relocs","--symbols",str(output/"adapter.o")],
        ["/usr/bin/objdump","-d","--no-show-raw-insn",str(output/"adapter.o")]]
    receipts=[]
    for i,cmd in enumerate(commands):
        p=subprocess.run(cmd,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False,
            timeout=60,env={"PATH":"/usr/bin:/bin","LANG":"C","LC_ALL":"C","TZ":"UTC"})
        (output/(str(i)+".stdout")).write_bytes(p.stdout);(output/(str(i)+".stderr")).write_bytes(p.stderr)
        receipts.append(dict(argv=cmd,timeout_seconds=60,exit_code=p.returncode,stdout=pin(p.stdout),stderr=pin(p.stderr)))
        (output/"ASSEMBLY-PROCESSES.json").write_bytes(encoded(receipts))
        if p.returncode!=0 or p.stderr:raise ValueError("adapter assembly failed: "+str(i)+" "+p.stderr.decode())
    symbols=(output/"2.stdout").read_text()
    assert"There are no relocations in this file."in symbols and len([l for l in symbols.splitlines()if" UND "in l])==1
    offsets={}
    for name,symbol in EXPORTS.items():
        found=re.findall(r"\d+:\s+([0-9a-f]+)\s+\d+\s+\S+\s+GLOBAL\s+DEFAULT\s+1\s+"+symbol+r"\s*$",symbols,re.M)
        assert len(found)==1,(name,symbols);offsets[name]=int(found[0],16)
    raw=(output/"template.bin").read_bytes();stub=raw[:offsets["owner"]]
    assert raw==stub+bytes(sum(map(len,images.values())))and 0<offsets["initialize"]<offsets["set_allocate"]<offsets["set_dispose"]<len(stub)
    (output/"adapter.bin").write_bytes(stub);generated=generate(root,hepta,stub,offsets,images)
    targets=dict(zip(("authoring/namespace_versions_callable.S","native/namespace_versions_callable.hepta",
        "native/namespace_versions_callable.composition.json","authoring/namespace_versions_callable.pseudo"),generated))
    for name,body in targets.items():(output/"generated"/name).write_bytes(body)
    result=dict(schema="hepta.namespace-versions.callable-author.v1",status="SOURCE_ONLY_PASS",commands=receipts,
        source=json.loads(generated[2]),generated={name:pin(body)for name,body in targets.items()},native_application_calls=0,original_application_calls=0)
    (output/"AUTHORING.json").write_bytes(encoded(result))
    for name,body in targets.items():
        print("GENERATED_FILE_BEGIN "+name);print(body.decode(),end="");print("GENERATED_FILE_END "+name)
    print("NAMESPACE_VERSIONS_CALLABLE_AUTHOR "+json.dumps(result["generated"],sort_keys=True))
if __name__=="__main__":
    p=argparse.ArgumentParser()
    for name in("root","hepta","build","output"):p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args();run(a.root.resolve(strict=True),a.hepta.resolve(strict=True),a.build.resolve(strict=True),a.output.absolute())
