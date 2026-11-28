"""Assemble the fixed native boundary and author its one-member HIA packer."""
import argparse,ast,hashlib,json,re,subprocess,sys
from pathlib import Path
def pin(raw):
    return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(value):
    return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+"\n").encode()
def run(hepta,root,output,owner_image):
    owner=pin(owner_image.read_bytes())
    output.mkdir(parents=True,exist_ok=False)
    (output/"generated/native").mkdir(parents=True)
    (output/"generated/authoring").mkdir()
    template=root/"authoring/namespace_watcher_callable.S.in"
    template_raw=template.read_bytes();assert template_raw.count(b"@OWNER_BYTES@")==1
    source=output/"namespace_watcher_callable.S"
    source.write_bytes(template_raw.replace(b"@OWNER_BYTES@",str(owner["bytes"]).encode()))
    commands=[
        ["/usr/bin/as","--64","--fatal-warnings","-o",str(output/"adapter.o"),str(source)],
        ["/usr/bin/objcopy","-O","binary","--only-section=.text",str(output/"adapter.o"),str(output/"template.bin")],
        ["/usr/bin/readelf","--wide","--relocs","--symbols",str(output/"adapter.o")],
        ["/usr/bin/objdump","-d","--no-show-raw-insn",str(output/"adapter.o")]]
    receipts=[]
    for index,command in enumerate(commands):
        completed=subprocess.run(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False,
            timeout=60,env={"PATH":"/usr/bin:/bin","LANG":"C","LC_ALL":"C","TZ":"UTC"})
        (output/(str(index)+".stdout")).write_bytes(completed.stdout)
        (output/(str(index)+".stderr")).write_bytes(completed.stderr)
        receipts.append(dict(argv=command,timeout_seconds=60,exit_code=completed.returncode,stdout=pin(completed.stdout),stderr=pin(completed.stderr)))
        (output/"ASSEMBLY-PROCESSES.json").write_bytes(encoded(receipts))
        if completed.returncode!=0 or completed.stderr:raise ValueError("fixed adapter assembly failed: "+str(index))
    symbols=(output/"2.stdout").read_text()
    assert "There are no relocations in this file." in symbols
    assert len([line for line in symbols.splitlines() if " UND " in line])==1
    offsets={}
    names={name:"namespace_watcher_"+name for name in ("entry","initialize","bind","dispose","owner","end")}
    names.update({name:"namespace_file_"+name for name in ("pin_adopt","pin_clone","pin_release")})
    for name,symbol in names.items():
        found=re.findall(r"\d+:\s+([0-9a-f]+)\s+\d+\s+\S+\s+GLOBAL\s+DEFAULT\s+1\s+"+symbol+r"\s*$",symbols,re.M)
        assert len(found)==1,(name,symbols)
        offsets[name]=int(found[0],16)
    raw=(output/"template.bin").read_bytes()
    assert offsets["entry"]==0 and 0<offsets["initialize"]<offsets["bind"]<offsets["dispose"]<offsets["pin_adopt"]<offsets["pin_clone"]<offsets["pin_release"]<offsets["owner"]
    assert offsets["owner"]%16==0 and offsets["end"]==len(raw)==offsets["owner"]+owner["bytes"]
    stub=raw[:offsets["owner"]];assert raw[len(stub):]==bytes(owner["bytes"])
    (output/"adapter.bin").write_bytes(stub)
    magic=int.from_bytes(b"HNWPK001","little")
    head=f"""def namespace_watcher_callable(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!={24+owner['bytes']} or read64(s,0)!={magic} or read64(s,8)!=1 or read64(s,16)!={owner['bytes']}:
        return 4294967295
    if length(o)<{len(raw)}:
        return 4294967294
"""
    functions=[]
    for start in range(0,len(stub),512):
        name="literal_"+str(start);head+="    "+name+"(o)\n"
        body="def "+name+"(o:mutbuf) -> u64:\n"
        for at in range(start,min(start+512,len(stub)),8):
            assert len(stub[at:at+8])==8
            body+=f"    put64(o,{at},{int.from_bytes(stub[at:at+8],'little')})\n"
        functions.append(body+"    return 0\n")
    head+=f"""    at=0
    while at<{owner['bytes']}:
        store(o,{offsets['owner']}+at,byte(s,24+at))
        at=at+1
    return {len(raw)}
"""
    functions.insert(0,head)
    functions.extend([
        "def read64(s:readbuf,at:u64) -> u64:\n    return byte(s,at)|(byte(s,at+1)<<8)|(byte(s,at+2)<<16)|(byte(s,at+3)<<24)|(byte(s,at+4)<<32)|(byte(s,at+5)<<40)|(byte(s,at+6)<<48)|(byte(s,at+7)<<56)\n",
        "def put64(o:mutbuf,at:u64,value:u64) -> u64:\n"+"".join(f"    store(o,at+{i},(value>>{8*i})&255)\n" for i in range(8))+"    return 0\n"])
    pseudo="\n".join(functions)
    sys.dont_write_bytecode=True;sys.path.insert(0,str(hepta))
    from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program,render_assembly
    nodes=ast.parse(pseudo).body;names={n.name:"f"+str(i) for i,n in enumerate(nodes)}
    signatures={n.name:([p.annotation.id for p in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes);rows=[]
    for node in nodes:
        b=Builder(node,names,signatures,total);b.statements(node.body)
        rows.append(dict(name=names[node.name],params=[b.param(p) for p in b.params],returns=[b.returns],
            effects=["read","write","trap"],entry="b0",blocks=b.blocks))
    program=compact_authoring_cfg(dict(schema="hepta.hia.program.v8",module="namespace_watcher_callable",functions=rows))
    hia=render_assembly(program).encode();checked=assemble_program(hia).as_dict()
    assert all(len(f["blocks"])<=256 for f in checked["functions"])
    count=sum(len(b["ops"]) for f in checked["functions"] for b in f["blocks"]);assert count<=8192
    proof=dict(schema="hepta.namespace-watcher-callable.source.v1",adapter_source=pin(source.read_bytes()),adapter_template=pin(template_raw),
        author=pin(Path(__file__).read_bytes()),semantic_source=pin((root/"native/namespace_watcher.hepta").read_bytes()),
        adapter=pin(stub),adapter_hex=stub.hex(),owner=owner,offsets=offsets,image_bytes=len(raw),context_bytes=131072,
        packer_source=pin(hia),pseudo=pin(pseudo.encode()),functions=len(checked["functions"]),instructions=count,
        relocations=0,unresolved_symbols=0,runtime_python_required=False,runtime_rust_required=False,observer_optional=True,
        libc_functions=["inotify_init1","read","fstat","fcntl","inotify_add_watch","inotify_rm_watch","close","__errno_location"],
        actual_native_syscalls=["mmap","munmap"],shared_file_refs="native atomic compare-and-exchange",
        native_policy_or_hash_algorithm=False,semantic_execution=False,qualification_pending=True,
        public_handler_qualified=False,whole_runtime_replaced=False)
    targets={"authoring/namespace_watcher_callable.S":source.read_bytes(),
        "native/namespace_watcher_callable.hepta":hia,
        "native/namespace_watcher_callable.composition.json":encoded(proof),
        "authoring/namespace_watcher_callable.pseudo":pseudo.encode()}
    for name,body in targets.items():(output/"generated"/name).write_bytes(body)
    result=dict(schema="hepta.namespace-watcher-callable.authoring.v1",status="SOURCE_ONLY_PASS",commands=receipts,
        source=proof,generated={name:pin(body) for name,body in targets.items()},native_or_rust_executions=0)
    (output/"AUTHORING.json").write_bytes(encoded(result))
    for name,body in targets.items():
        print("GENERATED_FILE_BEGIN "+name);print(body.decode(),end="");print("GENERATED_FILE_END "+name)
    print("GENERATED_MANIFEST "+json.dumps(result["generated"],sort_keys=True));print(encoded(result).decode(),end="")
if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--hepta",type=Path,required=True)
    p.add_argument("--root",type=Path,required=True);p.add_argument("--output",type=Path,required=True);p.add_argument("--owner-image",type=Path,required=True)
    a=p.parse_args();run(a.hepta.resolve(strict=True),a.root.resolve(strict=True),a.output.absolute(),a.owner_image.resolve(strict=True))
