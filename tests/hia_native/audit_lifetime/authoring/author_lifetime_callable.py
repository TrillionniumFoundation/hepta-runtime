"""Author the HIA packer for the actual native audit lifetime callable."""
import argparse
import json
from pathlib import Path
import re
import sys

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root",type=Path,required=True)
    parser.add_argument("--hepta",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    root,output=args.root.resolve(),args.output.resolve()
    output.mkdir(parents=True,exist_ok=False)
    sys.dont_write_bytecode=True
    sys.path.insert(0,str(args.hepta.resolve()))
    sys.path.insert(0,str(root/"authoring"))
    sys.path.insert(0,str(root))
    from author_lifetime import render,pin
    from process import Recorder
    earlier=json.loads((root/"native/audit_lifetime.composition.json").read_bytes())
    refs=earlier["reference_instructions"]["bytes"]
    assert refs==1051 and earlier["reference_instructions"]["sha256"]=="6929b4cc3b92ab7ca6e2d92f62a545588c027d5f841770a7c8751c58d8c5d2e2"
    template=root/"authoring/audit_lifetime_callable.S.in"
    source=template.read_text()
    constants=dict(REQUEST=b"HARGQ001",CONTEXT=b"HARCTX01",ACTOR=b"HARGA001",
                   MAP=b"HARMAP01",SYNC_REQUEST=b"HASCMD01")
    for name,value in constants.items():
        source=source.replace("@"+name+"@","0x"+format(int.from_bytes(value,"little"),"x"))
    source=source.replace("@REF_BYTES@",str(refs))
    assert "@" not in source.replace("@function","").replace("@progbits","")
    assembly=output/"callable.S"
    assembly.write_text(source)
    recorder=Recorder(root,output/"processes")
    commands=[
        ["/usr/bin/as","--64","-o",str(output/"callable.o"),str(assembly)],
        ["/usr/bin/objcopy","-O","binary","--only-section=.text",str(output/"callable.o"),str(output/"template.bin")],
        ["/usr/bin/readelf","--wide","--relocs","--symbols",str(output/"callable.o")]]
    records=[]
    for index,command in enumerate(commands):
        raw,row=recorder.run("author-pump-"+str(index),command,timeout=60)
        records.append(row)
    symbols=raw.decode()
    assert "There are no relocations in this file." in symbols
    assert len([line for line in symbols.splitlines() if " UND " in line])==1
    offsets={}
    for name in ("entry","refs","sync","controller","adapter_end"):
        matches=re.findall(r"\d+:\s+([0-9a-f]+)\s+\d+\s+\S+\s+GLOBAL\s+DEFAULT\s+1\s+audit_lifetime_"+name+r"\s*$",symbols,re.M)
        assert len(matches)==1,(name,symbols)
        offsets[name]=int(matches[0],16)
    code=(output/"template.bin").read_bytes()
    assert offsets["entry"]==0 and len(code)==offsets["controller"]==offsets["adapter_end"]
    assert offsets["refs"]+refs<=offsets["sync"] and offsets["sync"]+1635<=len(code)
    assert code[offsets["refs"]:offsets["refs"]+refs]==bytes(refs)
    assert code[offsets["sync"]:offsets["sync"]+1635]==bytes(1635)
    magic=int.from_bytes(b"HARPMP01","little")
    start=f"""def audit_lifetime_callable(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<40 or read64(s,0)!={magic} or read64(s,8)!=1:
        return 4294967295
    controller=read64(s,16)
    if controller==0 or controller>4294960000-{len(code)}:
        return 4294967295
    if read64(s,24)!={refs} or read64(s,32)!=1635 or length(s)!=40+controller+{refs}+1635:
        return 4294967295
    needed={len(code)}+controller
    if length(o)<needed:
        return 4294967294
"""
    positions=[i for i in range(len(code)) if not (offsets["refs"]<=i<offsets["refs"]+refs or offsets["sync"]<=i<offsets["sync"]+1635)]
    chunks=[]
    for at in range(0,len(positions),96):
        name="emit_"+str(at)
        start+=f"    {name}(o)\n"
        body=f"def {name}(o:mutbuf) -> u64:\n"
        body+="".join(f"    store(o,{i},{code[i]})\n" for i in positions[at:at+96])
        chunks.append(body+"    return 0\n")
    start+=f"""    at=0
    while at<controller:
        store(o,{offsets['controller']}+at,byte(s,40+at))
        at=at+1
    at=0
    while at<{refs}:
        store(o,{offsets['refs']}+at,byte(s,40+controller+at))
        at=at+1
    at=0
    while at<1635:
        store(o,{offsets['sync']}+at,byte(s,40+controller+{refs}+at))
        at=at+1
    return needed
"""
    read64="""def read64(s:readbuf,at:u64) -> u64:
    return byte(s,at)|(byte(s,at+1)<<8)|(byte(s,at+2)<<16)|(byte(s,at+3)<<24)|(byte(s,at+4)<<32)|(byte(s,at+5)<<40)|(byte(s,at+6)<<48)|(byte(s,at+7)<<56)
"""
    hia,shape=render("\n".join([start,*chunks,read64]),"audit_lifetime_callable")
    native=root/"native"
    path=native/"audit_lifetime_callable.hepta"
    path.write_bytes(hia)
    proof=dict(schema="hepta.audit-lifetime.callable-authoring.v1",
        source_template=pin(template.read_bytes()),resolved_assembly=pin(assembly.read_bytes()),
        author=pin(Path(__file__).read_bytes()),hia=pin(hia),shape=shape,
        template_instructions=pin(code),template_hex=code.hex(),offsets=offsets,
        emitted_positions=positions,reference_instructions=earlier["reference_instructions"],
        synchronization=dict(bytes=1635,sha256="b2a5f181d26382ab4c7d0759097b922eb4df1864636e0209b66db2e80f3c0ca9"),
        controller_source=earlier["controller"],commands=records,
        runtime_rust_required=False,runtime_python_required=False,observer_optional=True,
        native_or_hia_execution=0,qualified=False,production_activated=False,
        public_handler_qualified=False,whole_runtime_replaced=False)
    composition=native/"audit_lifetime_callable.composition.json"
    composition.write_text(json.dumps(proof,sort_keys=True,indent=2)+"\n")
    files={}
    for path in (path,composition):
        relative=path.relative_to(root).as_posix()
        raw=path.read_bytes()
        files[relative]=pin(raw)
        print("GENERATED_FILE_BEGIN "+relative)
        print(raw.decode(),end="")
        print("GENERATED_FILE_END "+relative)
    (output/"AUTHORING.json").write_text(json.dumps(dict(source_files=files,native_or_hia_execution=0),sort_keys=True,indent=2)+"\n")
    print("GENERATED_MANIFEST "+json.dumps(files,sort_keys=True))

if __name__=="__main__":
    main()
