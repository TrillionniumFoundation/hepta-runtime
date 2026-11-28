"""Build frozen real engines and one actual HIA leaf; CI-only native compilation."""
from pathlib import Path
import argparse,json,os,shutil,stat,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
sys.path[:0]=[str(ROOT),str(ROOT/"scripts")]
from common import source,read,pin,put,SHA
from layout import layout,rebind,upgrade,undo
from process import Recorder
from hia_native_build import NativeBuild
EXPORTS=["runtime_grow_create","fixture_invoke","fixture_destroy","fixture_detach","fixture_restore","view_allocate"]
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--hepta",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--source-manifest-sha256",required=True)
    a=p.parse_args();identity=source(a.source_manifest_sha256)
    assert not a.output.exists();a.output.mkdir(parents=True)
    out=a.output.resolve();rec=Recorder(ROOT,out/"processes")
    reference=json.loads(read(ROOT/"REFERENCE.json"))
    for path,expected in reference["files"].items():
        assert pin(read(ROOT/"reference"/Path(path).name))==expected
    domain=json.loads(read(ROOT/"DOMAIN.json"));layouts=json.loads(read(ROOT/"LAYOUTS.json"))["layouts"]
    old=read(ROOT/"reference/runtime_mcp_extra_engine.S").decode()
    base=read(ROOT/"engines/new_59.S").decode()
    assert upgrade(old)==base and undo(base)==old
    for count in domain["new_slot_counts"]:
        assert layouts[str(count)]==layout(count)
        value=read(ROOT/"engines"/("new_"+str(count)+".S")).decode()
        assert value==rebind(base,count)
        assert undo(rebind(value,59))==old
    compiler=json.loads(read(ROOT/"COMPILER_IDENTITY.json"))
    build=NativeBuild(a.hepta,out/"hia")
    assert build.identity==compiler
    compiler_image=read(build.bootstrap())
    assert pin(compiler_image)==dict(bytes=673413,sha256="bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0")
    manifest=build.compile("fixture-leaf",ROOT/"native/fixture_leaf.hepta",standalone=None)
    leaf_image=read(manifest.parent/"module.image.bin")
    for name,expected in compiler["files"].items():
        raw=read(a.hepta/name);assert SHA(raw)==expected
        path=out/"compiler-source"/name;path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(raw);path.chmod(stat.S_IMODE((a.hepta/name).stat().st_mode))
    tool_ids={}
    tools={name:str(Path(shutil.which(name)).resolve(strict=True)) for name in ("as","ld","objcopy","nm")}
    for name,path in tools.items():
        raw=read(Path(path));target=out/"toolchain"/name;target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(raw);target.chmod(0o755)
        tool_ids[name]=dict(path=path,**pin(raw))
        rec.run(name+"-version",[path,"--version"],timeout=60)
    allocator_raw=read(ROOT/"reference/view_call_engine.S").decode()
    start=allocator_raw.index("view_allocate:\n")
    end=allocator_raw.index("view_write_all:\n")
    allocator=".intel_syntax noprefix\n.section .text\n.global view_allocate\n.global view_resize\n"+allocator_raw[start:end]
    (out/"allocator.S").write_text(allocator)
    images={}
    roles=[("old59",59,old)]+[("new"+str(n),n,read(ROOT/"engines"/("new_"+str(n)+".S")).decode())
                             for n in domain["new_slot_counts"]]
    for role,count,engine in roles:
        folder=out/role;folder.mkdir()
        combined=(".equ PM_FIXED_TRACE_FD, 0\n.equ PM_FIXED_FIXTURE_FDS, 0\n"+engine+"\n"+
            read(ROOT/"reference/runtime_mcp_task_storage.S").decode()+"\n"+
            read(ROOT/"reference/runtime_mcp_workdir_io_bridge.S").decode()+"\n"+
            read(ROOT/"reference/runtime_mcp_filesystem_io_bridge.S").decode()+"\n"+
            allocator+"\n"+read(ROOT/"fixture.S").decode())
        (folder/"combined.S").write_text(combined)
        rec.run(role+"-assemble",[tools["as"],"--64",folder/"combined.S","-o",folder/"combined.o"],timeout=60)
        undefined_raw,_=rec.run(role+"-undefined",[tools["nm"],"-u",folder/"combined.o"],timeout=60)
        undefined=[]
        for line in undefined_raw.decode().splitlines():
            fields=line.split()
            assert len(fields)==2 and fields[0]=="U" and all(c.isalnum() or c=="_" for c in fields[1])
            undefined.append(fields[1])
        assert len(undefined)==len(set(undefined)) and undefined
        stubs=(".intel_syntax noprefix\n.section .text\n"+
            "".join(".global "+name+"\n"+name+":\n" for name in undefined)+
            "    mov edi,71\n    mov eax,231\n    syscall\n    ud2\n.section .note.GNU-stack,\"\",@progbits\n")
        (folder/"stubs.S").write_text(stubs)
        rec.run(role+"-stubs",[tools["as"],"--64",folder/"stubs.S","-o",folder/"stubs.o"],timeout=60)
        rec.run(role+"-link",[tools["ld"],"--build-id=none","-z","noexecstack","-e","_start","-Ttext=0",
            "-o",folder/"linked.elf",folder/"combined.o",folder/"stubs.o"],timeout=60)
        rec.run(role+"-flat",[tools["objcopy"],"-O","binary","--only-section=.text",
            folder/"linked.elf",folder/"module.bin"],timeout=60)
        symbols_raw,_=rec.run(role+"-symbols",[tools["nm"],"-n","-P",folder/"linked.elf"],timeout=60)
        symbols={}
        for line in symbols_raw.decode().splitlines():
            row=line.split()
            if len(row)>=3 and row[1].lower()=="t":symbols[row[0]]=int(row[2],16)
        image=read(folder/"module.bin")
        images[role]=dict(slots=count,layout=layout(count),source=pin(engine.encode()),combined=pin(combined.encode()),
            image=pin(image),exports={key:symbols[key] for key in EXPORTS},
            undefined_traps=undefined,old_low_words_only=role=="old59")
    assert source()==identity
    report=dict(schema="hepta.runtime.engine-layout.build.v1",status="PASS",source_manifest_sha256=identity,
        compiler=compiler,compiler_image=pin(compiler_image),
        hia_leaf=dict(manifest=str(manifest.relative_to(out)),manifest_pin=pin(read(manifest)),image=pin(leaf_image)),
        assembler_toolchain=tool_ids,images=images,engine_variants=len(images),native_or_rust_executed_in_this_stage="HIA compiler only",
        rust_executed=False,public_handler_qualified=False,whole_runtime_replaced=False)
    put(out/"BUILD.json",report)
    print(json.dumps(dict(status="PASS",engine_variants=len(images),leaf_image=pin(leaf_image),
        native_compiler=pin(compiler_image),source_manifest_sha256=identity),sort_keys=True))
if __name__=="__main__":main()
