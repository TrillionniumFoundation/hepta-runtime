#!/usr/bin/env python3
"""Four actual corrupt files and two complete relocations, with zero application calls."""
from pathlib import Path
import argparse,os,shutil,sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from callable_common import decode,encoded,pin,require
from bootstrap_input import inventory
from readonly import guarded
import read_callable_build

def run(source,build,output):
    source,build=source.resolve(strict=True),build.resolve(strict=True)
    require(not output.exists(),"fresh physical-control directory");output.mkdir(parents=True)
    manifest=decode((build/"BUILD.json").read_bytes())
    body=Path(manifest["members"]["body"]["manifest"])
    body_meta=decode((build/body).read_bytes())
    cases=[
        ("source-native","source","asm/binary_entropy_callable.S","source bytes/mode differ"),
        ("compiled-owner","build",(body.parent/body_meta["source"]).as_posix(),"actual member bytes differ"),
        ("packed-output","build","pack.output.bin","full build artifact bytes differ"),
        ("copied-B3","build","build/bootstrap/B3.image.bin","bootstrap generation differs"),
        ("relocation-a",None,None,None),("relocation-b",None,None,None)]
    result=[]
    for name,which,relative,expected in cases:
        folder=output/name;folder.mkdir()
        work=folder/"working";work.mkdir()
        shutil.copytree(source,work/"source",copy_function=os.link)
        shutil.copytree(build,work/"build",copy_function=os.link)
        changed=None
        if which is not None:
            target=work/which/relative;before=target.read_bytes();mode=target.stat().st_mode&0o777
            require(before,"nonempty physical mutation");after=bytes([before[0]^1])+before[1:]
            target.unlink();target.write_bytes(after);target.chmod(mode)
            (folder/"before.bin").write_bytes(before);(folder/"after.bin").write_bytes(after)
            changed=dict(root=which,path=relative,before=pin(folder/"before.bin"),
                after=pin(folder/"after.bin"),mode=mode,changed_offset=0)
        def body_read():
            if expected is None:
                value=read_callable_build.verify(work/"source",work/"build")
                return dict(status="COMPLETE_RELOCATED_BUILD_PASS",qualification=value)
            try:read_callable_build.verify(work/"source",work/"build")
            except (ValueError,AssertionError,KeyError) as exc:
                require(expected in str(exc),"wrong physical refusal: "+str(exc))
                return dict(status="TARGETED_PHYSICAL_REFUSAL",error_type=type(exc).__name__,message=str(exc))
            raise ValueError("physically corrupted build accepted")
        checked=guarded(body_read,roots=[work/"source",work/"build"])
        (folder/"READONLY.json").write_bytes(encoded(checked))
        require(checked["before"]==checked["after"] and len(checked["probes"])==11,"control pure guard")
        if changed is not None:
            target=work/which/relative;target.unlink();target.write_bytes(before);target.chmod(mode)
        require(inventory(work/"source")==inventory(source) and inventory(work/"build")==inventory(build),
            "full copied bytes and modes before retirement")
        retired=len(inventory(work/"source")["files"])+len(inventory(work/"build")["files"])
        shutil.rmtree(work)
        result.append(dict(name=name,physical=changed,guard=pin(folder/"READONLY.json"),
            result=checked["evidence"],retired_complete_duplicate_files=retired))
    report=dict(status="FOUR_PHYSICAL_REFUSALS_TWO_COMPLETE_RELOCATIONS_PASS",cases=result,
        guarded_process_calls=6,guard_probes=66,new_native_application_calls=0,new_rust_calls=0)
    (output/"CONTROLS.json").write_bytes(encoded(report));print(encoded(report).decode(),end="")
    return report

if __name__=="__main__":
    p=argparse.ArgumentParser()
    for key in("source","build","output"):p.add_argument("--"+key,type=Path,required=True)
    a=p.parse_args();run(a.source,a.build,a.output.absolute())
