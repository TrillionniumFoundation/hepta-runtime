#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Compile four real HIA owners and assemble their native syscall adapter; zero applications."""
from pathlib import Path
import argparse,base64,json,os,shutil,subprocess,sys,time
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import canonical,pin,require,source_evidence
def command(argv,root,label):
    began=time.monotonic()
    with (root/(label+".stdout")).open("xb") as out,(root/(label+".stderr")).open("xb") as err:
        value=subprocess.run(argv,cwd=root,stdin=subprocess.DEVNULL,stdout=out,stderr=err,timeout=180,check=False)
    row=dict(command=[str(x) for x in argv],exit_code=value.returncode,timeout_seconds=180,
        elapsed_seconds=time.monotonic()-began,stdout=pin(root/(label+".stdout")),stderr=pin(root/(label+".stderr")))
    (root/(label+".json")).write_bytes(canonical(row))
    if value.returncode:sys.stderr.write((root/(label+".stderr")).read_text(errors="replace"))
    require(value.returncode==0,"native build tool failed: "+label)
    return row
def main():
    p=argparse.ArgumentParser()
    for n in ("source","hepta","output"):p.add_argument("--"+n,type=Path,required=True)
    a=p.parse_args();source=a.source.resolve();hepta=a.hepta.resolve();output=a.output.absolute()
    require(os.environ.get("GITHUB_ACTIONS")=="true","CI-only build")
    require(not output.exists(),"fresh output");output.mkdir(parents=True)
    identity=source_evidence(source)
    for path in source.rglob("*.py"):compile(path.read_bytes(),str(path),"exec")
    shutil.copytree(source,output/"recipe-source")
    sys.path.insert(0,str(source/"authoring"));from author import author
    proof=author(source,hepta,output/"generated")
    sys.path.insert(0,str(source/"scripts"));from hia_native_build import NativeBuild
    builder=NativeBuild(hepta,output/"build");members={};images={}
    for name in proof["modules"]:
        path=builder.compile(name.replace("_","-"),output/("generated/"+name+".hepta"),standalone=None,buffer_profile="history.v1")
        manifest=json.loads(path.read_bytes());images[name]=path.parent/manifest["image"]
        members[name]=dict(manifest=pin(path),manifest_path=path.relative_to(output).as_posix(),
            source=pin(path.parent/manifest["source"]),image=pin(images[name]))
    compiler=output/"compiler-source";compiler.mkdir()
    for name in builder.identity["files"]:
        destination=compiler/name;destination.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(hepta/name,destination)
    native=output/"native";native.mkdir()
    parts=["core.S","api.S","spawn.S","ownership.S","io.S","owner.S"]
    assembly="\n".join((source/("native/"+name)).read_text() for name in parts)
    assembly+='\n.section .note.GNU-stack,"",@progbits\n'
    (native/"owner.S").write_text(assembly)
    labels={"ssh_original_child":"child","ssh_request_admission":"admission","ssh_shared_owner":"core","ssh_capture_io":"io"}
    embedded=['.intel_syntax noprefix','.section .text']
    for name,label in labels.items():
        dest=native/(name+".bin");shutil.copyfile(images[name],dest)
        embedded+=['.balign 16','.global ssh_hia_'+label,'ssh_hia_'+label+':','.incbin "'+dest.name+'"']
    embedded+=['.section .note.GNU-stack,"",@progbits']
    (native/"images.S").write_text("\n".join(embedded)+"\n")
    records=[]
    records.append(command(["as","--64","-o","owner.o","owner.S"],native,"assemble-owner"))
    records.append(command(["as","--64","-o","images.o","images.S"],native,"assemble-images"))
    records.append(command(["ld","-r","-o","ssh-direct-owner.o","owner.o","images.o"],native,"link-relocatable"))
    records.append(command(["ld","-nostdlib","-z","noexecstack","-e","ssh_direct_start","-o","ssh-direct-owner.elf","ssh-direct-owner.o"],native,"link-inspection-elf"))
    records.append(command(["readelf","--all","ssh-direct-owner.elf"],native,"readelf"))
    records.append(command(["nm","-n","ssh-direct-owner.elf"],native,"symbols"))
    text=(native/"readelf.stdout").read_text()
    require("INTERP" not in text and "NEEDED" not in text,"native adapter has dynamic runtime dependencies")
    require(source_evidence(source)==identity,"build source changed")
    result=dict(status="FRESH_SSH_NATIVE_ACTOR_BUILD_PASS",source=identity,author=proof,
        members=members,compiler_identity=builder.identity,native=dict(object=pin(native/"ssh-direct-owner.o"),
        inspection_elf=pin(native/"ssh-direct-owner.elf"),source=pin(native/"owner.S"),build_tools=records),
        applications_executed=0,source_authoring_only=True,
        independent_native_actor_assembled=True,actual_process_qualified=False,public_ssh_qualified=False,full_sdk=False)
    (output/"BUILD.json").write_bytes(canonical(result));print(json.dumps(result,sort_keys=True))
    for name in proof["modules"]:
        raw=(output/("generated/"+name+".hepta")).read_bytes()
        print("EXACT_GENERATED_HIA "+json.dumps(dict(path="generated/"+name+".hepta",**pin(output/("generated/"+name+".hepta")),base64=base64.b64encode(raw).decode()),sort_keys=True))
if __name__=="__main__":main()
