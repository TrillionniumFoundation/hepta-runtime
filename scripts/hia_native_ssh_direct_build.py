#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Build the fixed HIA SSH direct library. Never execute its inspection entry."""
from pathlib import Path
import argparse,hashlib,json,os,shutil,stat,subprocess,sys,time
sys.dont_write_bytecode=True
def pin(path):
    path=Path(path)
    with path.open("rb")as f:return dict(bytes=path.stat().st_size,sha256=hashlib.file_digest(f,"sha256").hexdigest())
def need(value,message):
    if not value:raise ValueError(message)
def encoded(value):return(json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode()
def sources(root):
    path=root/"native/ssh_direct_sources.json";manifest=json.loads(path.read_bytes())
    need(manifest["schema"]=="hepta.ssh.direct.production-sources.v1","exact SSH library source schema")
    for row in manifest["files"]:
        rel=Path(row["path"]);need(not rel.is_absolute()and".."not in rel.parts and str(rel)==row["path"],"canonical source path")
        p=root/rel;need(p.is_file()and not p.is_symlink()and stat.S_IMODE(p.stat().st_mode)==0o644,"ordinary fixed source")
        raw=p.read_bytes();need(pin(p)=={k:row[k]for k in("bytes","sha256")}and hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()==row["git_blob"],"entire SSH production source")
    return dict(manifest=pin(path),files=manifest["files"])
def tool(argv,root,label):
    start=time.monotonic_ns();row=dict(argv=list(map(str,argv)),timeout_seconds=180,applications=0)
    with(root/(label+".stdout")).open("xb")as out,(root/(label+".stderr")).open("xb")as err:
        try:r=subprocess.run(row["argv"],cwd=root,stdin=subprocess.DEVNULL,stdout=out,stderr=err,timeout=180,check=False);row.update(exit_code=r.returncode,timed_out=False)
        except subprocess.TimeoutExpired:row.update(exit_code=None,timed_out=True)
    row.update(elapsed_ns=time.monotonic_ns()-start,stdout=pin(root/(label+".stdout")),stderr=pin(root/(label+".stderr")))
    (root/(label+".json")).write_bytes(encoded(row));need(row["exit_code"]==0 and not row["timed_out"],"build tool failed "+label)
    return row
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in("source","hepta","output"):p.add_argument("--"+n,type=Path,required=True)
    a=p.parse_args();root=a.source.resolve(strict=True);hepta=a.hepta.resolve(strict=True);output=a.output.absolute()
    need(os.environ.get("GITHUB_ACTIONS")=="true","SSH library compilation remains CI-only")
    need(not output.exists(),"fresh library output");output.mkdir(parents=True);binding=sources(root)
    sys.path.insert(0,str(root/"scripts"));from hia_native_build import NativeBuild
    builder=NativeBuild(hepta,output/"build")
    layout=[("ssh_original_child","child"),("ssh_request_admission","admission"),("ssh_shared_owner","core"),("ssh_capture_io","io"),("ssh_capture_future","future")]
    members={};images={}
    for name,label in layout:
        manifest=builder.compile(name.replace("_","-"),root/("native/"+name+".hepta"),standalone=None,buffer_profile="history.v1")
        meta=json.loads(manifest.read_bytes());image=manifest.parent/meta["image"]
        composition=json.loads((root/("native/"+name+"_composition.json")).read_bytes())
        need(pin(image)==composition["qualified_image"],"actual freshly compiled HIA image differs "+name)
        members[name]=dict(manifest=pin(manifest),source=pin(root/("native/"+name+".hepta")),image=pin(image),entry=composition["entry"])
        images[name]=image
    native=output/"native";native.mkdir()
    parts=["core.S","api.S","spawn.S","ownership.S","io.S","owner.S","future.S"]
    text="\n".join((root/("asm/ssh_direct/"+name)).read_text()for name in parts)+'\n.section .note.GNU-stack,"",@progbits\n'
    (native/"owner.S").write_text(text);embedded=[".intel_syntax noprefix",".section .text"]
    for name,label in layout:
        path=native/(name+".bin");shutil.copyfile(images[name],path)
        embedded+=[".balign 16",".global ssh_hia_"+label,"ssh_hia_"+label+":",'.incbin "'+path.name+'"']
    embedded+=['.section .note.GNU-stack,"",@progbits'];(native/"images.S").write_text("\n".join(embedded)+"\n")
    records=[tool(["as","--64","-o","owner.o","owner.S"],native,"assemble-owner"),
        tool(["as","--64","-o","images.o","images.S"],native,"assemble-images"),
        tool(["ld","-r","-o","ssh-direct-owner.o","owner.o","images.o"],native,"link-relocatable"),
        tool(["ld","-nostdlib","-z","noexecstack","-e","ssh_direct_start","-o","ssh-direct-owner.elf","ssh-direct-owner.o"],native,"link-inspection"),
        tool(["readelf","--all","ssh-direct-owner.elf"],native,"readelf")]
    elf=(native/"readelf.stdout").read_text();need("INTERP"not in elf and"NEEDED"not in elf,"fixed library has a dynamic runtime dependency")
    need(pin(native/"ssh-direct-owner.o")==dict(bytes=565456,sha256="137d7d004e6dc0ffaaf9f29528d9d7ffb5879b4a4df2dd085fb0fdddbd324695"),"new final-layout library differs from actually captured production object")
    need(pin(native/"ssh-direct-owner.elf")==dict(bytes=571920,sha256="0fd61a340a62c398cf0f8f00c8d7cf1696fe45a33b69f9bbb46b76375c3cb341"),"new final-layout inspection ELF differs")
    need(sources(root)==binding,"production source changed during build")
    result=dict(status="FINAL_SSH_NATIVE_LIBRARY_BUILD_PASS",source=binding,members=members,
        object=pin(native/"ssh-direct-owner.o"),inspection_elf=pin(native/"ssh-direct-owner.elf"),build_tools=records,
        applications_executed=0,production_bytes_equal_actual_capture=True,public_ssh=False,full_sdk=False,old_stack_removed=False)
    (output/"BUILD.json").write_bytes(encoded(result));print(encoded(result).decode(),end="")
if __name__=="__main__":main()
