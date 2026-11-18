#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Read the sole final SSH build archive without any build or application replay."""
from pathlib import Path
import argparse,os,sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from capture_util import canonical,decode,need,pin,unpack,inventories
from common import source_evidence
PROTECTED=[]
def inside(p,r):
    try:return os.path.commonpath((str(Path(p).absolute()),str(r)))==str(r)
    except(TypeError,ValueError):return False
def audit(event,args):
    if event.startswith(("subprocess.","os.exec","os.spawn","os.posix_spawn"))or event in("os.system","ctypes.dlopen"):
        raise PermissionError("final reader cannot execute applications or controls")
    if event=="open":
        p,m,f=args
        if isinstance(p,(str,bytes,os.PathLike))and any(inside(p,r)for r in PROTECTED)and((isinstance(m,str)and any(x in m for x in"wax+"))or f&(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND)):
            raise PermissionError("immutable final input")
    effects={"os.remove":(0,),"os.rmdir":(0,),"os.mkdir":(0,),"os.rename":(0,1),"os.chmod":(0,),"os.utime":(0,),"os.link":(0,1),"os.symlink":(1,)}
    if event in effects and any(i<len(args)and any(inside(args[i],r)for r in PROTECTED)for i in effects[event]):raise PermissionError("immutable final metadata")
def guard(root,output):
    f=next(x for x in root.rglob("*")if x.is_file())
    plans=[("write",lambda:f.open("wb")),("append",lambda:f.open("ab")),("unlink",lambda:os.unlink(f)),
        ("chmod",lambda:os.chmod(f,0o600)),("utime",lambda:os.utime(f,None)),("rename",lambda:os.rename(f,output/"bad")),
        ("mkdir",lambda:os.mkdir(root/"bad")),("link",lambda:os.link(f,output/"badlink")),("symlink",lambda:os.symlink("bad",root/"badlink")),
        ("shell",lambda:os.system("exit 0")),("exec",lambda:os.execv("/usr/bin/true",["true"]))]
    out=[]
    for name,fn in plans:
        try:fn()
        except PermissionError as e:out.append(dict(name=name,status="REFUSED_BEFORE_EFFECT",reason=str(e)))
        else:raise ValueError("final guard failed "+name)
    return out

def main():
    p=argparse.ArgumentParser()
    for n in("source","archive","stage","output"):p.add_argument("--"+n,type=Path,required=True)
    a=p.parse_args();sys.addaudithook(audit)
    need(not a.output.exists()and not a.stage.exists(),"fresh pure reading destination");a.output.mkdir(parents=True)
    source=source_evidence(a.source);spec=decode((a.source/"INPUTS.json").read_bytes())
    root=unpack(a.archive,a.stage,spec);recipe=a.stage/"recipe-source";PROTECTED.extend((a.source.absolute(),a.stage.absolute()))
    before=inventories(a.stage);guards=guard(a.stage,a.output)
    binding=source_evidence(recipe);need(binding["files"]==spec["source_files"],"all frozen build-source files")
    need(pin(recipe/"SOURCE_MANIFEST.json")=={k:spec["source_manifest"][k]for k in("bytes","sha256")},"exact original build source closure")
    result=decode((root/"BUILD.json").read_bytes());need(result==spec["result"],"whole actual build result differs")
    need(result["status"]=="FINAL_SSH_NATIVE_LIBRARY_BUILD_PASS"and result["applications_executed"]==0,"completed zero-application build")
    need(result["production_bytes_equal_actual_capture"]and not result["public_ssh"]and not result["full_sdk"]and not result["old_stack_removed"],"exact qualified build scope")
    need(pin(root/"native/ssh-direct-owner.o")==dict(bytes=565456,sha256="137d7d004e6dc0ffaaf9f29528d9d7ffb5879b4a4df2dd085fb0fdddbd324695"),"full object equals actual captured production")
    need(pin(root/"native/ssh-direct-owner.elf")==dict(bytes=571920,sha256="0fd61a340a62c398cf0f8f00c8d7cf1696fe45a33b69f9bbb46b76375c3cb341"),"full inspection ELF equals actual captured production")
    expected_sources={r["path"]:r for r in decode((recipe/"SOURCE_MANIFEST.json").read_bytes())["files"]}
    for row in spec["production_files"]:
        need(expected_sources[row["path"]]["git_blob"]==row["git_blob"]and pin(recipe/row["path"])=={k:row[k]for k in("bytes","sha256")},"every final installed source raw byte")
    production=decode((recipe/"native/ssh_direct_sources.json").read_bytes())
    need(production["files"]==result["source"]["files"]and pin(recipe/"native/ssh_direct_sources.json")==result["source"]["manifest"],"entire qualified production dependency binding")
    members={}
    for name,wanted in result["members"].items():
        folder=root/"build/modules"/name.replace("_","-");manifest=folder/"manifest.json";meta=decode(manifest.read_bytes())
        need(pin(manifest)==wanted["manifest"],"entire compiler-produced manifest")
        need(pin(folder/meta["image"])==wanted["image"]and pin(root/("native/"+name+".bin"))==wanted["image"],"all compiled and embedded HIA image bytes")
        need(pin(recipe/("native/"+name+".hepta"))==wanted["source"],"entire raw HIA source")
        composition=decode((recipe/("native/"+name+"_composition.json")).read_bytes())
        need(composition["qualified_image"]==wanted["image"]and composition["entry"]=="f0","entire final composition source qualification")
        members[name]=dict(source=wanted["source"],image=wanted["image"],compiler_manifest=wanted["manifest"])
    need(len(members)==5,"five actual HIA owners")
    elf=(root/"native/readelf.stdout").read_text();need("INTERP"not in elf and"NEEDED"not in elf,"no dynamic implementation runtime")
    for step in result["build_tools"]:
        need(step["applications"]==0 and step["exit_code"]==0 and not step["timed_out"],"build tools only, all completed")
    need(inventories(a.stage)==before and source_evidence(a.source)==source,"all archived bytes, metadata and reader source remain immutable")
    proof=dict(status="SOLE_FINAL_SSH_LIBRARY_UPLOADED_READ_PASS",input={k:spec[k]for k in("artifact","run","job","commit","zip","tar")},source=source,
        production_sources=len(spec["production_files"]),build_sources=binding,members=members,
        object=result["object"],inspection_elf=result["inspection_elf"],complete_inventory=before,guards=guards,
        new_applications=0,new_builds=0,application_replays=0,physical_control_replays=0,public_ssh=False,full_sdk=False,old_stack_removed=False)
    (a.output/"RESULT.json").write_bytes(canonical(proof))
    print(canonical(dict(status=proof["status"],complete_files=sum(x["kind"]=="file"for x in before),complete_bytes=sum(x.get("bytes",0)for x in before),
        production_sources=proof["production_sources"],build_source_count=binding["files"],images=len(members),fresh_guards=len(guards),
        object=proof["object"],inspection_elf=proof["inspection_elf"],new_applications=0,new_builds=0,proof=pin(a.output/"RESULT.json"))).decode(),end="")
if __name__=="__main__":main()
