#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Build the fixed native binary-write stdio graph with actual HIA link and pack."""
from __future__ import annotations
import argparse, hashlib, json, re, shutil, struct, subprocess, sys, time
from pathlib import Path
sys.dont_write_bytecode=True
def sha(b):return hashlib.sha256(b).hexdigest()
def pin(p):
 p=Path(p);b=p.read_bytes();return dict(bytes=len(b),sha256=sha(b))
def require(v,m):
 if not v:raise ValueError(m)
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2)+"\n").encode()
IMAGES=("walk","body","metadata","codec","stat","error","publish","read","base64","entropy")
MEMBERS=(("walk","native/public_binary_write.hepta"),("body","native/public_binary_write_body_profile.hepta"),
 ("metadata","native/file_metadata.hepta"),("codec","native/binary_codec.hepta"),("stat","native/stat_version.hepta"),
 ("error","native/path_error.hepta"),("publish","native/publish_at.hepta"),("read","native/binary_read_body.hepta"),
 ("base64","native/public_binary_write_base64_profile.hepta"),("entropy","native/binary_entropy.hepta"),
 ("linker","compiler/elf_static_linker.hepta"),("packer","native/runtime_mcp_image_packer.hepta"))
PATCHES=(("public_binary_write_body_call_displacement",0),("binary_write_body_body_call_displacement",1),
 ("binary_write_body_stat_call_displacement",4),("binary_write_body_codec_call_displacement",3),
 ("binary_write_body_base64_call_displacement",8),("publish_at_body_call_displacement",6),
 ("publish_at_stat_call_displacement",4),("binary_read_body_body_call_displacement",7),
 ("binary_read_body_codec_call_displacement",3),("binary_read_body_stat_call_displacement",4),
 ("file_metadata_body_call_displacement",2),("file_metadata_codec_call_displacement",3),
 ("binary_entropy_body_call_displacement",9),("public_binary_write_error_call_displacement",5))
ASM=("asm/binary_write_body_callable.S","asm/publish_at_callable.S","asm/binary_read_body_callable.S",
 "asm/file_metadata_callable.S","asm/binary_entropy_callable.S","asm/process_orphans.S")
VARIANTS={"production":(0,0,0),"observed":(1,0,0),"fd-zero":(1,1,0),"close-error":(1,0,1)}
def flatten(source):
 names=re.findall(r"^\.global ([A-Za-z_][A-Za-z_0-9]*)$",source,re.M)
 require(len(names)==len(set(names)) and names.count("_start")==1,"global symbols differ")
 text=source
 for name in names:
  if name=="_start":continue
  alias=name+"_flat"
  require("\n"+alias+":" not in text,"flatten alias already exists")
  text=text.replace("\n"+name+":","\n"+name+":\n"+alias+":")
  text=re.sub(r"\b(call|jmp) "+re.escape(name)+r"\b",lambda m:m[1]+" "+alias,text)
  text=re.sub(r"\[rip\s*\+\s*"+re.escape(name)+r"\]",lambda m:m[0].replace(name,alias),text)
 restored=text
 for name in reversed(names):
  if name=="_start":continue
  alias=name+"_flat"
  restored=restored.replace("\n"+alias+":","")
  restored=re.sub(r"\b(call|jmp) "+re.escape(alias)+r"\b",lambda m:m[1]+" "+name,restored)
  restored=re.sub(r"\[rip\s*\+\s*"+re.escape(alias)+r"\]",lambda m:m[0].replace(alias,name),restored)
 require(restored==source,"flattening is not exactly invertible")
 return text
def process(out,name,argv,timeout=30):
 start=time.monotonic()
 with (out/(name+".stdout")).open("xb") as stdout,(out/(name+".stderr")).open("xb") as stderr:
  p=subprocess.run([str(x) for x in argv],stdout=stdout,stderr=stderr,timeout=timeout)
 row=dict(argv=[str(x) for x in argv],returncode=p.returncode,seconds=time.monotonic()-start,timeout_seconds=timeout,
  stdout=pin(out/(name+".stdout")),stderr=pin(out/(name+".stderr")))
 (out/(name+".json")).write_bytes(encoded(row))
 require(p.returncode==0,"process failed: "+name)
 require(row["stderr"]["bytes"]==0,"process stderr: "+name)
 return row
def main():
 p=argparse.ArgumentParser(description=__doc__)
 for key in ("source","hepta","bootstrap","output"):p.add_argument("--"+key,required=True,type=Path)
 p.add_argument("--variants",nargs="+",choices=tuple(VARIANTS),default=list(VARIANTS))
 a=p.parse_args();root=a.source.resolve(strict=True);hepta=a.hepta.resolve(strict=True);out=a.output.absolute()
 require(not out.exists(),"fresh build output required");out.mkdir(parents=True)
 q=root/"qualification/binary_write_body/v1/native_build"
 sys.path.insert(0,str(root/"scripts"))
 from hia_native_build import NativeBuild
 from hia_native_loader import NativeModule
 sys.path.insert(0,str(q/"scripts"))
 from build_callable import object_layout
 from callable_common import sources
 qualified=sources(q)
 paths=[root/"scripts/hia_native_public_binary_write.py",root/"authoring/public_binary_write/author_walk.py",
  root/"authoring/public_binary_write/walk.pseudo",root/"native/public_binary_write.hepta",
  root/"native/public_binary_write_composition.json",root/"asm/public_binary_write_stdio.S",
  root/"scripts/hia_native_build.py",root/"scripts/hia_native_loader.py",
  root/"native/public_binary_write_body_profile.hepta",root/"native/public_binary_write_body_profile.json",
  root/"authoring/public_binary_write/author_base64.py",root/"authoring/public_binary_write/base64.pseudo",
  root/"native/public_binary_write_base64_profile.hepta",root/"native/public_binary_write_base64_profile.json"]
 bindings={str(x.relative_to(root)):pin(x) for x in paths}
 author=process(out,"author",[sys.executable,"-I","-B",root/"authoring/public_binary_write/author_walk.py",
  "--source",root,"--hepta",hepta,"--output",out/"authored"],60)
 for name in ("public_binary_write.hepta","public_binary_write_composition.json","public_binary_write_body_profile.hepta","public_binary_write_body_profile.json"):
  require((out/"authored"/name).read_bytes()==(root/"native"/name).read_bytes(),"author reproduction differs")
 decoder_author=process(out,"author-base64",[sys.executable,"-I","-B",root/"authoring/public_binary_write/author_base64.py",
  "--source",root,"--hepta",hepta,"--output",out/"authored-base64"],60)
 for name in ("public_binary_write_base64_profile.hepta","public_binary_write_base64_profile.json"):
  require((out/"authored-base64"/name).read_bytes()==(root/"native"/name).read_bytes(),"decoder author reproduction differs")
 build=out/"build";build.mkdir()
 shutil.copytree(a.bootstrap.resolve(strict=True),build/"bootstrap")
 native=NativeBuild(hepta,build)
 compiler=native.bootstrap()
 require(sha(compiler.read_bytes())=="bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0","qualified compiler differs")
 members={}
 for name,path in MEMBERS:
  src=root/path if name in ("walk","body","base64") else q/path
  start=time.monotonic()
  manifest=native.compile("public-binary-write-"+name,src,standalone=None,buffer_profile="history.v1")
  meta=json.loads(manifest.read_bytes())
  members[name]=dict(source_path=str(src.relative_to(root)),source=pin(src),
   manifest=str(manifest.relative_to(out)),manifest_pin=pin(manifest),image=pin(manifest.parent/meta["image"]),
   seconds=time.monotonic()-start)
  print(json.dumps({"compiled":name,**members[name]["image"]}),flush=True)
 expected=json.loads((q/"NATIVE_PROVENANCE.json").read_bytes())["hia_sources"]
 for name in ("metadata","codec","stat","error","publish","read","entropy"):
  require(members[name]["source"]["sha256"]==expected[name],"qualified child source differs: "+name)
 profile=json.loads((root/"native/public_binary_write_body_profile.json").read_bytes())
 require(profile["original"]["sha256"]==expected["body"] and profile["unchanged_functions"]==42
  and profile["inverse_restores_complete_original_ir"] is True
  and profile["source_sha256"]==members["body"]["source"]["sha256"],"write literal profile differs")
 decoder_profile=json.loads((root/"native/public_binary_write_base64_profile.json").read_bytes())
 require(decoder_profile["original"]["sha256"]==expected["base64"] and decoder_profile["unchanged_functions"]==17
  and decoder_profile["inverse_restores_complete_original_ir"] is True
  and decoder_profile["source_sha256"]==members["base64"]["source"]["sha256"],"decoder profile differs")
 require(members["codec"]["image"]["sha256"]=="469f2b555224499b2d9d3c95cc3d772f65fcbe6705fb79804f31fa7c473debe2","codec image differs")
 require(members["error"]["image"]["sha256"]=="531c65b74394565a9c2a8ba70f9daa0d466f9c0cb2567525d4397593b6c80943","formatter image differs")
 images=[]
 for name in IMAGES:
  m=out/members[name]["manifest"];meta=json.loads(m.read_bytes());images.append((m.parent/meta["image"]).read_bytes())
 results={}
 for variant in a.variants:
  work=out/variant;work.mkdir()
  observe,zero,fault=VARIANTS[variant]
  prefix=f".set PBWR_OBSERVE,{observe}\n.set PBWR_CLOSE_STDIN,{zero}\n.set PBWR_FAIL_CLOSE,{fault}\n"
  original=prefix+"\n".join((q/n).read_text() for n in ASM)+"\n"+(root/"asm/public_binary_write_stdio.S").read_text()
  (work/"combined.S").write_text(flatten(original))
  mechanical=[process(work,"assemble",["as","--64","-o",work/"bridge.o",work/"combined.S"]),
   process(work,"relocations",["readelf","-r",work/"bridge.o"])]
  require(b"There are no relocations" in (work/"relocations.stdout").read_bytes(),"unresolved relocations")
  obj=(work/"bridge.o").read_bytes();text,symbols=object_layout(obj)
  frame=b"HIALNK01"+struct.pack("<3Q",1,6,0)+b"_start"+struct.pack("<Q",len(obj))+obj
  (work/"link.input.bin").write_bytes(frame)
  with NativeModule(out/members["linker"]["manifest"],manifest_sha256=members["linker"]["manifest_pin"]["sha256"]) as module:
   code,raw,arena=module.invoke_raw(frame,output_capacity=8<<20,workspace_capacity=32<<20,output_fill=0,workspace_fill=0)
  (work/"link.output.bin").write_bytes(raw);(work/"link.workspace.bin").write_bytes(arena)
  end=256+len(text);aligned=(end+4095)&~4095
  require(code==aligned and 256<end<=code<=len(raw),"link extent differs")
  elf_prefix=raw[:code];(work/"prefix.elf").write_bytes(elf_prefix)
  require(elf_prefix[256:end]==text and elf_prefix[end:]==bytes(code-end) and raw[code:]==bytes(len(raw)-code)
   and elf_prefix[:4]==b"\x7fELF" and struct.unpack_from("<Q",elf_prefix,24)[0]==4194304+232
   and elf_prefix[238]==0xe8 and 243+struct.unpack_from("<i",elf_prefix,239)[0]==256+symbols["_start"]
   and struct.unpack_from("<QQ",elf_prefix,96)==(end,end)
   and struct.unpack_from("<QQQ",elf_prefix,128)==(code,4194304+code,4194304+code),"actual linked layout differs")
  patches=[(2,256+symbols[name],index) for name,index in PATCHES]
  for _,at,_ in patches:require(elf_prefix[at-1:at+4]==b"\xe9\0\0\0\0","fixed patch location differs")
  frame=b"HIAIMG02"+struct.pack("<4Q",len(elf_prefix),len(images),len(patches),0)+elf_prefix
  frame+=b"".join(struct.pack("<Q",len(im)) for im in images)+b"".join(struct.pack("<3Q",*x) for x in patches)+b"".join(images)
  (work/"pack.input.bin").write_bytes(frame)
  expected=bytearray(elf_prefix);positions=[]
  for im in images:expected+=bytes(-len(expected)%16);positions.append(len(expected));expected+=im
  end=len(expected);expected+=bytes(-len(expected)%4096)
  for _,at,index in patches:struct.pack_into("<I",expected,at,positions[index]-at-4)
  struct.pack_into("<QQ",expected,96,end,end)
  struct.pack_into("<QQQ",expected,128,len(expected),4194304+len(expected),4194304+len(expected))
  with NativeModule(out/members["packer"]["manifest"],manifest_sha256=members["packer"]["manifest_pin"]["sha256"]) as module:
   packed,raw,arena=module.invoke_raw(frame,output_capacity=32+len(expected),workspace_capacity=4096,output_fill=0xb3,workspace_fill=0xc7)
  (work/"pack.output.bin").write_bytes(raw);(work/"pack.workspace.bin").write_bytes(arena)
  require(packed==32 and raw==b"HIAIMR02"+struct.pack("<3Q",0,len(expected),0)+expected,"actual pack differs")
  executable=work/"public-binary-write.elf";executable.write_bytes(raw[32:]);executable.chmod(0o500)
  result=dict(variant=variant,fixture_constants=VARIANTS[variant],mechanical=mechanical,link_return=code,pack_return=packed,
   patches=patches,image_offsets=positions,executable=pin(executable),
   artifacts={n:pin(work/n) for n in ("combined.S","bridge.o","link.input.bin","link.output.bin","link.workspace.bin",
    "prefix.elf","pack.input.bin","pack.output.bin","pack.workspace.bin")})
  (work/"BUILD.json").write_bytes(encoded(result));results[variant]=result
  print(json.dumps({"variant":variant,**result["executable"]}),flush=True)
 require(bindings=={str(x.relative_to(root)):pin(x) for x in paths},"source changed during build")
 require(qualified==sources(q),"qualified closure changed during build");native._recheck()
 result=dict(schema="hepta.runtime.public-binary-write-build.v1",status="PASS",source_files=bindings,
  qualified_source=qualified,compiler=native.identity,members=members,author=author,decoder_author=decoder_author,variants=results,
  runtime_images=list(IMAGES),runtime_python_required=False,runtime_libc_required=False,
  original_filesystem_compared=False,public_route_qualified=False,whole_runtime_replaced=False)
 (out/"BUILD.json").write_bytes(encoded(result))
 print(json.dumps({"status":"PASS","build":str(out/"BUILD.json"),"variants":list(results)}),flush=True)
if __name__=="__main__":main()
