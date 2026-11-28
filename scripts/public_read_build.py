"""Fixed native public-read dependencies; all paths and image identities are build-owned."""
from pathlib import Path
import json,struct,subprocess,sys,time
from hia_native_public_read_dependencies import build_public_ssh,build_read,pin,require,encoded
EXTRA_SOURCES=(
 "scripts/public_read_build.py","scripts/hia_native_public_read_dependencies.py",
 "scripts/hia_native_ssh_direct_build.py","native/public_read_transport_component.json",
 "asm/ssh_public_exec_path.S","asm/binary_read_stdio.S","asm/binary_read_body_callable.S",
 "native/binary_read_body.hepta","native/binary_read_body_composition.json",
 "native/public_binary_read_body.hepta","native/public_binary_read_body_composition.json",
 "native/binary_error.hepta","native/binary_error_composition.json","native/stat_version.hepta",
 "native/platform_data.json","authoring/public_read/REMOTE_DEPENDENCIES.json",
 "authoring/public_read/REMOTE_PARENT_LIFETIME.json",
 "authoring/public_read/author_binary_read_current.py","authoring/public_read/binary_current_error.pseudo",
 "scripts/hia_native_public_file_info_walk.py","authoring/public_file_info_walk/author_walk.py",
 "authoring/public_file_info_walk/walk.pseudo","native/public_file_info_walk.hepta",
 "native/public_file_info_walk_composition.json","asm/public_file_info_walk_stdio.S",
 "scripts/hia_native_public_multi_read.py","authoring/public_multi_read_helper/author_result.py",
 "authoring/public_multi_read_helper/result.pseudo","native/public_multi_read_result.hepta",
 "native/public_multi_read_result_composition.json","asm/public_multi_read_stdio.S",
)
def source_paths(root):
 paths=set(EXTRA_SOURCES)
 for f in (root/"asm/ssh_direct").glob("*.S"):paths.add(str(f.relative_to(root)))
 for name in ("ssh_original_child","ssh_request_admission","ssh_shared_owner","ssh_capture_io","ssh_capture_future"):
  paths.add("native/"+name+".hepta");paths.add("native/"+name+"_composition.json")
 old=root/"qualification/binary_read_stdio/v1/build"
 for folder,suffixes in (("scripts",(".py",)),("asm",(".S",)),("native",(".hepta",".json"))):
  for f in (old/folder).glob("*"):
   if f.is_file()and f.suffix in suffixes:paths.add(str(f.relative_to(root)))
 for f in (root/"qualification/file_info_at/v1/final/source").rglob("*"):
  if f.is_file():paths.add(str(f.relative_to(root)))
 for f in (root/"qualification/multi_read_body/v1/codec_reserved_native_build").rglob("*"):
  if f.is_file():paths.add(str(f.relative_to(root)))
 return sorted(paths)
def constants(root):
 profile=json.loads((root/"native/public_read_transport_component.json").read_bytes())
 return "".join(".equ %s,%d\n"%(key,value)for key,value in profile["assembly_constants"].items())
def build_info(root,build,folder,bootstrap):
 output=folder/"public-file-info"
 command=[sys.executable,"-I","-S","-B",str(root/"scripts/hia_native_public_file_info_walk.py"),
  "--source",str(root),"--hepta",str(build.hepta),"--bootstrap",str(bootstrap),
  "--output",str(output),"--variants","production"]
 start=time.monotonic()
 with (folder/"file-info-build.stdout").open("xb")as stdout,(folder/"file-info-build.stderr").open("xb")as stderr:
  process=subprocess.run(command,cwd=root,stdout=stdout,stderr=stderr,check=False)
 receipt={"command":command,"returncode":process.returncode,"seconds":time.monotonic()-start,
  "stdout":pin(folder/"file-info-build.stdout"),"stderr":pin(folder/"file-info-build.stderr")}
 (folder/"file-info-build.process.json").write_bytes(encoded(receipt))
 require(process.returncode==0 and receipt["stderr"]["bytes"]==0,"actual file-info dependency build failed")
 report=json.loads((output/"BUILD.json").read_bytes())
 require(report["status"]=="PASS"and set(report["variants"])=={"production"},"file-info variant identity differs")
 profile=json.loads((root/"native/public_read_transport_component.json").read_bytes())
 elf=output/"production/public-file-info.elf"
 require(pin(elf)==profile["file_info_elf_identity"]==report["variants"]["production"]["executable"],"fixed file-info executable differs")
 report["process"]=receipt;report["elf"]=str(elf)
 return report
def build_multi(root,build,folder,bootstrap):
 output=folder/"public-multi-read"
 command=[sys.executable,"-I","-S","-B",str(root/"scripts/hia_native_public_multi_read.py"),
  "--source",str(root),"--hepta",str(build.hepta),"--bootstrap",str(bootstrap),
  "--output",str(output),"--variants","production"]
 start=time.monotonic()
 with (folder/"multi-read-build.stdout").open("xb")as stdout,(folder/"multi-read-build.stderr").open("xb")as stderr:
  process=subprocess.run(command,cwd=root,stdout=stdout,stderr=stderr,check=False)
 receipt={"command":command,"returncode":process.returncode,"seconds":time.monotonic()-start,
  "stdout":pin(folder/"multi-read-build.stdout"),"stderr":pin(folder/"multi-read-build.stderr")}
 (folder/"multi-read-build.process.json").write_bytes(encoded(receipt))
 require(process.returncode==0 and receipt["stderr"]["bytes"]==0,"actual multi-read dependency build failed")
 report=json.loads((output/"BUILD.json").read_bytes())
 require(report["status"]=="PASS"and set(report["variants"])=={"production"},"multi-read variant identity differs")
 profile=json.loads((root/"native/public_read_transport_component.json").read_bytes())
 elf=output/"production/public-multi-read.elf"
 require(pin(elf)==profile["multi_read_elf_identity"]==report["variants"]["production"]["executable"],"fixed multi-read executable differs")
 report["process"]=receipt;report["elf"]=str(elf)
 return report
def build_images(root,build,folder):
 profile=json.loads((root/"native/public_read_transport_component.json").read_bytes())
 bootstrap=build.root/"bootstrap"
 ssh=build_public_ssh(root,build.hepta,folder/"public-read-ssh",bootstrap)
 require(ssh["elf_identity"]==profile["elf_identity"],"fixed public SSH ELF differs")
 require(ssh["origin"]==profile["origin"]and ssh["memory_bytes"]==profile["memory_bytes"],"fixed public SSH layout differs")
 require(ssh["exports"]==profile["exports"],"fixed public SSH exports differ")
 read=build_read(root,build.hepta,folder/"public-read-stdio",bootstrap)
 info=build_info(root,build,folder,bootstrap)
 multi=build_multi(root,build,folder,bootstrap)
 info_data=Path(info["elf"]).read_bytes();read_data=Path(read["elf"]).read_bytes();multi_data=Path(multi["elf"]).read_bytes()
 bundle=folder/"public-read-helper-images.bin"
 bundle.write_bytes(b"HRRMIMG1"+struct.pack("<7Q",len(info_data),len(read_data),len(multi_data),0,0,0,0)+info_data+read_data+multi_data)
 report={"schema":"hepta.runtime.public-read.packed-dependencies.v1",
  "ssh":ssh,"read":read,"info":info,"multi":multi,"helper_bundle":pin(bundle),"helper_kinds_built":[1,2,3],
  "runtime_hia_image_instances":23,"public_routes_qualified":False,
  "file_info_remote_integrated":True,"multi_read_remote_integrated":True}
 (folder/"PUBLIC_READ_BUILD.json").write_bytes(encoded(report))
 return {"read_ssh":Path(ssh["elf"]),"read_helpers":bundle},report
