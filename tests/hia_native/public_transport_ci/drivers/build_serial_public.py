"""Build public81 serial target framing with exact optional public80 reuse."""
from pathlib import Path
import argparse,hashlib,json,shutil,sys,time
sys.dont_write_bytecode=True
SHA=lambda b:hashlib.sha256(b).hexdigest()
def put(p,x):p.write_text(json.dumps(x,sort_keys=True,indent=2)+"\n")
def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ("source","hepta","output"):p.add_argument("--"+name,type=Path,required=True)
 p.add_argument("--bootstrap",type=Path);p.add_argument("--reuse-base-build",type=Path)
 p.add_argument("--reuse-module-map",type=Path)
 a=p.parse_args();source=a.source.resolve(strict=True);out=a.output.resolve()
 assert not out.exists();out.mkdir(parents=True)
 result=dict(schema="hepta.runtime.public-serial-transport-build.v1",status="RUNNING",
   rust_executed=False,full_async_runtime_qualified=False,full_sdk_qualified=False,
   actual_target_transport_compared=False,independent_cold_qualified=False)
 start=time.monotonic()
 def save():result["elapsed_seconds"]=time.monotonic()-start;put(out/"BUILD.json",result)
 save()
 try:
  if a.bootstrap:shutil.copytree(a.bootstrap.resolve(strict=True),out/"build/bootstrap")
  sys.path.insert(0,str(source/"scripts"))
  from public_nine_build import MEMBERS,EXTRA,build_runtime_mcp
  assert len(MEMBERS)==81 and len(EXTRA)==54 and EXTRA[47:53]==[None]*6 and EXTRA[53]=="target_shutdown"
  possible={}
  if a.reuse_base_build:
   base=a.reuse_base_build.resolve(strict=True)
   receipt=json.loads((base/"BUILD.json").read_bytes())
   assert receipt["status"]=="NATIVE_BUILD_PASS" and receipt["physical_images"]==80
   raw=(base/"build/public-nine-constructor/manifest.json").read_bytes()
   assert SHA(raw)==receipt["manifest_sha256"]
   prior=json.loads(raw);assert prior["physical_images"]==80 and prior["status"]=="PASS"
   maps=json.loads(a.reuse_module_map.read_bytes())["modules"] if a.reuse_module_map else None
   for row in prior["members"]:
    if maps is not None:
     rel=Path(maps[row["manifest"]]);assert not rel.is_absolute() and ".." not in rel.parts
     path=a.reuse_module_map.resolve().parent/rel
    else:path=Path(row["manifest"]).resolve(strict=True)
    assert SHA(path.read_bytes())==row["manifest_sha256"]
    possible[(row["source_sha256"],row["buffer_profile"])]=path
   result["base_manifest_sha256"]=SHA(raw)
  reuse={}
  for name,owner,profile in MEMBERS:
   key=SHA((source/"native"/(owner+".hepta")).read_bytes()),profile
   if key in possible:reuse[name]=str(possible[key])
  put(out/"reuse.json",reuse)
  manifest=build_runtime_mcp(a.hepta.resolve(strict=True),out/"build",
      name="public-nine-serial-transport",source_root=source,manifests=reuse or None)
  raw=manifest.read_bytes();md=json.loads(raw)
  assert md["physical_images"]==81 and len(md["members"])==81
  fresh=sum(r["fresh_compile"] is True for r in md["members"])
  assert fresh==81-len(reuse)
  binary=manifest.parent/md["elf"]
  assert SHA(binary.read_bytes())==md["elf_sha256"]
  result.update(status="NATIVE_BUILD_PASS",physical_images=81,manifest=str(manifest),
      manifest_sha256=SHA(raw),elf=str(binary),elf_bytes=binary.stat().st_size,
      elf_sha256=md["elf_sha256"],fresh_member_compiles=fresh,checked_reused_members=len(reuse),
      bootstrap_reused=a.bootstrap is not None,fresh_hia_link_and_pack=True,
      target_serial_async_rw_framing_integrated=True,target_eof_shutdown_owner_integrated=True)
 except BaseException as e:result.update(status="FAIL",error=repr(e));raise
 finally:save()
 print(json.dumps(result,sort_keys=True),flush=True)
if __name__=="__main__":main()
