#!/usr/bin/env python3
import pathlib,os,stat,hashlib,json,subprocess,sys
R=pathlib.Path("/home/qian-qi/hepta-runtime-dc-functional-20261013")
V=pathlib.Path("/home/qian-qi/hepta-runtime-operation-v10-20261013")
I=pathlib.Path("/home/qian-qi/hepta-successor-inventory-integration-drafts-20261013-r1")
HEAD="aa41acbdd181a814f51b51c91e01fceedb797fab"
Q=R/"docs/qualification/dc-functional-v10-integrated-evidence-20261013/r1-controlled-integration"
QI=R/"docs/qualification/dc-functional-v10-integrated-evidence-20261013/r2-large-inventory-source"
def sha(raw):return hashlib.sha256(raw).hexdigest()
def git(*args):return subprocess.check_output(["git",*args],cwd=R,text=True).strip()
assert git("rev-parse","HEAD")==HEAD and git("ls-remote","origin","refs/heads/feat/operator-parity-20261006").split()[0]==HEAD
assert not git("diff","--cached","--name-only") and not git("diff","--name-only","--","src","Cargo.toml","Cargo.lock","deploy","tests")
mp=V/"docs/qualification/dc-functional-v10-operation-candidate-20261013/final-shipping-498/manifest.json"
raw=mp.read_bytes();assert sha(raw)=="179d95223b95efc3d93f427fce3702f86a0375622e74ab055237e6d486e6a018";m=json.loads(raw)
assert m["source_code_fingerprint"]=="498cca6da8c442c70534b0a35807c94d7b5f7fbef4b2b4d8f15fa9c22484e33c" and len(m["owned_compile_changes"])==15
patch=V/m["patch"]["path"];assert sha(patch.read_bytes())=="55a41debe6b796f23f21b9072f1c4405e148bd6b36c1b319952dfcbafd640b1a"
sys.path.insert(0,str(R/"deploy"))
import stage_dc_successor as S
assert sha((R/"deploy/stage_dc_successor.py").read_bytes())=="80fb34a7d55157032a5a8da007d31f289eb2862746ea16747de7b3cb305f0582"
before=S.source_identity(R);assert before["source_code_fingerprint"]=="b376418a2b3346a707dfd2592f99ce6fbceb6c86c8445995069f1e4ac0ed32bf" and before["dirty_source"] is False
for row in m["owned_compile_changes"]:
 p=R/row["path"]
 if row["base_exists"]:assert sha(p.read_bytes())==row["base_sha256"]
 else:assert not p.exists()
 assert sha((V/row["path"]).read_bytes())==row["new_sha256"]
extra={}
for name,pin in m["non_compile_copy_whitelist"].items():
 assert name.startswith("docs/qualification/dc-functional-v10-") or name=="deploy/contracts/hepta-runtime-full-operator-v10.json" or name=="tests/dc_functional_v10_operation_async_acceptance.py"
 p=V/name;s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_uid==os.getuid() and s.st_nlink==1
 blob=p.read_bytes();assert len(blob)==pin["bytes"] and sha(blob)==pin["sha256"]
 dest=R/name
 if dest.exists():assert dest.is_file() and not dest.is_symlink() and sha(dest.read_bytes())==pin["sha256"]
 extra[name]=blob
ipins={"deploy/preflight_dc_successor.py":("e3bf754dbcf58219994af79f935f9166d9ff39534ae8b55b4d6593446c843fec","7bfcf63208db6992fd31bd398caf4fb5635e5f8253803b1141f71bd0d2d7fb61"),"tests/dc_successor_preflight_tests.py":("35ca6e4d3993d834ce84899a929e7605ccbaed02d8769b076d94629ce4fdfdde","d4c7ec13ba794ef02e0bc3e7f3aa7f5c864947dae912efda8ec9ffbfad9e6d8c"),"deploy/dc_successor_inventory.py":(None,"a198944235a8b71763a612d077bf41c8915028487beb96888da003868e24e5c9"),"tests/dc_successor_inventory_tests.py":(None,"3e0431497a23d56b5f8aeb81c4035173a819134ca44cae48d802b9972849876f")}
iblobs={}
for name,(old,new) in ipins.items():
 p=R/name
 if old is None:assert not p.exists()
 else:assert sha(p.read_bytes())==old
 blob=(I/name).read_bytes();assert sha(blob)==new;iblobs[name]=blob
eraw=(I/"evidence/artifact-index.json").read_bytes();assert sha(eraw)=="cd92a549a7a406f304e190ca4a27460ae8b574857b5530182723bf5602c34ce9"
assert sha((I/"evidence/final-reviewable-source-manifest.json").read_bytes())=="432818d1f12f9406a87278ccd7206497cdb19a1241a0b12774641a201b334af3"
assert sha((I/"evidence/independent-review-r2-final.json").read_bytes())=="04f76774e766ac157b442c69e572c41a21586c400af2e59821b30e67ff0c55c9"
assert not Q.exists() and not QI.exists()
Q.mkdir(mode=0o700,parents=True);QI.mkdir(mode=0o700)
(Q/"r1-whitelist-refusal.json").write_text(json.dumps({"job":"1a137b41a44-b2f-b5d","exit":1,"before_any_source_or_evidence_copy":True,"unexpected_path":"tests/dc_functional_v10_operation_async_acceptance.py","subsequently_reviewed_exact_sha256":"3c3e53a1f9e63954e251580ed643be743da4add4702b166faece762b4486b5fa"},sort_keys=True,indent=2)+"\n")
(Q/"original-r1-refused-driver.py").write_bytes(pathlib.Path("/home/qian-qi/hepta-v10-controlled-integration-20261013-r35.py").read_bytes())
(Q/"driver.py").write_bytes(pathlib.Path(__file__).read_bytes());(Q/"shipping-manifest.json").write_bytes(raw);(Q/"source-before.json").write_text(json.dumps(before,sort_keys=True,indent=2)+"\n")
subprocess.run(["git","apply","--check",str(patch)],cwd=R,check=True)
subprocess.run(["git","apply",str(patch)],cwd=R,check=True)
modes={}
for row in m["owned_compile_changes"]:
 p=R/row["path"];assert sha(p.read_bytes())==row["new_sha256"]
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  a=os.fstat(fd);assert stat.S_ISREG(a.st_mode) and a.st_uid==os.getuid() and a.st_nlink==1
  oldmode=stat.S_IMODE(a.st_mode);newmode=oldmode&~0o022;os.fchmod(fd,newmode)
  b=os.fstat(fd);assert a.st_ino==b.st_ino and sha(p.read_bytes())==row["new_sha256"]
  modes[row["path"]]={"before":oct(oldmode),"after":oct(newmode),"bytes_unchanged":True}
 finally:os.close(fd)
def create_copy(dest,blob):
 dest.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
 parent,name=S.open_parent(dest)
 try:
  fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent)
  with os.fdopen(fd,"wb") as f:f.write(blob);f.flush();os.fsync(f.fileno())
  os.fsync(parent)
 finally:os.close(parent)
for name,blob in extra.items():
 dest=R/name
 if not dest.exists():create_copy(dest,blob)
for name,blob in iblobs.items():
 dest=R/name;old,new=ipins[name]
 if old is None:create_copy(dest,blob)
 else:
  parent,leaf=S.open_parent(dest)
  try:
   a=os.stat(leaf,dir_fd=parent,follow_symlinks=False);assert stat.S_ISREG(a.st_mode) and a.st_uid==os.getuid() and a.st_nlink==1 and sha(dest.read_bytes())==old
   temp=leaf+".owned-v10-integration-20261013-r35"
   fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
   with os.fdopen(fd,"wb") as f:f.write(blob);f.flush();os.fsync(f.fileno())
   b=os.stat(leaf,dir_fd=parent,follow_symlinks=False);assert (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns) and sha(dest.read_bytes())==old
   os.replace(temp,leaf,src_dir_fd=parent,dst_dir_fd=parent);os.fsync(parent)
  finally:os.close(parent)
 assert sha(dest.read_bytes())==new
for p in (I/"evidence").rglob("*"):
 if p.is_file():
  assert not p.is_symlink()
  create_copy(QI/"draft-evidence"/p.relative_to(I/"evidence"),p.read_bytes())
after=S.source_identity(R)
assert after["source_code_fingerprint"]==m["source_code_fingerprint"] and after["source_files"]==m["complete_source_files"] and after["dirty_source"] is True
(Q/"source-after.json").write_text(json.dumps(after,sort_keys=True,indent=2)+"\n")
receipt={"completed":True,"head_at_integration":HEAD,"source_before_fingerprint":before["source_code_fingerprint"],"source_after_fingerprint":after["source_code_fingerprint"],"source_inputs":len(after["source_files"]),"owned_compile_paths":15,"non_compile_copies":len(extra),"inventory_source_pins":{n:new for n,(_,new) in ipins.items()},"source_mode_changes":modes,"actual_new_root_cargo_native_or_six_tests_performed":False,"candidate_installed_or_dc_stopped":False,"full_dc_replacement_qualified":False}
(Q/"receipt.json").write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
print(json.dumps(receipt,sort_keys=True))
