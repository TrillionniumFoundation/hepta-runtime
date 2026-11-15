#!/usr/bin/env python3
import pathlib,json,hashlib,os,stat,sys
R=pathlib.Path("/home/qian-qi/hepta-runtime-dc-functional-20261013")
V=pathlib.Path("/home/qian-qi/hepta-runtime-operation-v10-20261013")
MP=V/"docs/qualification/dc-functional-v10-operation-candidate-20261013/final-version-shipping-r10-approved/manifest.json"
raw=MP.read_bytes();assert hashlib.sha256(raw).hexdigest()=="ba2ea046ba922fff55c07be41c4197a2fa1d5d37bbabd5485fb71b4529e30659"
m=json.loads(raw)
assert m["source_code_fingerprint"]=="498cca6da8c442c70534b0a35807c94d7b5f7fbef4b2b4d8f15fa9c22484e33c"
assert m["fresh_native_R9"]["complete"] is True
sys.path.insert(0,str(R/"deploy"));import stage_dc_successor as S
before=S.source_identity(R);assert before["source_files"]==m["complete_compile_input_files"]
blobs={}
for group in ("version_evidence_copy_whitelist","version_source_copy_whitelist"):
 for name,pin in m[group].items():
  assert (group=="version_source_copy_whitelist" and name.startswith("tests/dc_") and name.endswith(".py")) or (group=="version_evidence_copy_whitelist" and name.startswith("docs/qualification/dc-functional-v10-operation-candidate-20261013/"))
  assert ".." not in pathlib.Path(name).parts
  p=V/name;s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_uid==os.getuid() and s.st_nlink==1
  b=p.read_bytes();assert len(b)==pin["bytes"] and hashlib.sha256(b).hexdigest()==pin["sha256"]
  dest=R/name
  if dest.exists():assert not dest.is_symlink() and hashlib.sha256(dest.read_bytes()).hexdigest()==pin["sha256"]
  blobs[name]=b
Q=R/"docs/qualification/dc-functional-v10-integrated-evidence-20261013/r4-controlled-version-package"
assert not Q.exists();Q.mkdir(mode=0o700)
(Q/"driver.py").write_bytes(pathlib.Path(__file__).read_bytes());(Q/"shipping-manifest.json").write_bytes(raw)
for name,b in blobs.items():
 p=R/name
 if p.exists():continue
 p.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
 parent,leaf=S.open_parent(p)
 try:
  fd=os.open(leaf,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent)
  with os.fdopen(fd,"wb") as f:f.write(b);f.flush();os.fsync(f.fileno())
  os.fsync(parent)
 finally:os.close(parent)
after=S.source_identity(R);assert before==after
receipt={"completed":True,"source_fingerprint":m["source_code_fingerprint"],"source_inputs":len(after["source_files"]),"version_sources":m["version_source_copy_whitelist"],"archival_evidence_files":len(m["version_evidence_copy_whitelist"]),"compiled_inputs_unchanged":True,"old_v9_harnesses_changed":False,"new_root_native_tests_borrowed":False,"full_dc_replacement_qualified":False}
(Q/"receipt.json").write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
print(json.dumps({"completed":True,"version_source_count":len(m["version_source_copy_whitelist"]),"archival_count":len(m["version_evidence_copy_whitelist"]),"compiled_inputs_unchanged":True},sort_keys=True))
