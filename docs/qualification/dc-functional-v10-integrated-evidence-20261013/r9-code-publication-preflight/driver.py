#!/usr/bin/env python3
import pathlib,os,stat,hashlib,json,subprocess,sys,types,datetime
R=pathlib.Path("/home/qian-qi/hepta-runtime-dc-functional-20261013")
Q=R/"docs/qualification/dc-functional-v10-integrated-evidence-20261013/r9-code-publication-preflight"
O=pathlib.Path("/home/qian-qi/hepta-v10-code-publication-20261014-r42")
H="aa41acbdd181a814f51b51c91e01fceedb797fab";FP="498cca6da8c442c70534b0a35807c94d7b5f7fbef4b2b4d8f15fa9c22484e33c"
def run(args,timeout=120):return subprocess.run(args,cwd=R,capture_output=True,timeout=timeout)
def sha(p):
 p=pathlib.Path(p);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 try:
  a=os.fstat(fd);assert stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_uid==os.getuid() and a.st_size<=64*1024**2
  h=hashlib.sha256();n=0
  while True:
   b=os.read(fd,1048576)
   if not b:break
   n+=len(b);h.update(b)
  z=os.fstat(fd);v=p.lstat();fields=("st_dev","st_ino","st_size","st_mtime_ns","st_ctime_ns","st_uid","st_gid","st_mode","st_nlink")
  assert n==a.st_size and all(getattr(a,f)==getattr(z,f)==getattr(v,f) for f in fields)
  return h.hexdigest()
 finally:os.close(fd)
assert run(["git","rev-parse","HEAD"]).stdout.decode().strip()==H
assert run(["git","diff","--cached","--quiet"]).returncode==0
lr=run(["git","ls-remote","origin","refs/heads/feat/operator-parity-20261006"],60);assert lr.returncode==0 and lr.stdout.decode().split()[0]==H
assert not O.exists() and not Q.exists();O.mkdir(mode=0o700);Q.mkdir(mode=0o700);os.umask(0o077)
(O/"remote-before.stdout").write_bytes(lr.stdout);(O/"remote-before.stderr").write_bytes(lr.stderr)
sp=R/"deploy/stage_dc_successor.py";assert sha(sp)=="80fb34a7d55157032a5a8da007d31f289eb2862746ea16747de7b3cb305f0582"
sys.path.insert(0,str(sp.parent));S=types.ModuleType("root_v10_publication_stage");S.__file__=str(sp);sys.modules[S.__name__]=S;exec(compile(sp.read_bytes(),str(sp),"exec"),S.__dict__)
before=S.source_identity(R);assert before["source_code_fingerprint"]==FP and len(before["source_files"])==98
pins={".github/workflows/operator-parity.yml":"b95310d5229ea63d8242f4fc121347020c2536bec0ac26c8d2edd222a3014000","deploy/contracts/hepta-runtime-full-operator-v10.json":"12994454084369fb31e44f0e1ceb7a7f2ace5bbed33057789399cf895e70d553","deploy/preflight_dc_successor.py":"7bfcf63208db6992fd31bd398caf4fb5635e5f8253803b1141f71bd0d2d7fb61","tests/dc_successor_preflight_tests.py":"d4c7ec13ba794ef02e0bc3e7f3aa7f5c864947dae912efda8ec9ffbfad9e6d8c","deploy/dc_successor_inventory.py":"a198944235a8b71763a612d077bf41c8915028487beb96888da003868e24e5c9","tests/dc_successor_inventory_tests.py":"3e0431497a23d56b5f8aeb81c4035173a819134ca44cae48d802b9972849876f","tests/dc_functional_v10_operation_async_acceptance.py":"3c3e53a1f9e63954e251580ed643be743da4add4702b166faece762b4486b5fa","docs/DC_FUNCTIONAL_V10_INTEGRATED_CANDIDATE.md":"23a2e78d4d19f0763fe266c58fe43eb6bd340560355a13e057b72322db6b7d40","docs/WORK_HANDOFF_DC_REPLACEMENT_20261013.md":"f7aeb57295f2c5a9ec375394974196d3d2a857b0dd10946a2ade63ced6fbb365"}
vr=R/"docs/qualification/dc-functional-v10-integrated-evidence-20261013/r4-controlled-version-package/receipt.json"
assert json.loads(vr.read_bytes())["completed"] is True
for n,m in json.loads(vr.read_bytes())["version_sources"].items():pins[n]=m["sha256"]
for n,p in pins.items():assert sha(R/n)==p
native=R/"docs/qualification/dc-functional-v10-integrated-evidence-20261013/r7-fresh-root-native/receipt.json"
assert sha(native)=="ee9614091cca8dc29d457520bd8297fe77ea78189334df941fd23588cc1ccff2"
assert json.loads(native.read_bytes())["complete"] is True
full=R/"docs/qualification/dc-functional-v10-integrated-evidence-20261013/r3-fresh-root-full-checks/receipt.json";assert json.loads(full.read_bytes())["completed"] is True
expected_services={"hepta-runtime-operator.service":(2863,"56e09529eb9d45bb977aab6fd6b705b7",1065),"hepta-openai-full-operator.service":(2873,"23ea3a29044547fb9a968cb36c3c46ea",1066),"desktop-commander-remote.service":(2809,"46f20b09e74c4ab38f1a402ee1e083fb",1061)}
def services():
 out={}
 for name,(pid,inv,ticks) in expected_services.items():
  p=run(["/usr/bin/systemctl","--user","show",name,"--no-pager","--property=ActiveState,SubState,MainPID,InvocationID"],15);assert p.returncode==0
  d=dict(x.split("=",1) for x in p.stdout.decode().splitlines() if "=" in x)
  proc=pathlib.Path("/proc")/str(pid);t=(proc/"stat").read_text();d["start_ticks"]=int(t[t.rfind(")")+2:].split()[19]);d["uid"]=proc.stat().st_uid
  d["matches_original"]=d["ActiveState"]=="active" and d["MainPID"]==str(pid) and d["InvocationID"]==inv and d["start_ticks"]==ticks and d["uid"]==os.getuid()
  out[name]=d
 return out
sv_before=services();assert all(x["matches_original"] for x in sv_before.values())
(Q/"driver.py").write_bytes(pathlib.Path(__file__).read_bytes())
(Q/"source-before.json").write_text(json.dumps(before,sort_keys=True,indent=2)+"\n")
(Q/"preflight.json").write_text(json.dumps({"parent":H,"source_fingerprint":FP,"source_inputs":98,"shipping_pins":pins,"services_before":sv_before,"fresh_native_receipt_sha256":sha(native),"hosted_new_head_CI_qualified":False,"full_dc_replacement_qualified":False},sort_keys=True,indent=2)+"\n")
status=run(["git","status","--porcelain=v1","-z","--untracked-files=all"]);assert status.returncode==0
paths=[]
prefixes=("docs/qualification/dc-functional-v10-operation-candidate-20261013/","docs/qualification/dc-functional-v10-integrated-evidence-20261013/")
for record in status.stdout.split(b"\0"):
 if not record:continue
 name=record[3:].decode();assert record[:2] in (b" M",b"??") and "\n" not in name and "\t" not in name
 assert name in before["source_files"] or name in pins or name.startswith(prefixes),"unreviewed path"
 assert not (R/name).is_symlink() and (R/name).is_file()
 paths.append(name)
assert paths
manifest={p:{"sha256":sha(R/p),"bytes":(R/p).stat().st_size} for p in sorted(paths)}
(Q/"publication-paths.json").write_text(json.dumps(manifest,sort_keys=True,indent=2)+"\n");paths.append(str((Q/"publication-paths.json").relative_to(R)))
g=run(["git","add","--",*paths]);assert g.returncode==0
cached=run(["git","diff","--cached","--name-only","-z"]);assert cached.returncode==0 and set(x.decode() for x in cached.stdout.split(b"\0") if x)==set(paths)
f=run(["git","diff","--cached","--check"]);(O/"full-diff-check.stdout").write_bytes(f.stdout);(O/"full-diff-check.stderr").write_bytes(f.stderr)
shipping=[p for p in paths if not p.startswith(prefixes) or p.endswith(".md")]
c=run(["git","diff","--cached","--check","--",*shipping]);(O/"shipping-diff-check.stdout").write_bytes(c.stdout);(O/"shipping-diff-check.stderr").write_bytes(c.stderr);assert c.returncode==0
if f.returncode:
 for line in f.stdout.decode().splitlines():
  if line.startswith("docs/"):assert line.startswith(prefixes),"nonarchival whitespace failure"
assert S.source_identity(R)["source_files"]==before["source_files"] and all(sha(R/n)==p for n,p in pins.items())
commit=run(["git","commit","-m","feat(runtime): retain encrypted async results for bounded native reads"],180)
(O/"commit.stdout").write_bytes(commit.stdout);(O/"commit.stderr").write_bytes(commit.stderr);assert commit.returncode==0
head=run(["git","rev-parse","HEAD"]).stdout.decode().strip();assert head!=H
push=run(["git","push","origin","HEAD:feat/operator-parity-20261006"],120)
(O/"push.stdout").write_bytes(push.stdout);(O/"push.stderr").write_bytes(push.stderr)
receipt={"schema":"hepta-v10-source-publication-v1","recorded_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"parent":H,"head":head,"commit_exit":commit.returncode,"push_exit":push.returncode,"full_diff_check_exit":f.returncode,"shipping_diff_check_exit":c.returncode,"original_archival_bytes_preserved":True,"compiled_source_fingerprint":FP,"published_paths":len(paths),"exact_head_CI_qualified":False,"full_dc_replacement_qualified":False}
(O/"receipt.json").write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
assert push.returncode==0
lr2=run(["git","ls-remote","origin","refs/heads/feat/operator-parity-20261006"],60);(O/"remote-after.stdout").write_bytes(lr2.stdout);(O/"remote-after.stderr").write_bytes(lr2.stderr)
receipt["remote_exact_head_verified"]=lr2.returncode==0 and lr2.stdout.decode().split()[0]==head
after=S.source_identity(R);receipt["compiled_source_after_commit_identical"]=after["source_files"]==before["source_files"];receipt["compiled_source_clean_after_commit"]=not after["dirty_source"]
sv_after=services();receipt["services_after"]=sv_after;receipt["protected_services_preserved"]=sv_before==sv_after
(O/"source-after.json").write_text(json.dumps(after,sort_keys=True,indent=2)+"\n");(O/"receipt.json").write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
print(json.dumps(receipt,sort_keys=True),flush=True)
assert receipt["remote_exact_head_verified"] and receipt["compiled_source_after_commit_identical"] and receipt["compiled_source_clean_after_commit"] and receipt["protected_services_preserved"]
