#!/usr/bin/env python3
import pathlib,os,stat,hashlib,json,subprocess,sys,types,datetime
R=pathlib.Path("/home/qian-qi/hepta-runtime-dc-functional-20261013")
Q=R/"docs/qualification/dc-functional-v10-integrated-evidence-20261013/r10-code-publication-resume"
O=pathlib.Path("/home/qian-qi/hepta-v10-code-publication-20261014-r42-r2")
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
archive_pins={'docs/qualification/dc-functional-v10-operation-engine-tests-20261013/export-r1.sh': '97b56751d7ec05741c755095942fa00a9d85e50a68736d5738f07f5ab584bcf6', 'docs/qualification/dc-functional-v10-operation-engine-tests-20261013/export-r1/after-pins.json': '70222025ed7d0e714ec62ce2633b2bda5ec8290118beb379ff9168bd124d3d5d', 'docs/qualification/dc-functional-v10-operation-engine-tests-20261013/export-r1/contract.json': 'd5c5d7dedd5e270a8077f5d3658fb0ec84a87db5eee7213e487b888fbe490f9f', 'docs/qualification/dc-functional-v10-operation-engine-tests-20261013/export-r1/receipt.json': '440d85c08eebcd0e5335db6c9959532c0dc1d74b60d55397ab6c7bb0c087134f', 'docs/qualification/dc-functional-v10-operation-engine-tests-20261013/export-r1/run.exit': '9a271f2a916b0b6ee6cecb2426f0b3206ef074578be55d9bc94f6f3fe3ab86aa', 'docs/qualification/dc-functional-v10-operation-engine-tests-20261013/export-r1/run.log': 'db8879a55439dda32d92aea7df1de9cf77efe62ae3647f6f6a2de0936fe757ed', 'docs/qualification/dc-functional-v10-operation-engine-tests-20261013/export-r2/failed-before-controller-process-read.json': 'c5b46eae1cd3032554f771d6d86cf9a0ac5a231bc5131b9325c504c1d7eec86f', 'docs/qualification/dc-functional-v10-operation-engine-tests-20261013/export-r2/known-failure.json': '3927d267139636925a2c26a5b5ca953fa03dc298470b0aecc80b2cb0f9224382', 'docs/qualification/dc-functional-v10-operation-engine-tests-20261013/export-r3/contract.json': '12994454084369fb31e44f0e1ceb7a7f2ace5bbed33057789399cf895e70d553', 'docs/qualification/dc-functional-v10-operation-engine-tests-20261013/export-r3/receipt.json': '07b1a7ba689c48777e80ed378e429f6674aff3fb0f8bb3adfcd03c3d443f1bbd', 'docs/qualification/dc-functional-v10-operation-engine-tests-20261013/native-r1/harness.py': 'ff6749349dfcc78f89a3fa72a86562b9ff1f017d29cd17e583da33d8e135072b', 'docs/qualification/dc-functional-v10-operation-engine-tests-20261013/native-r1/receipt.json': 'ccf9b2ee19fcd4aa9fd19aaa2be3be75bb8ee8a65698db14abcb1c6b1588dbfe', 'docs/qualification/dc-functional-v10-operation-engine-tests-20261013/native-r2-status-diagnostic/receipt.json': 'fd6b68149922ec133bbec9331d341ba274edf198c1dc0a01df354646cf02f004', 'docs/qualification/dc-functional-v10-operation-engine-tests-20261013/native-r3-audit-fixed/harness.py': '5539a9055e728b8af3e177f8280f4796e0f35d800321191791bc641ee58677b6', 'docs/qualification/dc-functional-v10-operation-engine-tests-20261013/native-r3-audit-fixed/receipt.json': '3c35fb293e696c57b03f20bd113d9138207c74c11345d9ee2698c55ba7694c24', 'docs/qualification/dc-functional-v10-operation-engine-tests-20261013/native-r4-primary-kind-fixed/receipt.json': '0c85d05c667c2cd67888295a9593b22fb2ebb89330e6fba32f657c8dcbe91742', 'docs/qualification/dc-functional-v10-operation-engine-tests-20261013/readonly-helper-offline-r1.harness.py': 'bc45f98b47fd061c923dbb46147c2bd341f9fbb67e979825c000d781d5c66b07', 'docs/qualification/dc-functional-v10-operation-engine-tests-20261013/readonly-helper-offline-r1.json': 'fbe0935fd10aed0483616f2b32fc1efd48a53fec8e5523fa2a81908632dd2aba'}
excluded_untracked={'docs/qualification/dc-functional-v9-integrated-evidence-20261013/r19-real-functional-matrix/neutral-r2-static-refinement.json': '6aa017f21031af55e631777b5e9f2f9d929c6647bad7ac4982f719e7df5f97b4', 'docs/qualification/dc-functional-v9-integrated-evidence-20261013/r19-real-functional-matrix/neutral-r3-offline-r1/00-intent.json': 'b106977afc66e5a1e845f0ad8ec22c08843f08bee0c1d5347c9cf30bc0a854e8', 'docs/qualification/dc-functional-v9-integrated-evidence-20261013/r19-real-functional-matrix/neutral-r3-offline-r1/receipt.json': '268a13b15f65f46481f66de7f0020c5e08e530963af5dc9356fbcf256004e48b', 'docs/qualification/dc-functional-v9-integrated-evidence-20261013/r19-real-functional-matrix/neutral-r3-offline-r1/stderr.log': 'ccd4735c654c78608034d47a2356551f3b83ebe0f4dfb5d8d68d030beee91fec', 'docs/qualification/dc-functional-v9-integrated-evidence-20261013/r19-real-functional-matrix/neutral-r3-offline-r1/stdout.log': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'docs/qualification/dc-functional-v9-integrated-evidence-20261013/r19-real-functional-matrix/r19-neutral-r3-offline-tests.py': '816635b7f43784a9d023bc0730ad408dfc91e77bc307976ae1c8764fae540991', 'docs/qualification/dc-functional-v9-integrated-evidence-20261013/r19-real-functional-matrix/r19-neutral-sequential-driver-r2.py': 'ddf2b53ccfd31bcb691a19cbffc4a04793a12fea9d4bec9a4bd31b2b864fbf8f', 'docs/qualification/dc-functional-v9-integrated-evidence-20261013/r19-real-functional-matrix/r19-neutral-sequential-driver-r3.py': '3b3bdbac3f330aa7a66a97dcf541c66ca27d601a4b1e320b9d37fa1e4cfc9c38', 'docs/qualification/dc-functional-v9-integrated-evidence-20261013/r19-real-functional-matrix/r19-neutral-sequential-driver.py': 'beef3249f8b4aa49f6bd4c52c835e46b2b2a45b38bdc81916fec5005b628c4b2', 'src/mcp/runtime/.hepta-lock-08c58c0168f2643840f0f1d7': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'src/mcp/runtime/.hepta-lock-18cbc9525c78b760900ac960': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'src/mcp/runtime/.hepta-lock-605de19b9eedf59c3e9c7c1f': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'src/mcp/runtime/.hepta-lock-752543f6826437e25be4873c': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'src/mcp/runtime/.hepta-lock-b4e83dd55993a68dfe758eee': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'src/mcp/runtime/.hepta-lock-d06aa2825c5badd1a2f3b2ca': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'tests/.hepta-lock-02bd92a54e0206af1c9e83a9': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}
shipping_manifest=pathlib.Path("/home/qian-qi/hepta-runtime-operation-v10-20261013/docs/qualification/dc-functional-v10-operation-candidate-20261013/final-shipping-498/manifest.json")
assert sha(shipping_manifest)=="179d95223b95efc3d93f427fce3702f86a0375622e74ab055237e6d486e6a018"
shipping=json.loads(shipping_manifest.read_bytes())["non_compile_copy_whitelist"]
for name,pin in archive_pins.items():assert shipping[name]["sha256"]==pin and sha(R/name)==pin
pins.update(archive_pins)
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
(Q/"original-publication-r42-failure.json").write_text(json.dumps({"job_id":"1a137e18cce-b2f-cd4","state":"failed","exit_code":1,"output_complete":True,"failure_phase":"unreviewed path before git add/commit","original_driver_sha256":"10c4541e05c2ee5bcccad9f4741a1dbcecf7132cd249c5dce666c4b43774f068","git_index_empty_independently_verified":True,"excluded_pending_artifacts_preserved":excluded_untracked},sort_keys=True,indent=2)+"\n")
(Q/"source-before.json").write_text(json.dumps(before,sort_keys=True,indent=2)+"\n")
(Q/"preflight.json").write_text(json.dumps({"parent":H,"source_fingerprint":FP,"source_inputs":98,"shipping_pins":pins,"services_before":sv_before,"fresh_native_receipt_sha256":sha(native),"hosted_new_head_CI_qualified":False,"full_dc_replacement_qualified":False},sort_keys=True,indent=2)+"\n")
status=run(["git","status","--porcelain=v1","-z","--untracked-files=all"]);assert status.returncode==0
paths=[]
prefixes=("docs/qualification/dc-functional-v10-operation-candidate-20261013/","docs/qualification/dc-functional-v10-integrated-evidence-20261013/","docs/qualification/dc-functional-v10-operation-engine-tests-20261013/")
for record in status.stdout.split(b"\0"):
 if not record:continue
 name=record[3:].decode();assert record[:2] in (b" M",b"??") and "\n" not in name and "\t" not in name
 if name in excluded_untracked:
  assert record[:2]==b"??" and sha(R/name)==excluded_untracked[name]
  continue
 assert name in before["source_files"] or name in pins or name.startswith(prefixes[:2]),"unreviewed path"
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
receipt["excluded_untracked_same_bytes"]=all((R/n).is_file() and sha(R/n)==pin for n,pin in excluded_untracked.items());(O/"receipt.json").write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
print(json.dumps(receipt,sort_keys=True),flush=True)
assert receipt["remote_exact_head_verified"] and receipt["compiled_source_after_commit_identical"] and receipt["compiled_source_clean_after_commit"] and receipt["protected_services_preserved"]
