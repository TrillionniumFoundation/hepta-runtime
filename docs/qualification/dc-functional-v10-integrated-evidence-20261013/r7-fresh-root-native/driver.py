#!/usr/bin/env python3
import pathlib,json,hashlib,subprocess,datetime,sys,os,types,stat
R=pathlib.Path("/home/qian-qi/hepta-runtime-dc-functional-20261013")
D=R/"docs/qualification/dc-functional-v10-integrated-evidence-20261013/r7-fresh-root-native"
B=pathlib.Path("/home/qian-qi/hepta-runtime-v10-root-pinned-native-757ef1-20261014-r1/hepta-runtime-debug")
BS="757ef140732744e4c29d50e615375d3bb300b6288c520d741bd6a3ed8f0813bd"
FP="498cca6da8c442c70534b0a35807c94d7b5f7fbef4b2b4d8f15fa9c22484e33c"
H="aa41acbdd181a814f51b51c91e01fceedb797fab"
fields=("st_dev","st_ino","st_size","st_mtime_ns","st_ctime_ns","st_uid","st_gid","st_mode","st_nlink")
def sha(p,returnraw=False):
 p=pathlib.Path(p);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 try:
  a=os.fstat(fd);assert stat.S_ISREG(a.st_mode) and a.st_uid==os.getuid() and not a.st_mode&0o022
  h=hashlib.sha256();count=0;pieces=[]
  while True:
   raw=os.read(fd,1048576)
   if not raw:break
   count+=len(raw);h.update(raw)
   if returnraw:pieces.append(raw)
  assert count==a.st_size and all(getattr(a,f)==getattr(os.fstat(fd),f)==getattr(p.lstat(),f) for f in fields)
  return (h.hexdigest(),b"".join(pieces)) if returnraw else h.hexdigest()
 finally:os.close(fd)
pinned="/home/qian-qi/hepta-runtime-v10-root-pinned-native-757ef1-20261014-r1/manifest.json"
assert sha(pinned)=="e7b205ab9516bb625c48ce7d49b2ead933f6f050ba1a0702ec46ec8022d6c545"
assert B.lstat().st_nlink==1 and sha(B)==BS
sp=R/"deploy/stage_dc_successor.py";hs,raw=sha(sp,True);assert hs=="80fb34a7d55157032a5a8da007d31f289eb2862746ea16747de7b3cb305f0582"
sys.path.insert(0,str(sp.parent));stage=types.ModuleType("root_v10_native_stage");stage.__file__=str(sp);sys.modules[stage.__name__]=stage;exec(compile(raw,str(sp),"exec"),stage.__dict__)
before=stage.source_identity(R);assert before["source_code_fingerprint"]==FP and len(before["source_files"])==98 and before["base_HEAD"]==H
mp=R/"docs/qualification/dc-functional-v10-operation-candidate-20261013/versioned-regression-r7-approved-guard/manifest.json"
assert sha(mp)=="4256eb78231be2c65987c13d3f614f309dba1a37fdfd709402d760dcf9f4034f"
package=json.loads(mp.read_bytes());sources=package["copy_whitelist"]
oldmap={x["original_path"]:x["original_sha256"] for x in package["copies"]};oldmap["tests/dc_successor_contract.py"]="0b039e2d667314fec32bde7827fd0f9ad01d35b8d3199e73a1e036c7b1eb3dde"
for p,meta in sources.items():assert sha(R/p)==meta["sha256"]
for p,pin in oldmap.items():assert sha(R/p)==pin
C=R/"deploy/contracts/hepta-runtime-full-operator-v10.json";CS="12994454084369fb31e44f0e1ceb7a7f2ace5bbed33057789399cf895e70d553";assert sha(C)==CS
HTTP="8b7ee206ccfc7978ac4abdf3eac3ddb8f7e7c36d053f601b5cfcb66f52fb8dba";TOOL="e2b29f987d3aaa863d7bf6879d0d6a835a807c133c5c355b6a4e69bce9c3e216";LOADER="4623c4da9493dccfc4bcef18c7267ba96ba7f5f1ddd799441214948c9da161fe";FACADE="b35313888a70a90dc72be44dc45d3f20be45337d7c2353556a382564299d649a"
common=["--binary",str(B),"--contract",str(C),"--expected-binary-sha256",BS,"--expected-source-fingerprint",FP]
helper=["--expected-http-helper-sha256",HTTP,"--expected-contract-helper-sha256",TOOL,"--expected-approval-loader-sha256",LOADER]
commands=[
("approval13","dc_functional_v10_contract_approval_tests.py",[],None),
("catalog","dc_functional_v10_catalog_acceptance.py",common+helper+["--expected-facade-sha256",FACADE,"--out",str(D/"catalog.json")],14),
("request-results","dc_functional_v10_request_results_acceptance.py",common+helper+["--out",str(D/"request-results.json")],12),
("request-async","dc_functional_v10_request_async_acceptance.py",common+["--expected-contract-sha256",CS,"--out",str(D/"request-async.json")],13),
("legacy-native","dc_functional_v10_legacy_native_acceptance.py",["--binary",str(B),"--out",str(D/"legacy-native.json"),"--verify-contract",str(R/"deploy/contracts/hepta-runtime-full-operator-v4.json"),"--allow-v4-directory-move","--successor-contract",str(C)],13),
("legacy-directory","dc_functional_v10_legacy_directory_move_acceptance.py",["--binary",str(B),"--out",str(D/"legacy-directory.json"),"--successor-contract",str(C)],16),
("legacy-root-guard","dc_functional_v10_legacy_workspace_root_guard_acceptance.py",["--binary",str(B),"--out",str(D/"legacy-root-guard.json"),"--successor-contract",str(C)],5),
("legacy-concurrency","dc_functional_v10_legacy_concurrent_text_acceptance.py",["--binary",str(B),"--contract",str(C),"--waves","3","--contenders","6","--out",str(D/"legacy-concurrency.json")],6),
("operation","dc_functional_v10_operation_acceptance.py",common+["--expected-contract-sha256",CS,"--expected-head",H,"--previous-contract",str(R/"deploy/contracts/hepta-runtime-full-operator-v9.json"),"--expected-previous-contract-sha256","3eb628812d0c70b9af8393ecf9d0ce47f69b1438a134148f75ae2dd3132e6761","--out",str(D/"operation.json")],16)]
assert not D.exists();D.mkdir(mode=0o700);os.umask(0o077)
(D/"driver.py").write_bytes(pathlib.Path(__file__).read_bytes());(D/"source-before.json").write_text(json.dumps(before,sort_keys=True,indent=2)+"\n")
report={"schema":"hepta-v10-fresh-root-native-regression-v1","recorded_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"precommit_head":H,"source_fingerprint":FP,"source_inputs":98,"binary":str(B),"binary_sha256":BS,"contract_sha256":CS,"commands":[],"complete":False,"actual_six_host_qualified":False,"all10_actual_arms_qualified":False,"full_dc_replacement_qualified":False};failure=None
def save():(D/"receipt.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
save()
try:
 for name,file,args,count in commands:
  v=os.statvfs(R);assert v.f_bavail*v.f_frsize>=2*1024**3
  assert sha(B)==BS and sha(C)==CS and stage.source_identity(R)["source_files"]==before["source_files"]
  for p,meta in sources.items():assert sha(R/p)==meta["sha256"]
  out,err=D/(name+".stdout.log"),D/(name+".stderr.log")
  print("RUN",name,flush=True)
  with out.open("xb") as o,err.open("xb") as e:
   result=subprocess.run(["/usr/bin/python3","-B",str(R/"tests"/file),*args],cwd=R,stdout=o,stderr=e,timeout=300,env={**os.environ,"PYTHONDONTWRITEBYTECODE":"1"})
  row={"name":name,"script":file,"exit":result.returncode,"stdout_sha256":sha(out),"stderr_sha256":sha(err)}
  if count is not None and (D/(name+".json")).exists():
   receipt=json.loads((D/(name+".json")).read_bytes());row.update(check_count=len(receipt.get("checks",[])),complete=receipt.get("complete"),receipt_sha256=sha(D/(name+".json")))
   row["explicit_cleanup_fields"]={k:v for k,v in receipt.items() if "cleanup" in k or k in ("private_fixture_removed",)}
  report["commands"].append(row);save();print(json.dumps(row,sort_keys=True),flush=True)
  assert result.returncode==0
  if count is not None:assert row["complete"] is True and row["check_count"]==count
 report["complete"]=True
except BaseException as e:failure=type(e).__name__;report["failure_type"]=failure
after=stage.source_identity(R);stable=after["source_files"]==before["source_files"] and sha(B)==BS and sha(C)==CS and all(sha(R/p)==meta["sha256"] for p,meta in sources.items()) and all(sha(R/p)==pin for p,pin in oldmap.items())
report["source_and_input_pins_stable"]=stable;report["complete"]=bool(report["complete"] and stable);report["native_checks_passed"]=sum(x.get("check_count",0) for x in report["commands"] if x.get("complete") is True);save()
(D/"source-after.json").write_text(json.dumps(after,sort_keys=True,indent=2)+"\n")
print(json.dumps({"complete":report["complete"],"failure_type":failure,"native_checks_passed":report["native_checks_passed"],"receipt_sha256":sha(D/"receipt.json")},sort_keys=True),flush=True)
raise SystemExit(0 if report["complete"] else 1)
