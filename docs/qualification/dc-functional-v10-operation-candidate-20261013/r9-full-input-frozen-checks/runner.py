from pathlib import Path
import subprocess,json,hashlib,os,sys,datetime,shutil
root=Path("/home/qian-qi/hepta-runtime-operation-v10-20261013")
sys.dont_write_bytecode=True
stage_path=root/"deploy/stage_dc_successor.py"
head=subprocess.check_output(["git","rev-parse","HEAD"],cwd=root,text=True).strip()
assert head=="50372629e0522d19b5bc4c1a800bfc311e4597f9"
assert stage_path.read_bytes()==subprocess.check_output(["git","show",head+":deploy/stage_dc_successor.py"],cwd=root)
stage_sha=hashlib.sha256(stage_path.read_bytes()).hexdigest()
assert stage_sha.startswith("80fb"), stage_sha
sys.path.insert(0,str(root/"deploy"))
from stage_dc_successor import source_identity
d=root/"docs/qualification/dc-functional-v10-operation-candidate-20261013/r9-full-input-frozen-checks"
assert not d.exists(), "never overwrite a previous job"
d.mkdir()
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def source():
 value=source_identity(root)
 assert value["base_HEAD"]==head and value["dirty_source"] is True
 return value
def save(name,value):(d/name).write_text(json.dumps(value,indent=2)+"\n")
env=dict(os.environ,CARGO_INCREMENTAL="0",CARGO_BUILD_JOBS="4",PYTHONDONTWRITEBYTECODE="1")
cargo=["/home/qian-qi/.cargo/bin/cargo","+1.99.0"]
compiled=source()
save("source-before.json",compiled)
with (d/"macro-static-input-inventory.log").open("wb") as log:
 subprocess.run(["rg","-n",r"include_(str|bytes)!|include!\(|#\[path","src"],cwd=root,stdout=log,stderr=subprocess.STDOUT,check=True)
commands=[
 ("fmt-check",cargo+["fmt","--all","--check"]),
 ("clippy",cargo+["clippy","--locked","--offline","--all-targets","--all-features","--","-D","warnings"]),
 ("rust-default-alltargets",cargo+["test","--locked","--offline","--all-targets"]),
 ("rust-allfeatures-alltargets",cargo+["test","--locked","--offline","--all-features","--all-targets"]),
 ("debug-build",cargo+["build","--locked","--offline"]),
 ("release-build",cargo+["build","--locked","--offline","--release"]),
]
receipt={"schema":"hepta-v10-full-input-frozen-checks-v2","base_HEAD":head,"recorded_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"CARGO_INCREMENTAL":"0","CARGO_BUILD_JOBS":"4","source_identity_helper":{"path":"deploy/stage_dc_successor.py","sha256":stage_sha,"exact_base_gitblob":True},"compiled_source_fingerprint":compiled["source_code_fingerprint"],"dirty_source_expected":True,"source_fingerprint_algorithm":compiled["source_fingerprint_algorithm"],"steps":[],"full_dc_replacement_qualified":False,"actual_six_host_or_business":False,"R7_mapping_gap_preserved":True}
result=0
try:
 for name,args in commands:
  free=shutil.disk_usage(root).free
  if free<2*1024**3:
   receipt["resource_block"]={"step":name,"free_bytes":free,"minimum_bytes":2*1024**3}
   raise RuntimeError("resource guard: below 2GiB; no next command started")
  assert source()==compiled,"whole source changed before "+name
  with (d/(name+".log")).open("wb") as log:
   status=subprocess.run(args,cwd=root,env=env,stdout=log,stderr=subprocess.STDOUT).returncode
  (d/(name+".exit")).write_text(str(status)+"\n")
  receipt["steps"].append({"name":name,"argv":args,"exit_code":status,"free_bytes_before":free,"log_sha256":sha(d/(name+".log"))})
  assert source()==compiled,"whole source changed during "+name
  print(json.dumps({"step":name,"exit":status,"free_bytes":shutil.disk_usage(root).free}),flush=True)
  save("progress.json",receipt)
  if status:result=status;break
 if result==0:
  receipt["artifacts"]={mode:{"path":str(root/"target"/mode/"hepta-runtime"),"bytes":(root/"target"/mode/"hepta-runtime").stat().st_size,"sha256":sha(root/"target"/mode/"hepta-runtime")} for mode in ["debug","release"]}
  receipt["predecessor_contract"]={"path":"deploy/contracts/hepta-runtime-full-operator-v9.json","sha256":sha(root/"deploy/contracts/hepta-runtime-full-operator-v9.json")}
  receipt["harness"]={"path":"tests/dc_functional_v10_operation_async_acceptance.py","sha256":sha(root/"tests/dc_functional_v10_operation_async_acceptance.py")}
  receipt["source_files"]=compiled["source_files"]
except Exception as error:
 result=1;receipt["runner_error"]=str(error);print(str(error),file=sys.stderr,flush=True)
finally:
 after=source();save("source-after.json",after)
 receipt["whole_source_stable"]=(compiled==after)
 receipt["exit_code"]=result
 save("receipt.json",receipt)
 (d/"full.exit").write_text(str(result)+"\n")
 print(json.dumps({"exit_code":result,"full_source_fp":receipt["compiled_source_fingerprint"],"whole_source_stable":receipt["whole_source_stable"]}),flush=True)
sys.exit(result)
