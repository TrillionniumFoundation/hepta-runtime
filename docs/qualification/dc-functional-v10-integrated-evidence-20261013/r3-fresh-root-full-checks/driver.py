#!/usr/bin/env python3
import pathlib,os,json,hashlib,subprocess,sys,datetime,stat
R=pathlib.Path("/home/qian-qi/hepta-runtime-dc-functional-20261013")
Q=R/"docs/qualification/dc-functional-v10-integrated-evidence-20261013/r3-fresh-root-full-checks"
FP="498cca6da8c442c70534b0a35807c94d7b5f7fbef4b2b4d8f15fa9c22484e33c"
sys.path.insert(0,str(R/"deploy"))
import stage_dc_successor as S
assert hashlib.sha256((R/"deploy/stage_dc_successor.py").read_bytes()).hexdigest()=="80fb34a7d55157032a5a8da007d31f289eb2862746ea16747de7b3cb305f0582"
before=S.source_identity(R);assert before["source_code_fingerprint"]==FP and len(before["source_files"])==98
extra_names=["deploy/preflight_dc_successor.py","tests/dc_successor_preflight_tests.py","deploy/dc_successor_inventory.py","tests/dc_successor_inventory_tests.py"]
extra={n:hashlib.sha256((R/n).read_bytes()).hexdigest() for n in extra_names}
assert extra=={"deploy/preflight_dc_successor.py":"7bfcf63208db6992fd31bd398caf4fb5635e5f8253803b1141f71bd0d2d7fb61","tests/dc_successor_preflight_tests.py":"d4c7ec13ba794ef02e0bc3e7f3aa7f5c864947dae912efda8ec9ffbfad9e6d8c","deploy/dc_successor_inventory.py":"a198944235a8b71763a612d077bf41c8915028487beb96888da003868e24e5c9","tests/dc_successor_inventory_tests.py":"3e0431497a23d56b5f8aeb81c4035173a819134ca44cae48d802b9972849876f"}
assert not Q.exists();Q.mkdir(mode=0o700)
(Q/"driver.py").write_bytes(pathlib.Path(__file__).read_bytes())
(Q/"source-before.json").write_text(json.dumps(before,sort_keys=True,indent=2)+"\n")
env=os.environ.copy();env.update(PATH="/home/qian-qi/.rustup/toolchains/1.99.0-x86_64-unknown-linux-gnu/bin:/home/qian-qi/.cargo/bin:/usr/local/bin:/usr/bin:/bin",RUSTUP_TOOLCHAIN="1.99.0",CARGO_BUILD_JOBS="4",CARGO_INCREMENTAL="0",CARGO_NET_OFFLINE="true")
cargo="/home/qian-qi/.rustup/toolchains/1.99.0-x86_64-unknown-linux-gnu/bin/cargo"
commands=[("fmt",[cargo,"fmt","--all","--check"]),("clippy",[cargo,"clippy","--locked","--offline","--all-features","--all-targets","--","-D","warnings"]),("rust-default",[cargo,"test","--locked","--offline","--all-targets"]),("rust-allfeatures",[cargo,"test","--locked","--offline","--all-features","--all-targets"]),("debug-build",[cargo,"build","--locked","--offline","--bin","hepta-runtime"]),("release-build",[cargo,"build","--locked","--offline","--release","--bin","hepta-runtime"]),("preflight94",["/usr/bin/python3","-B","tests/dc_successor_preflight_tests.py"]),("stage26",["/usr/bin/python3","-B","tests/dc_successor_stage_tests.py"]),("inventory55",["/usr/bin/python3","-B","tests/dc_successor_inventory_tests.py","--results-dir",str(Q/"inventory55-receipts")])]
rows=[];failure=None
def free():
 v=os.statvfs(R);return v.f_bavail*v.f_frsize
def artifact(path):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 try:
  a=os.fstat(fd);assert stat.S_ISREG(a.st_mode) and a.st_uid==os.getuid() and not a.st_mode&0o022
  h=hashlib.sha256();count=0
  while True:
   raw=os.read(fd,1048576)
   if not raw:break
   h.update(raw);count+=len(raw)
  b=os.fstat(fd);linked=path.lstat();fields=("st_dev","st_ino","st_size","st_mtime_ns","st_ctime_ns","st_uid","st_mode","st_nlink")
  assert count==a.st_size and all(getattr(a,f)==getattr(b,f)==getattr(linked,f) for f in fields)
  return {"path":str(path),"bytes":count,"sha256":h.hexdigest(),"inode":a.st_ino,"nlink":a.st_nlink}
 finally:os.close(fd)
try:
 for label,argv in commands:
  assert free()>=2*1024**3,"resource guard before next command"
  assert S.source_identity(R)==before and {n:hashlib.sha256((R/n).read_bytes()).hexdigest() for n in extra_names}==extra
  with (Q/(label+".log")).open("w") as log:result=subprocess.run(argv,cwd=R,env=env,stdout=log,stderr=subprocess.STDOUT)
  row={"step":label,"command":argv,"exit":result.returncode,"free_bytes_after":free()}
  rows.append(row);(Q/"progress.json").write_text(json.dumps(rows,sort_keys=True,indent=2)+"\n")
  print(json.dumps(row,sort_keys=True),flush=True)
  assert result.returncode==0,"preserve failure and stop without unrelated rerun"
except BaseException as error:failure={"type":type(error).__name__}
after=S.source_identity(R)
stable=after==before and {n:hashlib.sha256((R/n).read_bytes()).hexdigest() for n in extra_names}==extra
pins={str(p.relative_to(R)):artifact(p) for p in (R/"target/debug/hepta-runtime",R/"target/release/hepta-runtime")}
receipt={"schema":"hepta-v10-fresh-root-complete-source-checks-v1","recorded_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"completed":failure is None and len(rows)==len(commands) and stable,"failure":failure,"source_fingerprint":FP,"source_inputs":len(before["source_files"]),"source_before_after_identical":stable,"head_at_start":before["base_HEAD"],"dirty_source_at_start":before["dirty_source"],"commands":rows,"artifact_pins":pins,"extra_source_pins":extra,"native_or_six_host_tests_borrowed":False,"model_origin_or_full_replacement_qualified":False}
(Q/"source-after.json").write_text(json.dumps(after,sort_keys=True,indent=2)+"\n")
(Q/"receipt.json").write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
print(json.dumps({"completed":receipt["completed"],"source_fingerprint":FP,"artifact_pins":pins,"failed_type":failure},sort_keys=True),flush=True)
raise SystemExit(0 if receipt["completed"] else 1)
