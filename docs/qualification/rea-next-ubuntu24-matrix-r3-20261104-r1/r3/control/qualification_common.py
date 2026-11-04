from pathlib import Path
import hashlib,json,os,subprocess
BASE=Path("/home/qian-qi/work/hepta-rea-ubuntu24-matrix-20261104-r3")
ROOT=Path("/home/qian-qi/work/hepta-rea-next-rog-20261104-r1")
RUST=Path("/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu")
TOOLS=Path("/home/qian-qi/work/hepta-rea-verification-tools-20261104-r1")
NEXTEST=TOOLS/"bin/cargo-nextest"
RUNNER=TOOLS/"run_frozen_commands.py"
REFERENCE=Path("/home/qian-qi/work/hepta-rea-reference-cache-20261104-r1")
IMAGE="sha256:120aee0fa701e4f9534dbd500ee7c101a5fc3793127c5820bf34d88cc13eb2d8"
PLAN_SHA="5e967f1d2136d447615de1274384e968ef5b523008c3da5feb3a12e739705bd8"
RUNNER_SHA="f7f449dbcbd7705876c7cc953937411ad07d521117285db2159e646a1942dec1"
SOURCE_SHA="9d08a4cc6b6c89f4db47eb300af5e54dd44092082434c93b1dee954c30b2209a"
VERIFY_SHA="b783c4f05a5c7f614ee7150ecc66bb4fe25f1cfd8ed548723e405e4612b6baa4"
def sha(path):
 with Path(path).open("rb") as f:return hashlib.file_digest(f,"sha256").hexdigest()
def write(path,data):
 with Path(path).open("xb") as f:f.write(data);f.flush();os.fsync(f.fileno())
def dump(path,value):write(path,(json.dumps(value,sort_keys=True,indent=2)+"\n").encode())
def inventory():
 raw=subprocess.check_output(["/usr/bin/git","ls-files","-z","--cached","--others","--exclude-standard"],cwd=ROOT)
 groups={"source":[],"verification":[]}
 for relative in sorted(set(raw.decode().split("\0"))-{""}):
  group=None
  if relative.startswith(("src/","examples/",".cargo/")) or relative in ("Cargo.toml","Cargo.lock","build.rs","rustfmt.toml"):group="source"
  elif relative.startswith(("tests/","scripts/",".github/")) or (relative.endswith(".py") and relative.startswith(("deploy/","tools/x230/","workers/"))):group="verification"
  if group:
   p=ROOT/relative
   if p.is_symlink() or not p.is_file():raise RuntimeError("non-regular frozen input: "+relative)
   groups[group].append({"path":relative,"bytes":p.stat().st_size,"sha256":sha(p)})
 return {name:{"files":rows,"count":len(rows),"sha256":hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(",",":")).encode()).hexdigest()} for name,rows in groups.items()}
def require_inputs(value):
 if (value["source"]["count"],value["source"]["sha256"],value["verification"]["count"],value["verification"]["sha256"])!=(295,SOURCE_SHA,613,VERIFY_SHA):raise RuntimeError("frozen source/verification pin mismatch")
def load_plan():
 if sha(BASE/"plan.json")!=PLAN_SHA or sha(RUNNER)!=RUNNER_SHA:raise RuntimeError("plan/runner pin mismatch")
 plan=json.loads((BASE/"plan.json").read_bytes())
 if len(plan["commands"])!=35 or any(x.get("expected_exit_code",0) not in (0,3) for x in plan["commands"]):raise RuntimeError("unexpected command contract")
 return plan
