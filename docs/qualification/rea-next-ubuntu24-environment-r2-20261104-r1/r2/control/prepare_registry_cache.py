#!/usr/bin/python3
from pathlib import Path
import hashlib,json,os,re,shutil,stat,subprocess,tomllib
BASE=Path("/home/qian-qi/work/hepta-rea-ubuntu24-matrix-20261104-r2")
ROOT=Path("/home/qian-qi/work/hepta-rea-next-rog-20261104-r1")
REGISTRY=Path("/home/qian-qi/.cargo/registry")
REGISTRY_ID="index.crates.io-1949cf8c6b5b557f"
CONTROL=BASE/"control"
CARGO=BASE/"cargo-home"
SOURCE_PIN="9d08a4cc6b6c89f4db47eb300af5e54dd44092082434c93b1dee954c30b2209a"
VERIFY_PIN="b783c4f05a5c7f614ee7150ecc66bb4fe25f1cfd8ed548723e405e4612b6baa4"
PLAN_PIN="ac5ed3a0e49f9cbb9b9dfb09c1ceb49926abc4478aa8b72a3cda32b8c12b71f6"
RUNNER=Path("/home/qian-qi/work/hepta-rea-verification-tools-20261104-r1/run_frozen_commands.py")
RUNNER_PIN="f7f449dbcbd7705876c7cc953937411ad07d521117285db2159e646a1942dec1"
def digest(data):return hashlib.sha256(data).hexdigest()
def file_digest(path):
 with path.open("rb") as f:return hashlib.file_digest(f,"sha256").hexdigest()
def write(path,data):
 path.parent.mkdir(parents=True,exist_ok=True)
 with path.open("xb") as f:f.write(data);f.flush();os.fsync(f.fileno())
def dump(path,obj):write(path,(json.dumps(obj,sort_keys=True,indent=2)+"\n").encode())
def safe_read(path):
 parts=path.parts
 fd=os.open("/",os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
 try:
  for component in parts[1:-1]:
   child=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=fd)
   os.close(fd);fd=child
  child=os.open(parts[-1],os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=fd)
  with os.fdopen(child,"rb") as stream:
   before=os.fstat(stream.fileno())
   if not stat.S_ISREG(before.st_mode):raise RuntimeError("non-regular public cache input")
   raw=stream.read()
   after=os.fstat(stream.fileno())
  identity=lambda x:(x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
  if identity(before)!=identity(after):raise RuntimeError("public cache file changed during read")
  return raw
 finally:os.close(fd)
def inventory():
 paths=subprocess.check_output(["/usr/bin/git","ls-files","-z","--cached","--others","--exclude-standard"],cwd=ROOT).decode().split("\0")
 groups={"source":[],"verification":[]}
 for relative in sorted(set(paths)-{""}):
  group=None
  if relative.startswith(("src/","examples/",".cargo/")) or relative in ("Cargo.toml","Cargo.lock","build.rs","rustfmt.toml"):group="source"
  elif relative.startswith(("tests/","scripts/",".github/")) or (relative.endswith(".py") and relative.startswith(("deploy/","tools/x230/","workers/"))):group="verification"
  if group:
   p=ROOT/relative
   if p.is_symlink() or not p.is_file():raise RuntimeError("input not regular: "+relative)
   groups[group].append({"path":relative,"bytes":p.stat().st_size,"sha256":file_digest(p)})
 return {name:{"count":len(rows),"sha256":digest(json.dumps(rows,sort_keys=True,separators=(",",":")).encode()),"files":rows} for name,rows in groups.items()}
if file_digest(BASE/"plan.json")!=PLAN_PIN or file_digest(RUNNER)!=RUNNER_PIN:raise RuntimeError("plan/runner pin mismatch")
before=inventory()
if (before["source"]["count"],before["source"]["sha256"],before["verification"]["count"],before["verification"]["sha256"])!=(295,SOURCE_PIN,613,VERIFY_PIN):raise RuntimeError("frozen source/verification groups differ")
dump(CONTROL/"inputs-preparation-before.json",before)
lock_bytes=safe_read(ROOT/"Cargo.lock")
if digest(lock_bytes)!="558136129c81ab5713f9ff381c6340be8b4ec61986b4c808d828aef85d901a59":raise RuntimeError("Cargo.lock changed")
lock=tomllib.loads(lock_bytes.decode())
write(CONTROL/"Cargo.lock",lock_bytes)
for p in (BASE/"target",CARGO,BASE/"output"):
 p.mkdir(mode=0o700)
packages=[]
for p in lock["package"]:
 source=p.get("source")
 if not source:continue
 if source!="registry+https://github.com/rust-lang/crates.io-index":raise RuntimeError("non-public-registry dependency requires explicit handling")
 name,version,checksum=p["name"],p["version"],p["checksum"]
 if not re.fullmatch(r"[A-Za-z0-9_-]+",name) or not re.fullmatch(r"[A-Za-z0-9.+_-]+",version) or not re.fullmatch(r"[0-9a-f]{64}",checksum):raise RuntimeError("invalid locked package identity")
 lower=name.lower()
 index_path=("1/"+lower if len(lower)==1 else "2/"+lower if len(lower)==2 else "3/"+lower[0]+"/"+lower if len(lower)==3 else lower[:2]+"/"+lower[2:4]+"/"+lower)
 packages.append({"name":name,"version":version,"checksum":checksum,"crate":name+"-"+version+".crate","index_path":index_path})
if len(packages)!=341:raise RuntimeError("locked registry package count changed")
dump(CONTROL/"registry-whitelist.json",{"lock_sha256":digest(lock_bytes),"registry":"crates.io","packages":packages})
copied=[];missing=[];indices=[];missing_indices=[]
for p in packages:
 source=REGISTRY/"cache"/REGISTRY_ID/p["crate"]
 try:data=safe_read(source)
 except FileNotFoundError:missing.append(p["crate"]);continue
 if digest(data)!=p["checksum"]:raise RuntimeError("cached .crate checksum mismatch: "+p["crate"])
 target=CARGO/"registry/cache"/REGISTRY_ID/p["crate"]
 write(target,data)
 copied.append({"file":str(target.relative_to(CARGO)),"bytes":len(data),"sha256":digest(data),"origin":str(source)})
by_name={}
for p in packages:by_name.setdefault(p["name"],[]).append(p)
for name,versions in sorted(by_name.items()):
 relative=versions[0]["index_path"]
 source=REGISTRY/"index"/REGISTRY_ID/".cache"/relative
 try:data=safe_read(source)
 except FileNotFoundError:missing_indices.append(relative);continue
 entries={}
 for fragment in data.split(b"\0"):
  if fragment.startswith(b"{"):
   try:entry=json.loads(fragment)
   except (ValueError,UnicodeError):continue
   if entry.get("name")==name:entries[entry.get("vers")]=entry
 if any(entries.get(p["version"],{}).get("cksum")!=p["checksum"] for p in versions):
  missing_indices.append(relative);continue
 target=CARGO/"registry/index"/REGISTRY_ID/".cache"/relative
 write(target,data)
 indices.append({"file":str(target.relative_to(CARGO)),"bytes":len(data),"sha256":digest(data),"origin":str(source),"locked_versions":[p["version"] for p in versions]})
config_source=REGISTRY/"index"/REGISTRY_ID/"config.json"
config_bytes=safe_read(config_source);config=json.loads(config_bytes)
if config.get("dl")!="https://static.crates.io/crates" or config.get("api")!="https://crates.io" or config.get("auth-required",False):raise RuntimeError("nonstandard/public registry configuration")
write(CARGO/"registry/index"/REGISTRY_ID/"config.json",config_bytes)
git_dir=subprocess.check_output(["/usr/bin/git","rev-parse","--absolute-git-dir"],cwd=ROOT,text=True).strip()
git_common=subprocess.check_output(["/usr/bin/git","rev-parse","--git-common-dir"],cwd=ROOT,text=True).strip()
after=inventory()
dump(CONTROL/"inputs-preparation-after-copy.json",after)
if before!=after:raise RuntimeError("frozen inputs changed while preparing public cache")
report={"schema":"hepta.rea.locked-registry-cache-preparation.v1","lock_sha256":digest(lock_bytes),"source":before["source"]["sha256"],"verification":before["verification"]["sha256"],"copied_crates":copied,"copied_index_records":indices,"missing_crates":missing,"missing_index_records":missing_indices,"registry_config_sha256":digest(config_bytes),"no_global_credentials_or_config_copied":True,"no_global_registry_sources_copied":True,"git_dir":git_dir,"git_common_dir":git_common,"new_directories":[str(BASE/"target"),str(CARGO),str(BASE/"output")],"network_fetch_required":bool(missing or missing_indices)}
dump(CONTROL/"cache-preparation.json",report)
print(json.dumps({"copied_crates":len(copied),"copied_crate_bytes":sum(x["bytes"] for x in copied),"copied_index_records":len(indices),"missing_crates":missing,"missing_index_records":missing_indices,"network_fetch_required":report["network_fetch_required"],"git_dir":git_dir,"git_common_dir":git_common,"cache_preparation":str(CONTROL/"cache-preparation.json"),"cache_preparation_sha256":file_digest(CONTROL/"cache-preparation.json"),"source":before["source"]["sha256"],"verification":before["verification"]["sha256"]},sort_keys=True))
