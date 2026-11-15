#!/usr/bin/python3
from qualification_common import *
import stat
CONTROL=BASE/"control";CARGO=BASE/"cargo-home";REGISTRY_ID="index.crates.io-1949cf8c6b5b557f"
owner=json.loads((BASE/"output/dependencies-owner-receipt.json").read_bytes())
if owner.get("qualified") is not True or owner.get("container_exit_state",{}).get("ExitCode")!=0 or owner.get("container_removed") is not True:raise RuntimeError("original dependency container not successful/removed")
spec=json.loads((CONTROL/"registry-whitelist.json").read_bytes());packages=spec["packages"]
allowed={p["crate"]:p for p in packages}
names={}
for p in packages:names.setdefault(p["index_path"],[]).append(p)
if (CARGO/"credentials").exists() or (CARGO/"credentials.toml").exists() or (CARGO/"config").exists() or (CARGO/"config.toml").exists():raise RuntimeError("unexpected global credential/config in dedicated Cargo home")
crates=[]
cache=CARGO/"registry/cache"/REGISTRY_ID
for p in sorted(cache.iterdir()):
 if p.is_symlink() or not p.is_file() or p.name not in allowed:raise RuntimeError("unapproved archive in task registry cache")
 actual=sha(p)
 if actual!=allowed[p.name]["checksum"]:raise RuntimeError("task .crate checksum mismatch")
 crates.append({"path":str(p.relative_to(CARGO)),"bytes":p.stat().st_size,"sha256":actual})
indices=[]
index=CARGO/"registry/index"/REGISTRY_ID
for p in sorted((index/".cache").rglob("*")):
 if p.is_dir():continue
 relative=str(p.relative_to(index/".cache"))
 if p.is_symlink() or not p.is_file() or relative not in names:raise RuntimeError("unapproved sparse index record")
 raw=p.read_bytes();entries={}
 for fragment in raw.split(b"\0"):
  if fragment.startswith(b"{"):
   try:e=json.loads(fragment)
   except (ValueError,UnicodeError):continue
   entries[(e.get("name"),e.get("vers"))]=e
 if any(entries.get((item["name"],item["version"]),{}).get("cksum")!=item["checksum"] for item in names[relative]):raise RuntimeError("locked index checksum record differs")
 indices.append({"path":str(p.relative_to(CARGO)),"bytes":p.stat().st_size,"sha256":sha(p)})
if len(indices)!=len(names):raise RuntimeError("missing locked index records")
configuration=json.loads((index/"config.json").read_bytes())
if configuration.get("dl")!="https://static.crates.io/crates" or configuration.get("api")!="https://crates.io" or configuration.get("auth-required",False):raise RuntimeError("non-public registry configuration after fetch")
unpacked=[]
sources=CARGO/"registry/src"/REGISTRY_ID
allowed_directories={p["name"]+"-"+p["version"]:p for p in packages}
if sources.exists():
 for p in sorted(sources.iterdir()):
  if p.is_symlink() or not p.is_dir() or p.name not in allowed_directories:raise RuntimeError("unapproved unpacked package")
  checksum_path=p/".cargo-checksum.json"
  checksum=json.loads(checksum_path.read_bytes())
  if checksum.get("package")!=allowed_directories[p.name]["checksum"]:raise RuntimeError("unpacked package checksum differs")
  unpacked.append({"directory":str(p.relative_to(CARGO)),"package_checksum":checksum["package"],"checksum_file_sha256":sha(checksum_path)})
for section in ("cache","index","src"):
 path=CARGO/"registry"/section
 if path.exists() and {p.name for p in path.iterdir()}!={REGISTRY_ID}:raise RuntimeError("unapproved registry source directory")
after=inventory();require_inputs(after)
original=json.loads((CONTROL/"inputs-preparation-before.json").read_bytes())
if original!=after:raise RuntimeError("source/verification changed during dependency preparation")
dump(CONTROL/"inputs-dependency-ready.json",after)
remaining=sorted(set(allowed)-{Path(x["path"]).name for x in crates})
receipt={"schema":"hepta.rea.locked-linux-dependency-preparation.v1","qualified":True,"target":"x86_64-unknown-linux-gnu","cargo_lock_sha256":spec["lock_sha256"],"locked_registry_packages":len(packages),"available_crates":crates,"available_crate_count":len(crates),"available_crate_bytes":sum(x["bytes"] for x in crates),"index_records":indices,"index_record_count":len(indices),"cargo_unpacked_packages":unpacked,"unpacked_package_count":len(unpacked),"remaining_locked_crates_not_requested_by_successful_linux_fetch":remaining,"dependency_container_receipt":str(BASE/"output/dependencies-owner-receipt.json"),"dependency_container_receipt_sha256":sha(BASE/"output/dependencies-owner-receipt.json"),"dependency_fetch_exit_code":0,"copied_user_credentials_or_global_config":False,"copied_global_registry_sources":False,"source_manifest":SOURCE_SHA,"verification_manifest":VERIFY_SHA,"source_and_verification_unchanged":True,"matrix_network":"none","matrix_cargo_net_offline":"true"}
dump(CONTROL/"dependency-preparation-receipt.json",receipt)
print(json.dumps({"qualified":True,"available_crates":len(crates),"available_crate_bytes":sum(x["bytes"] for x in crates),"index_records":len(indices),"unpacked_packages":len(unpacked),"remaining_nonrequested_locked_crates":len(remaining),"receipt":str(CONTROL/"dependency-preparation-receipt.json"),"receipt_sha256":sha(CONTROL/"dependency-preparation-receipt.json")},sort_keys=True))
