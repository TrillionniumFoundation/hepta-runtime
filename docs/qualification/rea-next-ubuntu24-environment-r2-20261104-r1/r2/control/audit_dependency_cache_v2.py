#!/usr/bin/python3
from qualification_common import *
import stat,tarfile
from pathlib import PurePosixPath
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
payload_manifests=[]
if sources.exists():
 for p in sorted(sources.iterdir()):
  if p.is_symlink() or not p.is_dir() or p.name not in allowed_directories:raise RuntimeError("unapproved unpacked package")
  package=allowed_directories[p.name];archive=cache/package["crate"]
  expected_files={};payload=[]
  with tarfile.open(archive,"r:gz") as members:
   for member in members:
    relative=PurePosixPath(member.name)
    if relative.is_absolute() or len(relative.parts)<2 or relative.parts[0]!=p.name or any(x in (".","..","") for x in member.name.split("/")):raise RuntimeError("noncanonical locked archive member")
    inside=str(PurePosixPath(*relative.parts[1:]))
    path=p/inside
    if member.isdir():
     if path.is_symlink() or not path.is_dir():raise RuntimeError("archive directory differs from Cargo unpack")
     continue
    if not member.isfile() or inside in expected_files:raise RuntimeError("unsupported or duplicate locked archive member")
    source=members.extractfile(member)
    if source is None:raise RuntimeError("locked archive member unreadable")
    with source:
     reference=hashlib.file_digest(source,"sha256").hexdigest()
    actual=path.lstat()
    if not stat.S_ISREG(actual.st_mode) or actual.st_size!=member.size or sha(path)!=reference:raise RuntimeError("Cargo unpacked bytes differ from pinned archive: "+str(path))
    expected_files[inside]=reference
    payload.append({"path":inside,"bytes":member.size,"sha256":reference})
  marker=p/".cargo-ok"
  if marker.is_symlink() or not marker.is_file() or json.loads(marker.read_bytes())!={"v":1}:raise RuntimeError("Cargo completion marker not recognized")
  actual_files=set()
  for candidate in p.rglob("*"):
   if candidate.is_symlink():raise RuntimeError("symlink in Cargo unpacked package")
   if candidate.is_file():actual_files.add(str(candidate.relative_to(p)))
  if actual_files!=set(expected_files)|{".cargo-ok"}:raise RuntimeError("Cargo unpack has unexpected or missing files")
  payload.sort(key=lambda x:x["path"])
  manifest_sha=hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(",",":")).encode()).hexdigest()
  payload_manifests.append({"package":p.name,"archive_sha256":package["checksum"],"files":payload,"files_sha256":manifest_sha,"cargo_generated_marker_sha256":sha(marker)})
  unpacked.append({"directory":str(p.relative_to(CARGO)),"package_checksum":package["checksum"],"payload_file_count":len(payload),"payload_bytes":sum(x["bytes"] for x in payload),"payload_manifest_sha256":manifest_sha,"cargo_generated_marker_sha256":sha(marker)})
dump(CONTROL/"unpacked-source-manifest.json",{"schema":"hepta.rea.cargo-unpack-byte-manifest.v1","method":"Every regular tar member is independently hashed against its actual unpacked file; only Cargo's generated .cargo-ok v1 marker may be extra.","packages":payload_manifests})
for section in ("cache","index","src"):
 path=CARGO/"registry"/section
 if path.exists() and {p.name for p in path.iterdir()}!={REGISTRY_ID}:raise RuntimeError("unapproved registry source directory")
after=inventory();require_inputs(after)
original=json.loads((CONTROL/"inputs-preparation-before.json").read_bytes())
if original!=after:raise RuntimeError("source/verification changed during dependency preparation")
dump(CONTROL/"inputs-dependency-ready.json",after)
remaining=sorted(set(allowed)-{Path(x["path"]).name for x in crates})
receipt={"schema":"hepta.rea.locked-linux-dependency-preparation.v2","qualified":True,"target":"x86_64-unknown-linux-gnu","cargo_lock_sha256":spec["lock_sha256"],"locked_registry_packages":len(packages),"available_crates":crates,"available_crate_count":len(crates),"available_crate_bytes":sum(x["bytes"] for x in crates),"index_records":indices,"index_record_count":len(indices),"cargo_unpacked_packages":unpacked,"unpacked_package_count":len(unpacked),"remaining_locked_crates_not_requested_by_successful_linux_fetch":remaining,"dependency_container_receipt":str(BASE/"output/dependencies-owner-receipt.json"),"dependency_container_receipt_sha256":sha(BASE/"output/dependencies-owner-receipt.json"),"dependency_fetch_exit_code":0,"unpacked_source_manifest_sha256":sha(CONTROL/"unpacked-source-manifest.json"),"superseded_audit_failure_job":"1a1a5b05b2f-fc05-20b7","superseded_audit_reason":"Registry unpack uses generated .cargo-ok, not .cargo-checksum.json; v2 independently compares pinned tar members to unpacked bytes.","copied_user_credentials_or_global_config":False,"copied_global_registry_sources":False,"source_manifest":SOURCE_SHA,"verification_manifest":VERIFY_SHA,"source_and_verification_unchanged":True,"matrix_network":"none","matrix_cargo_net_offline":"true"}
dump(CONTROL/"dependency-preparation-receipt.json",receipt)
print(json.dumps({"qualified":True,"available_crates":len(crates),"available_crate_bytes":sum(x["bytes"] for x in crates),"index_records":len(indices),"unpacked_packages":len(unpacked),"remaining_nonrequested_locked_crates":len(remaining),"receipt":str(CONTROL/"dependency-preparation-receipt.json"),"receipt_sha256":sha(CONTROL/"dependency-preparation-receipt.json")},sort_keys=True))
