#!/usr/bin/python3
from pathlib import Path
from io import BytesIO
import hashlib,json,os,re,stat,tarfile
BASE=Path("/home/qian-qi/work/hepta-rea-ubuntu24-matrix-20261104-r3")
R2=Path("/home/qian-qi/work/hepta-rea-ubuntu24-matrix-20261104-r2")
OUT=Path("/home/qian-qi/work/hepta-rea-ubuntu24-evidence-transfer-20261104-r1")
RUNNER=Path("/home/qian-qi/work/hepta-rea-verification-tools-20261104-r1/run_frozen_commands.py")
JOB_BASE=Path("/home/qian-qi/.local/state/hepta-runtime-mac-worker/jobs")
SOURCE="9d08a4cc6b6c89f4db47eb300af5e54dd44092082434c93b1dee954c30b2209a"
VERIFY="b783c4f05a5c7f614ee7150ecc66bb4fe25f1cfd8ed548723e405e4612b6baa4"
QUAL_SHA="b28e9e47e11e18e99e192ee05abb1034386632a7495002c6bbb18d5097906ab9"
OWNER_SHA="f799283e32f9595569daa2a9c0341f418f9930280f2046128c29dd1652eec7ad"
R2_ARCHIVE_SHA="591d48aaab4f6f6faad675a1d29035baa3e183afc375324df876ab7ed2017841"
JOBS=json.loads("[[\"environment-prepare\",\"1a1a5975a4a-fc05-1fc8\"],[\"dependency-cache-copy\",\"1a1a5a9cd24-fc05-207e\"],[\"dependency-fetch\",\"1a1a5ae8a6c-fc05-20a3\"],[\"dependency-audit-v1-failed\",\"1a1a5b05b2f-fc05-20b7\"],[\"dependency-audit-v2\",\"1a1a5b37ecc-fc05-20d1\"],[\"matrix-r2-failed\",\"1a1a5b446b4-fc05-20d8\"],[\"matrix-r3\",\"1a1a5c82e93-fc05-216c\"],[\"r2-pack-create\",\"1a1a5d1c87e-fc05-21a8\"],[\"r2-pack-execute\",\"1a1a5d52366-fc05-21c7\"]]")
TOOL_STATUS="{\n  \"at_unix_ms\": 1793783379452,\n  \"audit_recorded\": true,\n  \"automatic_retry\": false,\n  \"cancelled\": false,\n  \"exit_code\": 0,\n  \"job_id\": \"1a1a5c82e93-fc05-216c\",\n  \"launch_nonce\": \"295abc3a9d356fe45895a2107fee75d0\",\n  \"log_bytes\": {\n    \"stderr\": {\n      \"seen\": 0,\n      \"stored\": 0\n    },\n    \"stdout\": {\n      \"seen\": 30147,\n      \"stored\": 30147\n    }\n  },\n  \"log_errors\": {\n    \"stderr\": null,\n    \"stdout\": null\n  },\n  \"log_synced\": {\n    \"stderr\": true,\n    \"stdout\": true\n  },\n  \"log_truncated\": {\n    \"stderr\": false,\n    \"stdout\": false\n  },\n  \"output_complete\": true,\n  \"output_durable\": true,\n  \"state\": \"succeeded\",\n  \"terminal_publication_confirmed\": true,\n  \"terminal_publication_protocol\": 1,\n  \"timed_out\": false\n}"
TOOL_START="{\n  \"audit_recorded\": true,\n  \"job\": {\n    \"args\": [\n      \"-B\",\n      \"-u\",\n      \"/home/qian-qi/work/hepta-rea-ubuntu24-matrix-20261104-r3/control/container_owner.py\",\n      \"matrix\"\n    ],\n    \"created_unix_ms\": 1793782722195,\n    \"cwd\": \"/home/qian-qi/work/hepta-rea-ubuntu24-matrix-20261104-r3\",\n    \"env_keys\": [],\n    \"executable\": \"/usr/bin/python3\",\n    \"execution_mode\": \"operator\",\n    \"host\": \"rog\",\n    \"id\": \"1a1a5c82e93-fc05-216c\",\n    \"idempotency_key\": \"rea-ubuntu24-matrix-r3-full-explicit-exec-20261104-r1\",\n    \"launch_error\": null,\n    \"launch_state\": \"launched\",\n    \"remote_job_dir\": \"/home/qian-qi/.local/state/hepta-runtime-mac-worker/jobs/1a1a5c82e93-fc05-216c\",\n    \"request_digest\": \"52f1e9f281157cba6ddb0ff182d2e7554a4e08ee08c9afad8d3dfb2e2912ffee\",\n    \"request_fingerprint\": 5976815408254385338,\n    \"ssh_target\": \"rog-ts\",\n    \"system_jobctl\": false,\n    \"unit\": \"hepta-runtime-job-1a1a5c82e93-fc05-216c\"\n  },\n  \"launch\": {\n    \"backend\": \"systemd\",\n    \"launcher_pid\": null,\n    \"ok\": true,\n    \"unit\": \"hepta-runtime-job-1a1a5c82e93-fc05-216c\"\n  },\n  \"local_record_pending\": false,\n  \"reused\": false\n}"
def sha(data):return hashlib.sha256(data).hexdigest()
def file_sha(path):
 with Path(path).open("rb") as f:return hashlib.file_digest(f,"sha256").hexdigest()
def stable(path):
 before=path.lstat()
 if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1:raise RuntimeError("nonregular or linked evidence: "+str(path))
 data=path.read_bytes();after=path.lstat()
 key=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_nlink)
 if key(before)!=key(after):raise RuntimeError("evidence changed while reading: "+str(path))
 return data,stat.S_IMODE(before.st_mode)
def write(path,data):
 with path.open("xb") as f:f.write(data);f.flush();os.fsync(f.fileno())
def dump(path,value):write(path,(json.dumps(value,indent=2,sort_keys=True)+"\n").encode())
qpath=BASE/"output/integrated-build-r3/qualification.json"
opath=BASE/"output/matrix-owner-receipt.json"
if file_sha(qpath)!=QUAL_SHA or file_sha(opath)!=OWNER_SHA:raise RuntimeError("original final receipt changed")
q=json.loads(qpath.read_bytes());owner=json.loads(opath.read_bytes())
if not q["qualified"] or len(q["commands"])!=35 or not q["source_and_verification_unchanged"]:raise RuntimeError("full matrix not qualified")
if not owner["qualified"] or not owner["container_removed"] or owner["container_exit_state"]["ExitCode"]!=0 or owner["timed_out"]:raise RuntimeError("owner not successfully terminal and cleaned")
for group,expected,count in [("source",SOURCE,295),("verification",VERIFY,613)]:
 info=q["inputs"][group]
 if info["sha256"]!=expected or info["after_sha256"]!=expected or not info["unchanged"] or info["count"]!=count:raise RuntimeError("frozen group mismatch")
if q["runner_sha256"]!=file_sha(RUNNER):raise RuntimeError("runner changed")
plan=json.loads((BASE/"plan.json").read_bytes());oldplan=json.loads((R2/"plan.json").read_bytes())
if plan["commands"]!=oldplan["commands"] or plan["env"]!=oldplan["env"]:raise RuntimeError("r3 changed commands or budgets")
for command in q["commands"]:
 if command["exit_code"]!=command["expected_exit_code"] or file_sha(Path(command["log"]))!=command["log_sha256"]:raise RuntimeError("command evidence mismatch")
binary=Path(q["binary"]["frozen_path"])
if binary.stat().st_size!=q["binary"]["bytes"] or file_sha(binary)!=q["binary"]["sha256"]:raise RuntimeError("frozen release changed")
r2archive=OUT/"ubuntu24-environment-dependencies-r2-failure.tar.xz"
if file_sha(r2archive)!=R2_ARCHIVE_SHA:raise RuntimeError("r2 archive changed")
with tarfile.open(r2archive,"r:xz") as tar:
 members=tar.getmembers()
 if any(not x.isfile() for x in members):raise RuntimeError("r2 package contains nonregular member")
 member_names=[x.name for x in members]
 if len(member_names)!=len(set(member_names)):raise RuntimeError("duplicate r2 archive entry")
 raw_manifest=tar.extractfile("transfer-manifest.json").read()
 original_manifest=json.loads(raw_manifest)
 expected={x["path"]:x for x in original_manifest["files"]}
 if set(member_names)!=set(expected)|{"transfer-manifest.json"}:raise RuntimeError("r2 package manifest membership differs")
 for name,entry in expected.items():
  data=tar.extractfile(name).read()
  if len(data)!=entry["bytes"] or sha(data)!=entry["sha256"]:raise RuntimeError("r2 package payload differs")
SEAL=BASE/"sealed";SEAL.mkdir(mode=0o700)
write(SEAL/"original-process-start-response.json",TOOL_START.encode())
write(SEAL/"original-process-terminal-response.json",TOOL_STATUS.encode())
python_rows=[];rust_rows=[]
for command in q["commands"]:
 text=Path(command["log"]).read_text()
 if command["name"].startswith("python-"):
  matches=list(re.finditer(r"Ran (\d+) tests? in ([\d.]+)s",text))
  if len(matches)!=1 or not re.search(r"\nOK\s*$",text):raise RuntimeError("non-unique or non-OK Python summary")
  python_rows.append({"name":command["name"],"tests":int(matches[0][1]),"summary_seconds":float(matches[0][2]),"command_seconds":command["elapsed_seconds"],"log_sha256":command["log_sha256"],"exit_code":command["exit_code"]})
 if command["name"] in ("test-all","test-no-default"):
  plain=re.sub(r"\x1b\[[0-9;]*m","",text)
  matches=re.findall(r"Summary[^\n]+",plain)
  if len(matches)!=1:raise RuntimeError("missing nextest summary")
  rust_rows.append({"name":command["name"],"original_summary":matches[0],"command_seconds":command["elapsed_seconds"],"log_sha256":command["log_sha256"]})
if len(python_rows)!=21 or sum(x["tests"] for x in python_rows)!=441:raise RuntimeError("Python totals differ")
summary={"schema":"hepta.rea.ubuntu24-matrix-r3-seal.v1","qualified":True,"original_job_id":"1a1a5c82e93-fc05-216c","source_sha256":SOURCE,"verification_sha256":VERIFY,"original_qualification_sha256":QUAL_SHA,"original_owner_receipt_sha256":OWNER_SHA,"commands_complete":35,"python_suites":len(python_rows),"python_tests":sum(x["tests"] for x in python_rows),"python":python_rows,"rust":rust_rows,"ledger":[{"name":x["name"],"exit_code":x["exit_code"],"expected_exit_code":x["expected_exit_code"],"log_sha256":x["log_sha256"]} for x in q["commands"] if x["name"].startswith("ledger-")],"release":q["binary"],"release_command_seconds":q["commands"][-1]["elapsed_seconds"],"warm_target_and_cargo_cache_reused_from_r2":True,"r2_remains_failed":True,"full_rea_parity":False,"r2_transfer_archive_sha256":R2_ARCHIVE_SHA,"r2_transfer_manifest_sha256":sha(raw_manifest),"r2_transfer_payload_verified":len(expected),"tmpfs_scope":"Only this task container /tmp; exec,nosuid,nodev; not a desktop ext4 durability qualification."}
dump(SEAL/"summary.json",summary)
readme="""# Ubuntu 24 full 35-command qualification, r3

This is the completed fixed-image Ubuntu 24 qualification on ROG, original durable job 1a1a5c82e93-fc05-216c. The final original qualification is true and all 35 commands met their recorded expected exits. Original logs, input inventories, command plan, wrapper code, image/mount/cgroup/system-bin facts, Docker lifecycle records, and owned-job records are retained without rewriting their bytes.

Both Rust nextest commands used test-threads=1, retries=0, no-fail-fast and retained the existing ignored cases: all-features 1886 passed / 39 skipped; no-default 1861 passed / 27 skipped. Twenty-one Python suites independently report 441 tests, all OK. Ledger full and offline checks exit 0; require-parity exits the required 3 because full REA parity remains OPEN. A successful build is not a claim of 229-tool parity.

This run reused the r2 Cargo target and whitelisted Cargo home as a warm cache. It changed no source, test, CI, frozen runner, command argv, expected exit or test budget. The source 295-file and verification 613-file inventories match before and after. Only the task's tmpfs mount was corrected to exec while retaining nosuid and nodev; the entry performed an actual owned mode0700 shim execution before the matrix. This is not a general bare-ROG support claim and not a desktop ext4 durability qualification.

The original r2 matrix remains a failed run: 1882 passed and four failures, caused by this wrapper's omitted exec mount option. The four fixtures correctly could not execute their own temporary shims from noexec /tmp. Its original exit100 was never accepted as success. Its environment, dependency prep, original failed logs and exact root-cause records are in the separate immutable r2 archive. This r3 archive additionally contains exact original owned-job records for that chain, including the first dependency auditor's failed assumption about Cargo 1.95 unpack metadata and its subsequent byte-for-byte archive-member audit.

The ROG release is pinned separately and omitted from the evidence archive. It is not the desktop release used for actual Ghidra, Chrome and JavaScript external qualifications. ROG frozen release is 17842176 bytes, SHA256 2d021297b50af9eb35bd4d698a90991ec410b2922b707155a506e42125b87442. Desktop external qualification runtime is SHA256 4da25b9b865ef262878098d3d97b5e0c70f44bc83192d4abb4c8d1888fb0dd5d.

The intermediate progress.json intentionally lacks final inventory/freeze success; authoritative completion is the original qualification.json plus matrix-owner-receipt.json and the original durable process terminal record. The container exited zero, was not OOM-killed or timed out, and was removed by its owner. No other containers, images, user global credentials or registry payloads are included or traversed.
"""
write(SEAL/"README.md",readme.encode())
selected=[];excluded=[]
for prefix,root in [("r3/control",BASE/"control"),("r3/output",BASE/"output"),("r3/sealed",SEAL)]:
 for path in sorted(root.rglob("*")):
  if path.is_symlink():raise RuntimeError("symlink in selected evidence: "+str(path))
  if not path.is_file():continue
  if path==binary:
   excluded.append({"path":str(path),"bytes":q["binary"]["bytes"],"sha256":q["binary"]["sha256"],"reason":"frozen runtime, pin retained only"})
   continue
  selected.append((prefix+"/"+str(path.relative_to(root)),path))
for rel in ["plan.json","environment-correction.json"]:selected.append(("r3/"+rel,BASE/rel))
selected.extend([("runner/run_frozen_commands.py",RUNNER),("packaging/pack_environment_dependencies_r2.py",OUT/"pack_environment_dependencies_r2.py"),("packaging/environment-dependencies-r2-pack-receipt.json",OUT/"environment-dependencies-r2-pack-receipt.json"),("packaging/pack_matrix_r3.py",Path(__file__))])
job_counts={}
for label,jobid in JOBS:
 jobdir=JOB_BASE/jobid
 if jobdir.is_symlink() or not jobdir.is_dir():raise RuntimeError("missing original owned job directory")
 rows=[]
 for path in sorted(jobdir.iterdir()):
  if path.is_symlink() or not path.is_file():raise RuntimeError("unexpected original job member: "+str(path))
  rows.append(path.name);selected.append(("original-jobs/"+label+"/"+path.name,path))
 job_counts[label]={"job_id":jobid,"files":rows}
dump(SEAL/"original-job-member-index.json",job_counts)
selected.append(("r3/sealed/original-job-member-index.json",SEAL/"original-job-member-index.json"))
captured=[];entries=[]
for name,path in sorted(selected):
 data,mode=stable(path)
 if len(data)>32*1024*1024:raise RuntimeError("unexpected large evidence payload")
 captured.append((name,data,mode))
 entries.append({"path":name,"source_path":str(path),"bytes":len(data),"sha256":sha(data),"mode":oct(mode)})
if len({x["path"] for x in entries})!=len(entries):raise RuntimeError("duplicate archive membership")
manifest={"schema":"hepta.rea.ubuntu24-matrix-r3-transfer.v1","original_job_id":"1a1a5c82e93-fc05-216c","qualified":True,"source_sha256":SOURCE,"verification_sha256":VERIFY,"files":entries,"payload_files":len(entries),"payload_bytes":sum(x["bytes"] for x in entries),"excluded":excluded+["Cargo target/cache/src payloads","installed engines","unrelated jobs/containers/images","user credentials and global config"],"separate_r2_archive":{"path":str(r2archive),"bytes":r2archive.stat().st_size,"sha256":R2_ARCHIVE_SHA,"manifest_sha256":sha(raw_manifest),"payload_verified":len(expected)}}
manifest_bytes=(json.dumps(manifest,indent=2,sort_keys=True)+"\n").encode()
manifest_path=OUT/"ubuntu24-matrix-r3-success.manifest.json";write(manifest_path,manifest_bytes)
archive=OUT/"ubuntu24-matrix-r3-success.tar.xz"
with archive.open("xb") as stream:
 with tarfile.open(fileobj=stream,mode="w:xz",preset=6,format=tarfile.PAX_FORMAT) as tar:
  for name,data,mode in captured+[("transfer-manifest.json",manifest_bytes,0o644)]:
   info=tarfile.TarInfo(name);info.type=tarfile.REGTYPE;info.size=len(data);info.mode=mode;info.mtime=0;info.uid=0;info.gid=0;info.uname="";info.gname=""
   tar.addfile(info,BytesIO(data))
 stream.flush();os.fsync(stream.fileno())
with tarfile.open(archive,"r:xz") as tar:
 actual=tar.getmembers()
 if len(actual)!=len(entries)+1 or any(not x.isfile() for x in actual):raise RuntimeError("new archive membership differs")
 for name,data,_ in captured+[("transfer-manifest.json",manifest_bytes,0o644)]:
  archived=tar.extractfile(name).read()
  if archived!=data:raise RuntimeError("new archive bytes differ")
receipt={"archive":str(archive),"archive_bytes":archive.stat().st_size,"archive_sha256":file_sha(archive),"manifest":str(manifest_path),"manifest_sha256":sha(manifest_bytes),"payload_files":len(entries),"payload_bytes":sum(x["bytes"] for x in entries),"tar_member_count":len(entries)+1,"archive_verified_after_write":True,"r2_archive_independently_verified":True,"original_qualification_sha256":QUAL_SHA,"qualified":True,"python_suites":21,"python_tests":441,"original_job_records":{label:len(x["files"]) for label,x in job_counts.items()},"frozen_binary":q["binary"],"script_path":str(Path(__file__)),"script_sha256":file_sha(Path(__file__))}
dump(OUT/"matrix-r3-pack-receipt.json",receipt)
print(json.dumps(receipt,sort_keys=True))
