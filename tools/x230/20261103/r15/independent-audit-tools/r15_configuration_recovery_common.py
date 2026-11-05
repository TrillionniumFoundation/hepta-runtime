#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Read-only shared terminal gates and independent allocator checks for R15 audits."""
import datetime,hashlib,json,math,os,stat
from pathlib import Path
ROOT=Path("/home/qian/hepta-runtime-optimization-20261103-r15")
R14=Path("/home/qian/hepta-runtime-optimization-20261103-r14")
QUAL,SOURCE=R14/"qualification-01",R14/"source"
CONFIG_QUAL=ROOT/"configuration-qualification-01"
INPUTS={}
RUNTIME_SHA="51480b3cf630a95419d3afeb571eec17c90cffa5944101920d05333673de031d"
PINS={
 "local-campaigns-01/report.json":"b65a3d425edd91620f859ee8e14a4556b40651f4d94a022c088f7707e8a180e8",
 "configuration-qualification-01/report.json":"bce0c05b8f13e6858ecd14d024364450cc08fd90f8adabb55d5c1323c0944a89",
 "baseline-binding.json":"d701ad5c2d101ed389614083b386324c092182dcf19cb4f4bf0777e232d3c37a",
 "configuration/configuration-ready.json":"fb4a2e8eab0bfafb0c272c4c3e259cd1d68dffbaa479796854a73a1100fcc947",
 "independent-audit-tools/tooling-install-01.json":"34f0d32bcdf5057ec1cf8148a51dd13773f1235841074e0f2b8914bdfb8e461d",
 "independent-audit-tools/environment-selftest-01.json":"0d82f2ee23f0bd5a8c92f431d7a403b413ca097b4ab0a7c53d392d15758f85fa",
 "independent-audit-tools/local-orchestrator-ready-01.json":"f321182f6bd94b948b22948e524b5eaa0c42d08436e49ed9bf778f8a27196960",
 "independent-audit-tools/remote-orchestrator-ready-01.json":"181c6385afeb9b253435dd15cb90c7804928512ad1e361fcfed1c644efaa2d20",
 "measurement-tools/allocator_environment.py":"0556884dae82916794820089d84f23d3433c297c3c3414582c4c114dcea91938"}
CANDIDATE_ENV={"MALLOC_ARENA_MAX":"1"}
def need(value,reason):
 if not value:raise RuntimeError(reason)
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def sha_file(path):
 path=Path(path);before=path.lstat()
 need(stat.S_ISREG(before.st_mode) and path.resolve()==path,"input not direct regular file")
 with path.open("rb") as stream:
  opened=os.fstat(stream.fileno());result=hashlib.file_digest(stream,"sha256").hexdigest();after=os.fstat(stream.fileno())
 identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
 need(identity(before)==identity(opened)==identity(after)==identity(path.lstat()),"input changed while hashing: "+str(path))
 return result
def bind(path,expected=None):
 digest=sha_file(path)
 need(expected is None or digest==expected,"SHA binding differs: "+str(path))
 need(str(path) not in INPUTS or INPUTS[str(path)]==digest,"input changed between reads")
 INPUTS[str(path)]=digest;return digest
def finite(value):
 if isinstance(value,float):need(math.isfinite(value),"nonfinite input")
 elif isinstance(value,dict):
  for part in value.values():finite(part)
 elif isinstance(value,list):
  for part in value:finite(part)
def load(path,expected=None):
 digest=bind(path,expected);raw=Path(path).read_bytes()
 need(hashlib.sha256(raw).hexdigest()==digest,"JSON changed while reading")
 value=json.loads(raw);finite(value);return value
def json_digest(value):
 return hashlib.sha256((json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False)+"\n").encode()).hexdigest()
def still_alive(generation):
 try:
  row=Path("/proc",str(generation["pid"]),"stat").read_text().rsplit(") ",1)[1].split()
  return row[0] not in {"Z","X"} and int(row[19])==generation["start_ticks"]
 except (OSError,IndexError,ValueError):return False

def all_measurements_finished():
 # Read three small terminal reports before any large artifact or raw input.
 configuration=load(CONFIG_QUAL/"report.json",PINS["configuration-qualification-01/report.json"])
 local=load(ROOT/"local-campaigns-01/report.json",PINS["local-campaigns-01/report.json"])
 remote=load(ROOT/"remote-campaigns-01/report.json")
 for name,value in (("configuration",configuration),("local",local),("remote",remote)):
  need(value.get("success") is True and value.get("finished_utc") and not value.get("error"),name+" is not successfully complete")
 for value in (local,remote):
  need(value.get("state")=="completed" and value.get("automatic_retries")==0 and value.get("compilation_started") is False,"pipeline policy/terminal state differs")
  need(not still_alive(value["driver_process"]),"formal orchestrator still running")
 need(remote["local_gate"]["sha256"]==INPUTS[str(ROOT/"local-campaigns-01/report.json")] and remote["local_gate"]["success"] is True,"remote/local terminal SHA differs")
 config_sha=INPUTS[str(CONFIG_QUAL/"report.json")]
 need(local["configuration_qualification"]["sha256"]==remote["configuration_qualification"]["sha256"]==config_sha,"configuration SHA differs across gates")
 local_stages=["isolated-tests","audit-isolated-tests","cancel-r14-r15","analyze-cancel-r14-r15","cancel-r11-r15","analyze-cancel-r11-r15"]
 remote_stages=["native-r14-r15","analyze-native-r14-r15","native-r11-r15","analyze-native-r11-r15","six-host-cancel-recovery","verify-six-host-cancel-recovery"]
 for value,stages in ((local,local_stages),(remote,remote_stages)):
  need([r["name"] for r in value["stages"]]==stages and all(r.get("returncode")==0 for r in value["stages"]),"missing/failed formal stage")
 need(configuration["tests"]=={"passed":1637,"failed":0,"ignored":33,"selected":1670,"retries":0} and configuration["runtime_sha256"]==RUNTIME_SHA and configuration["allocator_environment"]==CANDIDATE_ENV,"complete arena1 qualification differs")
 for name,expected in PINS.items():bind(ROOT/name,expected)
 need(configuration["local_orchestrator_ready_sha256"]==PINS["independent-audit-tools/local-orchestrator-ready-01.json"] and remote["remote_orchestrator_ready_sha256"]==PINS["independent-audit-tools/remote-orchestrator-ready-01.json"] and configuration["configuration_ready_sha256"]==PINS["configuration/configuration-ready.json"] and configuration["tooling_install_sha256"]==PINS["independent-audit-tools/tooling-install-01.json"],"reviewed configuration identity differs")
 for name in ("configuration/configuration-ready.json","independent-audit-tools/tooling-install-01.json","independent-audit-tools/local-orchestrator-ready-01.json","independent-audit-tools/remote-orchestrator-ready-01.json"):
  manifest=load(ROOT/name);need(manifest.get("success") is True,"frozen readiness unsuccessful")
  rows=manifest["files"]
  for row in rows.values() if isinstance(rows,dict) else rows:bind(row["path"],row["sha256"])
 for value in (local,remote):
  for row in value["retained_result_files"]:bind(row["path"],row["sha256"])
 for field in ("summary","audit"):bind(configuration[field]["path"],configuration[field]["sha256"])
 gate=load(ROOT/"perf-ready-01.json",local["performance_gate_wait"]["gate"]["sha256"])
 need(local["performance_gate_wait"]["passed"] is True and local["performance_gate_wait"]["wait_attempts"]==1 and gate["release_performance"] is True and gate["archive_io_finished"] is True and gate["configuration_qualification_sha256"]==config_sha,"explicit performance release differs")
 return configuration,local,remote

def selected_configuration(value,binary_sha):
 need(value["schema"]=="hepta-x230-child-allocator-run/v1" and value["platform"]=="linux" and value["libc"]==os.confstr("CS_GNU_LIBC_VERSION"),"allocator run platform differs")
 need(value["helper_sha256"]==PINS["measurement-tools/allocator_environment.py"] and value["parent_environment_modified"] is False and value["allocator_keys_cleared"]==["MALLOC_*","GLIBC_TUNABLES"],"allocator isolation/helper differs")
 need(value["comparison_identity"]=="binary_sha256+allocator_environment" and value["same_binary_sha256"] is False and set(value["variants"])=={"candidate"},"selected configuration identity differs")
 variant=value["variants"]["candidate"]
 need(variant["environment"]==CANDIDATE_ENV and variant["binary_sha256"]==binary_sha,"candidate environment/binary differs")
 need(variant["environment_sha256"]==json_digest(CANDIDATE_ENV) and variant["configuration_fingerprint"]==json_digest({"binary_sha256":binary_sha,"allocator_environment":CANDIDATE_ENV}),"candidate environment/configuration hash differs")
 return variant

def live_observation(value,pid,birth,phase,agent):
 need(value["schema"]=="hepta-x230-child-allocator-observation/v1" and value["status"]=="verified","live process environment missing")
 need(type(pid) is int and pid>0 and value["pid"]==pid and type(value["birth_ticks"]) is int and value["birth_ticks"]>0,"live PID generation missing")
 if birth is not None:need(value["birth_ticks"]==birth,"live PID/start binding differs")
 need(value["phase"]==phase and value["requested"]==value["observed"]==CANDIDATE_ENV and value["environment_sha256"]==json_digest(CANDIDATE_ENV),"live allocator values/hash/phase differ")
 need(value["source"]=="same-PID/start-ticks /proc/PID/environ" and value["full_environment_retained"] is False,"live evidence provenance differs")
 need(value["ssh_auth_sock_present"] is agent and value["held_ssh_agent_preserved"] is agent,"held SSH agent preservation differs")

def command_environment(command):
 need(command["allocator_environment"]==CANDIDATE_ENV and command["allocator_environment_sha256"]==json_digest(CANDIDATE_ENV),"explicit Popen allocator environment differs")
 value=command["allocator_observation"]
 if value["status"]=="verified":
  live_observation(value,command["pid"],None,"after-direct-Popen",False)
  return "verified"
 need(value["schema"]=="hepta-x230-child-allocator-observation/v1" and value["status"]=="unavailable_process_exited" and value["pid"]==command["pid"] and value["phase"]=="after-direct-Popen" and command["exit_code"]==0 and command["timed_out"] is False,"unavailable environment not a successful short-child exit race")
 need(value["reason"]=="child exited before a complete live snapshot" and value["binding"]=="explicit Popen(env=...) recorded separately; no automatic retry","short-process evidence limitation omitted")
 return "unavailable_process_exited"

def source_map():
 files=[SOURCE/n for n in ("Cargo.toml","Cargo.lock","rustfmt.toml")]
 for name in ("src","examples"):files.extend(p for p in (SOURCE/name).rglob("*") if p.is_file())
 return {str(p.relative_to(SOURCE)):sha_file(p) for p in sorted(files)}

def inputs_unchanged():
 for path,expected in INPUTS.items():need(sha_file(path)==expected,"input changed during audit: "+path)

def write_json(path,value):
 with Path(path).open("x",encoding="utf-8") as stream:
  json.dump(value,stream,indent=2,sort_keys=True,allow_nan=False);stream.write("\n")
