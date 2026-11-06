#!/usr/bin/python3
from qualification_common import *
import re,signal,sys,threading,time,traceback
PHASE=sys.argv[1]
if PHASE not in ("dependencies","matrix"):raise RuntimeError("unknown phase")
CONTROL=BASE/"control";OUTPUT=BASE/"output"
PREFIX=PHASE+"-owner"
NAME="hepta-rea-ubuntu24-"+PHASE+"-20261104-r2"
DOCKER=["/usr/bin/sudo","-n","/usr/bin/docker"]
def emit(value):print(json.dumps(value,sort_keys=True),flush=True)
def command(label,argv,required=True):
 request={"argv":argv,"started_unix_ns":time.time_ns(),"stdin":"DEVNULL"}
 dump(CONTROL/(PREFIX+"-"+label+".request.json"),request)
 p=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=40)
 write(CONTROL/(PREFIX+"-"+label+".stdout.log"),p.stdout)
 write(CONTROL/(PREFIX+"-"+label+".stderr.log"),p.stderr)
 record={"exit_code":p.returncode,"finished_unix_ns":time.time_ns(),"stdout_sha256":sha(CONTROL/(PREFIX+"-"+label+".stdout.log")),"stderr_sha256":sha(CONTROL/(PREFIX+"-"+label+".stderr.log"))}
 dump(CONTROL/(PREFIX+"-"+label+".result.json"),record)
 if required and p.returncode!=0:raise RuntimeError(label+" failed: "+p.stderr.decode(errors="replace")[:1000])
 return p.returncode,p.stdout,p.stderr
plan=load_plan()
before=inventory();require_inputs(before)
dump(OUTPUT/(PHASE+"-host-inputs-before.json"),before)
if PHASE=="matrix":
 if (Path(plan["evidence"])).exists():raise RuntimeError("create-only integrated evidence already exists")
 cache_gate=json.loads((CONTROL/"dependency-preparation-receipt.json").read_bytes())
 if cache_gate.get("qualified") is not True:raise RuntimeError("dependency preparation is not qualified")
_,raw,_=command("image-inspect",DOCKER+["image","inspect",IMAGE])
image=json.loads(raw)[0]
if image["Id"]!=IMAGE or image["Config"].get("User")!="1000:1000":raise RuntimeError("fixed image identity/user mismatch")
mounts=[(ROOT,True),(RUST,True),(BASE/"cargo-home",False),(BASE/"target",False),(OUTPUT,False),(CONTROL,True),(BASE/"plan.json",True),(RUNNER,True)]
if PHASE=="matrix":mounts.extend([(NEXTEST,True),(REFERENCE,True)])
environment=dict(plan["env"])
environment["CARGO_NET_OFFLINE"]="true" if PHASE=="matrix" else "false"
environment["TMPDIR"]="/tmp"
argv=DOCKER+["create","--name",NAME,"--label","org.hepta.qualification.task=rea-ubuntu24-matrix-20261104-r2","--label","org.hepta.qualification.phase="+PHASE,"--stop-timeout","20","--cpus","4","--memory","17179869184","--pids-limit","1024","--user","1000:1000","--read-only","--network","none" if PHASE=="matrix" else "bridge","--tmpfs","/tmp:rw,nosuid,nodev,size=4294967296,mode=1777","--workdir",str(ROOT)]
for key,value in sorted(environment.items()):argv.extend(["--env",key+"="+value])
for path,readonly in mounts:argv.extend(["--mount","type=bind,src="+str(path)+",dst="+str(path)+(",readonly" if readonly else "")])
limit="6800s" if PHASE=="matrix" else "600s"
argv.extend([IMAGE,"/usr/bin/timeout","--signal=TERM","--kill-after=20s",limit,"/usr/bin/python3","-B","-u",str(CONTROL/"container_entry.py"),PHASE])
cid=None;owned=False;start_process=None;error=None;final_state=None;removed=False;start_exit=None;timed_out=False;qualified=False
summary={"schema":"hepta.rea.container-owner.v1","phase":PHASE,"name":NAME,"image_id":IMAGE,"started_unix_ns":time.time_ns(),"controller_pid":os.getpid(),"source":SOURCE_SHA,"verification":VERIFY_SHA,"retry_count":0,"inner_timeout_seconds":6800 if PHASE=="matrix" else 600,"inner_kill_after_seconds":20,"outer_controller_wait_seconds":6900 if PHASE=="matrix" else 700}
try:
 _,raw,_=command("create",argv)
 cid=raw.decode().strip()
 if not re.fullmatch("[0-9a-f]{64}",cid):raise RuntimeError("invalid new container ID")
 write(CONTROL/(PREFIX+"-container-id.txt"),(cid+"\n").encode())
 _,raw,_=command("created-inspect",DOCKER+["container","inspect",cid])
 created=json.loads(raw)[0]
 labels=created["Config"].get("Labels",{})
 if created["Id"]!=cid or created["Name"]!="/"+NAME or labels.get("org.hepta.qualification.task")!="rea-ubuntu24-matrix-20261104-r2" or labels.get("org.hepta.qualification.phase")!=PHASE:raise RuntimeError("new container ownership not established")
 owned=True
 host=created["HostConfig"]
 if host["Privileged"] or host.get("CapAdd") or host.get("SecurityOpt") or not host["ReadonlyRootfs"] or host["Memory"]!=17179869184 or host["NanoCpus"]!=4000000000 or host["PidsLimit"]!=1024:raise RuntimeError("container isolation/resources differ")
 observed={x["Destination"]:not x["RW"] for x in created["Mounts"] if x["Type"]=="bind"}
 if observed!={str(p):ro for p,ro in mounts}:raise RuntimeError("container bind set differs")
 start_argv=DOCKER+["start","--attach",cid]
 dump(CONTROL/(PREFIX+"-start.request.json"),{"argv":start_argv,"started_unix_ns":time.time_ns(),"stdin":"DEVNULL"})
 out_path=CONTROL/(PREFIX+"-start.stdout.log");err_path=CONTROL/(PREFIX+"-start.stderr.log")
 emit({"event":"container_started","phase":PHASE,"container_id":cid,"name":NAME,"inner_timeout_seconds":summary["inner_timeout_seconds"],"stdout":str(out_path),"stderr":str(err_path)})
 with out_path.open("xb") as out,err_path.open("xb") as err:
  start_process=subprocess.Popen(start_argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  io_errors=[]
  def pump(source,destination,original):
   try:
    while True:
     block=source.read1(65536)
     if not block:break
     destination.write(block);destination.flush();original.buffer.write(block);original.flush()
   except BaseException as e:io_errors.append(str(e))
  threads=[threading.Thread(target=pump,args=(start_process.stdout,out,sys.stdout)),threading.Thread(target=pump,args=(start_process.stderr,err,sys.stderr))]
  for t in threads:t.start()
  try:start_exit=start_process.wait(timeout=summary["outer_controller_wait_seconds"])
  except subprocess.TimeoutExpired:
   timed_out=True
   command("deadline-stop",DOCKER+["stop","--time","20",cid],False)
   try:start_exit=start_process.wait(timeout=30)
   except subprocess.TimeoutExpired:
    command("deadline-kill",DOCKER+["kill","--signal","KILL",cid],False)
    start_exit=start_process.wait(timeout=20)
  finally:
   for t in threads:t.join(timeout=10)
   if any(t.is_alive() for t in threads):raise RuntimeError("Docker attach output threads did not join")
   out.flush();err.flush();os.fsync(out.fileno());os.fsync(err.fileno())
  if io_errors:raise RuntimeError("Docker attach stream error: "+str(io_errors))
 dump(CONTROL/(PREFIX+"-start.result.json"),{"exit_code":start_exit,"timed_out":timed_out,"stdout_sha256":sha(out_path),"stderr_sha256":sha(err_path),"finished_unix_ns":time.time_ns()})
 _,raw,_=command("terminal-inspect",DOCKER+["container","inspect",cid])
 terminal=json.loads(raw)[0];final_state=terminal["State"]
 command("docker-logs",DOCKER+["logs","--timestamps",cid],False)
 if final_state.get("Running") or final_state.get("Status")!="exited" or start_exit!=0 or final_state.get("ExitCode")!=0 or timed_out:raise RuntimeError("original container did not exit successfully")
 if PHASE=="matrix":
  report=json.loads((Path(plan["evidence"])/"qualification.json").read_bytes())
  if report.get("qualified") is not True or len(report.get("commands",[]))!=35 or report.get("runner_sha256")!=RUNNER_SHA:raise RuntimeError("complete original 35-command qualification did not pass")
  if any(x["exit_code"]!=x["expected_exit_code"] for x in report["commands"]):raise RuntimeError("original command result mismatch")
  for name,expected,count in (("source",SOURCE_SHA,295),("verification",VERIFY_SHA,613)):
   item=report["inputs"][name]
   if item["count"]!=count or item["sha256"]!=expected or item["after_sha256"]!=expected or item["unchanged"] is not True:raise RuntimeError("qualified input pin mismatch")
  binary=report.get("binary",{})
  frozen=Path(plan["evidence"])/"hepta-runtime-qualified"
  if binary.get("frozen_path")!=str(frozen) or sha(frozen)!=binary.get("sha256"):raise RuntimeError("release freeze differs from original report")
  summary["release_binary"]=binary
  summary["original_qualification_sha256"]=sha(Path(plan["evidence"])/"qualification.json")
 qualified=True
except BaseException as e:
 error=str(e);qualified=False
 emit({"event":"container_owner_failure","phase":PHASE,"error":error})
finally:
 if owned and cid:
  try:
   _,raw,_=command("cleanup-inspect",DOCKER+["container","inspect",cid])
   state=json.loads(raw)[0]["State"]
   if state.get("Running"):
    command("cleanup-stop",DOCKER+["stop","--time","20",cid],False)
    _,raw,_=command("cleanup-stopped-inspect",DOCKER+["container","inspect",cid])
    state=json.loads(raw)[0]["State"]
    if state.get("Running"):
     command("cleanup-kill",DOCKER+["kill","--signal","KILL",cid],False)
     _,raw,_=command("cleanup-killed-inspect",DOCKER+["container","inspect",cid])
     state=json.loads(raw)[0]["State"]
   if state.get("Running"):raise RuntimeError("owned container remains running")
   if final_state is None:final_state=state
   command("cleanup-remove",DOCKER+["rm",cid])
   code,_,err=command("cleanup-removed-inspect",DOCKER+["container","inspect",cid],False)
   removed=code!=0 and (b"No such container" in err or b"No such object" in err)
   if not removed:raise RuntimeError("owned container removal not confirmed")
  except BaseException as e:
   qualified=False;summary["cleanup_error"]=str(e)
 if start_process is not None and start_process.poll() is None:
  start_process.terminate()
  try:start_process.wait(timeout=10)
  except subprocess.TimeoutExpired:start_process.kill();start_process.wait(timeout=10)
 try:
  after=inventory();require_inputs(after);dump(OUTPUT/(PHASE+"-host-inputs-after.json"),after)
  summary["source_and_verification_unchanged"]=before==after
  if before!=after:qualified=False;summary["input_error"]="frozen inputs changed"
 except BaseException as e:
  qualified=False;summary["input_error"]=str(e)
 if not removed:qualified=False
 summary.update({"qualified":qualified,"error":error,"container_id":cid,"container_exit_state":final_state,"container_removed":removed,"docker_attach_exit_code":start_exit,"timed_out":timed_out,"finished_unix_ns":time.time_ns()})
 dump(OUTPUT/(PHASE+"-owner-receipt.json"),summary)
 emit({"event":"container_owner_finished",**summary})
sys.exit(0 if qualified else 1)
