#!/usr/bin/python3
from qualification_common import *
import socket,stat,sys,time,tempfile
phase=sys.argv[1]
if phase not in ("dependencies","matrix"):raise RuntimeError("unknown phase")
plan=load_plan()
current=inventory();require_inputs(current)
dump(BASE/"output"/(phase+"-container-inputs-before.json"),current)
facts={"schema":"hepta.rea.container-execution-facts.v1","phase":phase,"unix_ns":time.time_ns(),"hostname":socket.gethostname(),"pid":os.getpid(),"ppid":os.getppid(),"uid":os.getuid(),"gid":os.getgid(),"image_pin":IMAGE,"source":SOURCE_SHA,"verification":VERIFY_SHA,"gates":{},"cgroup":{},"environment":{},"system_files":[]}
facts["gates"]["user_1000"]=os.getuid()==1000 and os.getgid()==1000
for name in ("cpu.max","memory.max","pids.max"):facts["cgroup"][name]=(Path("/sys/fs/cgroup")/name).read_text().strip()
facts["gates"]["cpu_4"]=facts["cgroup"]["cpu.max"]=="400000 100000"
facts["gates"]["memory_16gib"]=facts["cgroup"]["memory.max"]=="17179869184"
facts["gates"]["pids_1024"]=facts["cgroup"]["pids.max"]=="1024"
proc={}
for line in Path("/proc/self/status").read_text().splitlines():
 key,sep,value=line.partition(":")
 if sep and key in ("Uid","Gid","CapEff","NoNewPrivs","Seccomp","Seccomp_filters"):proc[key]=value.strip()
facts["proc_status"]=proc
facts["gates"]["seccomp_active"]=proc.get("Seccomp")=="2"
facts["gates"]["no_effective_caps"]=proc.get("CapEff")=="0000000000000000"
for name in ("PATH","CARGO_HOME","CARGO_TARGET_DIR","CARGO_NET_OFFLINE","CARGO_BUILD_JOBS","CARGO_PROFILE_DEV_DEBUG","CARGO_PROFILE_TEST_DEBUG","CARGO_INCREMENTAL","RUSTUP_TOOLCHAIN","RUSTUP_AUTO_INSTALL","TMPDIR","TMP","TEMP"):
 facts["environment"][name]=os.environ.get(name)
facts["gates"]["offline_mode"]=facts["environment"]["CARGO_NET_OFFLINE"]==("true" if phase=="matrix" else "false")
for path,expected,maximum in [
("/usr/bin/false","e51fc98d1215569a555c03c991835c234d6f05ded01a23ae99a33b8854270e86",1024*1024),
("/usr/bin/ssh","fc47ea24323fdd5687c5aefae6fd0060faabfa8f2944c6a68f6a442fbe0dd131",16*1024*1024),
("/usr/bin/dash","86d31f6fb799e91fa21bad341484564510ca287703a16e9e46c53338776f4f42",16*1024*1024)]:
 p=Path(path);s=p.lstat();actual=sha(p)
 info={"path":path,"mode":oct(stat.S_IMODE(s.st_mode)),"uid":s.st_uid,"gid":s.st_gid,"nlink":s.st_nlink,"bytes":s.st_size,"sha256":actual,"regular":stat.S_ISREG(s.st_mode)}
 facts["system_files"].append(info)
 facts["gates"][p.name+"_pin"]=stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and s.st_size<=maximum and actual==expected and s.st_mode&0o6022==0
facts["shell"]={"alias":"/bin/sh","link_target":os.readlink("/bin/sh"),"resolved":str(Path("/bin/sh").resolve(strict=True))}
facts["gates"]["shell_alias"]=facts["shell"]["resolved"]=="/usr/bin/dash"
mounts={}
selected={"/tmp",str(ROOT),str(RUST),str(Path(plan["env"]["CARGO_HOME"])),str(Path(plan["env"]["CARGO_TARGET_DIR"])),str(BASE/"output"),str(REFERENCE),str(NEXTEST),str(RUNNER),str(BASE/"control"),str(BASE/"plan.json")}
for line in Path("/proc/self/mountinfo").read_text().splitlines():
 fields=line.split();where=fields[4]
 if where in selected:
  split=fields.index("-")
  mounts[where]={"mount_options":fields[5],"filesystem":fields[split+1],"super_options":fields[split+3],"raw":line}
facts["mounts"]=mounts
tmp_options=set(mounts.get("/tmp",{}).get("mount_options","").split(","))
facts["gates"]["tmpfs_scope"]=mounts.get("/tmp",{}).get("filesystem")=="tmpfs"
facts["gates"]["tmpfs_exec_nosuid_nodev"]="noexec" not in tmp_options and {"nosuid","nodev"}.issubset(tmp_options)
probe={"limit_seconds":5,"scope":"only the newly created qualification-owned temporary executable"}
temporary_path=None
try:
 with tempfile.TemporaryDirectory(prefix="hepta-qualification-exec-",dir="/tmp") as temporary:
  temporary_path=Path(temporary)
  shim=temporary_path/"owned-shim"
  payload=b"#!/bin/sh\nprintf 'hepta-owned-exec-ok\\n'\n"
  with shim.open("xb") as stream:stream.write(payload)
  os.chmod(shim,0o700)
  probe.update({"path":str(shim),"uid":shim.stat().st_uid,"mode":oct(stat.S_IMODE(shim.stat().st_mode)),"source_sha256":sha(shim)})
  result=subprocess.run([str(shim)],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
  probe.update({"exit_code":result.returncode,"stdout":result.stdout.decode(),"stderr":result.stderr.decode()})
  probe["passed"]=result.returncode==0 and result.stdout==b"hepta-owned-exec-ok\n" and result.stderr==b""
except BaseException as error:
 probe.update({"passed":False,"error_type":type(error).__name__,"error":str(error)})
probe["temporary_directory_removed"]=temporary_path is not None and not temporary_path.exists()
facts["owned_executable_preflight"]=probe
facts["gates"]["owned_executable_preflight"]=probe.get("passed") is True and probe["temporary_directory_removed"]
for path in (ROOT,RUST,BASE/"control",BASE/"plan.json",RUNNER):
 facts["gates"]["readonly:"+str(path)]="ro" in mounts.get(str(path),{}).get("mount_options","").split(",")
if phase=="matrix":
 for path in (REFERENCE,NEXTEST):facts["gates"]["readonly:"+str(path)]="ro" in mounts.get(str(path),{}).get("mount_options","").split(",")
facts["qualified_preconditions"]=all(facts["gates"].values())
dump(BASE/"output"/(phase+"-container-facts.json"),facts)
print(json.dumps({"event":"container_preconditions","phase":phase,"passed":facts["qualified_preconditions"],"facts":str(BASE/"output"/(phase+"-container-facts.json"))}),flush=True)
if not facts["qualified_preconditions"]:raise RuntimeError("container execution preconditions failed")
if phase=="dependencies":
 os.execv(str(RUST/"bin/cargo"),[str(RUST/"bin/cargo"),"fetch","--locked","--target","x86_64-unknown-linux-gnu"])
fd=os.open(BASE/"plan.json",os.O_RDONLY)
os.dup2(fd,0)
if fd!=0:os.close(fd)
os.execv("/usr/bin/python3",["/usr/bin/python3","-u",str(RUNNER)])
