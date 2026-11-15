#!/usr/bin/python3
import hashlib,importlib.metadata,json,os,stat,subprocess,sys
from pathlib import Path
def digest(path):
 with open(path,"rb") as f:return hashlib.file_digest(f,"sha256").hexdigest()
def identity(path):
 p=Path(path);s=p.lstat()
 value={"path":str(p),"mode":oct(stat.S_IMODE(s.st_mode)),"uid":s.st_uid,"gid":s.st_gid,"nlink":s.st_nlink,"size":s.st_size,"kind":"symlink" if stat.S_ISLNK(s.st_mode) else "regular" if stat.S_ISREG(s.st_mode) else "directory" if stat.S_ISDIR(s.st_mode) else "other"}
 if p.is_symlink():value["link_target"]=os.readlink(p)
 resolved=p.resolve(strict=True);value["resolved"]=str(resolved)
 if resolved.is_file():
  rs=resolved.stat();value["resolved_file"]={"uid":rs.st_uid,"gid":rs.st_gid,"nlink":rs.st_nlink,"size":rs.st_size,"mode":oct(stat.S_IMODE(rs.st_mode)),"sha256":digest(resolved)}
 return value
def command(argv):
 try:
  p=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=20)
  return {"argv":argv,"exit_code":p.returncode,"stdout":p.stdout,"stderr":p.stderr}
 except subprocess.TimeoutExpired:return {"argv":argv,"timed_out":True}
report={"schema":"hepta.rea.ubuntu24-environment-preflight.v1","scope":"isolated Ubuntu24 environment only; no source/tests/target mounted; no test matrix","uid":os.getuid(),"gid":os.getgid(),"gates":{}}
report["gates"]["uid_1000"]=os.getuid()==1000 and os.getgid()==1000
report["system_paths"]=[identity(p) for p in ("/usr/bin/false","/usr/bin/ssh","/bin","/bin/sh","/usr/bin/dash")]
false=report["system_paths"][0];fr=false["resolved_file"]
report["gates"]["false_contract"]=false["kind"]=="regular" and fr["uid"]==0 and fr["nlink"]==1 and fr["size"]<=1024*1024 and (int(fr["mode"],8)&0o6022)==0 and (int(fr["mode"],8)&0o111)!=0
try:
 cap=os.getxattr("/usr/bin/false","security.capability",follow_symlinks=False)
 report["false_capability_bytes"]=len(cap);report["gates"]["false_no_file_capabilities"]=False
except OSError as e:
 report["false_capability_errno"]=e.errno;report["gates"]["false_no_file_capabilities"]=e.errno in (61,95)
report["python"]=sys.version
report["jsonschema_version"]=importlib.metadata.version("jsonschema")
report["commands"]={}
commands={
"python":["/usr/bin/python3","--version"],
"rg":["/usr/bin/rg","--version"],
"ssh":["/usr/bin/ssh","-V"],
"rustc":["/opt/rust/bin/rustc","--version"],
"cargo":["/opt/rust/bin/cargo","--version"],
"rustfmt":["/opt/rust/bin/rustfmt","--version"],
"clippy":["/opt/rust/bin/cargo","clippy","--version"],
"nextest":["/opt/rust/bin/cargo","nextest","--version"],
"distribution_packages":["/usr/bin/dpkg-query","-W","-f=\u0024{binary:Package}\t\u0024{Version}\n","python3","python3-jsonschema","ripgrep","git","build-essential","pkg-config","openssh-client","ca-certificates","procps","util-linux"]}
for name,argv in commands.items():
 result=command(argv);report["commands"][name]=result;report["gates"][name+"_executable"]=result.get("exit_code")==0
report["gates"]["rustc_1_95_0"]=report["commands"]["rustc"].get("stdout","").startswith("rustc 1.95.0 ")
report["gates"]["cargo_1_95_0"]=report["commands"]["cargo"].get("stdout","").startswith("cargo 1.95.0 ")
report["gates"]["nextest_0_9_137"]="0.9.137" in report["commands"]["nextest"].get("stdout","")
status={}
for line in Path("/proc/self/status").read_text().splitlines():
 key,sep,value=line.partition(":")
 if sep and key in ("Uid","Gid","CapEff","NoNewPrivs","Seccomp","Seccomp_filters"):status[key]=value.strip()
report["proc_status"]=status
report["gates"]["default_seccomp_active"]=status.get("Seccomp")=="2"
report["cgroup"]={}
for name in ("cpu.max","memory.max","pids.max"):
 path=Path("/sys/fs/cgroup")/name
 try:report["cgroup"][name]=path.read_text().strip()
 except OSError as e:report["cgroup"][name]={"errno":e.errno}
cpu=report["cgroup"].get("cpu.max","").split()
report["gates"]["cpu_4"]=len(cpu)==2 and cpu[0]!="max" and int(cpu[0])==4*int(cpu[1])
report["gates"]["memory_16gib"]=report["cgroup"].get("memory.max")==str(16*1024**3)
report["gates"]["pids_1024"]=report["cgroup"].get("pids.max")=="1024"
report["qualified"]=all(report["gates"].values())
print(json.dumps(report,sort_keys=True))
sys.exit(0 if report["qualified"] else 2)
