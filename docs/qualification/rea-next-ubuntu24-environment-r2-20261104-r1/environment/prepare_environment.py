#!/usr/bin/python3
from pathlib import Path
import hashlib,json,os,stat,subprocess,sys,time
BASE=Path("/home/qian-qi/work/hepta-rea-ubuntu24-qualification-env-20261104-r1")
TAG="hepta-rea-qualification:ubuntu24-20261104-r1"
RUST=Path("/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu")
NEXTEST=Path("/home/qian-qi/work/hepta-rea-verification-tools-20261104-r1/bin/cargo-nextest")
DOCKER=["/usr/bin/sudo","-n","/usr/bin/docker"]
def sha(path):
 with path.open("rb") as f:return hashlib.file_digest(f,"sha256").hexdigest()
def write(path,data):
 with path.open("xb") as f:f.write(data);f.flush();os.fsync(f.fileno())
def dump(path,value):write(path,(json.dumps(value,sort_keys=True,indent=2)+"\n").encode())
def emit(value):print(json.dumps(value,sort_keys=True),flush=True)
def command(label,argv,required=True):
 request={"argv":argv,"cwd":str(BASE),"started_unix_ns":time.time_ns(),"stdin":"DEVNULL"}
 dump(BASE/(label+".request.json"),request)
 out=BASE/(label+".stdout.log");err=BASE/(label+".stderr.log")
 emit({"phase":label,"event":"started","stdout":str(out),"stderr":str(err)})
 with out.open("xb") as stdout,err.open("xb") as stderr:
  result=subprocess.run(argv,cwd=BASE,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr)
  stdout.flush();stderr.flush();os.fsync(stdout.fileno());os.fsync(stderr.fileno())
 record={"exit_code":result.returncode,"finished_unix_ns":time.time_ns(),"stdout_sha256":sha(out),"stderr_sha256":sha(err),"stdout_bytes":out.stat().st_size,"stderr_bytes":err.stat().st_size}
 dump(BASE/(label+".result.json"),record);emit({"phase":label,"event":"finished",**record})
 if required and result.returncode!=0:raise RuntimeError(label+" failed; retained original logs")
 return result.returncode,out.read_bytes(),err.read_bytes()
if not BASE.is_dir():raise RuntimeError("task directory absent")
identities={}
for name,path in [("rustc",RUST/"bin/rustc"),("cargo",RUST/"bin/cargo"),("rustfmt",RUST/"bin/rustfmt"),("cargo-clippy",RUST/"bin/cargo-clippy"),("clippy-driver",RUST/"bin/clippy-driver"),("nextest",NEXTEST)]:
 resolved=path.resolve(strict=True);s=resolved.stat()
 if not stat.S_ISREG(s.st_mode):raise RuntimeError("tool is not regular: "+str(path))
 identities[name]={"path":str(path),"resolved":str(resolved),"bytes":s.st_size,"sha256":sha(resolved)}
dump(BASE/"mounted-tool-pins-before.json",identities)
code,out,err=command("00-task-tag-inspect",DOCKER+["image","inspect",TAG],False)
if code==0:raise RuntimeError("create-only task tag already exists")
if b"No such image" not in err:raise RuntimeError("task image absence not established")
command("01-pull-base",DOCKER+["pull","--platform","linux/amd64","ubuntu:24.04"])
_,raw,_=command("02-base-image-inspect",DOCKER+["image","inspect","ubuntu:24.04"])
write(BASE/"base-image-inspect.json",raw)
info=json.loads(raw)[0]
digests=[x for x in info.get("RepoDigests",[]) if x.startswith("ubuntu@sha256:") or x.startswith("docker.io/library/ubuntu@sha256:")]
if len(digests)!=1:raise RuntimeError("exact Ubuntu RepoDigest unavailable or ambiguous")
digest=digests[0]
if info.get("Architecture")!="amd64" or info.get("Os")!="linux":raise RuntimeError("unexpected base image platform")
dockerfile=("FROM "+digest+"\n"
"ARG DEBIAN_FRONTEND=noninteractive\n"
"RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-jsonschema ripgrep git build-essential pkg-config openssh-client ca-certificates procps util-linux && rm -rf /var/lib/apt/lists/*\n"
"RUN install -d -m 0700 -o 1000 -g 1000 /home/hepta-qualification\n"
"ENV LANG=C.UTF-8 LC_ALL=C.UTF-8 PYTHONDONTWRITEBYTECODE=1\n"
"WORKDIR /home/hepta-qualification\n"
"USER 1000:1000\n")
write(BASE/"Dockerfile",dockerfile.encode())
dump(BASE/"base-pin.json",{"tag_requested":"ubuntu:24.04","repo_digest":digest,"image_id":info["Id"],"dockerfile_sha256":sha(BASE/"Dockerfile")})
command("03-build-task-image",DOCKER+["build","--platform","linux/amd64","--label","org.hepta.qualification.task=rea-ubuntu24-20261104-r1","--tag",TAG,"--file",str(BASE/"Dockerfile"),str(BASE/"build-context")])
_,raw,_=command("04-final-image-inspect",DOCKER+["image","inspect",TAG])
write(BASE/"final-image-inspect.json",raw);final_info=json.loads(raw)[0]
if final_info.get("Config",{}).get("User")!="1000:1000":raise RuntimeError("image default user mismatch")
mounts=["--mount","type=bind,src="+str(RUST)+",dst=/opt/rust,readonly","--mount","type=bind,src="+str(NEXTEST)+",dst=/opt/nextest/cargo-nextest,readonly","--mount","type=bind,src="+str(BASE/"preflight.py")+",dst=/qualification/preflight.py,readonly"]
argv=DOCKER+["run","--rm","--name","hepta-rea-ubuntu24-preflight-20261104-r1","--cpus","4","--memory",str(16*1024**3),"--pids-limit","1024","--user","1000:1000","--read-only","--network","none","--tmpfs","/tmp:rw,nosuid,nodev,size=268435456,mode=1777","--env","PATH=/opt/rust/bin:/opt/nextest:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]+mounts+[final_info["Id"],"/usr/bin/python3","/qualification/preflight.py"]
code,raw,_=command("05-preflight",argv,False)
if raw:
 try:preflight=json.loads(raw)
 except ValueError:preflight={"qualified":False,"invalid_json":True}
else:preflight={"qualified":False,"missing_output":True}
dump(BASE/"preflight.json",preflight)
after={}
for name,pin in identities.items():
 actual=sha(Path(pin["resolved"]));after[name]=actual
 if actual!=pin["sha256"]:raise RuntimeError("read-only mounted tool changed: "+name)
dump(BASE/"mounted-tool-pins-after.json",after)
summary={"schema":"hepta.rea.ubuntu24-qualification-environment.v1","scope":"isolated Ubuntu24 environment; not ROG bare-host observation pool support; no test matrix executed","base_repo_digest":digest,"base_image_id":info["Id"],"task_tag":TAG,"final_image_id":final_info["Id"],"dockerfile_sha256":sha(BASE/"Dockerfile"),"preflight_script_sha256":sha(BASE/"preflight.py"),"preflight_exit_code":code,"preflight_qualified":preflight.get("qualified",False),"preflight_gates":preflight.get("gates"),"preflight_path":str(BASE/"preflight.json"),"preflight_sha256":sha(BASE/"preflight.json"),"tool_pins_unchanged":True}
dump(BASE/"environment-summary.json",summary)
emit(summary)
sys.exit(0 if preflight.get("qualified") else 2)
