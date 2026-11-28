#!/usr/bin/env python3
"""Input capability survey only: real owned Linux fixtures, no metadata/HIA/Rust execution."""
from pathlib import Path
import argparse,errno,hashlib,json,os,platform,stat,struct,sys,time
def pin(path):
    path=Path(path)
    with path.open("rb") as f:return dict(bytes=path.stat().st_size,sha256=hashlib.file_digest(f,"sha256").hexdigest())
def attrs(fd):
    return [{"name_hex":os.fsencode(n).hex(),"value_hex":os.getxattr(fd,n).hex()} for n in os.listxattr(fd)]
def metadata(st):
    return {name:getattr(st,name) for name in ("st_dev","st_ino","st_mode","st_nlink","st_uid","st_gid","st_size","st_mtime_ns","st_ctime_ns")}
def error(exc):return dict(type=type(exc).__name__,errno=getattr(exc,"errno",None),message=str(exc))
def family(base,name,action):
    path=base/name;fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_RDWR|os.O_CLOEXEC,0o600)
    out=dict(name=name,file=str(path),before=metadata(os.fstat(fd)),events=[])
    try:
        action(fd,out["events"])
        out["status"]="COMPLETE"
    except OSError as exc:out.update(status="ACTUAL_OS_REFUSAL",error=error(exc))
    try:out["attributes"]=attrs(fd)
    except OSError as exc:out["inspection_error"]=error(exc)
    out["after"]=metadata(os.fstat(fd));os.close(fd)
    return out
def put(fd,name,value,events):
    try:os.setxattr(fd,name,value)
    except OSError as exc:
        events.append(dict(name_hex=os.fsencode(name).hex(),value_bytes=len(value),value_sha256=hashlib.sha256(value).hexdigest(),status="REFUSED",error=error(exc)));raise
    actual=os.getxattr(fd,name)
    if actual!=value:raise ValueError("actual xattr readback")
    events.append(dict(name_hex=os.fsencode(name).hex(),value_bytes=len(value),value_sha256=hashlib.sha256(value).hexdigest(),status="SET_AND_GET_EXACT"))
def ordinary(fd,events):
    for name,value in [
        (b"user.empty",b""),(b"user.quote\"slash\\line\n",b"\x00\xff"),
        (b"user.\xff",b"invalid-name"),("user.\U0010ffff",b"maximum-scalar"),
        ("user.\u20ac",b"euro"),("user.\U0001f600",b"astral"),
        (b"user."+b"x"*250,b"long-name")]:put(fd,name,value,events)
def values(fd,events):
    for n in (127,128,129,1024,4096,32768,65536):
        put(fd,b"user.value",bytes(i%251 for i in range(n)),events)
def counts(fd,events):
    for n in range(257):put(fd,("user.k%03d"%n).encode(),b"",events)
def budget(fd,events):
    for n in range(65):put(fd,("user.v%03d"%n).encode(),b"v"*65536,events)
def acl(fd,events):
    value=struct.pack("<I",2)+b"".join(struct.pack("<HHI",tag,perm,uid) for tag,perm,uid in
        [(1,6,0xffffffff),(2,4,(os.geteuid()+1)&0xffffffff),(4,4,0xffffffff),(16,4,0xffffffff),(32,0,0xffffffff)])
    put(fd,b"system.posix_acl_access",value,events)
def group(fd,events):
    choices=[g for g in os.getgroups() if g!=os.getegid()]
    if not choices:events.append(dict(status="NO_SUPPLEMENTARY_GROUP"));return
    os.fchown(fd,-1,choices[0]);events.append(dict(status="FCHOWN_TO_EXISTING_SUPPLEMENTARY_GROUP",gid=choices[0],actual=metadata(os.fstat(fd))))
def main():
    p=argparse.ArgumentParser();p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    if a.output.exists():raise ValueError("fresh survey evidence")
    a.output.mkdir(parents=True)
    status=Path("/proc/self/status").read_text().splitlines()
    result=dict(schema="hepta.runtime.file-metadata.platform-input-survey.v1",
        python=dict(version=sys.version,version_info=list(sys.version_info),executable=sys.executable,identity=pin(sys.executable),
            filesystem_encoding=sys.getfilesystemencoding(),filesystem_errors=sys.getfilesystemencodeerrors(),platform=sys.platform),
        machine=platform.machine(),kernel=platform.release(),uid=os.geteuid(),gid=os.getegid(),groups=os.getgroups(),
        capabilities=[s for s in status if s.split(":",1)[0] in("CapInh","CapPrm","CapEff","CapBnd","NoNewPrivs")],
        filesystems=[],preexisting_readonly=[],metadata_function_calls=0,hia_calls=0,rust_calls=0,permission_grants=0)
    for label,parent in (("runner-temp",a.output/"fixtures"),("existing-shm",Path("/dev/shm")/("hia-metadata-input-survey-"+str(os.getpid())))):
        parent.mkdir(parents=True,exist_ok=False)
        row=dict(label=label,path=str(parent),statvfs=list(os.statvfs(parent)),families=[])
        for name,fn in(("ordinary",ordinary),("value-capacity",values),("attribute-count",counts),("metadata-budget",budget),("posix-acl",acl),("existing-group",group)):
            row["families"].append(family(parent,name,fn))
        result["filesystems"].append(row)
    for name in("/usr/bin/ping","/bin/ping","/usr/bin/traceroute6.iputils","/usr/bin/mtr-packet","/etc/debian_version","/etc/hosts"):
        row=dict(path=name)
        try:
            fd=os.open(name,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
            try:row.update(status="READONLY",stat=metadata(os.fstat(fd)),attributes=attrs(fd),identity=pin(name))
            finally:os.close(fd)
        except OSError as exc:row.update(status="UNAVAILABLE",error=error(exc))
        result["preexisting_readonly"].append(row)
    (a.output/"SURVEY.json").write_text(json.dumps(result,sort_keys=True,indent=2,ensure_ascii=True)+"\n")
    print(json.dumps(result,sort_keys=True,ensure_ascii=True))
if __name__=="__main__":main()
