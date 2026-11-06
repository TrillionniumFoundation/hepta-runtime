import base64, hashlib, json, os, stat
from pathlib import Path
ROOT=Path("/home/qian/hepta-runtime-phase-cost-20261106-d1")
INPUT=ROOT/"c1-holder-copy-input-01.json"
REPORT=ROOT/"c1-holder-report-01.json"
DEST=ROOT/"c1-holder-originals-01"
OUTPUT=ROOT/"c1-holder-copy-report-01.json"
def need(ok, message):
    if not ok: raise ValueError(message)
def sha(raw): return hashlib.sha256(raw).hexdigest()
def read(path):
    need(path.resolve()==path, "indirect input")
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid==os.getuid() and st.st_nlink==1 and st.st_size<=1048576,"unsafe input")
        raw=b""
        while len(raw)<=1048576:
            part=os.read(fd,65536)
            if not part: break
            raw+=part
        after=os.fstat(fd)
        need(len(raw)==st.st_size and (st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns)==(after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),"input changed")
        return raw
    finally: os.close(fd)
def write_new(path,raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        view=memoryview(raw)
        while view:
            n=os.write(fd,view)
            need(n>0,"no write progress")
            view=view[n:]
        os.fsync(fd)
    finally: os.close(fd)
    need(read(path)==raw,"copy readback differs")
os.umask(0o077)
st=ROOT.lstat()
need(ROOT.resolve()==ROOT and stat.S_ISDIR(st.st_mode) and st.st_uid==os.getuid() and not(st.st_mode&0o022),"unprotected root")
raw=read(INPUT)
need(len(raw)==74421 and sha(raw)=="9c40c2e188a8c2788ea08e48eb208919e15df1c36d3af236bfd6cfdcd7c94090","copy input differs")
data=json.loads(raw)
original=read(REPORT)
need(len(original)==data["holder_report"]["bytes"] and sha(original)==data["holder_report"]["sha256"],"holder report differs")
holder=json.loads(original)
need(data["files"]==holder["log_files"],"original log inventory differs")
need(not os.path.lexists(DEST) and not os.path.lexists(OUTPUT),"copy destination already exists")
names=set()
resolved=[]
for row in data["files"]:
    name=row["file"]
    need(isinstance(name,str) and Path(name).name==name and name not in ("",".","..") and name not in names,"unsafe or duplicate original name")
    names.add(name)
    content=base64.b64decode(data["bodies"][row["sha256"]],validate=True)
    need(len(content)==row["bytes"] and sha(content)==row["sha256"],"original log content differs")
    resolved.append((name,content))
need(set(data["bodies"])==set(row["sha256"] for row in data["files"]),"extra content")
need(len(resolved)==21 and sum(len(v) for _,v in resolved)<=1048576,"copy bound differs")
DEST.mkdir(mode=0o700)
for name,content in resolved: write_new(DEST/name,content)
need(read(INPUT)==raw and read(REPORT)==original,"copy source changed")
receipt={"schema":"hepta-d1-c1-holder-log-copy/v1","files":data["files"],"file_count":len(resolved),"bytes":sum(len(v) for _,v in resolved),"holder_report":data["holder_report"],"content_sources":data["content_sources"],"hash_identical_content_deduplicated":True,"original_log_bytes_unchanged":True,"workload_started":False,"overwrite_or_deletion":False}
write_new(OUTPUT,(json.dumps(receipt,sort_keys=True,indent=2)+"\n").encode())
for directory in (DEST,ROOT):
    fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try: os.fsync(fd)
    finally: os.close(fd)
print(json.dumps({"copied":True,"files":len(resolved),"bytes":receipt["bytes"],"receipt":str(OUTPUT),"workload_started":False},sort_keys=True))
