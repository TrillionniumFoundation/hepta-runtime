import ctypes,hashlib,json,os,pathlib,select,stat,struct,subprocess,threading,time,sys
os.umask(0o022)
repo=pathlib.Path("/home/qian-qi/hepta-runtime-rea-full-20261103-r1")
root=pathlib.Path("/home/qian-qi/work/hepta-rea-blockers-20261103-r1")
out=root/"baseline-release"
target=pathlib.Path("/home/qian-qi/work/hepta-rea-blockers-20261103-r1-target")
expected="23246a5313957e9e97e324303bc47a91808f1ea8"
root.mkdir(mode=0o700,exist_ok=True)
assert root.stat().st_uid==os.getuid() and stat.S_IMODE(root.stat().st_mode)==0o700
out.mkdir(mode=0o700,exist_ok=True)
def save(name,data):
    p=out/name
    content=(json.dumps(data,sort_keys=True,indent=2)+"\n").encode()
    with p.open("xb") as f:
        f.write(content);f.flush();os.fsync(f.fileno())
def git(*args):
    return subprocess.check_output(["git",*args],cwd=repo).decode().strip()
assert git("rev-parse","HEAD")==expected
assert git("status","--porcelain=v1")==""
paths=sorted(subprocess.check_output(["git","ls-files","-z"],cwd=repo).decode().rstrip("\0").split("\0"))
def inventory():
    rows=[]
    for name in paths:
        p=repo/name
        s=p.lstat()
        if p.is_symlink():
            data=os.readlink(p).encode()
            digest=hashlib.sha256(data).hexdigest()
        else:
            with p.open("rb") as f:
                a=os.fstat(f.fileno());h=hashlib.sha256()
                while True:
                    b=f.read(1024*1024)
                    if not b:break
                    h.update(b)
                z=os.fstat(f.fileno())
            assert (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns),name
            digest=h.hexdigest()
        rows.append({"path":name,"mode":stat.S_IMODE(s.st_mode),"size":s.st_size,"sha256":digest})
    encoded=json.dumps(rows,sort_keys=True,separators=(",",":")).encode()
    return {"sha256":hashlib.sha256(encoded).hexdigest(),"files":rows}
lib=ctypes.CDLL(None,use_errno=True)
lib.inotify_init1.argtypes=[ctypes.c_int];lib.inotify_init1.restype=ctypes.c_int
lib.inotify_add_watch.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_uint32];lib.inotify_add_watch.restype=ctypes.c_int
fd=lib.inotify_init1(os.O_NONBLOCK|os.O_CLOEXEC)
assert fd>=0,ctypes.get_errno()
watchdirs={repo}
for name in paths:
    p=(repo/name).parent
    while p!=repo:
        watchdirs.add(p);p=p.parent
wds={}
for p in sorted(watchdirs):
    wd=lib.inotify_add_watch(fd,os.fsencode(p),0x00000fce)
    assert wd>=0,(str(p),ctypes.get_errno())
    wds[wd]=p
events=[];errors=[];stop=threading.Event()
def consume():
    while True:
        try:
            ready,_,_=select.select([fd],[],[],0.2)
            if not ready:
                if stop.is_set():break
                continue
            raw=os.read(fd,65536);at=0
            while at<len(raw):
                wd,mask,cookie,length=struct.unpack_from("iIII",raw,at);at+=16
                name=raw[at:at+length].split(b"\0",1)[0].decode(errors="replace");at+=length
                p=wds.get(wd,repo)/name
                rel=str(p.relative_to(repo))
                if rel==".git" or rel.startswith(".git/"):continue
                events.append({"path":rel,"mask":mask,"cookie":cookie})
                if mask&0x4000:errors.append("inotify queue overflow")
        except Exception as e:
            errors.append(repr(e));break
thread=threading.Thread(target=consume,daemon=True);thread.start()
before=inventory();save("source-before.json",before)
env=dict(os.environ)
env.update({"CARGO_HOME":"/home/qian-qi/work/hepta-rea-full-20261103-r1-cargo","CARGO_TARGET_DIR":str(target),"CARGO_BUILD_JOBS":"4","CARGO_TERM_COLOR":"never","RUSTC":"/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin/rustc","RUSTUP_TOOLCHAIN":"1.95.0"})
cmd=["/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin/cargo","build","--locked","--offline","--all-features","--release","--bin","hepta-runtime"]
save("launch.json",{"head":expected,"argv":cmd,"env":{k:env.get(k) for k in ["CARGO_HOME","CARGO_TARGET_DIR","CARGO_BUILD_JOBS","CARGO_TERM_COLOR","RUSTC","RUSTUP_TOOLCHAIN","RUSTFLAGS","CARGO_ENCODED_RUSTFLAGS"]},"umask":"0022","uid":os.getuid(),"cwd":str(repo),"filesystem":subprocess.check_output(["findmnt","-T",str(out),"-n","-o","FSTYPE,TARGET"]).decode().strip(),"started_unix":time.time()})
start=time.monotonic();failure=None;returncode=None;artifact=None
try:
    with (out/"build.log").open("xb") as log:
        returncode=subprocess.run(cmd,cwd=repo,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=1500).returncode
    if returncode==0:
        source=target/"release/hepta-runtime";dest=out/"hepta-runtime"
        srcfd=os.open(source,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
        try:
            a=os.fstat(srcfd);h=hashlib.sha256()
            with dest.open("xb") as f:
                os.fchmod(f.fileno(),0o600)
                while True:
                    b=os.read(srcfd,1024*1024)
                    if not b:break
                    h.update(b);f.write(b)
                f.flush();os.fsync(f.fileno());os.fchmod(f.fileno(),0o500)
            z=os.fstat(srcfd)
            assert (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns)
        finally:os.close(srcfd)
        with dest.open("rb") as f: copied=hashlib.file_digest(f,"sha256").hexdigest()
        assert copied==h.hexdigest() and dest.stat().st_nlink==1
        artifact={"path":str(dest),"sha256":copied,"bytes":dest.stat().st_size,"mode":"0500","single_source_fd":True}
except Exception as e:
    failure=repr(e)
after=inventory();save("source-after.json",after)
stop.set();thread.join(timeout=3);os.close(fd)
monitor={"completed":not thread.is_alive(),"watch_directories":len(wds),"events":events,"errors":errors}
save("source-monitor.json",monitor)
result={"head":expected,"source_before":before["sha256"],"source_after":after["sha256"],"source_unchanged":before==after,"git_head_unchanged":git("rev-parse","HEAD")==expected,"git_status":git("status","--porcelain=v1"),"exit_code":returncode,"elapsed_seconds":time.monotonic()-start,"failure":failure,"artifact":artifact,"monitor":monitor}
result["qualified"]=bool(returncode==0 and not failure and before==after and result["git_head_unchanged"] and result["git_status"]=="" and monitor["completed"] and not events and not errors and artifact)
save("result.json",result)
print(json.dumps(result))
sys.exit(0 if result["qualified"] else 1)
