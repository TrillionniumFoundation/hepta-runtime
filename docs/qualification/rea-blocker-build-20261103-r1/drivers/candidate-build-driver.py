import ctypes,hashlib,json,os,pathlib,select,stat,struct,subprocess,threading,time,sys
os.umask(0o022)
repo=pathlib.Path("/home/qian-qi/hepta-runtime-rea-blockers-20261103-r1")
root=pathlib.Path("/home/qian-qi/work/hepta-rea-blockers-20261103-r1")
out=root/"candidate-build"
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
initial_status=git("status","--porcelain=v1")
assert initial_status and all(line[3:] in ["src/mcp/runtime/request_archive_index.rs","src/mcp/runtime/request_usage_batch.rs","src/mcp/runtime/request_archive_index_tests.rs","src/mcp/weight_native.rs","src/mcp/weight_native_tests.rs","src/mcp/server.rs"] for line in initial_status.splitlines())
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

env=dict(os.environ)
env.update({"CARGO_HOME":"/home/qian-qi/work/hepta-rea-full-20261103-r1-cargo","CARGO_BUILD_JOBS":"4","CARGO_TERM_COLOR":"never","RUSTC":"/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin/rustc","RUSTFMT":"/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin/rustfmt","RUSTUP_TOOLCHAIN":"1.95.0"})
cargo="/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin/cargo"
temp=pathlib.Path("/tmp/hb3")
temp.mkdir(mode=0o700,exist_ok=True)
assert not temp.is_symlink() and temp.stat().st_uid==os.getuid() and stat.S_IMODE(temp.stat().st_mode)==0o700
assert subprocess.check_output(["findmnt","-T",str(temp),"-n","-o","FSTYPE"]).decode().strip()=="ext4"
env["TMPDIR"]=str(temp)
env["CARGO_TARGET_DIR"]="/home/qian-qi/work/hepta-rea-full-20261103-r1-target"
def copy_artifact(source,dest,expected_sha=None):
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
    if expected_sha:assert copied==expected_sha
    dirfd=os.open(dest.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(dirfd)
    finally:os.close(dirfd)
    return {"path":str(dest),"sha256":copied,"bytes":dest.stat().st_size,"mode":"0500","single_source_fd":True}
baseline_test=copy_artifact(pathlib.Path("/home/qian-qi/work/hepta-rea-full-20261103-r1-target/debug/deps/hepta_runtime-6697a3b98397d108"),out/"baseline-test-lib","7ec5383c2f5f56006564fb2eb3f8f7c72027c73f94f7c5e524cf7567ab8f90ed")
save("baseline-test.json",baseline_test)
subprocess.run([cargo,"fmt","--all"],cwd=repo,env=env,check=True)
subprocess.run(["git","diff","--check"],cwd=repo,check=True)
initial_status=git("status","--porcelain=v1")
initial_diff=hashlib.sha256(subprocess.check_output(["git","diff","--binary"],cwd=repo)).hexdigest()

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

save("launch.json",{"head":expected,"env":{k:env.get(k) for k in ["CARGO_HOME","CARGO_TARGET_DIR","CARGO_BUILD_JOBS","CARGO_TERM_COLOR","RUSTC","RUSTFMT","RUSTUP_TOOLCHAIN","RUSTFLAGS","CARGO_ENCODED_RUSTFLAGS","TMPDIR"]},"umask":"0022","uid":os.getuid(),"cwd":str(repo),"filesystem":subprocess.check_output(["findmnt","-T",str(out),"-n","-o","FSTYPE,TARGET"]).decode().strip(),"started_unix":time.time(),"diff_sha256":initial_diff,"status":initial_status})
stages=[];artifacts={};failure=None;start=time.monotonic()
def run(name,cmd,timeout=1200):
    launched=time.monotonic()
    record={"name":name,"argv":cmd,"target":env.get("CARGO_TARGET_DIR"),"started_unix":time.time(),"timeout_seconds":timeout}
    with (out/(name+".log")).open("xb") as log:
        try:
            record["exit_code"]=subprocess.run(cmd,cwd=repo,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=timeout).returncode
        except Exception as e:
            record["error"]=repr(e);record["exit_code"]=None
    record["elapsed_seconds"]=time.monotonic()-launched
    stages.append(record);save(name+".json",record)
    print(json.dumps(record),flush=True)
    if record["exit_code"]!=0:raise RuntimeError(name+" failed")
def test_artifact(name):
    candidates=[]
    for line in (out/(name+".log")).read_text().splitlines():
        try:row=json.loads(line)
        except ValueError:continue
        if row.get("reason")=="compiler-artifact" and row.get("target",{}).get("name")=="hepta_runtime" and "lib" in row.get("target",{}).get("kind",[]) and row.get("profile",{}).get("test") and row.get("executable"):
            candidates.append(row)
    assert len(candidates)==1,candidates
    item=candidates[0];record=copy_artifact(pathlib.Path(item["executable"]),out/(name+"-lib"))
    record["features"]=item["features"];record["compiler_artifact"]=item
    artifacts[name]=record;save(name+"-artifact.json",record)
    return record["path"]
try:
    run("fmt",[cargo,"fmt","--all","--","--check"],120)
    run("all-test-build",[cargo,"test","--locked","--offline","--all-features","--lib","--no-run","--message-format=json"])
    alltests=test_artifact("all-test-build")
    run("warm-store-turn",[alltests,"mcp::runtime::request_audit::index::tests::warm_usage_keeps_its_admitted_store_turn","--exact","--nocapture","--test-threads=1"],90)
    run("weight-native-all",[alltests,"mcp::weight_native::tests::","--nocapture","--test-threads=1"],180)
    run("no-default-test-build",[cargo,"test","--locked","--offline","--no-default-features","--lib","--no-run","--message-format=json"])
    minimal=test_artifact("no-default-test-build")
    run("weight-native-no-default",[minimal,"mcp::weight_native::tests::","--nocapture","--test-threads=1"],180)
    env["CARGO_TARGET_DIR"]=str(target)
    run("release",[cargo,"build","--locked","--offline","--all-features","--release","--bin","hepta-runtime"])
    artifacts["release"]=copy_artifact(target/"release/hepta-runtime",out/"hepta-runtime")
    save("release-artifact.json",artifacts["release"])
except Exception as e:
    failure=repr(e)
after=inventory();save("source-after.json",after)
stop.set();thread.join(timeout=3);os.close(fd)
monitor={"completed":not thread.is_alive(),"watch_directories":len(wds),"events":events,"errors":errors}
save("source-monitor.json",monitor)
final_diff=hashlib.sha256(subprocess.check_output(["git","diff","--binary"],cwd=repo)).hexdigest()
result={"head":expected,"source_before":before["sha256"],"source_after":after["sha256"],"source_unchanged":before==after,"git_head_unchanged":git("rev-parse","HEAD")==expected,"git_status":git("status","--porcelain=v1"),"diff_before":initial_diff,"diff_after":final_diff,"elapsed_seconds":time.monotonic()-start,"failure":failure,"artifacts":artifacts,"stages":stages,"monitor":monitor}
result["qualified"]=bool(not failure and before==after and initial_diff==final_diff and result["git_head_unchanged"] and result["git_status"]==initial_status and monitor["completed"] and not events and not errors and "release" in artifacts)
save("result.json",result)
print(json.dumps(result),flush=True)
sys.exit(0 if result["qualified"] else 1)
