#!/usr/bin/env python3
"""One diagnostic invocation of a pinned existing test executable; no Cargo."""
from pathlib import Path
import datetime, hashlib, json, os, stat, subprocess, sys, time
R=Path("/home/qian-qi/hepta-runtime-rea-full-20261103-r1")
W=Path("/home/qian-qi/work/hepta-rea-audit-budget-diagnostic-20261103-r1")
D=R/"docs/qualification/rea-audit-budget-diagnostic-20261103-r1"
P=R/"docs/qualification/rea-final-focused-20261103-r1"
T=Path("/home/qian-qi/work/hepta-rea-full-20261103-r1-target")
S=T/"debug/deps/hepta_runtime-6697a3b98397d108"
F=T/"debug/.fingerprint/hepta-runtime-6697a3b98397d108/test-lib-hepta_runtime.json"
B=W/"hepta-runtime-all-features-test-lib"
TMP=W/"ext4-fixtures"
TEST="mcp::runtime::request_audit::index::tests::large_pending_view_remains_exact_while_continuous_publications_progress"
WATCH="src/mcp/runtime/request_archive_index_tests.rs"
WATCH_SHA="b2f60424f1e72a5c474bf47e0bf109a6e0692d85fabe83f67677c6d4c3299788"
TREE="eff016991ae56572d55f6ba487550c8ded550a68028a0c24184ec75aa52e64d7"
FP_SHA="a52c2ec724b031da741097afbb439729364c28a00381b086fa8444fc9f5028d3"
EXPECTED={"device":2050,"inode":56675435,"size":573870560,"mtime_ns":1793715719193605531,"ctime_ns":1793715719255599733,"mode":"0o755","uid":1000,"nlink":1}
MARKERS=[b"writer made no durable completion for ",b"/64 before join",b"durable completion ",b" stalled for "]
def now(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def sha(b): return hashlib.sha256(b).hexdigest()
def info(s): return dict(device=s.st_dev,inode=s.st_ino,size=s.st_size,mtime_ns=s.st_mtime_ns,ctime_ns=s.st_ctime_ns,mode=oct(s.st_mode&0o7777),uid=s.st_uid,nlink=s.st_nlink)
def put(p,b):
    with os.fdopen(os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),"wb") as f:
        f.write(b);f.flush();os.fsync(f.fileno())
def save(p,j): put(p,(json.dumps(j,sort_keys=True,indent=2)+"\n").encode())
def private_log(p): return os.fdopen(os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),"wb")
def sources(manifest):
    rows=[];different=[]
    for old in manifest["files"]:
        p=R/old["path"];b=p.read_bytes()
        new=dict(path=old["path"],bytes=len(b),sha256=sha(b),mode=oct(p.stat().st_mode&0o7777))
        rows.append(new)
        if any(old[k]!=new[k] for k in ["bytes","sha256","mode"]): different.append({"expected":old,"observed":new})
    return dict(at=now(),reference_tree_sha256=TREE,checked_files=len(rows),all_match=not different,differences=different,files=rows,
                scope="All 555 recorded paths; root's separate source monitor covers new/deleted source paths.")
def proc(pid):
    try:
        fields={}
        for line in (Path("/proc")/str(pid)/"status").read_text().splitlines():
            k,_,v=line.partition(":")
            if k in ["Name","State","Umask","Uid","Gid","Cpus_allowed_list","Mems_allowed_list"]: fields[k]=v.strip()
        fields["exe"]=os.readlink(Path("/proc")/str(pid)/"exe")
        return fields
    except OSError as e: return {"unavailable":type(e).__name__}
def host():
    return dict(at=now(),loadavg=list(os.getloadavg()),pressure={n:(Path("/proc/pressure")/n).read_text() for n in ["cpu","io","memory"]})
def publish():
    if not D.exists(): D.mkdir(mode=0o700)
    assert D.is_dir() and D.stat().st_uid==os.geteuid()
    for p in sorted(W.iterdir()):
        if p.is_file() and (p.suffix in [".json",".log",".py"]):
            put(D/p.name,p.read_bytes())
def main():
    assert os.geteuid()==1000 and W.stat().st_uid==1000 and W.stat().st_mode&0o7777==0o700
    assert not D.exists(),"Evidence directory must be new."
    TMP.mkdir(mode=0o700)
    mount=json.loads(subprocess.check_output(["findmnt","-T",str(TMP),"-o","TARGET,SOURCE,FSTYPE,OPTIONS","-J"],text=True))["filesystems"]
    assert len(mount)==1 and mount[0]["fstype"]=="ext4",mount
    assert TMP.stat().st_mode&0o7777==0o700
    prior={}
    for name in ["source-before.json","source-after.json","source-events.json","summary.json"]:
        raw=(P/name).read_bytes();prior[name]=json.loads(raw);put(W/("prior-"+name),raw)
    assert (P/"source-before.json").read_bytes()==(P/"source-after.json").read_bytes()
    m=prior["source-before.json"];summary=prior["summary.json"]
    assert m["tree_sha256"]==TREE and summary["source_monitor_complete"] and not summary["source_changed"]
    assert prior["source-events.json"]["event_count"]==0 and not prior["source-events.json"]["errors"]
    row=next(x for x in m["files"] if x["path"]==WATCH)
    assert row["sha256"]==WATCH_SHA
    before=sources(m);save(W/"source-verification-before.json",before)
    assert before["all_match"],before["differences"]
    raw=F.read_bytes();assert sha(raw)==FP_SHA
    fp=json.loads(raw);assert json.loads(fp["features"])==["default","remote-fs"] and fp["rustflags"]==[]
    put(W/"selected-test-lib-fingerprint.json",raw)
    dep=S.with_suffix(".d").read_bytes();assert WATCH.encode() in dep
    stage=next(x for x in summary["stages"] if x["name"]=="focused-all-features")
    lo=datetime.datetime.fromisoformat(stage["started_at"]).timestamp()
    hi=datetime.datetime.fromisoformat(stage["finished_at"]).timestamp()
    source_fd=os.open(S,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW);dest_fd=None
    try:
        s=os.fstat(source_fd);pre=info(s)
        assert stat.S_ISREG(s.st_mode) and pre==EXPECTED,pre
        assert lo<=s.st_mtime_ns/1e9<=hi
        dest_fd=os.open(B,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o500)
        first=hashlib.sha256();found={x.decode():False for x in MARKERS};tail=b"";count=0
        while True:
            data=os.read(source_fd,1024*1024)
            if not data: break
            first.update(data);count+=len(data);scan=tail+data
            for marker in MARKERS:
                if marker in scan: found[marker.decode()]=True
            tail=scan[-max(map(len,MARKERS)):]
            remaining=memoryview(data)
            while remaining:
                n=os.write(dest_fd,remaining);assert n>0;remaining=remaining[n:]
        assert all(found.values()) and count==s.st_size,found
        os.fsync(dest_fd);post=info(os.fstat(source_fd))
        assert pre==post==info(os.stat(S,follow_symlinks=False))
        os.lseek(dest_fd,0,os.SEEK_SET);second=hashlib.sha256()
        while True:
            data=os.read(dest_fd,1024*1024)
            if not data: break
            second.update(data)
        assert first.hexdigest()==second.hexdigest()
        os.fchmod(dest_fd,0o500);os.fsync(dest_fd);fixed_pre=info(os.fstat(dest_fd))
    finally:
        os.close(source_fd)
        if dest_fd is not None: os.close(dest_fd)
    identity=dict(schema="hepta.rea.audit-budget-diagnostic-binary.v1",at=now(),source_binary=str(S),fixed_binary=str(B),
        sha256=first.hexdigest(),bytes=count,source_before=pre,source_after=post,fixed_stat=fixed_pre,
        copy_method="One source FD, hash during copy, fstat/path identity stable; hash destination through same destination FD; fixed copy mode 0500.",
        fingerprint_path=str(F),fingerprint_sha256=sha(raw),features=json.loads(fp["features"]),profile=fp["profile"],rustflags=fp["rustflags"],
        dep_info_path=str(S.with_suffix(".d")),dep_info_sha256=sha(dep),dep_info_contains_watchdog=True,
        watchdog_source=row,new_watchdog_embedded_markers=found,source_tree_sha256=TREE,
        prior_summary_sha256=sha((P/"summary.json").read_bytes()),
        build_stage={k:stage[k] for k in ["name","command","started_at","finished_at","exit_code"]},
        identity_limit="Cargo fingerprint, dependency membership, build-window timestamps, frozen-source monitor and unique new watchdog strings establish build linkage; Cargo metadata is not a cryptographic source attestation.")
    save(W/"binary-provenance.json",identity)
    env={"PATH":"/usr/local/bin:/usr/bin:/bin","LANG":"C.UTF-8","LC_ALL":"C.UTF-8","TZ":"UTC","TMPDIR":str(TMP),
         "RUST_LIB_BACKTRACE":"1","HEPTA_ARCHIVE_INDEX_TRACE":"1","RUST_TEST_THREADS":"1"}
    save(W/"environment.json",dict(schema="hepta.rea.audit-budget-diagnostic-environment.v1",at=now(),child_environment=env,
        policy="Explicit allowlist; no inherited credentials, production runtime configuration, or profile environment.",
        child_launch_umask="0022",cwd=str(R),fixture_root=str(TMP),fixture_root_stat=info(TMP.stat()),filesystem=mount[0],
        parent_process=proc(os.getpid()),parent_nice=os.getpriority(os.PRIO_PROCESS,0),host_before=host(),
        concurrent_gate_job="1a1a1d2ebf8-96a-715f",concurrency_limit="Root's tmpfs matrix may overlap; this is not an isolated host latency benchmark."))
    list_argv=[str(B),"--list","--exact",TEST]
    with private_log(W/"test-list.stdout.log") as out,private_log(W/"test-list.stderr.log") as err:
        listed=subprocess.run(list_argv,cwd=R,env=env,stdout=out,stderr=err,umask=0o022,check=False)
    listing=(W/"test-list.stdout.log").read_text()
    assert listed.returncode==0
    assert [x for x in listing.splitlines() if x.endswith(": test")]==[TEST+": test"],listing
    assert "1 test, 0 benchmarks" in listing,listing
    argv=[str(B),"--exact",TEST,"--nocapture","--test-threads=1"]
    started=now();save(W/"execution-started.json",dict(started_at=started,argv=argv,list_argv=list_argv,
        actual_test_invocation_number=1,authorized_test_invocations=1,cargo_invocations=0,retries=0,child_launch_umask="0022"))
    clock=time.monotonic()
    with private_log(W/"test.stdout.log") as out,private_log(W/"test.stderr.log") as err:
        child=subprocess.Popen(argv,cwd=R,env=env,stdout=out,stderr=err,umask=0o022)
        observed=proc(child.pid);rc=child.wait()
    finished=now();elapsed=time.monotonic()-clock
    after=sources(m);save(W/"source-verification-after.json",after)
    result=dict(schema="hepta.rea.audit-budget-diagnostic-result.v1",started_at=started,finished_at=finished,duration_seconds=elapsed,
        test_exit_code=rc,test_status="passed" if rc==0 else "failed",test_invocations=1,retries=0,cargo_invocations=0,
        argv=argv,cwd=str(R),child_pid=child.pid,observed_child=observed,configured_child_umask="0022",binary_sha256=identity["sha256"],
        binary_stat_unchanged=info(B.stat())==fixed_pre,source_recorded_files_unchanged=after["all_match"],host_after=host(),
        fixture_entries_after=sorted(x.name for x in TMP.iterdir()),
        logs={n:dict(bytes=(W/n).stat().st_size,sha256=sha((W/n).read_bytes())) for n in ["test.stdout.log","test.stderr.log","test-list.stdout.log","test-list.stderr.log"]},
        scope="One direct all-features test-lib execution with task-private ext4 fixtures and diagnostics. A pass does not repair or relabel prior failures; a failure supports only its captured stack and stages.")
    save(W/"result.json",result);publish()
    print(json.dumps(dict(evidence=str(D),test_status=result["test_status"],test_exit_code=rc,duration_seconds=elapsed,
        binary_sha256=identity["sha256"],source_unchanged=after["all_match"],binary_stat_unchanged=result["binary_stat_unchanged"],
        observed_child_umask=observed.get("Umask"))),flush=True)
    if not after["all_match"] or not result["binary_stat_unchanged"]: return 2
    return rc if 0<=rc<=255 else 1
try:
    code=main()
except BaseException as e:
    save(W/"preflight-failure.json",dict(at=now(),type=type(e).__name__,message=str(e),
        actual_execution_started=(W/"execution-started.json").exists(),note="No automatic retry."))
    publish()
    raise
raise SystemExit(code)
