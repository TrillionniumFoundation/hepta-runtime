"""Independent complete archive relocation of frozen audit queue V3; no native/Rust replay."""
from pathlib import Path, PurePosixPath
import hashlib, json, os, stat, sys, tarfile, time, urllib.request, zipfile
sys.dont_write_bytecode = True
ROOT=Path("/home/qq/hepta-runtime-migration-6780/audit-queue-v3-readback-20261116")
HEAD="7768ffc5317a927824380c3420c41ccd8b443dea"
MANIFEST_SHA="3b6935ae95e2244ee01031ba63995950b53d29203fe549b7b1b720e2d643b33c"
ZIP_PIN={"bytes":29371813,"sha256":"4f6bf2a39ba45fbba0f1ef62f8de18569c59eaec0e94e42bd8d5148a9be4166f"}
TAR_PIN={}
STATUS="COMPLETE_NATIVE_AND_LIMITED_ORIGINAL_AUDIT_QUEUE_PASS"
SOURCE_PINS=json.loads(r'''{"DOMAIN.json":{"bytes":13802,"sha256":"e436c50718633d9f5540eefba4863a42a8a3f8e0eb36d69664df7ed455cd28e8","git_blob":"89e80de8d74c64b1668da4c657e2cf0fdbc15dad","mode":420},"README.md":{"bytes":7189,"sha256":"2f226c2b164c203302645ca6dcccbe42cd77b059fc4f8561be66ed531731d698","git_blob":"dec4c81bbbd37112be6e443af1eb4b53707ebac8","mode":420},"REFERENCE_DOMAIN.json":{"bytes":875,"sha256":"865852e5ffadeed10362fcf2aafc16a49a23956215d50278808fca5e8d735943","git_blob":"6b395c12b3bb055289cba36d87824918bcc93d2d","mode":420},"SOURCE_MANIFEST.json":{"bytes":4379,"sha256":"3b6935ae95e2244ee01031ba63995950b53d29203fe549b7b1b720e2d643b33c","git_blob":"d40f946f903661bab93e6ca7d0363e2404dd1256","mode":420},"authoring/audit_store_queue.pseudo":{"bytes":10716,"sha256":"6b1c72117c173d0f81cf5e38843c562a1cf30bebd9f9411959c9f6ef9578a491","git_blob":"facb60f6aa0cfe60cf4b57a45baef249396874ad","mode":420},"authoring/author_audit_store_queue.py":{"bytes":5307,"sha256":"afa7703a431fd49c1db0febe4d6c3df1214f520c84d451696f0d382c55570154","git_blob":"b11fcbbc174a390400fd8fd5a8883dbf911e29a6","mode":420},"build.py":{"bytes":2845,"sha256":"a37ae537a963276d8b35c0288cf6c27ad7f1180f760fef2f8d7d78a4a03629a5","git_blob":"eea3d28ad1fb203ee44ef7ed61f5ccf65faf1ba8","mode":420},"cases.py":{"bytes":18613,"sha256":"e659baf782e98d34f824850e844aeba316151fcb28f62132e5da045886eda762","git_blob":"41c7dfaec7cb7e90ba8a3c9ef21d4fab4a1f821f","mode":420},"export.py":{"bytes":3539,"sha256":"ae6bafc24d9d0b3cabf3643996fd8270a75e01894aefba6c5aa5e16ac1ff4a55","git_blob":"524bd42b3ded3064b37d068b11c349078ce38bdb","mode":420},"native/audit_store_queue.composition.json":{"bytes":2464,"sha256":"e3b26296dfd0317e2bdbe0335fa14b40852d9df65bb4fab862cffd7c2b826d52","git_blob":"8c354594930ad7a79637ae74cfc4f24ac5bcb59e","mode":420},"native/audit_store_queue.hepta":{"bytes":71230,"sha256":"bf3ff92341d14caee4028e4130e83a1cfcfcb87285564c8da343ba50205b4269","git_blob":"b8a0aad0302231f1437196d5edbfa56376ea82e9","mode":420},"original.py":{"bytes":5514,"sha256":"182c99536bdce9456e794558974025952840b108424cb0e923943ad5be0e874e","git_blob":"c392874d94e0b1a5698b5d24fc85ffe6cfe8cd90","mode":420},"process.py":{"bytes":5374,"sha256":"ab98793a3f2715f8f9ffa542c9c5b277b235f40140f64726d6897a73fc800126","git_blob":"d745bd27c6121eda3e590bea01c765e91c932881","mode":420},"projection.py":{"bytes":1608,"sha256":"0695b3751bc3980707eb7c1ec242ce524aad439f67f7ff3a2a2813b711887289","git_blob":"236efb0ba012137ae12910f0a6615db9f4f140f9","mode":420},"read_capture.py":{"bytes":19074,"sha256":"9d659cf82a90ab0868d29673fa26dee6337792b2c6c54d390136697073b47b1e","git_blob":"45b85b99e3a52a9b3bd5a7493fa942ec96915544","mode":420},"read_only_guard.py":{"bytes":8848,"sha256":"621b8caa09f62f401c5816e3fbc07690f077feed7153552a720ced66150ce647","git_blob":"6e2bb795949307bc422eaef5a3eb75d15c4dd9d1","mode":420},"reader_controls.py":{"bytes":14014,"sha256":"4aa44404e73b561c04b59d0b657a7c2f6ab8484111aabcd5765f4697070c5370","git_blob":"0b90467c17be722a77e50e9ec6e47ab980d195a2","mode":420},"reference/audit_store_lock.rs.txt":{"bytes":7395,"sha256":"6b80246ce3c2ff97edb71f6f70d21b692b801648c355427672780d01b5f14b25","git_blob":"be56d2d8dca9e4918b074978de0b62d5cc99b84f","mode":420},"reference/audit_store_tests.rs.txt":{"bytes":8045,"sha256":"88aa6e9b82591cab9d3198a820e54d0cc871191d65e99322ca0f660700524d2a","git_blob":"5f588fdbe42d94a26b5a65dd67afc01ce55e4514","mode":420},"reference/original_tests.rs":{"bytes":455,"sha256":"23f12550d0da461c17bfea1c8f79b96abb875a0b54316398d392f985aba34b4e","git_blob":"5211fc4a82c231a7de444583c310d016cedc23fe","mode":420},"reference/target/Cargo.toml":{"bytes":4259,"sha256":"bf00111f6ec88df9df4d0d1d14c125a64ce4f6bdc6724ba20e70498f56dcae7f","git_blob":"af0960b6ad360f26589de66e26cdcabe2fb3266f","mode":420},"reference/target/src/mcp/runtime/request_audit.rs":{"bytes":68414,"sha256":"b5189f2923153ffa83d0b45a7cdf89873b0f17ebbe6ec1b174c05bab291d73da","git_blob":"984668cfdfcee0a7eb00de14e02086f5ad90bcc0","mode":420},"reference/target/src/mcp/runtime/request_audit_tests.rs":{"bytes":47327,"sha256":"a066822705a713929dd2791f1e889f9cf6b7c16567d0d6e71a4c4946b20e14a7","git_blob":"d0e1daf6e06caa62a411ae7c233a2ae44fb2f485","mode":420},"reference/trace.rs":{"bytes":4519,"sha256":"c0a32a7847eac173562cdca7951cf39dff7a9f35cbd91b0cb69472514441a291","git_blob":"98e517d9636281c7c4d62a4d74e44c9074f953b9","mode":420},"run_gate.py":{"bytes":2681,"sha256":"0b75d43dfe38b327bd63923f132074cb435ae854af19bf0b6a17366657eb0388","git_blob":"94a6af67ff4b26395a8c8601d13f8170e2a5118b","mode":420},"run_native.py":{"bytes":7630,"sha256":"30d40cf6369a1dcc375ed078349f9c7dd2acec3d0f72ab6662c4adeec4ced4a2","git_blob":"b316e46a856f769dede7df930e2b748c30461a80","mode":420},"scripts/hia_native_build.py":{"bytes":16538,"sha256":"839a1eb7aed16df369a4ae80291680b2754c6794dac3c3029027a5df4f4e8f3f","git_blob":"104126933484122272d72ce916c2a00c6c1ab085","mode":420},"scripts/hia_native_loader.py":{"bytes":12849,"sha256":"367d600d808eaf95fe4e76d8d999b29ba46f1a3969e79fe20b70e23f79a48e96","git_blob":"5578486e3a769c699c35edd96137b41bae55d9c7","mode":420},"verify_readonly.py":{"bytes":1091,"sha256":"ebf054117cce602cc6ccbe04e7a70c653ebe5682753a1e3fb5bca7eb152a49f3","git_blob":"a2c6a0507da7033385d7ede70e2bb805be9f2871","mode":420}}''')
def put(path,value):
    path.write_bytes((json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+"\n").encode())
def sha(raw):return hashlib.sha256(raw).hexdigest()
def git_blob(raw):return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def pin(path):
    with path.open("rb") as stream:digest=hashlib.file_digest(stream,"sha256").hexdigest()
    return dict(bytes=path.stat().st_size,sha256=digest)
def safe(name):
    parts=name.split("/")
    assert parts and all(p and p not in (".","..") and "\\" not in p and "\0" not in p for p in parts),name
    assert not PurePosixPath(name).is_absolute() and str(PurePosixPath(name))==name,name
    return parts
def copied(stream,path):
    path.parent.mkdir(parents=True,exist_ok=True)
    total=0;digest=hashlib.sha256()
    with path.open("xb") as out:
        while block:=stream.read(1<<20):
            out.write(block);total+=len(block);digest.update(block)
    return dict(bytes=total,sha256=digest.hexdigest())
def guard_summary(proof):
    assert proof["source_bound_guard"] is True
    assert len(proof["probes"])==12 and proof["before"]==proof["after"]
    assert proof["native_or_rust_executions"]==proof["reader_writes"]==0
    assert proof["evidence"]["status"]==STATUS
    assert proof["evidence"]["original"]["limited_original_projection_pass"] is True
    assert proof["evidence"]["original"]["unchanged_original_tests"]==5
    assert proof["evidence"]["original"]["observable_projection_records"]==748
    assert proof["evidence"]["reader_controls"]==dict(status="PASS",refusals=16,relocations=2,post_refusal=2,complete_guard_proofs=20,native_or_rust_executions=0,reader_writes=0)
    assert proof["evidence"]["native"]["counts"]["semantic_calls"]==1933
    return dict(entries=len(proof["before"]),guard_refusals=12,complete_before_after_equal=True,
                native_or_rust_executions=0,reader_writes=0,status=STATUS,
                limited_original_projection_pass=True,concurrent_native_lock_qualified=False,
                public_handler_qualified=False,whole_runtime_replaced=False)
def main():
    started=time.monotonic()
    args=sys.orig_argv
    own=args[args.index("-c")+1].encode()
    assert git_blob(own)==os.environ["HIA_READBACK_DRIVER_BLOB"]
    request=json.load(sys.stdin)
    assert set(request)=={"download_url"} and request["download_url"].startswith("https://")
    ROOT.parent.mkdir(parents=True,exist_ok=True)
    assert ROOT.parent.resolve()==ROOT.parent
    ROOT.mkdir(exist_ok=False)
    (ROOT/"driver.py").write_bytes(own)
    put(ROOT/"DRIVER.json",dict(git_blob=git_blob(own),bytes=len(own),sha256=sha(own),
        native_or_rust_executions=0,source_head=HEAD,inner_reader_timeout_seconds=180))
    print(json.dumps(dict(stage="download",driver_blob=git_blob(own))),flush=True)
    archive=ROOT/"complete.zip"
    with urllib.request.urlopen(request["download_url"],timeout=60) as source:
        got=copied(source,archive)
    assert got==ZIP_PIN
    del request
    put(ROOT/"DOWNLOAD.json",dict(artifact_id=14264203482,run_id=43946019751,head=HEAD,**got,
        credential_url_not_logged=True))
    zip_dir=ROOT/"zip";zip_dir.mkdir()
    zip_files={}
    with zipfile.ZipFile(archive) as source:
        for member in source.infolist():
            safe(member.filename)
            assert not member.is_dir() and member.filename not in zip_files
            assert (member.external_attr>>16)&0o170000 in (0,stat.S_IFREG)
            with source.open(member) as stream: row=copied(stream,zip_dir/member.filename)
            assert row["bytes"]==member.file_size
            zip_files[member.filename]=row
    assert set(zip_files)=={"audit-store-queue-v2.tar.gz","audit-independent-processes/audit-independent-reader.stdout",
        "audit-independent-processes/audit-independent-reader.stderr","audit-independent-processes/processes.json",
        "audit-store-queue-v2.tar.gz.json","audit-queue-export.stdout","audit-queue-export.stderr"}
    receipt=json.loads((zip_dir/"audit-store-queue-v2.tar.gz.json").read_bytes())
    assert receipt["all_members_reread"] is True and receipt["gate_status"]==STATUS
    assert receipt["source_manifest_sha256"]==MANIFEST_SHA and receipt["semantic_executions"]==0
    TAR_PIN.update({key:receipt[key] for key in ("bytes","sha256")})
    assert zip_files["audit-store-queue-v2.tar.gz"]==TAR_PIN
    put(ROOT/"ZIP_FILES.json",zip_files)
    print(json.dumps(dict(stage="full-archive-relocation",zip_bytes=got["bytes"])),flush=True)
    expanded=ROOT/"expanded";expanded.mkdir()
    observed={}
    with tarfile.open(zip_dir/"audit-store-queue-v2.tar.gz","r|gz") as source:
        while member:=source.next():
            parts=safe(member.name)
            assert member.isfile() and member.name not in observed
            assert parts[0] in ("source","run") or member.name=="artifact-manifest.json"
            assert member.mode&~0o777==0
            with source.extractfile(member) as stream:row=copied(stream,expanded/member.name)
            assert row["bytes"]==member.size
            os.chmod(expanded/member.name,member.mode)
            row["mode"]=member.mode;observed[member.name]=row
            source.members.clear()
    raw=(expanded/"artifact-manifest.json").read_bytes();meta=json.loads(raw)
    assert meta["git_head"]==HEAD and meta["gate_status"]==STATUS
    assert meta["semantic_reexecutions_by_exporter"]==0 and meta["whole_runtime_replaced"] is False
    expected=dict(meta["files"])
    expected["artifact-manifest.json"]=dict(bytes=len(raw),sha256=sha(raw),mode=0o644)
    assert expected==observed
    assert len(observed)==receipt["files"] and sum(r["bytes"] for r in observed.values())==receipt["logical_bytes"]
    disk={}
    for path in sorted(expanded.rglob("*")):
        info=path.lstat()
        assert stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)
        assert path.resolve()==path.absolute()
        if stat.S_ISREG(info.st_mode):
            disk[path.relative_to(expanded).as_posix()]={**pin(path),"mode":stat.S_IMODE(info.st_mode)}
    assert disk==observed
    put(ROOT/"TAR_FILES.json",observed)
    source=expanded/"source";capture=expanded/"run"
    source_set={name.removeprefix("source/") for name in observed if name.startswith("source/")}
    assert source_set==set(SOURCE_PINS)
    for name,identity in SOURCE_PINS.items():
        raw=(source/name).read_bytes()
        assert len(raw)==identity["bytes"] and sha(raw)==identity["sha256"] and git_blob(raw)==identity["git_blob"]
        assert stat.S_IMODE((source/name).stat().st_mode)==identity["mode"]
    assert sha((source/"SOURCE_MANIFEST.json").read_bytes())==MANIFEST_SHA
    previous=json.loads((zip_dir/"audit-independent-processes/audit-independent-reader.stdout").read_bytes())
    existing=guard_summary(previous)
    del previous
    archive_report=dict(schema="hepta.audit-store-queue-v3.independent-archive-read.v1",head=HEAD,
        source_manifest_sha256=MANIFEST_SHA,zip=ZIP_PIN,tar=TAR_PIN,files=len(observed),
        logical_bytes=sum(r["bytes"] for r in observed.values()),complete_member_bytes_and_modes_equal=True,
        source_git_blobs_verified=len(SOURCE_PINS),retained_ci_independent_reader=existing,
        native_or_rust_executions=0,whole_runtime_replaced=False)
    put(ROOT/"ARCHIVE.json",archive_report)
    print(json.dumps(dict(stage="guarded-readonly",archive_files=len(observed))),flush=True)
    sys.path.insert(0,str(source))
    from process import Recorder
    recorder=Recorder(source,ROOT/"reader-processes")
    stdout,row=recorder.run("independent-reader",
        [sys.executable,"-I","-B",str(source/"verify_readonly.py"),"--output",str(capture),
         "--source-manifest-sha256",MANIFEST_SHA,"--require-controls"],timeout=180)
    assert row["completed"] and not row["timed_out"] and row["exit_code"]==0 and row["stderr"]["bytes"]==0
    proof=json.loads(stdout)
    summary=guard_summary(proof)
    assert proof["pid"]==row["pid"] and proof["ppid"]==row["parent_pid"] and proof["pgid"]==row["pgid"]
    put(ROOT/"READBACK.json",dict(schema="hepta.audit-store-queue-v3.ai395-readback.v1",
        archive=archive_report,driver=pin(ROOT/"driver.py"),driver_git_blob=git_blob(own),
        source_head=HEAD,source_manifest_sha256=MANIFEST_SHA,host="ai395",root=str(ROOT),
        process=row,reader=summary,elapsed_seconds=time.monotonic()-started,
        full_proof_file="reader-processes/independent-reader.stdout",
        native_or_rust_executions=0,whole_runtime_replaced=False))
    print(json.dumps(dict(status="PASS",root=str(ROOT),source_head=HEAD,
        proof=row["stdout"],reader=summary,elapsed_seconds=time.monotonic()-started,
        readback=pin(ROOT/"READBACK.json")),sort_keys=True),flush=True)
if __name__=="__main__":main()
