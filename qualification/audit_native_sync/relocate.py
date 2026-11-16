"""Independent full relocation of frozen HIA native synchronization evidence; no semantic replay."""
from pathlib import Path, PurePosixPath
import hashlib, json, os, stat, sys, tarfile, time, urllib.request, zipfile
sys.dont_write_bytecode = True
ROOT=Path("/home/qq/hepta-runtime-migration-6780/audit-native-sync-readback-20261116")
HEAD="0aad43e82c040ce24dfeb1e214ecdf9ac7620356"
MANIFEST_SHA="e780e46fcdb3278b6b4e87b56da79397dc6f8abbb741e7260e7e71ac4bab07a5"
ZIP_PIN={"bytes":215083549,"sha256":"3e5d28d616c2bfec6c84588af0fd70e8d54a00acf7a33b19220bda4f374ab2ac"}
TAR_PIN={}
STATUS="COMPLETE_NATIVE_OS_BOUNDARY_PASS"
SOURCE_PINS=json.loads(r'''{"COMPILER_FILES.json":{"bytes":123249,"sha256":"adebfbbab857cd87e9b8f975f522e51b7cd1ed8fd65a8108d29e941651b28b06","git_blob":"aee54ee21b7f7c2e5c00f413f248c197ad8af965","mode":420},"DOMAIN.json":{"bytes":3088,"sha256":"17db83dda5becdfbbd42e2ab441e1cfb125099f61477292823e8cc74eaeef993","git_blob":"4cc32f108e6aa5e4abb994705e8195ed697f5e2a","mode":420},"README.md":{"bytes":3944,"sha256":"d9d4e628d6121502e3cc2aa9d5f0ff012b5bb591b1176dde998b33a434072d12","git_blob":"881ebf3e69b8e8cc0eac592f6e2d413680492cd1","mode":420},"SOURCE_MANIFEST.json":{"bytes":3178,"sha256":"e780e46fcdb3278b6b4e87b56da79397dc6f8abbb741e7260e7e71ac4bab07a5","git_blob":"e81410dd991f42d0a777a53d51ac771352a00939","mode":420},"authoring/audit_sync_adapter.S":{"bytes":7718,"sha256":"fa597133f2c2111615b2b775fec66082f72e910c88c17452893a87b30cf67e64","git_blob":"807f813a14d2099b05d47753f67cf21bd1cd761a","mode":420},"authoring/author_sync_boundary.py":{"bytes":5730,"sha256":"ed439fc9f70eb712e8d65ad239beef57dcd66f07f11669e0a5093f318d0b4dd9","git_blob":"255781aca7c5c0c04bf005e128f38645b9e02110","mode":420},"build.py":{"bytes":2847,"sha256":"31fd2ea19010dd27edae161631c5e5938557d24ff2b6be52f564b1ea8e29ffde","git_blob":"69dc92c00ae360ceeab75571b6bfcc093571763b","mode":420},"common.py":{"bytes":3120,"sha256":"44fc2713d09fbf996e4b7d0af0d8e0be897976670649d442996ffc470fb76663","git_blob":"b7e5fe82260059652cf42089d16b82006a9ae5ab","mode":420},"emit.py":{"bytes":4169,"sha256":"a317bcdd31c52c8b41fbd00c3ee32dd4dbc9bc30935a9da63535103b5f0c8a99","git_blob":"ed0160ff8505df1a9d1c1f799e69fed54117ebb8","mode":420},"export.py":{"bytes":3539,"sha256":"61ddff9f0b01a64b897304ce837fb40b984c017d2bbdf5b32cb4a141380d51ad","git_blob":"dbfe7ea72f13a5a3897d737feefbc1f4485f2521","mode":420},"native/audit_sync_boundary.composition.json":{"bytes":1230,"sha256":"1362e956d6244d7d27afff297439494a80852a0e0dbec5c4789f259ed55cb7c9","git_blob":"d7665b55167c47408d5428b122b11b12dac6b19a","mode":420},"native/audit_sync_boundary.hepta":{"bytes":239418,"sha256":"78a73f0e888261160248ad68b7e2718fe173be2036bca6bd4d26d084f0d97872","git_blob":"44324e87c82ec71c3e49bc4cc0140a1d43520216","mode":420},"process.py":{"bytes":5373,"sha256":"304cf26bada371b6dd8932efab09dd202445599299f2a3bb895a6629865b56df","git_blob":"645db7eafdd0cac5d04b566839b368c918ea85df","mode":420},"read_capture.py":{"bytes":21435,"sha256":"4e261affd15e4b02575ee41993934fbfc8fe0fb88bc0b98313d87ac135f1aebe","git_blob":"454c179533aaa9738b51ea4ad28f747636964e94","mode":420},"read_only_guard.py":{"bytes":8848,"sha256":"621b8caa09f62f401c5816e3fbc07690f077feed7153552a720ced66150ce647","git_blob":"6e2bb795949307bc422eaef5a3eb75d15c4dd9d1","mode":420},"reader_controls.py":{"bytes":10542,"sha256":"73719ad80d73df52b7b6ecb53b3d68a1a23f23ad31f41661d122b9c8088b6789","git_blob":"8db21f74e9eea2112ef59732ad0bb531ed6b36b9","mode":420},"reference/sync_tests.rs":{"bytes":24213,"sha256":"e6cdb77d903742f73f415e7cc2b2d102052e4f7305b1735188b4cddd92fc5e1b","git_blob":"c535986970547600a55a34d2fecfcad51c4a00f3","mode":420},"run_gate.py":{"bytes":5854,"sha256":"e706506eb9fe35cc8133d6c230d5e2cc1f99c0eb53a778c4d887e7ef4dc52f56","git_blob":"ebf6706d5b68686e29e2546e6b7aa5bb3913b0a0","mode":420},"scripts/hia_native_build.py":{"bytes":16538,"sha256":"839a1eb7aed16df369a4ae80291680b2754c6794dac3c3029027a5df4f4e8f3f","git_blob":"104126933484122272d72ce916c2a00c6c1ab085","mode":420},"scripts/hia_native_loader.py":{"bytes":12849,"sha256":"367d600d808eaf95fe4e76d8d999b29ba46f1a3969e79fe20b70e23f79a48e96","git_blob":"5578486e3a769c699c35edd96137b41bae55d9c7","mode":420},"verify_readonly.py":{"bytes":1233,"sha256":"36d67ab4039f8952378780a08aa03ddc09b3540f421a759d559af7b9b176468a","git_blob":"1b9a38e5d61a6c2228632526f44d0e1253bd01b7","mode":420}}''')
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
    evidence=proof["evidence"]
    assert evidence["status"]==STATUS and evidence["source_manifest_sha256"]==MANIFEST_SHA
    assert evidence["journal"]["calls"]==8732 and evidence["journal"]["contexts"]==24
    assert evidence["journal"]["refusals"]==47 and evidence["journal"]["quiescent_states"]==59
    assert evidence["journal"]["observations"]==135
    assert evidence["emission"]["calls"]==7 and evidence["emission"]["refusals"]==6
    assert evidence["actual_thread_tests"]==15 and evidence["build"]["compiler_files"]==1080
    assert evidence["controls"]==dict(status="PASS",refusals=8,relocated_admissions=2,
        post_refusal_admissions=2,guard_proofs=12,guards_per_proof=12,native_or_rust_executions=0,reader_writes=0)
    assert evidence["native_os_boundary_only"] is True
    assert evidence["audit_queue_controller_qualified"] is False
    assert evidence["public_handler_qualified"] is False and evidence["whole_runtime_replaced"] is False
    return dict(entries=len(proof["before"]),guard_refusals=12,complete_before_after_equal=True,
                native_or_rust_executions=0,reader_writes=0,status=STATUS,
                actual_thread_tests=15,actual_calls=8732,physical_refusals=47,contexts=24,
                native_os_boundary_only=True,audit_queue_controller_qualified=False,
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
    put(ROOT/"DOWNLOAD.json",dict(artifact_id=14271020141,run_id=43953026708,head=HEAD,**got,
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
    assert set(zip_files)=={"audit-native-sync.tar.gz","audit-native-sync-independent/independent-reader.stdout",
        "audit-native-sync-independent/independent-reader.stderr","audit-native-sync-independent/processes.json",
        "audit-native-sync.tar.gz.json","audit-native-sync-export.stdout","audit-native-sync-export.stderr"}
    receipt=json.loads((zip_dir/"audit-native-sync.tar.gz.json").read_bytes())
    assert receipt["all_members_reread"] is True and receipt["gate_status"]==STATUS
    assert receipt["source_manifest_sha256"]==MANIFEST_SHA and receipt["semantic_executions"]==0
    TAR_PIN.update({key:receipt[key] for key in ("bytes","sha256")})
    assert zip_files["audit-native-sync.tar.gz"]==TAR_PIN
    put(ROOT/"ZIP_FILES.json",zip_files)
    print(json.dumps(dict(stage="full-archive-relocation",zip_bytes=got["bytes"])),flush=True)
    expanded=ROOT/"expanded";expanded.mkdir()
    observed={}
    with tarfile.open(zip_dir/"audit-native-sync.tar.gz","r|gz") as source:
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
    previous=json.loads((zip_dir/"audit-native-sync-independent/independent-reader.stdout").read_bytes())
    existing=guard_summary(previous)
    del previous
    archive_report=dict(schema="hepta.audit-native-sync.independent-archive-read.v1",head=HEAD,
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
    put(ROOT/"READBACK.json",dict(schema="hepta.audit-native-sync.ai395-readback.v1",
        archive=archive_report,driver=pin(ROOT/"driver.py"),driver_git_blob=git_blob(own),
        source_head=HEAD,source_manifest_sha256=MANIFEST_SHA,host="ai395",root=str(ROOT),
        process=row,reader=summary,elapsed_seconds=time.monotonic()-started,
        full_proof_file="reader-processes/independent-reader.stdout",
        native_or_rust_executions=0,whole_runtime_replaced=False))
    print(json.dumps(dict(status="PASS",root=str(ROOT),source_head=HEAD,
        proof=row["stdout"],reader=summary,elapsed_seconds=time.monotonic()-started,
        readback=pin(ROOT/"READBACK.json")),sort_keys=True),flush=True)
if __name__=="__main__":main()
