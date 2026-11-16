"""Independent full relocation of frozen HIA native audit callable evidence; no semantic replay."""
from pathlib import Path, PurePosixPath
import hashlib, json, os, stat, sys, tarfile, time, urllib.request, zipfile
sys.dont_write_bytecode = True
ROOT=Path("/tmp/hia-audit-callable-6780-ci-readback-v1")
HEAD="bde43ad26e20171658753cd1d270f2a5ffec3660"
MANIFEST_SHA="a4fb641634384362c888493d927fb310e5de76b5093c8325d01a06dedb7a298b"
ZIP_PIN={"bytes":391794492,"sha256":"61357f2850adc9744af7b71650d3a779b16d03b134ac816ba2f289dcd279c566"}
TAR_PIN={}
STATUS="COMPLETE_HIA_NATIVE_AUDIT_CALLABLE_PASS"
SOURCE_PINS=json.loads(r'''{"DOMAIN.json":{"bytes":4753,"sha256":"6d6068f64ba4be8cc629cb97e8db326d0028088f434ff8b808911fd1483a94c1","git_blob":"0d3fdccbc631ee61afd6a49080be4eb2153c9f5e","mode":420},"README.md":{"bytes":4589,"sha256":"02b13af5eca6c6a6bb7b926cd3717c36db8fca542ce1422f70d692f543bc3ab8","git_blob":"86de0ec0f39faf3523610be23bb56a116fa2f3d5","mode":420},"SOURCE_MANIFEST.json":{"bytes":5799,"sha256":"a4fb641634384362c888493d927fb310e5de76b5093c8325d01a06dedb7a298b","git_blob":"0d49d14cfcaffc39219e9a31e5c0046f137526a3","mode":420},"authoring/audit_controller_callable.S":{"bytes":8035,"sha256":"0205c0dea3f7343d794309171734cf2bc7d8f8fa9a219c4ccf9e2e0d6288b348","git_blob":"85b8268e622b75d442eaf9798816e6b04a52cd5b","mode":420},"authoring/audit_store_controller.pseudo":{"bytes":16877,"sha256":"2f6f227a8b4cb76babcb05c9526b2c01667c436319bfd69c3e7f2d767d53ee34","git_blob":"38ceb0443a4519bd3467adea7f424f2a3adcc4e3","mode":420},"authoring/author_audit_store_controller.py":{"bytes":6195,"sha256":"19159d4b4045427d3a436c39b23150a9a28ddc5d08889b03d70d8c67b51da130","git_blob":"01be44f34e346c37f1ffe2a37371aca84dcd7bcb","mode":420},"authoring/author_callable.py":{"bytes":6671,"sha256":"d589e1b508641e5f216013fb2bdd2ab50a69ce5a8e604f0e941670e18048dc5e","git_blob":"ad5de29733cac0a6b7adaa5d303a6c142e6064b1","mode":420},"build.py":{"bytes":4220,"sha256":"83112118973ef74b8fdbd1862fd2aa11e2d42ebff020ffa1cc924aac19e92c3e","git_blob":"03852352303307b9e7e351e8b8a3643b77b05d81","mode":420},"callable_contract.py":{"bytes":1619,"sha256":"e8e9e7a8bef45d7dbf2ad6b8698bb9b53cc592d589aa843e5eeb1047b6433c4c","git_blob":"c17b540cf4ba19dedfdf34e506d3dd82611f2219","mode":420},"common.py":{"bytes":3125,"sha256":"6e2772a9d22a54cf051d2edbb095b34a2cb2fd2cc6914ed354701ae55c897d2c","git_blob":"86c77e5254d974872d46f00f2073a126fbdcb4c1","mode":420},"emit_callable.py":{"bytes":4151,"sha256":"7d2fd131fcf561758d45a4ac4b8a248a3525c830badb393c9edad13db069b373","git_blob":"30fea1008b2c57b700a0da1bdd5285e92e33aded","mode":420},"export.py":{"bytes":3549,"sha256":"477bf020731b9f03dea1504a8e1242d2c200261ba2cec9caa57a6fd0f0255740","git_blob":"802ca484568fc2c86133291800f7523ce25dca89","mode":420},"native/audit_controller_callable.composition.json":{"bytes":4869,"sha256":"ddc1ac53d85837d1e91d5e65ec1a7eda1ebc047a1059069526fde3d72a0ba940","git_blob":"a97a48af789e0650a015b9d375a12e2bec340b4e","mode":420},"native/audit_controller_callable.hepta":{"bytes":253792,"sha256":"fb452914cc38cdfcffb9cb1b6ca0a01328a893c5976eb2eb3144befdd7c3c54d","git_blob":"0eb2c9e5c058292abffd3bbcfb72e6101d35093f","mode":420},"native/audit_store_controller.composition.json":{"bytes":3676,"sha256":"9ac76549f86d0f92b23d980592eeaa3114ef3f5ed1461eb8ca7e012a4d50b627","git_blob":"26172da3806a8951861ddde1b6c8a785f8051700","mode":420},"native/audit_store_controller.hepta":{"bytes":107596,"sha256":"349410fca804c082da9d7297f771c4a24c8fcef2d1b3be47ad2524e77d64f3e9","git_blob":"e79044776b26158f391c2eee9734f52a63e6de2f","mode":420},"native/callable_compiler_pin.json":{"bytes":588,"sha256":"4e76be07a6250b5bda8f0e5b6ebd5687ab5bb1e8e0331a4b07c655a1ba2de33a","git_blob":"e51b14d58d201012d133418db24a307ca275f40e","mode":420},"process.py":{"bytes":5373,"sha256":"304cf26bada371b6dd8932efab09dd202445599299f2a3bb895a6629865b56df","git_blob":"645db7eafdd0cac5d04b566839b368c918ea85df","mode":420},"qualify_callable.py":{"bytes":6908,"sha256":"f991e85157f7f8616b247334208b6617a8e31fd022ceafccc26a6ed53ff92fbb","git_blob":"19f19f7af6c0596108a81c31aacb08713bc43c8d","mode":420},"read_callable.py":{"bytes":11245,"sha256":"149de4b95aad518cbba69f2eb661948746a5d212c755d60dd642c56dcdfde357","git_blob":"ebca55d50de35b1e49524a68c3476df5e39e66a5","mode":420},"read_capture.py":{"bytes":39044,"sha256":"7b7dad42e1759614262a6d7a4284935e4437c236368c3516274e00899e85b2ab","git_blob":"0fa491ca1223d9962e4a9ee25ec84dfb662de16e","mode":420},"read_only_guard.py":{"bytes":8848,"sha256":"621b8caa09f62f401c5816e3fbc07690f077feed7153552a720ced66150ce647","git_blob":"6e2bb795949307bc422eaef5a3eb75d15c4dd9d1","mode":420},"reader_controls.py":{"bytes":11746,"sha256":"aa32b9d6fdd0047b104a720177a5604d3cac01c5c78722ca2cb47beba85ebe2b","git_blob":"c944973606b32dec77102104d8bf63c731021ea3","mode":420},"recipes.py":{"bytes":2700,"sha256":"45cf1b9f242ad0f7ffaa311a172a9545638de5480bb534d05f8d7c20031b98a1","git_blob":"34a55cdffcc5ac745ebf04935047df91e8fa134c","mode":420},"reference/audit_store_lock.rs.txt":{"bytes":7395,"sha256":"6b80246ce3c2ff97edb71f6f70d21b692b801648c355427672780d01b5f14b25","git_blob":"be56d2d8dca9e4918b074978de0b62d5cc99b84f","mode":420},"reference/audit_store_tests.rs.txt":{"bytes":8045,"sha256":"88aa6e9b82591cab9d3198a820e54d0cc871191d65e99322ca0f660700524d2a","git_blob":"5f588fdbe42d94a26b5a65dd67afc01ce55e4514","mode":420},"reference/controller_extra_tests.rs.txt":{"bytes":5079,"sha256":"9b7e7ff59dcd47ccedab09e118a246263c207abe0f75c5d01c794ac6595310a4","git_blob":"5b66ab884fbe023662d447b6941ad544e0ccf6e0","mode":420},"reference/controller_host.rs":{"bytes":18762,"sha256":"1fe60572a6761f24e37b2841cc23a376b3ff4efd3b86843585f5ac5934369dfc","git_blob":"d85f93c9d601e1e561d1dd90ed60e214c9d360a6","mode":420},"reference/native_tests.rs":{"bytes":676,"sha256":"3cdd37a168a53ca86dc46d2031fcb7a592bd151e6c0f2fdcf2de2c34f26e8118","git_blob":"80903dfe7919c29c23f5535bd2c739a496e38504","mode":420},"reference/original_tests.rs":{"bytes":1050,"sha256":"bdff79a5cb610490199ed2b03f9e20adc3659b96c7d0545d1438392e21f3d32f","git_blob":"3ebd6e554f73687c5a04a06c99734ee2eebc3fae","mode":420},"reference/target/src/mcp/runtime/request_audit.rs":{"bytes":68414,"sha256":"b5189f2923153ffa83d0b45a7cdf89873b0f17ebbe6ec1b174c05bab291d73da","git_blob":"984668cfdfcee0a7eb00de14e02086f5ad90bcc0","mode":420},"reference/target/src/mcp/runtime/request_audit_tests.rs":{"bytes":47327,"sha256":"a066822705a713929dd2791f1e889f9cf6b7c16567d0d6e71a4c4946b20e14a7","git_blob":"d0e1daf6e06caa62a411ae7c233a2ae44fb2f485","mode":420},"run_gate.py":{"bytes":5238,"sha256":"7bea4732017622befe3e6aef931ed930661733727f38d84c1688473dfe6c923d","git_blob":"99e19abdf11a1a4426fa8cd38c174846ee9b58dc","mode":420},"scripts/hia_native_build.py":{"bytes":16538,"sha256":"839a1eb7aed16df369a4ae80291680b2754c6794dac3c3029027a5df4f4e8f3f","git_blob":"104126933484122272d72ce916c2a00c6c1ab085","mode":420},"scripts/hia_native_loader.py":{"bytes":12849,"sha256":"367d600d808eaf95fe4e76d8d999b29ba46f1a3969e79fe20b70e23f79a48e96","git_blob":"5578486e3a769c699c35edd96137b41bae55d9c7","mode":420},"verify_readonly.py":{"bytes":1233,"sha256":"36d67ab4039f8952378780a08aa03ddc09b3540f421a759d559af7b9b176468a","git_blob":"1b9a38e5d61a6c2228632526f44d0e1253bd01b7","mode":420}}''')
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
    assert evidence["journal"]["contexts"]==13 and evidence["journal"]["actors"]==399
    assert evidence["journal"]["completed_operations"]==774
    assert evidence["journal"]["api_starts"]=={"0":13,"1":273,"2":113,"4":105,"5":270}
    assert evidence["journal"]["outcomes"]=={"0":384,"3":375,"5":3,"6":12}
    assert evidence["journal"]["clock_mappings"]==128 and evidence["journal"]["actual_original_native_observations"]==4
    assert evidence["emission"]["calls"]==7 and evidence["emission"]["refusals"]==6
    assert evidence["original_tests"]==9 and evidence["native_tests"]==10
    assert evidence["callable_emission"]["calls"]==9 and evidence["callable_emission"]["refusals"]==8
    assert evidence["observer_free"]["calls"]==15 and evidence["observer_free"]["refusals"]==9
    assert evidence["observer_free"]["ordinary_calls"]==6
    assert evidence["observer_free"]["observer_pointer"]==evidence["observer_free"]["foreign_effect_calls"]==0
    assert evidence["observer_free"]["complete_native_queue_disposal"] is True
    assert set(evidence["build"]["modules"])=={"audit-store-controller","audit-native-sync","audit-controller-callable"}
    assert evidence["build"]["compiler_files"]==1080
    assert evidence["controls"]==dict(status="PASS",refusals=12,relocated_admissions=2,
        post_refusal_admissions=2,guard_proofs=16,guards_per_proof=12,native_or_rust_executions=0,reader_writes=0)
    assert evidence["public_handler_qualified"] is False and evidence["whole_runtime_replaced"] is False
    return dict(entries=len(proof["before"]),guard_refusals=12,complete_before_after_equal=True,
                native_or_rust_executions=0,reader_writes=0,status=STATUS,
                original_tests=9,native_tests=10,contexts=13,actors=399,completed_operations=774,
                journal=evidence["journal"],callable_emission=evidence["callable_emission"],observer_free=evidence["observer_free"],public_handler_qualified=False,whole_runtime_replaced=False)
def main():
    started=time.monotonic()
    own=Path(__file__).read_bytes()
    assert git_blob(own)==sys.argv[1]
    assert ROOT.is_dir() and ROOT.resolve()==ROOT
    assert not (ROOT/"expanded").exists() and not (ROOT/"zip").exists()
    archive=Path("/tmp/hia-audit-callable-6780-ci-readback-v1/complete.zip")
    got=pin(archive)
    assert got==ZIP_PIN
    put(ROOT/"DRIVER.json",dict(git_blob=git_blob(own),bytes=len(own),sha256=sha(own),
        native_or_rust_executions=0,source_head=HEAD,inner_reader_timeout_seconds=180))
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
    assert set(zip_files)=={"audit-store-controller.tar.gz","audit-store-controller-independent/independent-reader.stdout",
        "audit-store-controller-independent/independent-reader.stderr","audit-store-controller-independent/processes.json",
        "audit-store-controller.tar.gz.json","audit-store-controller-export.stdout","audit-store-controller-export.stderr"}
    receipt=json.loads((zip_dir/"audit-store-controller.tar.gz.json").read_bytes())
    assert receipt["all_members_reread"] is True and receipt["gate_status"]==STATUS
    assert receipt["source_manifest_sha256"]==MANIFEST_SHA and receipt["semantic_executions"]==0
    TAR_PIN.update({key:receipt[key] for key in ("bytes","sha256")})
    assert zip_files["audit-store-controller.tar.gz"]==TAR_PIN
    put(ROOT/"ZIP_FILES.json",zip_files)
    print(json.dumps(dict(stage="full-archive-relocation",zip_bytes=got["bytes"])),flush=True)
    expanded=ROOT/"expanded";expanded.mkdir()
    observed={}
    with tarfile.open(zip_dir/"audit-store-controller.tar.gz","r|gz") as source:
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
    previous=json.loads((zip_dir/"audit-store-controller-independent/independent-reader.stdout").read_bytes())
    existing=guard_summary(previous)
    del previous
    archive_report=dict(schema="hepta.audit-store-controller.independent-archive-read.v1",head=HEAD,
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
    put(ROOT/"READBACK.json",dict(schema="hepta.audit-store-controller.ci-readback.v1",
        archive=archive_report,driver=dict(bytes=len(own),sha256=sha(own)),driver_git_blob=git_blob(own),
        source_head=HEAD,source_manifest_sha256=MANIFEST_SHA,host="github-actions-independent-readonly",root=str(ROOT),
        process=row,reader=summary,elapsed_seconds=time.monotonic()-started,
        full_proof_file="reader-processes/independent-reader.stdout",
        native_or_rust_executions=0,whole_runtime_replaced=False))
    print(json.dumps(dict(status="PASS",root=str(ROOT),source_head=HEAD,
        proof=row["stdout"],reader=summary,elapsed_seconds=time.monotonic()-started,
        readback=pin(ROOT/"READBACK.json")),sort_keys=True),flush=True)
if __name__=="__main__":main()
