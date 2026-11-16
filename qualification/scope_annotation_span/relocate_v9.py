"""Independent complete archive relocation of frozen annotation V9; no native/Rust replay."""
from pathlib import Path, PurePosixPath
import hashlib, json, os, stat, sys, tarfile, time, urllib.request, zipfile
sys.dont_write_bytecode = True
ROOT=Path("/home/qq/hepta-runtime-migration-6780/annotation-v9-readback-20261116")
HEAD="00f7a5b51a6f84675b24ed06f09430ecfca6f8be"
MANIFEST_SHA="1dcb9f748c49ebaeaa3cf018ac22989cab615c73689a08449c05c89453372697"
ZIP_PIN={"bytes":241661425,"sha256":"943df67c0662afd8a66dbf2580ef6761ee0e6cc63d7030f753fd160b154c12c7"}
TAR_PIN={"bytes":245013157,"sha256":"5a332e6c54612072361a48f41a1d2e0d6537e2efeb6d38d9035fb2b113993845"}
STATUS="COMPLETE_ORIGINAL_COMPARISON_SPAN_ANNOTATION_PASS"
SOURCE_PINS=json.loads(r'''{"authoring/author_constructor_fast.py":{"bytes":6428,"sha256":"aa45bb3d83f06ae3349b4679c4b8ef2725602bba2b30f17d47a93d8abb832130","git_blob":"6888c9a7116aba76c8ce79c7153d45cc3de456df","mode":420},"authoring/author_scope_span.py":{"bytes":12085,"sha256":"fceb5adc65810e3303128ab549c4d433dc37352baf3ab826b4dc82ae6963aede","git_blob":"8f577344b632c58a23cfec0240f2fdd5830ec640","mode":420},"authoring/retained_transform.json":{"bytes":4339,"sha256":"c2395117846244fc26a87a4a2c521d81bad612b7183eb132f7d68eea9d6e8e0b","git_blob":"373429e344a409b940a561cf21477f4649b86d2b","mode":420},"authoring/scope_span.pseudo":{"bytes":21841,"sha256":"c81d229649c762ccdb4314b92cec9d83e7d19ad401cdc9004ce17516fd0e4119","git_blob":"c99b7a2fe6851c214ca5f2dfe8a6edbe9c4328c6","mode":420},"BASELINE_CONTROL_COVERAGE.json":{"bytes":3124,"sha256":"97ec67690b0c53b577ff39f4c8e1dd2221ae92edbe5812673bbce9f210777e26","git_blob":"682f0265e2e7329da4517406361038ce9ed9dc30","mode":420},"build.py":{"bytes":2956,"sha256":"fd1c4ca3d7cf45d2f489e02913caf83cf4eec16d07b6e524d2516e5b8ba238a0","git_blob":"5b84c31e687edc58dec46640a1428f8e083e804c","mode":420},"capture.py":{"bytes":14408,"sha256":"972d59613aca916e0ecd8846c5fc13ccefb337374c0bed21fbe1f76f63daeaf6","git_blob":"db0d0bf2b68e9a249ecccf993823a186038a6e60","mode":420},"cases.py":{"bytes":7543,"sha256":"1a53a26860d2c55f5768da057d1affb2c8e2afade24c2ca9eb3e08bda3e1dd3b","git_blob":"3cc55b61e35e01fd60764b738248597664a34175","mode":420},"CONTROL_DOMAIN.json":{"bytes":2163,"sha256":"54f8caf8280297b23b264ba749d9f8b8e5c5488cec86c6f0e1ec08b45cb01bd9","git_blob":"4b045d05aabb955c737cd98177bfa775aa68f501","mode":420},"controls.py":{"bytes":14661,"sha256":"a29ad6b0be8cea6732d58ff6a539107c04fb30768bb129608939e790763fb987","git_blob":"8c2c137036e542a4cfccadf49b5143a64b4d175d","mode":420},"COPIED_INPUTS.json":{"bytes":2440,"sha256":"7f11296ddfb6ff4a4fe44fa83ea3d407aa98a828e4bde5ea8e46e7c50c57042e","git_blob":"f6b86bd03b668cf8e62cf9890770b3ccd76f0c6a","mode":420},"DOMAIN.json":{"bytes":268682,"sha256":"38e00d59ee161c045bf0131cd8c23d299d2e16a639e4f805d08108dce6f41af7","git_blob":"7a3ca833a0a29abb0d6bb1db80eb4277c0b67b41","mode":420},"evidence_controls.py":{"bytes":22426,"sha256":"5fd77bce7a03bc46622887fcd4c305985eeb859bae56279b38695fe87ff2d013","git_blob":"0c881f9bc2f2377c973f03098039f603767db6ef","mode":420},"export.py":{"bytes":3547,"sha256":"417a1d5aeed9f51c91bb0a247df5e7bec4ae4138bebaa8f456f165382d21a224","git_blob":"390ae990707d040718adf346cd733c2c4e2501b6","mode":420},"extract_reference.py":{"bytes":4253,"sha256":"8910ac93473951be7125e44d1da186df1f4e494c111ba2a89fa16c7ea522e7f2","git_blob":"ee354d4d16a660dbdc94d8ee2e7e4db26d9a8f04","mode":420},"names.json":{"bytes":898,"sha256":"bfe473c89d762da2e1270a9657f2a33af170b27857e7c1ce44e15e695cbc70e8","git_blob":"2da76c9708ef7ff288da1e3b8d9455b37c86819d","mode":420},"native/scope_annotation_span.composition.json":{"bytes":3922,"sha256":"352866937678f345b8870f46609981d02666f85472e8a25b143d141a0212f299","git_blob":"0480ff0c8c7a203ac6d559ec90ed10296a467d1e","mode":420},"native/scope_annotation_span.hepta":{"bytes":193087,"sha256":"6404cefe1a077b0d8d557775b5eb08f09ede4b5c792462f23dedcd8c744e5519","git_blob":"f1240282b9fde83495cd5ed50d7ec8983c313a17","mode":420},"native/serde_error_span_composition.json":{"bytes":4867,"sha256":"46e149ba4db7571582936232934a5db994a0644262f1ceaf644308a5dde7523d","git_blob":"53ae9cb0611e9b9385d6312a99da200fda9da794","mode":420},"native/serde_error_span.hepta":{"bytes":230793,"sha256":"460e2e57008e3960ee55c9feaabec3b19abd08b3336b9c5b0b98df61d49b1d26","git_blob":"4b3714a62457de5c33e79a5f21a7c12757097d31","mode":420},"native/serde_error.hepta":{"bytes":225712,"sha256":"14eea1ebc4bd12cb10e961d61bea58dded9befb15a3c67191fe6301577bc00e9","git_blob":"515fea3c2c2f853a800e5559ebbbea35bc869008","mode":420},"native/serde_json_span.hepta":{"bytes":379164,"sha256":"7a9355792f5044c9887c4194df5bc169664cf08fa8d084e8480c941fa2416a41","git_blob":"64a3b94044b9cda827f2dc12e68d2d2f049c4b67","mode":420},"native/serde_json.hepta":{"bytes":342221,"sha256":"ef9dd3a567acf523257c4245c022b8cefa9b3ddb83075e826f129b1a1f341d18","git_blob":"e6502141f28e6f4a25434d35b9db5a17df473325","mode":420},"native/text_budget.hepta":{"bytes":47464,"sha256":"89df7b4320fdbd3525450e9446267ae3d54a5b62660d8904fe8f09be36a7fbf9","git_blob":"53446a668847b04353833c240feab89aa115b5ad","mode":420},"native/text_result_constructor.hepta":{"bytes":30139,"sha256":"785315acd60821313e4683df67e0b83c59c572d798ad3849efaa3108a9e36d58","git_blob":"fd96d0d1b53ad910f14dec96ab57a166ab91496b","mode":420},"native/typed_result_json.hepta":{"bytes":365892,"sha256":"a9dfe2fec3f35b2ef2bcfaec56229007c75301cccb06a96a36691dc361aa0bec","git_blob":"69a95c2d2926c65e9a6bcc43828a701554cb9bbc","mode":420},"original_evidence_controls.py":{"bytes":6640,"sha256":"019d13817851edbe4cfea83f38311d780070c55f75c2d8bfb1af99a680027788","git_blob":"dd23e5e477e92f7d40230b1941312ec74900b675","mode":420},"original_reader.py":{"bytes":12481,"sha256":"a6e166cf33fef769c6f5bf1d4d3ca3faea7a04bfc4a32a86f18ea3b179721767","git_blob":"36e4006669333ed007423d2ec111a80bbb934da6","mode":420},"parallel_reader.py":{"bytes":13079,"sha256":"4df740c8cd5885314f5957f02d80840c4d7003bdd205dd8b6ed6c60888f2a32d","git_blob":"d12512db3c856047ec843afc2f109b1aaa143b6f","mode":420},"provenance/constructor-fast-proof.json":{"bytes":1012,"sha256":"f98b67be4b4123a1f22beb4c902327e72b7b9b6b31daead209be35fefba51ae8","git_blob":"95b37bb8cb8992f363b9faefa6dd63a686ae0cfc","mode":420},"provenance/constructor-fast-reuse-index.json":{"bytes":1978,"sha256":"f3f2e047d846617f1940f7c26bf9e3b98dd3c04b120c40d835632f98fd75e032","git_blob":"cd03fb61294df4053312ff2ddb397c98652c30f8","mode":420},"provenance/owner-allocation-observation.json":{"bytes":15025,"sha256":"24c9e6fdc9eace50b8fa891cf918b755db55c4b234e5ee6a73062caaba0e1fec","git_blob":"f4384100199b149cd8ae61908929f7fc3756cfef","mode":420},"provenance/value-paired-span-index.json":{"bytes":5720,"sha256":"70cb210a9b360ca83dc94103b162ca4103a3bc68354fb7c57a28c42b922b3d4b","git_blob":"ffc9f1da7ce1f6ff0df7551d0febf3506cc41787","mode":420},"provenance/value-source-and-numeric-index.json":{"bytes":7318,"sha256":"108b36555ab688140d70d2420639fdabc99fba81724d50ee4c3f6af098573ec7","git_blob":"d6a18e63f0863f5c56687ae4074d4865b4a643f5","mode":420},"qualify.py":{"bytes":29586,"sha256":"4448ac09ff9f483ff0d056d7e75bf1d099d9cbc8e2bebd5a9ff42c4d971d5f75","git_blob":"5bd3b278dd96106e74d3cb3a5b5204e88254ce5a","mode":420},"read_capture.py":{"bytes":24681,"sha256":"54cc0cf630138b19e41825cfad82159fddb53cc24ce93139a5a9c578d51fbccc","git_blob":"854047c1add74175c7b5656c8574355bd56fd255","mode":420},"read_only_guard.py":{"bytes":8848,"sha256":"621b8caa09f62f401c5816e3fbc07690f077feed7153552a720ced66150ce647","git_blob":"6e2bb795949307bc422eaef5a3eb75d15c4dd9d1","mode":420},"README.md":{"bytes":14416,"sha256":"26b4db34a36112215a1a1bb0b72dd2a40e62f18b3254bf04b5ef183912326af7","git_blob":"d23217fa7300476f51dff263cf44cee983a499c3","mode":420},"reference/Cargo.toml":{"bytes":513,"sha256":"a0d3408a3f242372ea2e7c3d5cab6f23304c5102fab5ec5c4c34f887608e7c8f","git_blob":"95d80f88f1473e94e6273b299ceea14117ee4d2f","mode":420},"reference/extraction.json":{"bytes":1679,"sha256":"c8dcd754a44a35ec0d70acc38f8a746cbf78b1be0a964fda4e64ea85623e3499","git_blob":"c27921d574e3c7ed46fb05d266b9bdfab534b73c","mode":420},"reference/main.rs":{"bytes":11299,"sha256":"387fe259ce199ac0802f7b09c5852aaf0a91bb0b4da12d92c1efeef22a06ae2a","git_blob":"53f8e902e99b413f33385597d1e40919c5c87fee","mode":420},"reference/observer.rs.txt":{"bytes":5567,"sha256":"4c8a5c4d5ccac74ef2453506859993ff5a7330b24c365cc181616ddcf980331f","git_blob":"670a85c374cf2645ea60139a18ef62196adb3ac5","mode":420},"reference/sdk/src/model.rs":{"bytes":225570,"sha256":"ac438543401b6b9d60021fc044dcf27b446df9539e837c6fecdf16a670091b9a","git_blob":"5a493d45e4a7e95f3ce2a477cb4d7f5180342f6e","mode":420},"reference/sdk/src/model/content.rs":{"bytes":15045,"sha256":"dee55056d587a4c4ee56114526167bb8cc7af8eebb4fc621465913330fe622b4","git_blob":"11b2f0e5358a7881d4f19f82acdbf1d66fe7a342","mode":420},"reference/target/Cargo.lock":{"bytes":90188,"sha256":"1509860cac0e7f26e6a845edfec1c87ae3bd92380ecaa357457e5263e861d631","git_blob":"23768e4ae7b4ba44d568134e91476b1c82069887","mode":420},"reference/target/Cargo.toml":{"bytes":4259,"sha256":"bf00111f6ec88df9df4d0d1d14c125a64ce4f6bdc6724ba20e70498f56dcae7f","git_blob":"af0960b6ad360f26589de66e26cdcabe2fb3266f","mode":420},"reference/target/src/mcp/runtime/caller_scope.rs":{"bytes":8967,"sha256":"1db8a3f4235339d8a7aef6e247ddc8f42f4791a26efe4dd298490421b8ca1d9a","git_blob":"ea360b7627695d212fd4fbe9f7e71d1dc8858591","mode":420},"REVISION.json":{"bytes":20069,"sha256":"65322631dd47b2f802de94d21d214346dd6fc15ad73a793b75a729f79184beb7","git_blob":"a63646ea278974a918d28f370df4564f7cce08b5","mode":420},"run_gate.py":{"bytes":5883,"sha256":"b313a8528945f33f3d444921af42c8a1ec9c1f6dc618a182adcb74679a62e6f7","git_blob":"c8b0fd981922d70f5f3034355970e00b37e485d8","mode":420},"run_native.py":{"bytes":4518,"sha256":"9fd5146e5368b0b39a97452b144f120ab2ddf87a6447cafd17b4b9ad9fed3786","git_blob":"b873736531a88bc87a0aa886230705c470452678","mode":420},"rust_reference.py":{"bytes":11945,"sha256":"fbbeb52a23e72c334f21f87c88c90f083f5ce58018da8e4ec15dc13fe6877118","git_blob":"cd7fd8aa0e8be1c9f9228cb1787eabf67c9ed5d9","mode":420},"scripts/author_serde_error_span.py":{"bytes":12176,"sha256":"4cde93c820d7c0b3ac09d34f207d540b845b3bbf3208a0619b9b0f0a67192c13","git_blob":"6393ce75cb5f0597da3a45d2b5fa89a904e6602e","mode":420},"scripts/hia_native_build.py":{"bytes":16538,"sha256":"839a1eb7aed16df369a4ae80291680b2754c6794dac3c3029027a5df4f4e8f3f","git_blob":"104126933484122272d72ce916c2a00c6c1ab085","mode":420},"scripts/hia_native_loader.py":{"bytes":12849,"sha256":"367d600d808eaf95fe4e76d8d999b29ba46f1a3969e79fe20b70e23f79a48e96","git_blob":"5578486e3a769c699c35edd96137b41bae55d9c7","mode":420},"scripts/serde_error_display_source.py.txt":{"bytes":1976,"sha256":"b6a92e6454c6db84185e095e92a12903f220b4545a4fff2ae994ce9490c6be28","git_blob":"b69fa34974b99687b95aaf232fb7484c519eb632","mode":420},"scripts/serde_error_parser_source.py.txt":{"bytes":11943,"sha256":"085ada65c5dc695f7633aeff38ec4431c4e9a7c4eef85c02fb4dffe3ad8e8267","git_blob":"5db93cc4f9f493e34371c28b8e852286db61fb02","mode":420},"scripts/serde_error_string_source.py.txt":{"bytes":4712,"sha256":"09413ccb910dc9a810ab5ed5030c635a1b7f4b4c23b1292840e634684e8425f8","git_blob":"0ce8557ccc5f0b3950c1e82a225074c812598bc6","mode":420},"SOURCE_MANIFEST.json":{"bytes":9108,"sha256":"1dcb9f748c49ebaeaa3cf018ac22989cab615c73689a08449c05c89453372697","git_blob":"34064515db624f7bbbc32a6375cc16bf9918c579","mode":420},"SPAN_PARENT.json":{"bytes":4390,"sha256":"18ff7151e9b83048613553dc0b9dfdd87f9bfcdc24f15b5fcbe54f8d124c827a","git_blob":"4296915cd74a5350d08297c26698d620e2b3e640","mode":420},"tests/baseline_cases.py":{"bytes":8584,"sha256":"4f487a36f0135bae47b6040a5be44a8435c7ff3436e1e9d08454a7b6cc1f7c7f","git_blob":"1e80c91633ab1b6fe033bf88f3607b1a0d83e3b6","mode":420},"verify_readonly.py":{"bytes":1622,"sha256":"04d29abdd806c97b85d96dd0444ea99229e263ef33d3d57eafb970dfffd96f94","git_blob":"f3f2341dd7e602f768ed84f54136ab5136e2b1e1","mode":420}}''')
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
    assert proof["evidence"]["original_qualified"] is True
    assert proof["evidence"]["native_reader_controls"]["refusals"]==33
    assert proof["evidence"]["original_reader_controls"]["refusals"]==12
    return dict(entries=len(proof["before"]),guard_refusals=12,complete_before_after_equal=True,
                native_or_rust_executions=0,reader_writes=0,status=STATUS,
                original_qualified=True,public_handler_qualified=False,whole_runtime_replaced=False)
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
    put(ROOT/"DOWNLOAD.json",dict(artifact_id=14256129090,run_id=43927794725,head=HEAD,**got,
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
    assert set(zip_files)=={"annotation-span-v2.tar.gz","annotation-independent-reader.json",
        "annotation-span-v2.tar.gz.json","annotation-export.stdout","annotation-export.stderr"}
    assert zip_files["annotation-span-v2.tar.gz"]==TAR_PIN
    put(ROOT/"ZIP_FILES.json",zip_files)
    print(json.dumps(dict(stage="full-archive-relocation",zip_bytes=got["bytes"])),flush=True)
    expanded=ROOT/"expanded";expanded.mkdir()
    observed={}
    with tarfile.open(zip_dir/"annotation-span-v2.tar.gz","r|gz") as source:
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
    assert len(observed)==21797 and sum(r["bytes"] for r in observed.values())==1723432506
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
    previous=json.loads((zip_dir/"annotation-independent-reader.json").read_bytes())
    existing=guard_summary(previous)
    del previous
    archive_report=dict(schema="hepta.scope-annotation-v9.independent-archive-read.v1",head=HEAD,
        source_manifest_sha256=MANIFEST_SHA,zip=ZIP_PIN,tar=TAR_PIN,files=len(observed),
        logical_bytes=sum(r["bytes"] for r in observed.values()),complete_member_bytes_and_modes_equal=True,
        source_git_blobs_verified=len(SOURCE_PINS),retained_ci_independent_reader=existing,
        native_or_rust_executions=0,whole_runtime_replaced=False)
    put(ROOT/"ARCHIVE.json",archive_report)
    print(json.dumps(dict(stage="guarded-readonly",archive_files=len(observed))),flush=True)
    sys.path.insert(0,str(source))
    from rust_reference import Recorder
    recorder=Recorder(source,ROOT/"reader-processes")
    stdout,row=recorder.run("independent-reader",
        [sys.executable,"-I","-B",str(source/"verify_readonly.py"),"--output",str(capture),
         "--source-manifest-sha256",MANIFEST_SHA,"--require-evidence-controls"],timeout=180)
    assert row["completed"] and not row["timed_out"] and row["exit_code"]==0 and row["stderr"]["bytes"]==0
    proof=json.loads(stdout)
    summary=guard_summary(proof)
    assert proof["pid"]==row["pid"] and proof["ppid"]==row["parent_pid"] and proof["pgid"]==row["pgid"]
    put(ROOT/"READBACK.json",dict(schema="hepta.scope-annotation-v9.ai395-readback.v1",
        archive=archive_report,driver=pin(ROOT/"driver.py"),driver_git_blob=git_blob(own),
        source_head=HEAD,source_manifest_sha256=MANIFEST_SHA,host="ai395",root=str(ROOT),
        process=row,reader=summary,elapsed_seconds=time.monotonic()-started,
        full_proof_file="reader-processes/independent-reader.stdout",
        native_or_rust_executions=0,whole_runtime_replaced=False))
    print(json.dumps(dict(status="PASS",root=str(ROOT),source_head=HEAD,
        proof=row["stdout"],reader=summary,elapsed_seconds=time.monotonic()-started,
        readback=pin(ROOT/"READBACK.json")),sort_keys=True),flush=True)
if __name__=="__main__":main()
