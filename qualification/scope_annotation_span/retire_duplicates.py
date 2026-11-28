from pathlib import Path
import hashlib,json,shutil,stat,tarfile,zipfile
root=Path("/home/qq/hepta-runtime-migration-6780/annotation-v9-readback-20261116")
def pin(path):
    with path.open("rb") as f:digest=hashlib.file_digest(f,"sha256").hexdigest()
    return dict(bytes=path.stat().st_size,sha256=digest)
def put(value):(root/"RETIREMENT.json").write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
zpin=dict(bytes=241661425,sha256="943df67c0662afd8a66dbf2580ef6761ee0e6cc63d7030f753fd160b154c12c7")
assert pin(root/"complete.zip")==zpin
assert pin(root/"READBACK.json")==dict(bytes=3286,sha256="cc3b4a68dab959afab479e71a55d41de6e7791fc37d4766ad38198dfbaa29563")
rb=json.loads((root/"READBACK.json").read_bytes())
assert pin(root/rb["full_proof_file"])=={k:rb["process"]["stdout"][k] for k in ("bytes","sha256")}
expanded=root/"expanded";members=root/"zip"
expected=json.loads((root/"TAR_FILES.json").read_bytes())
zexpected=json.loads((root/"ZIP_FILES.json").read_bytes())
seen={};zseen={};total=0
def compare(stream,path):
    global total
    info=path.lstat()
    assert stat.S_ISREG(info.st_mode) and path.resolve()==path.absolute()
    digest=hashlib.sha256();count=0
    with path.open("rb") as disk:
        while block:=stream.read(1<<20):
            assert disk.read(len(block))==block
            digest.update(block);count+=len(block)
        assert disk.read(1)==b""
    assert count==info.st_size
    total+=count
    return dict(bytes=count,sha256=digest.hexdigest())
with zipfile.ZipFile(root/"complete.zip") as archive:
    for member in archive.infolist():
        assert not member.is_dir() and member.filename in zexpected and member.filename not in zseen
        with archive.open(member) as stream:zseen[member.filename]=compare(stream,members/member.filename)
    assert zseen==zexpected
    with archive.open("annotation-span-v2.tar.gz") as compressed,tarfile.open(fileobj=compressed,mode="r|gz") as tar:
        while member:=tar.next():
            assert member.isfile() and member.name in expected and member.name not in seen
            path=expanded/member.name
            assert path.resolve().is_relative_to(expanded)
            with tar.extractfile(member) as stream:identity=compare(stream,path)
            assert stat.S_IMODE(path.stat().st_mode)==member.mode
            seen[member.name]={**identity,"mode":member.mode};tar.members.clear()
assert seen==expected and len(seen)==21797
for directory,index in ((expanded,expected),(members,zexpected)):
    assert directory.resolve()==directory.absolute()
    assert {p.relative_to(directory).as_posix() for p in directory.rglob("*") if p.is_file()}==set(index)
    assert all(stat.S_ISDIR(p.lstat().st_mode) or stat.S_ISREG(p.lstat().st_mode) for p in directory.rglob("*"))
report=dict(schema="hepta.annotation-v9.duplicate-retirement.v1",status="ADMITTED",
    source_head="00f7a5b51a6f84675b24ed06f09430ecfca6f8be",retained_zip=zpin,
    complete_direct_archive_file_byte_comparisons=len(seen)+len(zseen),all_tar_modes_equal=True,
    retired_logical_bytes=total,planned_directories=["expanded","zip"],
    native_or_rust_executions=0,unique_source_or_evidence_removed=False,whole_runtime_replaced=False)
put(report)
shutil.rmtree(expanded)
shutil.rmtree(members)
assert pin(root/"complete.zip")==zpin
report.update(status="COMPLETED",retained_artifact_reverified=True)
put(report);print(json.dumps(report,sort_keys=True))
