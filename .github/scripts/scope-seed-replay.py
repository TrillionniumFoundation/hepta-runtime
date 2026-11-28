"""Replay the unchanged complete OS-scope domain on retained exact binaries."""
from pathlib import Path
import hashlib,json,os,subprocess,sys,time,zipfile
root=Path(__file__).resolve().parents[2]
output=Path(os.environ["RUNNER_TEMP"])/"scope-seed-replay";output.mkdir()
archive=Path(os.environ["RUNNER_TEMP"])/"scope-seed-source.zip"
def sha(p):
    with Path(p).open("rb") as f:return hashlib.file_digest(f,"sha256").hexdigest()
assert archive.stat().st_size==266209549
assert sha(archive)=="053de0a1ef8d7b2b46460d9dd9e95a67aa5e12ebe5515c9701bf74f80c80dd2d"
with zipfile.ZipFile(archive) as z:
    manifests=[n for n in z.namelist() if n.startswith("build/composition/") and n.endswith("/manifest.json")]
    matches=[n for n in manifests if any(r.get("name")=="scope-os-hex-fixture" for r in json.loads(z.read(n)).get("profile",[]))]
    assert len(matches)==1
    name=matches[0];prefix=str(Path(name).parent)+"/"
    for member in z.namelist():
        if member.startswith(prefix):
            relative=Path(member).relative_to(prefix)
            assert ".." not in relative.parts and not relative.is_absolute()
            dest=output/"scope"/relative;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(z.read(member))
    original=output/"original-1.95.elf"
    original.write_bytes(z.read("operation-scope-os-reference/target/release/hia-operation-scope-os-reference"));original.chmod(0o755)
    (output/"prior-packer.json").write_bytes(z.read("operation-scope-os-reference/scope-os-packer.json"))
manifest=output/"scope/manifest.json"
native=manifest.parent/json.loads(manifest.read_text())["executable"];native.chmod(0o755)
assert sha(original)=="164714d312b2c98c73a80741305cac12c9270a7e96d2fdd0f544508b7a5ed1d9"
assert sha(native)=="cb0e3e7fbd8ad0045998bcc24f8ba594f5f1258b8bed52c4c4fcace7861afa7d"
sys.path.insert(0,str(root/"scripts"))
import hia_native_scope_os_qualification as q
artifact=q.exact_profile(root,manifest)
before={n:sha(root/"tests/hia_native"/n) for n in q.KERNEL_SOURCES}
checks=[]
for label,paired in (("native",False),("original-1.95",True)):
    receipt=output/(label+".json")
    env=dict(os.environ,HIA_REFERENCE_RUNTIME=str(root),HIA_SCOPE_OS_SOURCE_ROOT=str(root),HIA_SCOPE_OS_MANIFEST=str(manifest),HIA_SCOPE_OS_RESULT=str(receipt))
    if paired:
        env.update(HIA_SCOPE_OS_REFERENCE_BINARY=str(original),HIA_SCOPE_OS_REFERENCE_SHA256=sha(original))
    started=time.monotonic()
    run=subprocess.run([sys.executable,"-I","-B",str(root/"tests/hia_native/test_scope_os.py")],env=env,capture_output=True,timeout=180)
    (output/(label+".stdout")).write_bytes(run.stdout);(output/(label+".stderr")).write_bytes(run.stderr)
    check={"label":label,"returncode":run.returncode,"wall_seconds":time.monotonic()-started,"timeout_seconds":180}
    checks.append(check)
    if run.returncode:raise SystemExit(run.stderr.decode(errors="replace"))
    report=json.loads(receipt.read_bytes())
    check["evidence"]=q.kernel_evidence(root,report,artifact,original_binary_sha256=sha(original) if paired else None)
    check["receipt_sha256"]=sha(receipt)
assert before=={n:sha(root/"tests/hia_native"/n) for n in q.KERNEL_SOURCES}
result={"status":"PASS","aggregate_qualification_run":False,"fresh_compilation":False,"runtime_production_activated":False,
"ci_source_archive_sha256":sha(archive),"native_executable_sha256":sha(native),"original_executable_sha256":sha(original),
"source_sha256":before,"checks":checks,"platform":os.uname()._asdict() if hasattr(os.uname(),"_asdict") else list(os.uname())}
(output/"result.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
print(json.dumps({"status":"PASS","checks":[{k:v for k,v in r.items() if k!="evidence"}|{"counts":r["evidence"]["counts"],"seed_profile":r["evidence"]["original_standard_library_kernel_profile"]} for r in checks]}))
