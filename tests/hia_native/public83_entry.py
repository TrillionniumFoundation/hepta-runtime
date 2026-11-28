"""Exercise the installed default build entry using this CI run's fresh members."""
from pathlib import Path
import argparse,hashlib,json,os,subprocess,sys,time
sys.dont_write_bytecode=True
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
def doc(path):return json.loads(path.read_bytes())
def pin(path):
    raw=path.read_bytes();return dict(bytes=len(raw),sha256=SHA(raw))
def graph_rows(root):
    return {p.relative_to(root).as_posix():pin(p) for p in sorted(root.rglob("*")) if p.is_file()}
def verify(source,run,output):
    reference=doc(run/"public/BUILD.json");current=doc(output/"build/BUILD.json");receipt=doc(output/"PROCESS.json")
    assert receipt["status"]=="ACTUAL_MAIN_DEFAULT_ENTRY_CAPTURED"
    assert receipt["exit_code"]==0 and receipt["outer_timeout_seconds"] is None
    for stream in ("stdout","stderr"):assert pin(output/(stream+".bin"))==receipt[stream]
    assert not (output/"stderr.bin").read_bytes()
    assert current["status"]=="NATIVE_BUILD_PASS" and current["default_public_entrypoint"] is True
    assert current["physical_images"]==reference["physical_images"]==83
    assert current["fresh_member_compiles"]==0 and current["checked_reused_members"]==83
    assert reference["fresh_member_compiles"]==83 and reference["checked_reused_members"]==0
    expected=graph_rows(run/"graph-source");assert len(expected)==172 and expected==receipt["source_files"]
    for name,identity in expected.items():assert pin(source/name)==identity,name
    folder=output/"build/build/public-connection";manifest=folder/"manifest.json"
    assert pin(manifest)["sha256"]==current["manifest_sha256"]
    md=doc(manifest);ref=doc(run/"public/build/public-connection/manifest.json")
    assert md["source_binding"]==ref["source_binding"]
    assert md["extra_table"]==ref["extra_table"] and md["implemented_tools"]==ref["implemented_tools"]
    assert len(md["members"])==len(ref["members"])==83
    for actual,old in zip(md["members"],ref["members"],strict=True):
        assert actual["fresh_compile"] is False and old["fresh_compile"] is True
        for key in ("name","source","source_sha256","image_sha256","image_bytes","buffer_profile"):
            assert actual[key]==old[key]
    binary=folder/md["elf"]
    assert pin(binary)==dict(bytes=current["elf_bytes"],sha256=current["elf_sha256"])
    assert current["elf_sha256"]==reference["elf_sha256"]==md["elf_sha256"]
    assert binary.read_bytes()==(run/"public/build/public-connection"/ref["elf"]).read_bytes()
    return dict(status="ACTUAL_MAIN_DEFAULT_ENTRY_EQUALS_QUALIFIED_PUBLIC83",physical_images=83,
        source_files=172,reference_fresh_members=83,entry_checked_reused_members=83,
        same_complete_executable_bytes=True,elf_sha256=current["elf_sha256"],
        production_activated=False,old_path_removed=False,full_sdk_qualified=False)
def audit(event,args):
    if event=="open":
        mode,flags=args[1:3]
        if isinstance(mode,str) and any(c in mode for c in "wax+"):raise PermissionError(event)
        if isinstance(flags,int) and flags&(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND):raise PermissionError(event)
    if event.startswith(("subprocess.","ctypes.","mmap.")) or event in (
        "os.system","os.fork","os.posix_spawn","os.exec","os.remove","os.rename","os.mkdir",
        "os.rmdir","os.chmod","os.chown","os.utime","os.truncate","os.link","os.symlink"):raise PermissionError(event)
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("source","run","output"):p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--hepta",type=Path);p.add_argument("--verify-only",action="store_true");a=p.parse_args()
    source=a.source.resolve(strict=True);run=a.run.resolve(strict=True);output=a.output.absolute()
    if a.verify_only:
        sys.addaudithook(audit);print(json.dumps(verify(source,run,output),sort_keys=True));return
    assert a.hepta is not None and not output.exists()
    assert doc(run/"RECIPE.json")["status"]=="PASS"
    assert doc(run/"verification.json")["fresh_member_compiles"]==83
    expected=graph_rows(run/"graph-source");assert len(expected)==172
    for name,identity in expected.items():assert pin(source/name)==identity,name
    output.mkdir(parents=True)
    original=doc(run/"public/BUILD.json");origin_run=Path(original["manifest"]).parents[3]
    md=doc(run/"public/build/public-connection/manifest.json")
    reuse={row["name"]:str(run/Path(row["manifest"]).relative_to(origin_run)) for row in md["members"]}
    (output/"reuse.json").write_text(json.dumps(reuse,sort_keys=True,indent=2)+"\n")
    command=[sys.executable,"-I","-B",str(source/"scripts/hia_native_runtime_mcp_build.py"),
        "--hepta",str(a.hepta.resolve(strict=True)),"--output",str(output/"build"),
        "--bootstrap",str(run/"retained-eight/build/bootstrap"),"--reuse-manifests",str(output/"reuse.json")]
    started=time.monotonic()
    with (output/"stdout.bin").open("xb") as stdout,(output/"stderr.bin").open("xb") as stderr:
        proc=subprocess.Popen(command,stdout=stdout,stderr=stderr);code=proc.wait()
    receipt=dict(status="ACTUAL_MAIN_DEFAULT_ENTRY_CAPTURED",command=command,exit_code=code,
        elapsed_seconds=time.monotonic()-started,outer_timeout_seconds=None,source_files=expected,
        stdout=pin(output/"stdout.bin"),stderr=pin(output/"stderr.bin"),rust_executed=False)
    (output/"PROCESS.json").write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
    (output/"producer.py").write_bytes(Path(__file__).read_bytes())
    print(json.dumps(verify(source,run,output),sort_keys=True))
if __name__=="__main__":main()
