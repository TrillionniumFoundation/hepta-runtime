"""Read complete fresh serial81, current Rust transport and public90 retained evidence."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,os,stat,sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from check_source import check,base,installed
from verify_public81 import verify as public_verify
from verify_transport_reference import verify as transport_verify
SHA=lambda b:hashlib.sha256(b).hexdigest()
LABELS=["install-serial81","fresh-retained62","fresh-public81","normal-corpus",
        "native-framing24","fresh-original28","retained-public90","readonly-complete"]
FALSE_FLAGS=("full_sdk_qualified","full_136_route_qualified","full_async_runtime_qualified",
    "service_task_or_future_lifecycle_qualified","cancellation_timing_qualified",
    "target_connection_identity_integrated","target_general_response_owner_integrated",
    "fixed_get_info_publicly_integrated","production_activated","old_path_removed","independent_cold_qualified")
def doc(path):return json.loads(path.read_bytes())
def verify(source,run,module_map=None,require_recipe_pass=False):
    source=Path(source).resolve(strict=True);run=Path(run).resolve(strict=True)
    closure=check(source);base_closure=base(run/"base-input");graph=installed(run/"graph-source")
    recipe=doc(run/"RECIPE.json")
    assert recipe["status"] in (("PASS",) if require_recipe_pass else ("RUNNING","PASS"))
    assert recipe["source_manifest"]==closure["source_manifest"] and recipe["base_source_manifest"]==base_closure["source_manifest"]
    expected=LABELS if recipe["status"]=="PASS" else LABELS[:-1]
    assert [r["label"] for r in recipe["processes"]]==expected
    for row in recipe["processes"]:
        assert row["exit_code"]==0 and row["outer_timeout_seconds"] is None
        for name in ("stdout","stderr"):
            raw=(run/"processes"/(row["label"]+"."+name)).read_bytes()
            assert row[name]==dict(bytes=len(raw),sha256=SHA(raw))
    path=run/"base-input/drivers/verify_complete.py"
    spec=importlib.util.spec_from_file_location("_retained_source_only_62_reader",path)
    retained=importlib.util.module_from_spec(spec);spec.loader.exec_module(retained)
    baseline=retained.baseline(run/"retained-eight")
    assert baseline["fresh_members"]==62
    public=public_verify(run/"graph-source",run/"public",run/"public-loop",module_map)
    assert public["physical_images"]==public["fresh_member_compiles"]==81 and public["checked_reused_members"]==0
    built=doc(run/"public/BUILD.json")
    assert built["fresh_member_compiles"]==81 and built["checked_reused_members"]==0 and built["bootstrap_reused"] is True
    native=doc(run/"native-framing/SUMMARY.json")
    assert native["elf_sha256"]==public["elf_sha256"] and native["manifest_sha256"]==built["manifest_sha256"]
    composition=doc(run/"graph-source/native/runtime_mcp_serial_transport_composition.json")
    assert composition["revision"]==2 and composition["utf8_bom_stripped_after_frame_limit_and_crlf"] is True
    assert composition["line_limit_bytes_including_lf"]==16777216
    assert composition["shutdown_events"]==[1,2,4,5] and composition["shutdown_actions"]==[1,2,3,4]
    original=transport_verify(source,run/"reference",run/"native-framing",run/"transport-inputs")
    assert original["status"]=="SERIAL_TRANSPORT_CURRENT_TARGET_PASS"
    for flag in FALSE_FLAGS:assert recipe[flag] is False,flag
    assert recipe["existing_binary_inputs"] is False
    result=dict(schema="hepta.public-serial81.complete-readonly.v1",status="READONLY_FRESH81_SERIAL_TRANSPORT_PUBLIC90_PASS",
        source_manifest=closure["source_manifest"],source_files=closure["files"],installed_source_binding=graph["source_binding"],
        fresh_retained_members=62,fresh_public_members=81,reused_public_members=0,
        public_counts=public["counts"],serial_public_wire_cases=24,codec_eof_reference_only_cases=4,
        original_processes=28,candidate_elf_sha256=public["elf_sha256"],
        original_elf_sha256=original["actual_original_elf_sha256"],actual_target_serial_transport_compared=True,
        full_transport_comparison=original,readonly=True,new_native_or_original_execution=False,
        **{k:False for k in FALSE_FLAGS})
    if recipe["status"]=="PASS":
        assert recipe["fresh_retained_62"] is True and recipe["fresh_public_81"] is True
        assert recipe["fresh_exact_rust_built"] is True and recipe["rust_executed"] is True
        assert recipe["actual_target_serial_transport_compared"] is True
        assert recipe["public_counts"]==public["counts"] and recipe["candidate_elf_sha256"]==public["elf_sha256"]
        assert doc(run/"verification.json")==result
    return result
def snapshot(root):
    result={};root=Path(root).resolve(strict=True)
    for path in sorted(root.rglob("*")):
        if path.is_dir():continue
        assert path.resolve(strict=True)==path and stat.S_ISREG(path.lstat().st_mode)
        info=path.stat()
        with path.open("rb") as f:digest=hashlib.file_digest(f,"sha256").hexdigest()
        result[path.relative_to(root).as_posix()]=(info.st_size,digest,info.st_mtime_ns,info.st_ctime_ns)
    return result
def readonly(event,args):
    if event=="open":
        if args[2]&(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND):raise PermissionError("readonly verifier forbids file mutation")
    elif event in {"os.mkdir","os.remove","os.rmdir","os.rename","os.link","os.symlink","os.chmod","os.chown","os.utime","os.truncate","os.system","os.exec","os.posix_spawn","os.fork"}:
        raise PermissionError("readonly verifier forbids mutation or child execution")
    elif event.startswith(("subprocess.","ctypes.","mmap.")):raise PermissionError("readonly verifier cannot execute native code")
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("source","run"):p.add_argument("--"+name,required=True,type=Path)
    p.add_argument("--module-map",type=Path);p.add_argument("--require-recipe-pass",action="store_true");a=p.parse_args()
    sys.addaudithook(readonly);before=(snapshot(a.source),snapshot(a.run))
    result=verify(a.source,a.run,a.module_map,a.require_recipe_pass)
    assert (snapshot(a.source),snapshot(a.run))==before,"reader changed retained bytes or metadata"
    print(json.dumps(result,sort_keys=True,separators=(",",":")))
if __name__=="__main__":main()
