"""Read all public83 source/build/wire evidence; execute and change nothing."""
from pathlib import Path
import argparse,ctypes,hashlib,importlib.util,json,mmap,os,stat,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from check_source import check,check_runner
from install_entrypoint import verify as verify_entry
from retained_baseline_reader import baseline
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
LABELS=("install-default-entry","fresh-retained62","fresh-public83","normal-corpus",
    "native-framing24","fresh-original28","fresh-original54","native-handshake54",
    "retained-public90","readonly-complete")
FALSE_FLAGS=("full_sdk_qualified","full_136_route_qualified","full_async_runtime_qualified",
    "service_task_or_future_lifecycle_qualified","cancellation_timing_qualified",
    "target_general_response_owner_integrated","production_activated","old_path_removed",
    "independent_cold_qualified")
def doc(path):return json.loads(path.read_bytes())
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
def verify(source,build,loop,handshake_reference,handshake_native,transport_reference,
           transport_native,transport_cases,retained_eight,graph_source=None,module_map=None,
           require_fresh=False,run=None,require_recipe_pass=False):
    closure=check(source);runner=check_runner(HERE)
    graph=source/"source" if graph_source is None else graph_source
    entry=verify_entry(source,HERE,graph) if graph_source is not None else None
    old=baseline(retained_eight)
    public=load("_public83_gate",source/"drivers/verify_public.py").verify(graph,build,loop,module_map)
    handshake=load("_public83_handshake_gate",source/"drivers/verify_handshake.py").verify(
        source/"handshake-reference",handshake_reference,handshake_native,build)
    transport=load("_public83_transport_gate",source/"drivers/verify_transport_reference.py").verify(
        source/"transport-reference",transport_reference,transport_native,transport_cases)
    built=doc(build/"BUILD.json")
    assert public["elf_sha256"]==handshake["candidate_elf_sha256"]==transport["actual_native_elf_sha256"]==built["elf_sha256"]
    assert public["physical_images"]==83 and handshake["sessions"]==54 and handshake["responses"]==324
    assert transport["serial_public_wire_cases"]==24 and transport["codec_eof_reference_only_cases"]==4
    if require_fresh:
        assert public["fresh_member_compiles"]==83 and public["checked_reused_members"]==0
        assert built["default_public_entrypoint"] is True and entry is not None
    if run is not None:
        recipe=doc(run/"RECIPE.json")
        assert recipe["status"] in (("PASS",) if require_recipe_pass else ("RUNNING","PASS"))
        assert recipe["source_manifest_sha256"]==closure["source_manifest_sha256"]
        assert recipe["fresh_retained_62"] is True and recipe["fresh_public_83"] is True
        assert recipe["fresh_exact_transport_original"] is True and recipe["fresh_exact_handshake_original"] is True
        assert recipe["existing_binary_inputs"] is False and recipe["rust_executed"] is True
        for name in FALSE_FLAGS:assert recipe[name] is False,name
        labels=LABELS if recipe["status"]=="PASS" else LABELS[:-1]
        assert [row["label"] for row in recipe["processes"]]==list(labels)
        for row in recipe["processes"]:
            assert row["exit_code"]==0 and row["outer_timeout_seconds"] is None
            for stream in ("stdout","stderr"):
                raw=(run/"processes"/(row["label"]+"."+stream)).read_bytes()
                assert row[stream]==dict(bytes=len(raw),sha256=SHA(raw))
    result=dict(schema="hepta.public83.complete-readonly.v1",
        status="READONLY_PUBLIC83_HANDSHAKE324_PUBLIC90_TRANSPORT24_PASS",
        source=closure,runner=runner,default_entrypoint=entry,retained_eight=old,
        public=public,handshake=handshake,transport=transport,
        candidate_elf_sha256=built["elf_sha256"],physical_images=83,
        fresh_member_compiles=public["fresh_member_compiles"],checked_reused_members=public["checked_reused_members"],
        default_public_entrypoint_verified=entry is not None,
        all_current_handshake_wire_bytes_equal=True,all_current_serial_framing_wire_bytes_equal=True,
        native_or_rust_executed_by_reader=False,source_or_evidence_written_by_reader=False,
        **{name:False for name in FALSE_FLAGS})
    if run is not None and doc(run/"RECIPE.json")["status"]=="PASS":
        assert doc(run/"verification.json")==result
    return result
def snapshot(root):
    result={}
    for path in [root,*sorted(root.rglob("*"))]:
        relative=path.relative_to(root)
        if "rust-build" in relative.parts:continue
        assert not path.is_symlink(),str(path)
        st=path.stat();assert stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)
        value=(st.st_dev,st.st_ino,st.st_mode,st.st_size,st.st_mtime_ns,st.st_ctime_ns)
        if path.is_file():value+= (SHA(path.read_bytes()),)
        result[str(path)]=value
    return result
def audit(event,args):
    if event=="open":
        mode,flags=args[1],args[2]
        if isinstance(mode,str) and any(x in mode for x in "wax+"):raise PermissionError("readonly gate: write")
        if isinstance(flags,int) and flags&(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND):raise PermissionError("readonly gate: write flags")
    if event.startswith(("subprocess.","ctypes.","mmap.")) or event in (
        "os.system","os.fork","os.posix_spawn","os.exec","os.remove","os.unlink","os.rename",
        "os.rmdir","os.mkdir","os.chmod","os.chown","os.utime","os.truncate","os.link","os.symlink"):
        raise PermissionError("readonly gate: "+event)
def paths(source,run):
    return dict(source=source,build=run/"public",loop=run/"public-loop",
        handshake_reference=run/"handshake-reference",handshake_native=run/"native-handshake",
        transport_reference=run/"transport-reference",transport_native=run/"native-framing",
        transport_cases=run/"transport-inputs",retained_eight=run/"retained-eight",
        graph_source=run/"graph-source")
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source",type=Path,required=True);p.add_argument("--run",type=Path)
    for name in ("build","loop","handshake-reference","handshake-native","transport-reference",
                 "transport-native","transport-cases","retained-eight","graph-source","module-map"):
        p.add_argument("--"+name,type=Path)
    p.add_argument("--require-fresh",action="store_true");p.add_argument("--require-recipe-pass",action="store_true")
    a=p.parse_args();source=a.source.resolve(strict=True)
    kwargs=paths(source,a.run.resolve(strict=True)) if a.run else dict(source=source)
    for name in ("build","loop","handshake_reference","handshake_native","transport_reference",
                 "transport_native","transport_cases","retained_eight","graph_source"):
        if getattr(a,name):kwargs[name]=getattr(a,name).resolve(strict=True)
    required=("build","loop","handshake_reference","handshake_native","transport_reference",
              "transport_native","transport_cases","retained_eight")
    assert all(name in kwargs for name in required)
    roots=sorted(set([HERE,*[value for value in kwargs.values() if isinstance(value,Path)]]))
    before=tuple(snapshot(root) for root in roots);sys.addaudithook(audit)
    result=verify(**kwargs,module_map=a.module_map,require_fresh=a.require_fresh,
        run=a.run,require_recipe_pass=a.require_recipe_pass)
    assert before==tuple(snapshot(root) for root in roots),"readonly evidence changed"
    print(json.dumps(result,sort_keys=True))
if __name__=="__main__":main()
