"""Build the 102-image HIA stdio executable with an installed-capability catalog.

This is the default public build API and command. Historical 58-image
qualification uses its explicit, source-pinned test profile.
"""
from pathlib import Path
import argparse,hashlib,json,os,shutil,sys,time
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from public_nine_build import (MEMBERS,EXTRA,BASE,BOUNDARIES,FIXTURE_BOUNDARIES,
    TRANSPORT,VIEW,CONFIG,CONFIG_SYMBOLS,FENCE,FALSE_FLAGS,adapter_source,
    source_check,build_runtime_mcp)
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
def put(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source",type=Path,default=ROOT)
    for name in ("hepta","output"):parser.add_argument("--"+name,type=Path,required=True)
    parser.add_argument("--bootstrap",type=Path)
    parser.add_argument("--reuse-manifests",type=Path)
    args=parser.parse_args();source=args.source.resolve(strict=True);output=args.output.absolute()
    assert source==ROOT,"Invoke the builder from the source checkout being built."
    assert not output.exists()
    if os.environ.get("CI")!="true":
        assert args.bootstrap is not None,"Local builds require an already verified B3 copy."
        assert SHA((args.bootstrap/"B3.image.bin").read_bytes())=="bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0"
    output.mkdir(parents=True);started=time.monotonic()
    report=dict(schema="hepta.runtime.public102-authority-batch.build.v1",status="RUNNING",rust_executed=False,
        actual_target_handshake_compared=False,full_async_runtime_qualified=False,full_sdk_qualified=False,
        independent_cold_qualified=False,production_activated=False,old_path_removed=False,
        default_public_entrypoint=True)
    def save():report["elapsed_seconds"]=time.monotonic()-started;put(output/"BUILD.json",report)
    save()
    try:
        if args.bootstrap:shutil.copytree(args.bootstrap.resolve(strict=True),output/"build/bootstrap")
        assert len(MEMBERS)==102 and len(EXTRA)==57
        assert EXTRA[47:53]==['batch_gateway','batch_params','batch_call','batch_adapter','batch_input',None] and EXTRA[53:]==["target_shutdown","current_get_info","target_connection",None]
        reuse=json.loads(args.reuse_manifests.resolve(strict=True).read_bytes()) if args.reuse_manifests else {}
        assert set(reuse).issubset({name for name,_,_ in MEMBERS})
        put(output/"reuse.json",reuse)
        manifest=build_runtime_mcp(args.hepta.resolve(strict=True),output/"build",
            name="public-authority-batch",source_root=source,manifests=reuse or None)
        raw=manifest.read_bytes();md=json.loads(raw)
        assert md["physical_images"]==len(md["members"])==102
        fresh=sum(row["fresh_compile"] is True for row in md["members"])
        assert fresh==102-len(reuse)
        binary=manifest.parent/md["elf"];assert SHA(binary.read_bytes())==md["elf_sha256"]
        report.update(status="NATIVE_BUILD_PASS",physical_images=102,manifest=str(manifest),
            manifest_sha256=SHA(raw),elf=str(binary),elf_bytes=binary.stat().st_size,
            elf_sha256=md["elf_sha256"],fresh_member_compiles=fresh,checked_reused_members=len(reuse),
            bootstrap_reused=args.bootstrap is not None,fresh_hia_link_and_pack=True,
            target_get_info_integrated=True,target_serial_async_rw_framing_integrated=True,
            target_eof_shutdown_owner_integrated=True,target_connection_lifecycle_integrated=True,target_connection_slot=55,
            serial_session_authority_integrated=True,authority_slot=56,
            authority_public_handler_comparison=False,request_audit_integrated=False,
            annotation_integrated=False,authority_concurrent_binding_qualified=False)
    except BaseException as exc:report.update(status="FAIL",error=repr(exc));raise
    finally:save()
    print(json.dumps(report,sort_keys=True),flush=True)
if __name__=="__main__":main()
