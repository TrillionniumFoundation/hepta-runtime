"""Install only the explicit serial transport delta over the frozen public80 base."""
from pathlib import Path
import argparse,hashlib,json,shutil
SHA=lambda b:hashlib.sha256(b).hexdigest()
BASE="7701165fceeaebdb9272d76e44c57985e0bc478b5ec8b96b7891c79e9d607d46"
def put(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def replace(text,old,new):
    assert text.count(old)==1,old[:100]
    return text.replace(old,new,1)
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("base-source","overlay","output"):p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args();base=a.base_source.resolve(strict=True);overlay=a.overlay.resolve(strict=True);out=a.output.resolve()
    original=(base/"native/runtime_mcp_sources.json").read_bytes();assert SHA(original)==BASE
    binding=json.loads(original)
    for relative,pin in binding["sources"].items():
        raw=(base/relative).read_bytes()
        assert pin==dict(bytes=len(raw),sha256=SHA(raw)),relative
    assert not out.exists()
    # Copy immutable source bytes into fresh writable output; do not preserve
    # a frozen input package's read-only modes on files that the installer edits.
    shutil.copytree(base,out,copy_function=shutil.copyfile)
    changed=[]
    def write(relative,text):
        target=out/relative
        before=target.read_bytes() if target.exists() else None
        raw=text.encode();target.write_bytes(raw)
        changed.append(dict(path=relative,before_sha256=SHA(before) if before is not None else None,
            after_sha256=SHA(raw),bytes=len(raw)))
    transport=(out/"scripts/runtime_mcp_transport.S").read_text()
    for old,new in json.loads((overlay/"scripts/serial_transport_edits.json").read_bytes()):
        transport=replace(transport,old,new)
    write("scripts/runtime_mcp_transport.S",transport)
    engine=(out/"scripts/runtime_mcp_extra_engine.S").read_text()
    engine=replace(engine,".equ RG_SLOTS, 47",".equ RG_SLOTS, 54")
    engine=replace(engine,"47 rows at engine+4096; slot41 has no public owner.",
        "54 rows at engine+4096; slots41 and47..52 have no public owner.")
    write("scripts/runtime_mcp_extra_engine.S",engine)
    fixture=(out/"scripts/runtime_mcp_filesystem_fixture.S").read_text()
    write("scripts/runtime_mcp_filesystem_fixture.S",replace(fixture,"    .zero 376","    .zero 432"))
    build=(out/"scripts/public_nine_build.py").read_text()
    build=replace(build,"    ('text_constructor', 'text_result_constructor', 'history.v1'),",
        "    ('text_constructor', 'text_result_constructor', 'history.v1'),\n    ('target_shutdown', 'sdk_shutdown_target', 'standard'),")
    build=replace(build,"'historical_protocol', 'text_constructor']",
        "'historical_protocol', 'text_constructor', None, None, None, None, None, None, 'target_shutdown']")
    build=replace(build,"or len(MEMBERS) != 80","or len(MEMBERS) != 81")
    build=replace(build,"'frontend_transport_fixed_input_limit': None",
        "'frontend_transport_fixed_input_limit': 16777216")
    build=replace(build,"'target_async_transport_integrated': False,",
        "'target_async_transport_integrated': False,\n"
        "              'target_serial_async_rw_framing_integrated': True,\n"
        "              'target_eof_shutdown_owner_integrated': True,\n"
        "              'target_shutdown_slot': 53,\n"
        "              'target_input_line_limit_includes_lf': True,\n"
        "              'target_eof_unterminated_tail_discarded': True,\n"
        "              'target_serial_transport_semantics_qualified': False,\n"
        "              'native_pending_handler_registry_qualified': False,\n"
        "              'native_future_cancellation_qualified': False,\n"
        "              'native_shutdown_timeout_timing_qualified': False,")
    write("scripts/public_nine_build.py",build)
    owner=(overlay/"native/sdk_shutdown_target.hepta").read_bytes()
    assert SHA(owner)=="8222930c7a7922b81df6aa25f9f308280eb4547a1fbb18d6113ec926b3d855f9"
    write("native/sdk_shutdown_target.hepta",owner.decode())
    composition=dict(schema="hepta.runtime.public-serial-transport-composition.v1",
        base_source_binding_sha256=BASE,slot=53,physical_images=81,
        reserved_batch_slots=[47,48,49,50,51,52],line_limit_bytes_including_lf=16777216,
        eof_unterminated_tail_discarded=True,codec_decode_eof_is_separate=True,
        revision=2,utf8_bom_stripped_after_frame_limit_and_crlf=True,
        input_is_public_json_rpc=True,private_selectors_from_input=False,
        shutdown_input_magic="HRSQ0001",shutdown_output_magic="HRSS0001",
        shutdown_events=[1,2,4,5],shutdown_actions=[1,2,3,4],
        shutdown_actual_serial_pending_send_and_child_counts=0,
        native_async_scheduler_or_token_registry=False,external_handle_cancellation_integrated=False,
        writer_descriptor_close_before_owner_teardown=True,result_output_limit_added=False,
        target_application_commit="d3d75c30719db966b004756f610007a7c723729e",
        rmcp_version="3.9.0",rmcp_source_commit="5596a8a0bba2a1ec5519cc855cdadf23e4dcecdc",
        shutdown_source_sha256=SHA(owner),transport_source_sha256=SHA(transport.encode()),
        full_async_runtime_qualified=False,full_sdk_qualified=False,production_activated=False,
        old_path_removed=False,historical_wide_input_evidence_preserved_as_original_profile=True)
    write("native/runtime_mcp_serial_transport_composition.json",json.dumps(composition,sort_keys=True,indent=2)+"\n")
    write("scripts/serial_transport_edits.json",(overlay/"scripts/serial_transport_edits.json").read_text())
    for row in changed:
        binding["sources"][row["path"]]=dict(bytes=row["bytes"],sha256=row["after_sha256"])
    binding["serial_transport_extension"]=composition
    put(out/"native/runtime_mcp_sources.json",binding)
    receipt=dict(schema="hepta.runtime.public-serial-transport-install.v1",base_sha256=BASE,
        source_binding_sha256=SHA((out/"native/runtime_mcp_sources.json").read_bytes()),
        changes=changed,base_unchanged=SHA((base/"native/runtime_mcp_sources.json").read_bytes())==BASE,
        native_or_rust_executed=False)
    put(out.with_name(out.name+"-INSTALL.json"),receipt)
    print(json.dumps(receipt,sort_keys=True))
if __name__=="__main__":main()
