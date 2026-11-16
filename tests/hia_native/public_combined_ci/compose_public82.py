"""Join qualified get_info and transport source deltas with exact source proofs."""
from pathlib import Path
import argparse, ast, hashlib, json, shutil
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
def put(path, value): path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
def replace(text, old, new):
    assert text.count(old) == 1, old
    return text.replace(old, new, 1)
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("get-info-source", "transport-source", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    base = args.get_info_source.resolve(strict=True)
    transport_source = args.transport_source.resolve(strict=True)
    output = args.output.absolute()
    assert not output.exists()
    original = (base / "native/runtime_mcp_sources.json").read_bytes()
    assert SHA(original) == "8cd8bc8c190be9bd5e3fdcbbb9fc62fa7ac855012f648b0675c2f8d5dc7493fe"
    binding = json.loads(original)
    for relative, pin in binding["sources"].items():
        raw = (base / relative).read_bytes()
        assert pin == dict(bytes=len(raw), sha256=SHA(raw)), relative
    manifest_raw = (transport_source / "source-manifest.json").read_bytes()
    manifest = json.loads(manifest_raw)
    for relative, pin in manifest["files"].items():
        raw = (transport_source / relative).read_bytes()
        assert pin == dict(bytes=len(raw), sha256=SHA(raw)), relative
    assert manifest["native_graph_revision"] == 2
    shutil.copytree(base, output, copy_function=shutil.copyfile)
    changes = []
    def write(relative, raw):
        if isinstance(raw, str): raw = raw.encode()
        path = output / relative
        old = path.read_bytes() if path.exists() else None
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        changes.append(dict(path=relative, before_sha256=SHA(old) if old is not None else None,
                            after_sha256=SHA(raw), bytes=len(raw)))
    raw_edits = (transport_source / "overlay/scripts/serial_transport_edits.json").read_bytes()
    transport = (output / "scripts/runtime_mcp_transport.S").read_text()
    skipped = []
    for index, (old, new) in enumerate(json.loads(raw_edits)):
        if index == 5:
            assert old == "    .zero 376\n" and new == "    .zero 432\n"
            assert transport.count("    .zero 440 /* 55 fixed public-engine image slots. */\n") == 1
            skipped.append(dict(index=index, reason="The get_info graph already reserves 55 image slots; both owners fit."))
        else: transport = replace(transport, old, new)
    write("scripts/runtime_mcp_transport.S", transport)
    fixture = (output / "scripts/runtime_mcp_filesystem_fixture.S").read_text()
    write("scripts/runtime_mcp_filesystem_fixture.S", replace(fixture, "    .zero 376\n", "    .zero 440\n"))
    assert ".equ RG_SLOTS, 55\n" in (output / "scripts/runtime_mcp_extra_engine.S").read_text()
    build = (output / "scripts/public_nine_build.py").read_text()
    before = ast.parse(build)
    build = replace(build, "    ('current_get_info', 'current_get_info', 'standard'),",
                    "    ('current_get_info', 'current_get_info', 'standard'),\n"
                    "    ('target_shutdown', 'sdk_shutdown_target', 'standard'),")
    build = replace(build, "None, None, None, None, None, None, None, 'current_get_info']",
                    "None, None, None, None, None, None, 'target_shutdown', 'current_get_info']")
    build = replace(build, "or len(MEMBERS) != 81", "or len(MEMBERS) != 82")
    build = replace(build, "'frontend_transport_fixed_input_limit': None", "'frontend_transport_fixed_input_limit': 16777216")
    build = replace(build, "'target_async_transport_integrated': False,",
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
    write("scripts/public_nine_build.py", build)
    owner = (transport_source / "overlay/native/sdk_shutdown_target.hepta").read_bytes()
    assert SHA(owner) == "8222930c7a7922b81df6aa25f9f308280eb4547a1fbb18d6113ec926b3d855f9"
    write("native/sdk_shutdown_target.hepta", owner)
    composition = dict(schema="hepta.runtime.public-serial-transport-composition.v1",
        base_source_binding_sha256=SHA(original), slot=53, physical_images=82,
        get_info_slot=54, reserved_batch_slots=[47,48,49,50,51,52],
        line_limit_bytes_including_lf=16777216, eof_unterminated_tail_discarded=True,
        codec_decode_eof_is_separate=True, revision=2, utf8_bom_stripped_after_frame_limit_and_crlf=True,
        input_is_public_json_rpc=True, private_selectors_from_input=False,
        shutdown_input_magic="HRSQ0001", shutdown_output_magic="HRSS0001",
        shutdown_events=[1,2,4,5], shutdown_actions=[1,2,3,4],
        shutdown_actual_serial_pending_send_and_child_counts=0,
        native_async_scheduler_or_token_registry=False, external_handle_cancellation_integrated=False,
        writer_descriptor_close_before_owner_teardown=True, result_output_limit_added=False,
        target_application_commit="d3d75c30719db966b004756f610007a7c723729e",
        rmcp_version="3.9.0", rmcp_source_commit="5596a8a0bba2a1ec5519cc855cdadf23e4dcecdc",
        shutdown_source_sha256=SHA(owner), transport_source_sha256=SHA(transport.encode()),
        source_qualification_commit="3b1dbd5ad5562f063d6b800bc11eaace5adf2df1",
        source_qualification_run=43810526241, composed_public_graph_qualified=False,
        full_async_runtime_qualified=False, full_sdk_qualified=False,
        production_activated=False, old_path_removed=False,
        historical_wide_input_evidence_preserved_as_original_profile=True)
    write("native/runtime_mcp_serial_transport_composition.json", json.dumps(composition,sort_keys=True,indent=2)+"\n")
    write("scripts/serial_transport_edits.json", raw_edits)
    for row in changes:
        binding["sources"][row["path"]] = dict(bytes=row["bytes"],sha256=row["after_sha256"])
    binding["serial_transport_extension"] = composition
    put(output / "native/runtime_mcp_sources.json", binding)
    after = ast.parse(build)
    def assigned(tree, name):
        nodes = [node for node in tree.body if isinstance(node, ast.Assign)
                 and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
        assert len(nodes) == 1
        return ast.literal_eval(nodes[0].value)
    old_members, new_members = assigned(before,"MEMBERS"), assigned(after,"MEMBERS")
    assert len(old_members)==81 and len(new_members)==82
    assert [row for row in new_members if row[0]!="target_shutdown"]==old_members
    old_extra,new_extra=assigned(before,"EXTRA"),assigned(after,"EXTRA")
    assert len(old_extra)==len(new_extra)==55
    expected=list(old_extra)
    assert expected[53] is None and expected[54]=="current_get_info"
    expected[53]="target_shutdown"
    assert new_extra==expected
    assert (output/"native/runtime_mcp.hepta").read_bytes()==(base/"native/runtime_mcp.hepta").read_bytes()
    receipt=dict(schema="hepta.runtime.public82.composition.v1",author_sha256=SHA(Path(__file__).read_bytes()),
        parent_public_get_info_commit="39ea7723157b01a3e9635cccb4bf79aeeb3184dc",
        transport_source_commit="3b1dbd5ad5562f063d6b800bc11eaace5adf2df1",
        transport_source_manifest_sha256=SHA(manifest_raw),
        installed_source_binding_sha256=SHA((output/"native/runtime_mcp_sources.json").read_bytes()),
        changes=changes,skipped_edits=skipped,retained_81_member_definitions_exact=True,
        frontend_unchanged=True,table_slots=55,physical_images=82,native_or_rust_executed=False,
        production_activated=False,old_path_removed=False)
    put(output.with_name(output.name+"-COMPOSITION.json"),receipt)
    print(json.dumps(receipt,sort_keys=True))
if __name__=="__main__":main()
