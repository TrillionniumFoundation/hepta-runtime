"""Install only fixed child55 and the mechanically required public83 table rows."""
from pathlib import Path
import hashlib,json
ROOT=Path(__file__).resolve().parent
source=ROOT/"source"
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
p=source/"scripts/runtime_mcp_extra_engine.S";s=p.read_text()
def replace(old,new):
    global s
    assert s.count(old)==1,old
    s=s.replace(old,new)
replace("55 rows at engine+4096; slots47-53 are reserved.","56 rows at engine+4096; slots47-52 are reserved for Batch.")
replace(".equ RG_SLOTS, 55",".equ RG_SLOTS, 56")
replace("    mov edi, 100663296\n    cmp ebp, 42", "    mov edi, 67108864\n    cmp ebp, 55\n    je runtime_grow_allocate_work\n    mov edi, 100663296\n    cmp ebp, 42")
replace("    mov edi, 4096\n    cmp ebp, 42\n    jb runtime_grow_allocate_output_ready", "    mov edi, 33554432\n    cmp ebp, 55\n    je runtime_grow_allocate_output_ready\n    mov edi, 4096\n    cmp ebp, 42\n    jb runtime_grow_allocate_output_ready")
replace("    cmp ebp, 54\n    je runtime_grow_get_info_result", "    cmp ebp, 54\n    je runtime_grow_get_info_result\n    cmp ebp, 55\n    je runtime_grow_connection_result")
replace("runtime_grow_protocol_result:\n", """runtime_grow_connection_result:
    cmp eax, 256
    jb runtime_grow_bad
    mov rdx, 0x313030534e435248 /* HRCNS001: the u32 is the complete extent. */
    cmp [r13], rdx
    jne runtime_grow_bad
    cmp qword ptr [r13 + 8], 6
    ja runtime_grow_bad
    cmp qword ptr [r13 + 16], 1
    ja runtime_grow_bad
    cmp qword ptr [r13 + 24], 1
    ja runtime_grow_bad
    cmp qword ptr [r13 + 48], 1
    ja runtime_grow_bad
    jmp runtime_grow_extent_ready
runtime_grow_protocol_result:
""")
replace("    cmp qword ptr [r13 + 16], 5\n    ja runtime_grow_bad\n    cmp qword ptr [r13 + 24], 8", """    cmp ebp, 19
    jne runtime_grow_historical_protocol_kind
    cmp qword ptr [r13 + 16], 6
    ja runtime_grow_bad
    jmp runtime_grow_protocol_kind_ready
runtime_grow_historical_protocol_kind:
    cmp qword ptr [r13 + 16], 5
    ja runtime_grow_bad
runtime_grow_protocol_kind_ready:
    cmp qword ptr [r13 + 24], 8""")
replace("runtime_grow_target_sdk_protocol:\n    cmp rsi, 3","runtime_grow_target_sdk_protocol:\n    cmp rsi, 4")
replace("    .zero 112 /* 41 empty; SDK42-45, constructor46, reserved47-53, get_info54. */","    .zero 120 /* 41 empty; SDK42-45, constructor46, Batch47-52, shutdown53, get_info54, connection55. */")
replace("runtime_grow_sdk_protocol_targets:\n    .byte 42, 43, 44, 45","runtime_grow_sdk_protocol_targets:\n    .byte 42, 43, 44, 45, 55")
p.write_text(s)
p=source/"scripts/public_nine_build.py";s=p.read_text()
old="    ('target_shutdown', 'sdk_shutdown_target', 'standard'),"
assert s.count(old)==1;s=s.replace(old,old+"\n    ('target_connection', 'sdk_connection_target', 'history.v1'),")
old="'target_shutdown', 'current_get_info']";assert s.count(old)==1;s=s.replace(old,"'target_shutdown', 'current_get_info', 'target_connection']")
old="'target_connection_identity_integrated': False,";assert s.count(old)==1
s=s.replace(old,"'target_connection_identity_integrated': True,\n              'target_connection_lifecycle_integrated': True,\n              'target_connection_slot': 55,\n              'target_connection_public_semantics_qualified': False,")
assert s.count("len(MEMBERS) != 82")==1
s=s.replace("len(MEMBERS) != 82","len(MEMBERS) != 83")
p.write_text(s)
p=source/"scripts/runtime_mcp_transport.S";s=p.read_text()
old=".zero 440 /* 55 fixed public-engine image slots. */";assert s.count(old)==1
s=s.replace(old,".zero 448 /* 56 fixed public-engine image slots; connection55 is an owned leaf. */");p.write_text(s)
p=source/"native/runtime_mcp_sources.json";binding=json.loads(p.read_bytes())
for name in list(binding["sources"])+["native/sdk_connection_target.hepta","native/sdk_public_protocol_composition.json","native/runtime_mcp_connection_composition.json"]:
    raw=(source/name).read_bytes();binding["sources"][name]=dict(bytes=len(raw),sha256=SHA(raw))
binding["connection_extension"]=dict(slot=55,controller_local_child=4,physical_images=83,
    source_sha256=SHA((source/"native/sdk_connection_target.hepta").read_bytes()),
    original_current_get_info_slot=54,persistent_state_in_owned_workspace=True,
    batch_engine_offsets_preserved=[416,424],sdk_default_fixture_linked=False,
    current_g1_initialize_id=True,current_g2_metadata_ping=True,
    generic_response_owner_complete=False,complete_protocol_routing=False,
    full_sdk_qualified=False,production_activated=False,old_path_removed=False)
p.write_text(json.dumps(binding,sort_keys=True,indent=2)+"\n")
print(json.dumps({"source_binding_sha256":SHA(p.read_bytes()),"source_files":len(binding["sources"]),"engine_slots":56,"physical_images":83},sort_keys=True))

