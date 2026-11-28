"""Bind fixed SessionOwner images without changing any authority policy owner."""
from __future__ import annotations
import argparse
import ast
import hashlib
import json
from pathlib import Path

sha=lambda raw:hashlib.sha256(raw).hexdigest()
encoded=lambda obj:(json.dumps(obj,sort_keys=True,indent=2)+"\n").encode()

def replace(text, before, after):
    if text.count(before)!=1:
        raise ValueError("mechanical source anchor differs: "+before[:100])
    return text.replace(before,after,1)

def author(a):
    changes={}
    def save(name,text):
        raw=text.encode();path=a.source/name
        if a.check: assert path.read_bytes()==raw,name
        else:path.write_bytes(raw)
        changes[name]={"baseline_sha256":sha((a.baseline/name).read_bytes()),"source_sha256":sha(raw),"source_bytes":len(raw)}
    name="scripts/runtime_mcp_extra_engine.S";s=(a.baseline/name).read_text()
    s=s.replace("56 rows at engine+4096","57 rows at engine+8192")
    s=replace(s,".equ RG_SLOTS, 56",".equ RG_SLOTS, 57")
    s=replace(s,".equ RG_ENGINE, 8192",".equ RG_ENGINE, 16384")
    s=replace(s,"lea rdx, [rbx + 4096]","lea rdx, [rbx + 8192]")
    s=replace(s,"    mov rax, rbx\nruntime_grow_create_done:",
        "    mov rdi, rbx\n    call runtime_authority_create\n    test rax, rax\n    jnz runtime_grow_create_authority_failed\n    mov rax, rbx\n    jmp runtime_grow_create_done\nruntime_grow_create_authority_failed:\n    mov r13, rax\n    mov rdi, rbx\n    mov esi, RG_ENGINE + 4096\n    mov eax, 11\n    syscall\n    mov rax, r13\nruntime_grow_create_done:")
    s=replace(s,"    xor ebp, ebp\n    xor r12d, r12d\n    mov rbx, [r15 + 8]",
        "    call runtime_authority_release\n    test rax, rax\n    jnz runtime_grow_destroy_done\n    xor ebp, ebp\n    xor r12d, r12d\n    mov rbx, [r15 + 8]")
    s=replace(s,"    cmp ebp, 40\n    je runtime_grow_text_body_dispatch",
        "    cmp ebp, 56\n    je runtime_grow_authority_dispatch\n    cmp ebp, 40\n    je runtime_grow_text_body_dispatch")
    s=replace(s,"runtime_grow_text_body_dispatch:\n", "runtime_grow_authority_dispatch:\n    call runtime_authority_owned\n    jmp runtime_grow_done\nruntime_grow_text_body_dispatch:\n")
    s=replace(s,"    cmp rax, 2\n    je runtime_grow_config_query_admitted\n", "    cmp rax, 2\n    je runtime_grow_config_query_admitted\n    cmp rax, 3\n    je runtime_grow_config_query_admitted\n")
    s=replace(s,"runtime_grow_target_frontend:\n    cmp rsi, 11", "runtime_grow_target_frontend:\n    cmp rsi, 12")
    s=replace(s,"    .byte 19, 1, 0, 10, 2, 13, 11, 20, 21, 37, 46, 54", "    .byte 19, 1, 0, 10, 2, 13, 11, 20, 21, 37, 46, 54, 56")
    s=replace(s,".zero 120 /* 41 empty; SDK42-45, constructor46, Batch47-52, shutdown53, get_info54, connection55. */",
        ".zero 128 /* 41 empty; SDK42-45, constructor46, Batch47-52, shutdown53, get_info54, connection55, authority56. */")
    save(name,s)
    name="scripts/runtime_mcp_transport.S";s=(a.baseline/name).read_text()
    s=replace(s,".zero 448 /* 56 fixed public-engine image slots; connection55 is an owned leaf. */",
        ".zero 456 /* 57 fixed slots; authority56 is a private callable capability. */")
    save(name,s)
    name="scripts/runtime_mcp_filesystem_fixture.S";s=(a.baseline/name).read_text()
    s=replace(s,"    cmp qword ptr [r12 + 80], 41\n    ja fs_fixture_failure", "    cmp qword ptr [r12 + 80], 56\n    je fs_fixture_authority_selector\n    cmp qword ptr [r12 + 80], 57\n    je fs_fixture_authority_selector\n    cmp qword ptr [r12 + 80], 58\n    je fs_fixture_authority_selector\n    cmp qword ptr [r12 + 80], 41\n    ja fs_fixture_failure\nfs_fixture_authority_selector:")
    s=replace(s,"    cmp qword ptr [r12 + 80], 41\n    je fs_fixture_text_snapshot", "    cmp qword ptr [r12 + 80], 57\n    je fs_fixture_authority_snapshot\n    cmp qword ptr [r12 + 80], 58\n    je fs_fixture_authority_release\n    cmp qword ptr [r12 + 80], 41\n    je fs_fixture_text_snapshot")
    s=replace(s,".zero 440", ".zero 456 /* 57 fixed public-engine slots. */")
    s += "\n" + (Path(__file__).parent/"authority_fixture_observer.S").read_text()
    save(name,s)
    name="scripts/runtime_mcp_filesystem_front_fixture.S";s=(a.baseline/name).read_text()
    assert s.count("[r12 + 56]")==2
    s=s.replace("[r12 + 56]", "[r12 + 488]")
    s=replace(s,"    cmp rax, 2\n    ja fs_fixture_failure", "    cmp rax, 3\n    ja fs_fixture_failure")
    s=replace(s,"    cmp qword ptr [r12 + 208], 2\n    je fs_fixture_public_publish", "    cmp qword ptr [r12 + 208], 2\n    je fs_fixture_public_publish\n    cmp qword ptr [r12 + 208], 3\n    je fs_fixture_public_publish_raw")
    s=replace(s,"fs_fixture_public_publish:\n", "fs_fixture_public_publish_raw:\n    cmp qword ptr [r13 + 32], 0\n    jne fs_fixture_failure\n    lea rdi, [r13 + 64]\n    mov rsi, [r13 + 24]\n    call runtime_publication_raw_span\n    test eax, eax\n    jnz fs_fixture_failure\n    jmp fs_fixture_public_newline\nfs_fixture_public_publish:\n")
    s=replace(s,"fs_fixture_public_closed:\n    mov qword ptr [r12 + 208], 3", "fs_fixture_public_closed:\n    mov qword ptr [r12 + 208], 4")
    s=replace(s,"0x323052504a534648 /* HFSJPR02 */", "0x333052504a534648 /* HFSJPR03: raw publication3; closed4. */")
    save(name,s)
    name="scripts/text_editor_create_private_pack.py";s=(a.baseline/name).read_text()
    s=replace(s,"*,create_images,body_images):","*,create_images,body_images,authority_images):")
    s=replace(s,"    raw_images=[image.read_bytes() for image in ordered]", "    if len(authority_images)!=9:raise ValueError('private authority table differs')\n    for slot,image in enumerate(authority_images):patches.append((1,256+symbols['runtime_authority_images']+slot*8,indices[image]))\n    raw_images=[image.read_bytes() for image in ordered]")
    save(name,s)
    name="scripts/public_nine_build.py";s=(a.baseline/name).read_text()
    s=replace(s,"    'scripts/runtime_mcp_extra_engine.S',", "    'scripts/runtime_mcp_extra_engine.S',\n    'scripts/runtime_mcp_authority_bridge.S',")
    rows=[('authority','caller_authority'),('authority_record','operation_record'),('authority_kdf','operation_kdf'),
        ('authority_aead','operation_aead'),('authority_nonce','operation_nonce'),('authority_scope','operation_scope'),
        ('authority_entropy','entropy_policy'),('authority_loader','authority_loader')]
    s=replace(s,"    ('rf_owner', 'effect_owner_fence', 'standard'),", "".join("    ("+repr(m)+", "+repr(n)+", 'standard'),\n" for m,n in rows)+"    ('rf_owner', 'effect_owner_fence', 'standard'),")
    s=replace(s,"'target_shutdown', 'current_get_info', 'target_connection']", "'target_shutdown', 'current_get_info', 'target_connection', None]")
    s=replace(s,"    if private_fixture:\n        raise ValueError('constructor public revision has no newly qualified private fixture')\n", "")
    s=replace(s,"len(MEMBERS) != 83", "len(MEMBERS) != 91")
    s=replace(s,"    assembly = adapter_source(root, private_fixture=private_fixture)", "    authority_profile = json.loads((root / 'native/caller_owner_export_profile.json').read_bytes())\n    authority_names = ['authority','authority_record','authority_kdf','rf_sha','authority_aead','authority_nonce','authority_scope','authority_entropy','authority_loader']\n    if len(authority_profile['members']) != 9:\n        raise ValueError('fixed authority profile member count differs')\n    for expected, authority_name in zip(authority_profile['members'], authority_names, strict=True):\n        actual = next(row for row in members if row['name'] == authority_name)\n        if any(actual[key] != expected[key] for key in ('source_sha256','image_sha256','image_bytes')):\n            raise ValueError('fixed authority source/image identity differs: ' + authority_name)\n    assembly = adapter_source(root, private_fixture=private_fixture)")
    s=replace(s,"body_images=[images[n] for n in ('tb_body','lc_read','key','tb_lock','tb_edit','tb_match','tb_history','tb_atomic','cache','tb_render','tb_unlink','view_error')])", "body_images=[images[n] for n in ('tb_body','lc_read','key','tb_lock','tb_edit','tb_match','tb_history','tb_atomic','cache','tb_render','tb_unlink','view_error')],\n                                    authority_images=[images[n] for n in ('authority','authority_record','authority_kdf','rf_sha','authority_aead','authority_nonce','authority_scope','authority_entropy','authority_loader')])")
    s=replace(s,"'fixture_pseudo_selectors': [33, 34, 41] if private_fixture else [],", "'fixture_pseudo_selectors': [33, 34, 41, 57, 58] if private_fixture else [],\n              'authority_slot': 56, 'authority_context_offset': 432,\n              'authority_fixed_local_members': ['authority','authority_record','authority_kdf','rf_sha','authority_aead','authority_nonce','authority_scope','authority_entropy','authority_loader'],\n              'authority_transport_mode': 'stdio', 'authority_public_http_qualified': False,\n              'authority_projection_from_current_call': True, 'request_audit_integrated': False,\n              'annotation_integrated': False, 'private_descriptor_base': 8192, 'private_engine_bytes': 16384,")
    save(name,s)
    name="scripts/hia_native_runtime_mcp_build.py";s=(a.baseline/name).read_text()
    s=s.replace('83-image','91-image').replace('public83.build.v1','public91-authority.build.v1')
    s=replace(s,"len(MEMBERS)==83 and len(EXTRA)==56", "len(MEMBERS)==91 and len(EXTRA)==57")
    s=replace(s,"EXTRA[53:]==[\"target_shutdown\",\"current_get_info\",\"target_connection\"]", "EXTRA[53:]==[\"target_shutdown\",\"current_get_info\",\"target_connection\",None]")
    s=replace(s,'name="public-connection"','name="public-authority"')
    s=replace(s,'len(md["members"])==83','len(md["members"])==91')
    s=replace(s,'fresh==83-len(reuse)','fresh==91-len(reuse)')
    s=replace(s,'physical_images=83','physical_images=91')
    s=replace(s,'target_connection_slot=55)', 'target_connection_slot=55,\n            serial_session_authority_integrated=True,authority_slot=56,\n            authority_public_handler_comparison=False,request_audit_integrated=False,\n            annotation_integrated=False,authority_concurrent_binding_qualified=False)')
    save(name,s)
    bridge=a.source/'scripts/runtime_mcp_authority_bridge.S'
    text=bridge.read_text()
    assert '.equ RA_BYTES, 24928256' in text
    profile=json.loads((a.source/'native/caller_owner_export_profile.json').read_bytes())
    import re
    lines=text.split('runtime_authority_caps:\n',1)[1].split('ra_descriptor_offsets:',1)[0]
    actual=[tuple(map(int,m.split(','))) for m in re.findall(r'\.quad ([0-9, ]+)',lines)]
    expected=[];offset=4096
    for row in profile['members']:
        expected.append((row['workspace_capacity'],row['input_capacity'],row['output_capacity'],row['flags'],row['call_mask'],offset))
        offset+=(row['workspace_capacity']+4095)&-4096
    assert actual==expected and offset==24928256
    literal=re.search(r'runtime_authority_request:\n\s*\.ascii "([0-9a-f]+)"',text)[1]
    assert bytes.fromhex(literal)==b'HRAUTR01'+(3).to_bytes(8,'little')+bytes(16)
    ast.parse((a.source/'scripts/public_nine_build.py').read_text())
    ast.parse((a.source/'scripts/hia_native_runtime_mcp_build.py').read_text())
    result=dict(schema='hepta.runtime.public-authority-mechanical.v1', changes=changes,
        new_boundary={'path':'scripts/runtime_mcp_authority_bridge.S','bytes':bridge.stat().st_size,'sha256':sha(bridge.read_bytes())},
        input_profile_sha256=sha((a.source/'native/caller_owner_export_profile.json').read_bytes()),
        extra_slots=57,private_engine_bytes=16384,descriptor_base=8192,record_range=[512,4160],
        descriptor_range=[8192,11840],authority_context_offset=432,physical_images=91,
        shared_old_images=82,new_authority_images=8,new_frontend_images=1,
        existing_hia_owners_modified=['native/runtime_mcp.hepta'],runtime_decisions_in_HIA=True,
        public_authority_mode='stdio',public_network_or_http_added=False,
        native_graph_executed=False,production_activated=False,whole_runtime_replaced=False)
    target=a.source/'native/runtime_mcp_authority_mechanical.json'
    if a.check:assert target.read_bytes()==encoded(result)
    else:target.write_bytes(encoded(result))
    print(json.dumps(result,sort_keys=True))

if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--source',required=True,type=Path);p.add_argument('--baseline',required=True,type=Path)
    p.add_argument('--check',action='store_true');author(p.parse_args())
