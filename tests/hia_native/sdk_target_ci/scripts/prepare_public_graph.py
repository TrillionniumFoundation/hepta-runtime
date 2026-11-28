#!/usr/bin/env python3
"""Prepare only this private eight-tool graph's mechanical bindings."""
from pathlib import Path
import hashlib,json,shutil
ROOT=Path(__file__).resolve().parents[1];SOURCE=ROOT/'source'
sha=lambda b:hashlib.sha256(b).hexdigest()
def replace(s,old,new):
    assert s.count(old)==1,old[:120]
    return s.replace(old,new,1)
def main():
    out=ROOT/'evidence/graph-overlay-v1';out.mkdir()
    changes={}
    def publish(rel,raw):
        p=SOURCE/rel;before=p.read_bytes() if p.exists() else None
        if before is not None:
            old=out/'before'/rel;old.parent.mkdir(parents=True,exist_ok=True);old.write_bytes(before)
        p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw)
        changes[rel]={'before_sha256':None if before is None else sha(before),'after_sha256':sha(raw),'bytes':len(raw)}
    baseline=ROOT/'baseline/runtime_mcp_extra_engine.S'
    assert sha(baseline.read_bytes())=='b0cf733f7245196a976c8c4d6bc5662ba6b9ede755e62fcabebf0a6a8778933c'
    s=baseline.read_text()
    s=s.replace('33 rows at engine+4096.','46 rows at engine+4096; new SDK leaves use fixed declared capacities.')
    s=replace(s,'.equ RG_SLOTS, 33','.equ RG_SLOTS, 46')
    s=replace(s,'    mov edi, 4096\n    cmp ebp, 4\n',
        '    mov edi, 100663296\n    cmp ebp, 42\n    jb runtime_grow_allocate_ordinary_work\n    cmp ebp, 44\n    jbe runtime_grow_allocate_work\nruntime_grow_allocate_ordinary_work:\n    mov edi, 4096\n    cmp ebp, 4\n')
    s=replace(s,'    mov edi, 4096\n    call view_allocate\n    cmp rax, -4095\n    jae runtime_grow_resource\n    mov [rbx + 32], rax\n    mov qword ptr [rbx + 40], 4096\n',
        '    mov edi, 4096\n    cmp ebp, 42\n    jb runtime_grow_allocate_output_ready\n    cmp ebp, 44\n    ja runtime_grow_allocate_output_ready\n    mov edi, 67108864\nruntime_grow_allocate_output_ready:\n    mov [rsp + 24], rdi\n    call view_allocate\n    cmp rax, -4095\n    jae runtime_grow_resource\n    mov [rbx + 32], rax\n    mov rcx, [rsp + 24]\n    mov [rbx + 40], rcx\n')
    s=replace(s,'    cmp ebp, 19\n    je runtime_grow_protocol_result\n',
        '    cmp ebp, 19\n    je runtime_grow_protocol_result\n    cmp ebp, 44\n    je runtime_grow_protocol_result\n    cmp ebp, 45\n    je runtime_grow_protocol_result\n')
    s=replace(s,'runtime_grow_target:\n    cmp edi, 18\n',
        'runtime_grow_target:\n    cmp edi, 19\n    je runtime_grow_target_sdk_protocol\n    cmp edi, 18\n')
    s=replace(s,'runtime_grow_target_frontend:\n',
        'runtime_grow_target_sdk_protocol:\n    cmp rsi, 3\n    ja runtime_grow_target_invalid\n    lea rdx, [rip + runtime_grow_sdk_protocol_targets]\n    jmp runtime_grow_target_byte\nruntime_grow_target_frontend:\n')
    s=replace(s,'    .ascii "HRMCFA02"\n    .quad 0, 0\n',
        '    .ascii "HRMCFA02"\n    .ascii "HRQPCA01"\n    .quad 0\n')
    s=replace(s,'runtime_grow_filesystem_gateway_targets:\n',
        '    .zero 104 /* Reserved 33-41, SDK leaves 42-44, historical protocol 45. */\nruntime_grow_sdk_protocol_targets:\n    .byte 42, 43, 44, 45\nruntime_grow_filesystem_gateway_targets:\n')
    publish('scripts/runtime_mcp_extra_engine.S',s.encode())
    for name in ['runtime_mcp_transport.S','runtime_mcp_filesystem_fixture.S']:
        p=ROOT/'baseline'/name;s=p.read_text()
        s=replace(s,'grow_fixture_images:\n    .zero 264','grow_fixture_images:\n    .zero 368')
        publish('scripts/'+name,s.encode())
    for source,target in [('baseline/sdk_message.hepta','sdk_message_target.hepta'),('native/sdk_request.hepta','sdk_request_target.hepta'),('native/sdk_frontend_bridge.hepta','sdk_frontend_bridge_target.hepta'),('native/runtime_mcp_catalog_target.hepta','runtime_mcp_catalog_target.hepta'),('native/sdk_public_protocol.hepta','sdk_public_protocol.hepta')]:
        publish('native/'+target,(ROOT/source).read_bytes())
    binding=SOURCE/'native/runtime_mcp_sources.json';before=binding.read_bytes();(out/'source-binding-before.json').write_bytes(before);data=json.loads(before)
    assert data['schema']=='hepta.runtime.public-source-closure.v2'
    for rel,row in changes.items():data['sources'][rel]={'bytes':row['bytes'],'sha256':row['after_sha256']}
    binding.write_text(json.dumps(data,sort_keys=True,indent=2)+'\n')
    record={'schema':'hepta.g5.public-eight-graph-overlay.v1','changes':changes,'source_binding_before_sha256':sha(before),'source_binding_after_sha256':sha(binding.read_bytes()),'base_mechanical_profile':'pinned v9 public58; private TextEditor mechanics preserved separately, not silently inherited','reserved_slots':list(range(33,42)),'target_slots':{'message':42,'request':43,'bridge':44,'historical_protocol':45},'controller_slot':19,'catalog_slot':0,'shared_source_modified':False,'target_canonical_v5_adopted':False,'full_sdk_qualified':False,'production_activated':False,'old_path_removed':False}
    (out/'summary.json').write_text(json.dumps(record,sort_keys=True,indent=2)+'\n')
    print(json.dumps({'status':'PASS','changes':len(changes),'source_binding_sha256':record['source_binding_after_sha256']},sort_keys=True))
if __name__=='__main__':main()
