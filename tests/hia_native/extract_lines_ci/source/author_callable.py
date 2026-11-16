#!/usr/bin/env python3
"""Derive a syscall-only Local extract callable from admitted mechanical owners.

The HIA controller owns operation order, error text, line decisions, locks,
history and cache requests. This source only adapts their fixed byte ABIs.
"""
from pathlib import Path
import argparse
import hashlib
import json
import re

PINS = {
    'text': '5120f566fe8e4ace6c441d2dd110188663cb29bcc28af26a759b44a6f86b15b6',
    'fixture': '2980ab23ed5b7ee37f449b81542473969b6d02dc0e2a6d15b0948296aec6f010',
    'create': '7e65424b896cd1022192275b91161479c2faa584662b1c513731f6d671cf0af7',
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def change(text, before, after, count=1):
    assert text.count(before) == count, (before, text.count(before), count)
    return text.replace(before, after)


def units(text):
    starts = list(re.finditer(r'(?m)^([A-Za-z_][A-Za-z0-9_]*):\n', text))
    return {m[1]: text[m.start(): starts[i + 1].start() if i + 1 < len(starts) else len(text)]
            for i, m in enumerate(starts)}


MKDIR = r'''
lel_child_mkdir:
    mov rbx,[r15+lel_CHILDREQ]
    cmp qword ptr [r15+lel_CHILDREQLEN],64
    jb lel_contract
    mov rax,0x3130514b4d485348
    cmp [rbx],rax
    jne lel_contract
    cmp qword ptr [rbx+8],1
    jne lel_contract
    cmp qword ptr [rbx+16],0
    jne lel_contract
    mov rcx,[r15+lel_CHILDREQLEN]
    sub rcx,64
    cmp [rbx+24],rcx
    jne lel_contract
    mov rax,[rbx+32]
    or rax,[rbx+40]
    or rax,[rbx+48]
    or rax,[rbx+56]
    jnz lel_contract
    lea rdi,[r15+lel_MKREQ]
    mov rsi,[r15+lel_CHILDREQLEN]
    xor edx,edx
    call lel_ensure_region
    mov rdi,[r15+lel_MKREQ]
    mov rsi,[r15+lel_MKREQCAP]
    mov edx,3
    call lel_protection
    mov rdi,[r15+lel_MKREQ]
    mov rsi,[r15+lel_CHILDREQ]
    mov rcx,[r15+lel_CHILDREQLEN]
    mov [r15+lel_MKLEN],rcx
    rep movsb
    mov rax,[r15+lel_META_POINTER]
    movzx eax,byte ptr [rax]
    cmp eax,2
    ja lel_contract
    mov rbx,[r15+lel_MKREQ]
    mov [rbx+16],rax
    mov rax,[rbx+24]
    inc rax
    jz lel_resource
    mov ecx,10
    mul rcx
    test rdx,rdx
    jnz lel_resource
    add rax,512
    jc lel_resource
    cmp rax,268435456
    ja lel_resource
    lea rdi,[r15+lel_MKWORK]
    mov rsi,rax
    xor edx,edx
    call lel_ensure_region
    mov rdi,[r15+lel_MKWORK]
    mov rcx,[r15+lel_MKWORKCAP]
    xor eax,eax
    rep stosb
    lea rdi,[r15+lel_SLOTS+640+24]
    mov esi,4096
    xor edx,edx
    call lel_ensure_region
    mov qword ptr [r15+lel_MKSEQ],0
lel_mkdir_invoke:
    mov rdi,[r15+lel_MKREQ]
    mov rsi,[r15+lel_MKREQCAP]
    mov edx,1
    call lel_protection
    mov rdi,[r15+lel_MKREQ]
    mov rsi,[r15+lel_MKLEN]
    mov rdx,[r15+lel_SLOTS+640+24]
    mov rcx,[r15+lel_SLOTS+640+32]
    mov r8,[r15+lel_MKWORK]
    mov r9,[r15+lel_MKWORKCAP]
    call qword ptr [r15+lel_SLOTS+640]
    mov edx,eax
    cmp rax,rdx
    jne lel_contract
    cmp eax,32
    je lel_mkdir_complete
    cmp eax,0xfffffffd
    jne lel_contract
    call lel_mkdir_effect
    mov rdi,[r15+lel_MKREQ]
    mov rsi,[r15+lel_MKREQCAP]
    mov edx,3
    call lel_protection
    mov rax,[r15+lel_MKREQ]
    mov qword ptr [rax+8],2
    mov qword ptr [rax+16],0
    jmp lel_mkdir_invoke
lel_mkdir_complete:
    mov rsi,[r15+lel_SLOTS+640+24]
    mov rax,0x3130524b4d485348
    cmp [rsi],rax
    jne lel_contract
    cmp qword ptr [rsi+24],2
    ja lel_contract
    mov rax,[rsi+24]
    mov rdx,[r15+lel_META_POINTER]
    mov [rdx],al
    mov [r15+lel_CHILDOUT],rsi
    mov eax,32
    jmp lel_child_completed
'''

SPAN = r'''    mov [r15+lel_CHILDCODE],rax
    mov [r15+lel_CHILDEXTENT],rax
    cmp qword ptr [r15+lel_CHILD],9
    je lel_parent_extent
    cmp qword ptr [r15+lel_CHILD],13
    je lel_endpoint_extent
    jmp lel_extent_ready
lel_parent_extent:
    cmp eax,80
    jne lel_contract
    mov rdx,[r15+lel_CHILDOUT]
    mov rcx,[rdx+16]
    cmp rcx,80
    jb lel_contract
    cmp rcx,[r15+lel_SLOTS+576+32]
    ja lel_contract
    mov [r15+lel_CHILDEXTENT],rcx
    jmp lel_extent_ready
lel_endpoint_extent:
    cmp eax,32
    jne lel_contract
    mov rdx,[r15+lel_CHILDOUT]
    mov ecx,32
    cmp qword ptr [rdx+8],0
    jne lel_endpoint_extent_checked
    add rcx,[rdx+24]
    jc lel_contract
lel_endpoint_extent_checked:
    cmp rcx,[r15+lel_SLOTS+768+32]
    ja lel_contract
    mov [r15+lel_CHILDEXTENT],rcx
lel_extent_ready:
'''

DATA_GROW = r'''lel_pure_data_growth:
    cmp r14,5
    jne lel_contract
    cmp qword ptr [rbx+32],32
    jb lel_contract
    mov rax,[rbx+24]
    mov rcx,0x3230305357524748
    cmp [rax],rcx
    jne lel_contract
    cmp qword ptr [rax+24],0
    jne lel_contract
    mov rsi,[rax+16]
    cmp qword ptr [rax+8],1
    je lel_pure_grow_work
    cmp qword ptr [rax+8],2
    jne lel_contract
    jmp lel_pure_grow_output
'''


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--runtime', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    paths = {'text': 'tests/hia_native/local_text_body/local_text_body_callable.S',
             'fixture': 'tests/hia_native/local_text_body/local_text_body_callable_fixture.S',
             'create': 'scripts/local_create_spec_callable.S'}
    raw = {k: (a.runtime / v).read_bytes() for k, v in paths.items()}
    assert {k: sha(v) for k, v in raw.items()} == PINS
    text = raw['text'].decode()
    result = text.replace('local_text_body_', 'local_extract_lines_').replace('ltb_', 'lel_')
    baseline = result
    for name, before, after in (('PUBLIC_CTX', 1024, 1280), ('RETURN_STACK', 1032, 1288),
        ('META_POINTER', 1040, 1296), ('RESULT_PAIR', 1048, 1304), ('WAIT_FLAG', 1064, 1320),
        ('ABORTING', 1072, 1328), ('CLEAN_FRAME', 1088, 1344), ('CLEAN_OUTPUT', 1152, 1408)):
        result = change(result, f'.equ lel_{name},{before}\n', f'.equ lel_{name},{after}\n')
    result = change(result, '.equ lel_MAIN_MAGIC,0x31304d4242544c48', '.equ lel_MAIN_MAGIC,0x31304d4354584548')
    result = change(result, '.equ lel_CONTEXT_MAGIC,0x3130494342544c48', '.equ lel_CONTEXT_MAGIC,0x3130494354584548')
    result = change(result, '.equ lel_META_BYTE,2432\n', '.equ lel_META_BYTE,2432\n'
        '.equ lel_MKREQ,1536\n.equ lel_MKREQCAP,1544\n.equ lel_MKLEN,1552\n'
        '.equ lel_MKSEQ,1560\n.equ lel_CHILDEXTENT,1568\n.equ lel_MKWORK,1584\n.equ lel_MKWORKCAP,1592\n')
    result = change(result, '    cmp ecx,12\n', '    cmp ecx,14\n', 2)
    result = change(result, '    cmp rax,80\n    jb lel_body_invoke', '    cmp rax,128\n    jb lel_body_invoke')
    result = change(result, '    mov rax,[rax+56]\n    mov [r15+lel_GENERATION],rax', '    mov rax,[rax+24]\n    mov [r15+lel_GENERATION],rax')
    result = change(result, '    mov r14d,21\n', '    mov r14d,27\n')
    result = change(result, '    .quad lel_SLOTS+704+8,lel_SLOTS+704+24\n', '    .quad lel_SLOTS+704+8,lel_SLOTS+704+24\n'
        '    .quad lel_SLOTS+768+8,lel_SLOTS+768+24,lel_SLOTS+832+8,lel_SLOTS+832+24\n'
        '    .quad lel_MKREQ,lel_MKWORK\n')
    result = change(result, '    cmp rcx,12\n    ja lel_contract', '    cmp rcx,14\n    ja lel_contract')
    result = change(result, '    je lel_child_unlink\n', '    je lel_child_mkdir\n')
    result = change(result, '    cmp eax,12\n    je lel_child_error\n    mov rdi,rax', '    cmp eax,12\n    je lel_child_error\n'
        '    cmp eax,13\n    je lel_child_endpoint\n    cmp eax,14\n    je lel_child_verify\n    mov rdi,rax')
    result = change(result, 'lel_child_error:\n', 'lel_child_endpoint:\n    mov edi,12\n    jmp lel_child_pure_selected\n'
        'lel_child_verify:\n    mov edi,13\n    jmp lel_child_pure_selected\nlel_child_error:\n')
    result = change(result, 'lel_child_error:\n    mov edi,11\n', 'lel_child_error:\n    mov edi,11\nlel_child_pure_selected:\n')
    result = change(result, '    mov [r15+lel_CHILDCODE],rax\n    mov rdi,[r15+lel_SLOTS+24]', SPAN + '    mov rdi,[r15+lel_SLOTS+24]')
    result = change(result, '    mov rsi,[r15+lel_CHILDCODE]\n    add rsi,64', '    mov rsi,[r15+lel_CHILDEXTENT]\n    add rsi,64')
    result = change(result, '    mov [rbx+40],rcx\n    mov [rbx+48],rcx', '    mov [rbx+40],rcx\n    mov rcx,[r15+lel_CHILDEXTENT]\n    mov [rbx+48],rcx')
    result = change(result, '    mov rax,[r15+lel_CHILDCODE]\n    add rax,64', '    mov rax,[r15+lel_CHILDEXTENT]\n    add rax,64')
    result = change(result, '    cmp r14,11\n    ja lel_contract', '    cmp r14,13\n    ja lel_contract')
    result = change(result, '    cmp eax,0xffffffef\n    je lel_pure_work_need', '    cmp eax,0xffffffd0\n    je lel_pure_data_growth\n    cmp eax,0xffffffef\n    je lel_pure_work_need')
    result = change(result, 'lel_pure_work_need:\n', DATA_GROW + 'lel_pure_work_need:\n')
    result = change(result, '    cmp r14,5\n    je lel_pure_work_pointer\n    cmp r14,9\n    jne lel_contract', '    jmp lel_contract')
    result = change(result, '    cmp r14,5\n    je lel_pure_output_pointer\n    cmp r14,9\n    jne lel_contract', '    jmp lel_contract')
    result = change(result, '    mov rsi,[rax+152]\n    cmp rsi,[rbx+32]', '    mov rsi,[rax+152]\nlel_pure_grow_output:\n    cmp rsi,[rbx+32]')
    result = change(result, '    cmp r14,8\n    jne lel_resource', '    cmp r14,8\n    je lel_pure_capacity_grow\n'
        '    cmp r14,9\n    je lel_pure_capacity_grow\n    cmp r14,12\n    je lel_pure_capacity_grow\n'
        '    cmp r14,13\n    jne lel_resource')
    start, end = result.index('lel_child_unlink:\n'), result.index('lel_round_capacity:\n')
    result = result[:start] + MKDIR.lstrip() + result[end:]
    original_effect = raw['create'].decode().split('lcsp_mkdir_effect:\n', 1)[1].split('lcsp_async_parent_dispatch:\n', 1)[0]
    effect = 'lcsp_mkdir_effect:\n' + original_effect
    effect = change(effect, '    mov edi,2\n    mov rsi,rbp\n    mov edx,96\n    call lcsp_write_all\n'
        '    test eax,eax\n    jnz lcsp_async_infrastructure\n', '')
    effect = effect.replace('lcsp_async_contract', 'lel_contract').replace('lcsp_', 'lel_')
    result += '\n/* Same admitted mkdir/statx/stat effect, without fixture journaling. */\n' + effect
    assert 'ltb_' not in result and 'lcsp_' not in result and 'child_unlink' not in result
    fixture = raw['fixture'].decode()
    assert fixture.count(text) == 1
    fixture = fixture.replace(text, '@@EXTRACT_CALLABLE@@').replace('local_text_body_', 'local_extract_lines_')
    fixture = change(fixture, '    cmp ecx,12\n', '    cmp ecx,14\n', 2)
    fixture = change(fixture, '    cmp r14,11\n    ja contract', '    cmp r14,13\n    ja contract')
    fixture = change(fixture, '    mov rax,0x3130515242544c48', '    mov rax,0x3130515254584548')
    fixture = change(fixture, '    cmp qword ptr [r15+INLEN],80', '    cmp qword ptr [r15+INLEN],128')
    fixture = change(fixture, '    mov rax,[rbx+56]\n    mov [r15+GENERATION],rax', '    mov rax,[rbx+24]\n    mov [r15+GENERATION],rax')
    fixture = change(fixture, '    mov rax,0x3130494342544c48', '    mov rax,0x3130494354584548')
    fixture = change(fixture, 'image_table:\n.quad 0,0,0,0,0,0,0,0,0,0,0,0\n', 'image_table:\n.quad 0,0,0,0,0,0,0,0,0,0,0,0,0,0\n')
    fixture = fixture.replace('@@EXTRACT_CALLABLE@@', result)
    before, after = units(baseline), units(result)
    proof = {'schema': 'hepta.runtime.extract-callable-author.v1', 'inputs': {k: {'path': paths[k], 'bytes': len(raw[k]), 'sha256': sha(raw[k])} for k in raw},
        'author_sha256': sha(Path(__file__).read_bytes()), 'callable': {'bytes': len(result.encode()), 'sha256': sha(result.encode())},
        'fixture': {'bytes': len(fixture.encode()), 'sha256': sha(fixture.encode())},
        'unchanged_label_units': {k: sha(v.encode()) for k, v in before.items() if after.get(k) == v},
        'changed_label_units': sorted(k for k, v in before.items() if k in after and after[k] != v),
        'removed_label_units': sorted(set(before) - set(after)), 'added_label_units': sorted(set(after) - set(before)),
        'physical_members': 14, 'logical_callback_hole': 10, 'context_bytes': 192,
        'private_descriptor_end': 1152, 'private_context_begin': 1280,
        'scalar_and_payload_extent_separate': True, 'workspace_and_output_grow': True,
        'blocking_local_effects_only': True, 'full_async_qualified': False,
        'native_executed': False, 'original_compared': False, 'public_handler_qualified': False}
    a.output.mkdir(parents=True, exist_ok=False)
    (a.output / 'local_extract_lines_callable.S').write_text(result)
    (a.output / 'local_extract_lines_fixture.S').write_text(fixture)
    (a.output / 'callable.proof.json').write_bytes(canonical(proof))
    print(json.dumps({k: proof[k] for k in ('schema', 'callable', 'fixture', 'changed_label_units', 'removed_label_units', 'added_label_units')}))


if __name__ == '__main__':
    main()
