# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Bind a held File and the exact frozen Namespace dispatcher to HIA archive_stamp."""
from pathlib import Path
import hashlib
import importlib.util
import json

ROOT = Path(__file__).resolve().parents[1]
SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def main():
    original = (ROOT / 'dependencies/legacy_adapter_main.S').read_text()
    prefix = original[:original.index('main_zero_span:')]
    prefix = prefix.replace('legacy_call_displacement', 'stamp_call_displacement')
    prefix = prefix.replace('.equ ANCHOR_BASE, 2097152\n', '')
    prefix = prefix.replace('.equ NAMESPACE_BASE, 5242880', '.equ NAMESPACE_BASE, 2097152')
    prefix = prefix.replace('.equ ENTROPY_WORK, 15728640\n', '')
    prefix = prefix.replace('.equ FINAL_GUARD, 16777216', '.equ FINAL_GUARD, 12582912')
    prefix = prefix.replace('.equ TOTAL_MAP, 16781312', '.equ TOTAL_MAP, 12587008')
    for line in ('.equ M_TEMP, 4096\n', '.equ M_LEGACY, 4352\n', '.equ M_ANCHOR, 4608\n', '.equ M_JSON, 6144\n',
        '    mov qword ptr [r15 + ANCHOR_BASE + 128], -1\n', '    mov qword ptr [r15 + ANCHOR_BASE + 136], -1\n',
        '    mov [r15 + ANCHOR_BASE + 128], rax\n'):
        assert line in prefix;prefix = prefix.replace(line, '')
    prefix = prefix.replace('    mov ecx, 5\n', '    mov ecx, 1\n')
    prefix = prefix.replace('    mov edx, 0xb0000\n', '    mov edx, 0xa0800\n')
    prefix = prefix.replace('0x313030414c415248', '0x3130304153415248')
    dispatch = prefix.index('    cmp rax, 1\n    je main_open')
    prefix = prefix[:dispatch]
    for kind, name in ((2, 'fstat'), (5, 'uid'), (8, 'statx'), (9, 'statx_probe'), (10, 'statat'), (11, 'statat_probe')):
        prefix += f'    cmp rax, {kind}\n    je main_{name}\n'
    prefix += '    jmp main_contract_fail\n'
    imports = []

    def exact(begin, end):
        part = original[original.index(begin + ':'):original.index(end + ':')]
        imports.append(dict(begin=begin, end=end, bytes=len(part.encode()), sha256=SHA(part.encode())))
        return part

    main_code = prefix + exact('main_zero_span', 'main_slot_live')
    main_code += '''main_slot_live:
    cmp qword ptr [r14 + 24], 0
    jne main_contract_fail
    mov rdi, [r15 + 128]
    test rdi, rdi
    js main_contract_fail
    ret
'''
    main_code += exact('main_uid', 'main_temp_open')
    main_code += exact('main_metadata_live', 'main_write')
    main_code += '''main_child:
    cmp rax, 101
    jne main_contract_fail
    cmp qword ptr [r14 + 24], 0
    jne main_contract_fail
    cmp qword ptr [r14 + 32], M_REQUEST
    jne main_contract_fail
    cmp qword ptr [r14 + 40], 32
    jne main_contract_fail
    cmp qword ptr [r14 + 48], M_REPLY
    jne main_contract_fail
    cmp qword ptr [r14 + 56], 72
    jne main_contract_fail
    cmp qword ptr [r12 + 8], 9
    jne main_contract_fail
    cmp qword ptr [r12 + M_REQUEST + 8], 1
    jne main_contract_fail
    cmp qword ptr [r12 + M_REQUEST + 16], 0
    jne main_contract_fail
    call namespace_entry
'''
    main_code += exact('main_child_return', 'main_result')
    main_code += '''main_result:
    cmp qword ptr [r12 + 8], 0
    jne main_contract_fail
    mov [r15 + 32], eax
    cmp eax, 48
    je main_result_header
    cmp eax, 160
    je main_result_header
    cmp eax, 0xffffffff
    je main_result_header
    cmp eax, 0xfffffffe
    jne main_contract_fail
main_result_header:
    lea rsi, [r15 + 32]
    mov edx, 4
    call main_write_exact
    mov edx, [r15 + 32]
    cmp edx, 4096
    ja main_next_frame
    lea rsi, [r15 + MAIN_OUTPUT]
    call main_write_exact
    jmp main_next_frame
'''
    main_code += exact('main_read_exact', 'main_success')
    main_code += '''main_success:
    xor ebp, ebp
    jmp main_cleanup
main_contract_fail:
    mov ebp, 2
    jmp main_cleanup
main_io_fail:
    mov ebp, 74
main_cleanup:
    mov r15, r13
    mov qword ptr [r15 + NAMESPACE_BASE + 16384], -1
    add r15, NAMESPACE_BASE
    mov ebx, 33793
main_namespace_cleanup_loop:
    mov rdi, [r15 + rbx*8 + 16384]
    mov qword ptr [r15 + rbx*8 + 16384], -1
    test rdi, rdi
    js main_namespace_cleanup_next
    call ns_raw_descriptor_referenced
    test eax, eax
    jnz main_namespace_cleanup_next
    mov eax, 3
    syscall
main_namespace_cleanup_next:
    dec ebx
    jns main_namespace_cleanup_loop
    mov r15, r13
    mov rdi, [r15 + 128]
    mov qword ptr [r15 + 128], -1
    test rdi, rdi
    js main_unmap
    mov eax, 3
    syscall
main_unmap:
    mov rdi, r15
    mov esi, TOTAL_MAP
    mov eax, 11
    syscall
    mov edi, ebp
    jmp main_exit
main_bare_fail:
    mov edi, 74
    jmp main_exit
main_usage:
    mov edi, 64
main_exit:
    mov eax, 60
    syscall
    ud2
'''
    spec = importlib.util.spec_from_file_location('frozen_legacy_composer', ROOT / 'dependencies/compose_legacy_adapter_frozen.py')
    composer = importlib.util.module_from_spec(spec);spec.loader.exec_module(composer)
    composer.ROOT = ROOT
    child_code, child_proof = composer.child('namespace', 'ns_', 'NAMESPACE_BASE', 1048576, 72)
    assert child_code.count('    mov rax, [r13 + 136]\n') == 1
    child_code = child_code.replace('    mov rax, [r13 + 136]\n', '    mov rax, [r13 + 128]\n')
    code = main_code + '\n' + child_code
    (ROOT / 'scripts/audit_stamp_adapter.S').write_text(code)
    proof = dict(schema='hepta.request-audit.stamp-adapter-composition.v1',
        adapter_source_sha256=SHA(code.encode()),
        main_import_source='dependencies/legacy_adapter_main.S', main_import_source_sha256=SHA(original.encode()),
        exact_main_dispatch_blocks=imports, namespace=child_proof,
        child_wrapper_delta='borrow parent descriptor slot 128 instead of 136',
        namespace_dispatch_unchanged_except_label_relocation=True,
        fixed_map_bytes=12587008, main_workspace=[1048576,1048576], namespace_base=2097152,
        startup_flags=0xa0800, trusted_parent_descriptor=True, explicit_startup_root_fixture=True,
        runtime_python_required=False, runtime_rust_required=False, runtime_libc_required=False,
        actual_qualification_executed=False, production_activated=False, whole_runtime_replaced=False)
    (ROOT / 'native/request_audit_stamp_adapter_composition.json').write_text(json.dumps(proof, sort_keys=True, indent=2) + '\n')
    print(json.dumps(dict(bytes=len(code.encode()), sha256=SHA(code.encode()))))


if __name__ == '__main__':main()
