# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Retain the frozen Stamp and Namespace dispatch exactly under a bounded cache owner."""
from pathlib import Path
import hashlib
import json
import re

ROOT=Path(__file__).resolve().parents[1]
SHA=lambda raw:hashlib.sha256(raw).hexdigest()


def main():
    path=ROOT/'dependencies/audit_stamp_adapter_frozen.S';original=path.read_text()
    symbols=set(re.findall(r'^([A-Za-z_]\w*):',original,re.M))|set(re.findall(r'^\.equ (\w+),',original,re.M))
    mapping={name:'s_'+name for name in symbols}
    def relocate(text):
        return re.sub(r'\b('+'|'.join(sorted(mapping,key=len,reverse=True))+r')\b',lambda m:mapping[m[0]],text)
    metadata=original[original.index('main_resume:'):original.index('main_result:')]
    namespace=original[original.index('.equ ns_INPUT,'):]
    equates='\n'.join(line for line in original[:original.index('_start:')].splitlines() if line.startswith('.equ '))+'\n'
    code=(ROOT/'scripts/cache_stamp_adapter_main.S').read_text()+'\n'
    code+=original[original.index('main_read_exact:'):original.index('main_success:')]
    code+=relocate(equates)+'.global s_stamp_call_displacement\n'
    code+='''stamp_entry:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    mov rax, r15
    lea r15, [r15 + STAMP_BASE]
    mov [r15 + 64], rax
    mov r13, r15
    mov [r15 + 128], rdi
    lea r12, [r15 + s_MAIN_OWNER]
    lea rdi, [r15 + s_MAIN_INPUT]
    mov esi, 4096
    mov edx, 3
    mov eax, 10
    syscall
    test rax, rax
    jnz s_main_io_fail
    mov rax, 0x3130305153415248
    mov [r15 + s_MAIN_INPUT], rax
    mov qword ptr [r15 + s_MAIN_INPUT + 8], 1
    mov qword ptr [r15 + 24], 16
    lea rdi, [r15 + s_MAIN_INPUT]
    mov esi, 4096
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz s_main_io_fail
'''+relocate(metadata)+'''s_main_result:
    cmp qword ptr [r12 + 8], 0
    jne s_main_contract_fail
    cmp eax, 48
    je stamp_result_ready
    cmp eax, 160
    jne s_main_contract_fail
stamp_result_ready:
    mov qword ptr [r15 + 128], -1
    mov rdi, [r15 + 64]
    add rdi, CACHE_WORK + 524288
    lea rsi, [r15 + s_MAIN_OUTPUT]
    mov ecx, eax
    rep movsb
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
s_main_contract_fail:
    mov r13, [r13 + 64]
    jmp main_contract_fail
s_main_io_fail:
    mov r13, [r13 + 64]
    jmp main_io_fail
'''+relocate(namespace)
    (ROOT/'scripts/cache_stamp_adapter.S').write_text(code)
    proof=dict(schema='hepta.request-audit.cache-stamp-adapter-composition.v1',adapter_source_sha256=SHA(code.encode()),
        main_source_sha256=SHA((ROOT/'scripts/cache_stamp_adapter_main.S').read_bytes()),
        imported_source='dependencies/audit_stamp_adapter_frozen.S',imported_source_sha256=SHA(path.read_bytes()),
        original_metadata_dispatch_sha256=SHA(metadata.encode()),relocated_metadata_dispatch_sha256=SHA(relocate(metadata).encode()),
        original_namespace_dispatch_sha256=SHA(namespace.encode()),relocated_namespace_dispatch_sha256=SHA(relocate(namespace).encode()),
        relocation=mapping,borrowed_stamp_root_alias_released_without_close=True,
        fixed_map_bytes=23072768,cache_workspace=[2097152,8388608],stamp_base=10485760,
        startup_fixture_files=17,startup_flags=0xa0800,cold_snapshot_admitted=False,
        runtime_python_required=False,runtime_rust_required=False,runtime_libc_required=False,
        actual_qualification_executed=False,public_dispatch_qualified=False,whole_runtime_replaced=False)
    (ROOT/'native/request_audit_cache_stamp_adapter_composition.json').write_text(json.dumps(proof,sort_keys=True,indent=2)+'\n')
    print(json.dumps(dict(bytes=len(code.encode()),sha256=SHA(code.encode()))))


if __name__=='__main__':main()
