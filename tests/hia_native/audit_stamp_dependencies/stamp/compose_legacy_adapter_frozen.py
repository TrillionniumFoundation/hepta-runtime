# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Compose the two unchanged, closed syscall dispatchers under one root owner."""
from pathlib import Path
import hashlib
import json
import re

ROOT = Path(__file__).resolve().parents[1]
SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def child(kind, prefix, base, owner, result_bytes):
    path = ROOT / 'dependencies' / (kind + '_adapter_frozen.S')
    original = path.read_text()
    assert not re.search(r'\br13\b', original)
    symbols = set(re.findall(r'^([A-Za-z_]\w*):', original, re.M))
    symbols |= set(re.findall(r'^\.equ (\w+),', original, re.M))
    names = {name: prefix + name for name in symbols}
    names['contract_fail'] = 'main_contract_fail'
    names['io_fail'] = 'main_io_fail'
    resume = 'resume_' + kind
    body = original[original.index(resume + ':'):original.index('owner_result:')]
    equates = '\n'.join(line for line in original.splitlines() if line.startswith('.equ ')) + '\n'
    def relocate(text):
        return re.sub(r'\b(' + '|'.join(sorted(names, key=len, reverse=True)) + r')\b', lambda m: names[m[0]], text)
    relocated = relocate(body)
    code = relocate(equates)
    globals_ = [prefix + kind + '_call_displacement']
    if kind == 'anchor': globals_.append(prefix + 'json_call_displacement')
    code += ''.join('.global ' + name + '\n' for name in globals_)
    code += f'''{kind}_entry:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    lea r15, [r13 + {base}]
    lea r12, [r15 + {owner}]
    lea rdi, [r15 + 4096]
    mov esi, 4096
    mov edx, 3
    mov eax, 10
    syscall
    test rax, rax
    jnz main_io_fail
    lea rdi, [r15 + 4096]
    lea rsi, [r13 + MAIN_OWNER + M_REQUEST]
    mov ecx, 32
    rep movsb
    mov qword ptr [r15 + 24], 32
    lea rdi, [r15 + 4096]
    mov esi, 4096
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz main_io_fail
'''
    if kind == 'anchor':
        code += '''    mov rax, [r13 + 128]
    cmp [r15 + 128], rax
    jne main_contract_fail
'''
    else:
        code += '''    cmp qword ptr [r15 + 16384], -1
    jne main_contract_fail
    mov rax, [r13 + 136]
    test rax, rax
    js main_contract_fail
    mov [r15 + 16384], rax
'''
    code += relocated
    code += prefix + 'owner_result:\n'
    if kind == 'anchor':
        tail = original[original.index('owner_result:') + len('owner_result:\n'):original.index('    mov [r15 + 32], eax\n', original.index('owner_result:'))]
        code += relocate(tail)
        code += '''    cmp eax, 64
    jb main_contract_fail
    cmp eax, 2368
    ja main_contract_fail
'''
    else:
        code += '''    cmp qword ptr [r12 + 4104], 0
    jne main_contract_fail
    cmp qword ptr [r12 + 4288], 0
    jne main_contract_fail
    cmp qword ptr [r12 + 4328], 0
    jne main_contract_fail
    cmp qword ptr [r15 + 16384 + 261*8], -1
    jne main_contract_fail
    cmp eax, 72
    jne main_contract_fail
    mov qword ptr [r15 + 16384], -1
'''
    code += '''    lea rdi, [r13 + MAIN_OWNER + M_REPLY]
    lea rsi, [r15 + 8192]
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
'''
    return code, dict(original=str(path.relative_to(ROOT)), original_sha256=SHA(path.read_bytes()),
        original_dispatch_sha256=SHA(body.encode()), relocated_dispatch_sha256=SHA(relocated.encode()),
        relocation=names, borrowed_root_alias_released_without_close=True,
        workspace_bytes=1048576 if kind == 'anchor' else 8388608,
        minimum_reply=result_bytes)


def main():
    pins = json.loads((ROOT / 'dependency-inputs.json').read_bytes())
    for name, expected in pins.items():
        raw = (ROOT / name).read_bytes()
        assert dict(bytes=len(raw), sha256=SHA(raw)) == expected
    code = (ROOT / 'scripts/legacy_adapter_main.S').read_text() + '\n'
    anchor, anchor_proof = child('anchor', 'a_', 'ANCHOR_BASE', 65536, 64)
    namespace, namespace_proof = child('namespace', 'ns_', 'NAMESPACE_BASE', 1048576, 72)
    entropy = (ROOT / 'scripts/legacy_entropy.S').read_text()
    code += anchor + '\n' + namespace + '\n' + entropy
    path = ROOT / 'scripts/legacy_adapter.S'
    path.write_text(code)
    proof = dict(schema='hepta.audit-legacy.adapter-composition.v1', adapter_source_sha256=SHA(code.encode()),
        children=dict(anchor=anchor_proof, namespace=namespace_proof),
        main_source_sha256=SHA((ROOT / 'scripts/legacy_adapter_main.S').read_bytes()),
        entropy_source_sha256=SHA(entropy.encode()),
        fixed_map_bytes=16781312, root_workspace=[1048576, 1048576],
        anchor_base=2097152, namespace_base=5242880, entropy_workspace=[15728640, 1024],
        runtime_python_required=False, runtime_rust_required=False,
        metadata_cache_exchange_owned_by_hia=True, actual_qualification_executed=False,
        complete_archive_acquisition=False, production_activated=False, whole_runtime_replaced=False)
    (ROOT / 'native/audit_legacy_adapter_composition.json').write_text(json.dumps(proof, sort_keys=True, indent=2) + '\n')
    print(json.dumps(dict(bytes=len(code.encode()), sha256=SHA(code.encode()))))


if __name__ == '__main__': main()
