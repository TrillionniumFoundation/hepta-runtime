"""Add fixed-FD4 timing observations to an isolated copy of frozen v2.

Every HIA and packed port byte remains unchanged. Removing the inserted
observations must recover the complete original mechanical engine text.
"""
from pathlib import Path
import argparse
import hashlib
import json
import shutil


def sha(data):
    return hashlib.sha256(data).hexdigest()


HOOK = r'''
/* Diagnostic-only fixed FD4 record, HPHASE01/112. No public input selects
 * this sink. The regular fixed trace entry preflights the inherited FD4.
 * All caller registers and flags survive; engine+184 is the preexisting
 * fixture event counter and is not application state. */
runtime_grow_profile_emit:
    pushfq
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    sub rsp, 128
    mov [rsp + 64], rax
    mov [rsp + 24], rdi
    mov [rsp + 56], rsi
    mov rax, 0x3130455341485048 /* HPHASE01 */
    mov [rsp], rax
    mov qword ptr [rsp + 8], 112
    inc qword ptr [r15 + 184]
    mov rax, [r15 + 184]
    mov [rsp + 16], rax
    mov [rsp + 32], r15
    mov [rsp + 40], rbp
    mov rax, [rbx + 16]
    mov [rsp + 72], rax
    mov rax, [rbx + 40]
    mov [rsp + 80], rax
    mov qword ptr [rsp + 88], 0
    mov rax, [rbx + 8]
    test rax, rax
    jz runtime_grow_profile_phase_done
    cmp qword ptr [rbx + 16], 16
    jb runtime_grow_profile_phase_done
    mov rax, [rax + 8]
    mov [rsp + 88], rax
runtime_grow_profile_phase_done:
    mov rax, [rbx + 24]
    mov [rsp + 96], rax
    mov [rsp + 104], rbx
    mov eax, 228
    mov edi, 1
    lea rsi, [rsp + 112]
    syscall
    test rax, rax
    jne runtime_grow_profile_failed
    imul rax, qword ptr [rsp + 112], 1000000000
    add rax, [rsp + 120]
    mov [rsp + 48], rax
    mov rsi, rsp
    mov edx, 112
runtime_grow_profile_write:
    mov eax, 1
    mov edi, 4
    syscall
    cmp rax, -4
    je runtime_grow_profile_write
    test rax, rax
    jle runtime_grow_profile_failed
    add rsi, rax
    sub rdx, rax
    jnz runtime_grow_profile_write
    add rsp, 128
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    popfq
    ret
runtime_grow_profile_failed:
    /* Observation failure is explicit and retains the complete raw capture. */
    mov eax, 60
    mov edi, 112
    syscall
    ud2

'''


def observe(event):
    return ('.if PM_FIXED_TRACE_FD\n    push rdi\n'
            f'    mov edi, {event}\n    call runtime_grow_profile_emit\n'
            '    pop rdi\n.endif\n')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    source = a.source.resolve(strict=True)
    output = a.output.resolve()
    original = (source / 'scripts/runtime_mcp_extra_engine.S').read_text()
    baseline_binding = (source / 'native/runtime_mcp_sources.json').read_bytes()
    assert sha(baseline_binding) == '86770f8bbd995c15038220add0ca8e9690c6465d4b3812329f3c7db22f277a1a'
    assert json.loads(baseline_binding)['sources']['scripts/runtime_mcp_extra_engine.S'] == {
        'bytes': len(original.encode()), 'sha256': sha(original.encode())}
    shutil.copytree(source, output)
    text = original
    edits = []

    def replace(before, after):
        nonlocal text
        assert text.count(before) == 1, before
        text = text.replace(before, after, 1)
        edits.append({'before': before, 'after': after})

    replace('    sub rsp, 96\n    mov [rsp], rdi\n',
            '    sub rsp, 96\n    mov qword ptr [rsp + 88], 0\n    mov [rsp], rdi\n')
    before = '    cmp ebp, 57\n    je runtime_grow_bellman_dispatch\n'
    replace(before, '    mov qword ptr [rsp + 88], 1\n' + observe(1) + before)
    before = 'runtime_grow_enter_native:\n'
    # Event 3 must observe the actual input length, not a prior scratch value.
    replace(before, before + '    mov rsi, [rsp + 8]\n' + observe(3))
    before = 'runtime_grow_called:\n'
    replace(before, before + observe(4))
    before = 'runtime_grow_done:\n    add rsp, 96\n'
    replace(before, 'runtime_grow_done:\n    cmp qword ptr [rsp + 88], 0\n'
            '    je runtime_grow_profile_no_enter\n' + observe(2) +
            'runtime_grow_profile_no_enter:\n    add rsp, 96\n')
    text += HOOK
    restored = text[:-len(HOOK)]
    for edit in reversed(edits):
        assert restored.count(edit['after']) == 1
        restored = restored.replace(edit['after'], edit['before'], 1)
    assert restored == original
    (output / 'scripts/runtime_mcp_extra_engine.S').write_text(text)
    proof = {'schema': 'hepta.runtime.pump-engine-profile.v1',
             'baseline_source_sha256': sha(original.encode()),
             'profile_source_sha256': sha(text.encode()),
             'author_sha256': sha(Path(__file__).read_bytes()),
             'inverse_recovers_complete_baseline': True,
             'all_hia_and_packed_port_bytes_unchanged': True,
             'edits': edits, 'appended_observer_sha256': sha(HOOK.encode()),
             'diagnostic_only': True, 'runtime_executed': False,
             'record': 'HPHASE01/112: magic, extent, sequence, event, engine, slot, monotonic_ns, entry_or_poll_input_length, actual_return_register, workspace_capacity, output_capacity, workspace_word8, descriptor_sequence, descriptor_pointer',
             'events': {'1': 'slot enter', '2': 'slot exit', '3': 'direct HIA poll begin', '4': 'direct HIA poll end'}}
    (output / 'native/runtime_mcp_engine_profile.json').write_text(json.dumps(proof, sort_keys=True, indent=2) + '\n')
    binding = json.loads((source / 'native/runtime_mcp_sources.json').read_bytes())
    binding['sources'] = {path.relative_to(output).as_posix(): {'bytes': path.stat().st_size, 'sha256': sha(path.read_bytes())}
                          for path in sorted(output.rglob('*')) if path.is_file() and path != output / 'native/runtime_mcp_sources.json'}
    (output / 'native/runtime_mcp_sources.json').write_text(json.dumps(binding, sort_keys=True, indent=2) + '\n')
    assert all((source / path.relative_to(output)).read_bytes() == path.read_bytes()
               for path in (output / 'native').glob('*.hepta'))
    print(json.dumps({'output': str(output), 'binding_sha256': sha((output / 'native/runtime_mcp_sources.json').read_bytes()),
                      'baseline_source_sha256': proof['baseline_source_sha256'], 'profile_source_sha256': proof['profile_source_sha256']}))


if __name__ == '__main__':
    main()
