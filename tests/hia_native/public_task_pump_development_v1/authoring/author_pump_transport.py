"""Apply the explicit host pump entry seam to the frozen serial transport."""
from pathlib import Path
import argparse, hashlib, json
SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--baseline', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    base = a.baseline.resolve(strict=True)
    out = a.output.resolve(strict=True)
    path = 'scripts/runtime_mcp_transport.S'
    old = (base / path).read_text()
    text = old
    changes = []
    def replace(before, after):
        nonlocal text
        assert text.count(before) == 1, before[:100]
        text = text.replace(before, after, 1)
        changes.append(dict(before=before, after=after))
    replace('    sub rsp, 256\n    mov r12, rsp\n    mov [r12 + 248], r15\n'
            '    xor eax, eax\n    mov rdi, r12\n    mov ecx, 240\n    rep stosb\n',
            '    sub rsp, 4096\n    mov r12, rsp\n'
            '    xor eax, eax\n    mov rdi, r12\n    mov ecx, 4096\n    rep stosb\n'
            '    mov [r12 + 248], r15\n')
    replace('    mov edi, 4096\n    call view_allocate\n',
            '    call pump_initialize\n    mov edi, 4096\n    call view_allocate\n')
    replace('public_span_scan:\n',
            'public_span_scan:\n    call pump_tick\n'
            '    cmp qword ptr [r12 + PM_BARRIER], 0\n    jne public_span_wait_input\n')
    first = text.index('public_span_wait_input:\n')
    end = text.index('public_span_begin_discard:\n', first)
    replace(text[first:end],
            'public_span_wait_input:\n    call pump_wait\n    jmp public_span_scan\n')
    first = text.index('public_span_request_ready:\n')
    end = text.index('public_span_finish:\n', first)
    replace(text[first:end],
            'public_span_request_ready:\n    call pump_accept\n    jmp public_span_next\n')
    first = text.index('public_span_finish:\n')
    end = text.index('    call runtime_text_body_release\n', first)
    replace(text[first:end],
            'public_span_finish:\n    call pump_finish\n'
            '    /* SDK registry58 has closed transport and drained owned tasks. */\n')
    replace('    .zero 456 /* 57 fixed slots; authority56 is a private callable capability. */',
            '    .zero 472 /* 59 fixed slots; Bellman57 and SDK registry58. */')
    restored = text
    for row in reversed(changes):
        assert restored.count(row['after']) == 1
        restored = restored.replace(row['after'], row['before'], 1)
    assert restored == old
    (out / path).write_text(text)
    proof = dict(schema='hepta.runtime.task-pump.transport-delta.v1',
        baseline_sha256=SHA(old.encode()), output_sha256=SHA(text.encode()),
        changes=changes, inverse_exact=True, framing_owner_bytes_preserved=True,
        old_serial_shutdown53_preserved_as_unchanged_component=True,
        active_async_drain_policy_owner=58, active_worker_capability=57,
        historical_serial_evidence_upgraded=False, full_async_runtime_qualified=False)
    (out / 'native/runtime_mcp_task_transport_composition.json').write_text(
        json.dumps(proof, sort_keys=True, indent=2) + '\n')
    print(json.dumps({key:value for key,value in proof.items() if key != 'changes'},sort_keys=True))


if __name__ == '__main__':
    main()
