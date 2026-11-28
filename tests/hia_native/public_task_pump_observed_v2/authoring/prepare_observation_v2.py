"""Bind the observer delta to the immutable native-v1 source checkpoint."""
from pathlib import Path
import difflib
import hashlib
import json

ROOT = Path(__file__).resolve().parent
BASE = ROOT / 'source'
OUT = ROOT / 'source-v2'
SHA = lambda data: hashlib.sha256(data).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def main():
    # The queue profile's old evidence retains its exact old source identity.
    name = 'native/sdk_request_task_composition.json'
    old = (BASE / name).read_bytes()
    (OUT / 'native/sdk_request_task_queue_baseline_composition.json').write_bytes(old)
    admission = json.loads((OUT / 'native/sdk_request_task_admission_composition.json').read_bytes())
    combined = json.loads(old)
    combined.update(schema='hepta.sdk-request-tasks.composition.v2',
        source_bytes=admission['output_bytes'], source_sha256=admission['output_sha256'],
        author_sha256=admission['author_sha256'], pseudo_sha256=admission['pseudo_sha256'],
        function_count=admission['functions'], public_registry_integrated=True,
        public_async_qualified=False, public_admission_operation=15,
        ordinary_notification_drops_handler_future=False,
        qualified_queue_baseline_composition_sha256=SHA(old),
        public_admission_proof_sha256=SHA((OUT / 'native/sdk_request_task_admission_composition.json').read_bytes()))
    combined['functions'].update(admission['added_functions'])
    combined.pop('blocks')
    combined.pop('instructions')
    write_json(OUT / name, combined)

    name = 'native/sdk_request_task_abi.md'
    old = (BASE / name).read_text()
    (OUT / 'native/sdk_request_task_queue_baseline_abi.md').write_text(old)
    before = ('No operation starts or polls a worker. The host sends Bellman command 3 only\n'
              'after a registry cancellation decision and acknowledges only after that real\n'
              'turn is delivered. It never uses an MCP ID as a private worker tag.')
    after = ('No operation starts or polls a worker. A normal notification cancels only\n'
             'the SDK context; the actual Bellman handler ignores that token and continues\n'
             'with command 2. Command 3 is limited to actual future destruction after\n'
             'transport closure. Context cancellation delivery and future destruction are\n'
             'different acknowledgements. No MCP ID becomes a private worker tag.')
    assert old.count(before) == 1
    text = old.replace(before, after, 1)
    text = text.replace('Retire handler interest after actual cancellation, without a response',
                        'Retire an actually destroyed handler future, without a response')
    text += '''

## Host admission operation 15

Operation 15 takes the complete current G1 HRCJR001 output, generation zero,
and the actual G2 mode before/after the uninterrupted first frontend turn.
Modes are bootstrap 0, legacy 1, inline 2, closed 3. It forwards a closed-mode
turn, treats a bootstrap request that did not enter inline mode as a bootstrap
reply, admits other requests through the original typed-ID admission, and
observes notifications only after the bootstrap mode. Disposition 15 means
bootstrap; 16 means forward-only. All older operations and the 34 unmodified
function ASTs remain identified in the admission composition proof.

The host does not read another public input between that first frontend turn
and this admission. This is a concrete current seam, not a claim that every
possible handler context is created at an identical instruction boundary.
G2 peer/protocol information is never used as an identity credential. The
current pending and observation ABI is runtime_mcp_task_host_abi.md.
'''
    (OUT / name).write_text(text)

    path = 'scripts/runtime_mcp_transport.S'
    proof = json.loads((BASE / 'native/runtime_mcp_task_transport_composition.json').read_bytes())
    before = 'public_span_fail:\n    mov r15, [r12 + 248]\n'
    after = 'public_span_fail:\n    call pump_restore_fd_flags\n    mov r15, [r12 + 248]\n'
    assert (BASE / path).read_text().count(before) == 1
    assert (BASE / path).read_text().replace(before, after, 1) == (OUT / path).read_text()
    proof['schema'] = 'hepta.runtime.task-pump.transport-delta.v2'
    proof['changes'].append(dict(before=before, after=after))
    proof['output_sha256'] = SHA((OUT / path).read_bytes())
    proof['failure_restores_observed_fd_flags'] = True
    restored = (OUT / path).read_text()
    for row in reversed(proof['changes']):
        assert restored.count(row['after']) == 1
        restored = restored.replace(row['after'], row['before'], 1)
    assert SHA(restored.encode()) == proof['baseline_sha256']
    write_json(OUT / 'native/runtime_mcp_task_transport_composition.json', proof)

    proof_name = 'native/runtime_mcp_task_observation_composition.json'
    excluded = {'native/runtime_mcp_sources.json', proof_name}
    changes = []
    for path in sorted(OUT.rglob('*')):
        if not path.is_file():
            continue
        name = path.relative_to(OUT).as_posix()
        if name in excluded:
            continue
        previous = BASE / name
        old = previous.read_bytes() if previous.exists() else b''
        new = path.read_bytes()
        if old == new:
            continue
        changes.append({'path': name, 'before_bytes': len(old),
            'before_sha256': SHA(old) if previous.exists() else None,
            'after_bytes': len(new), 'after_sha256': SHA(new),
            'unified_diff': ''.join(difflib.unified_diff(old.decode().splitlines(True),
                new.decode().splitlines(True), fromfile='native-v1/' + name,
                tofile='native-v2/' + name))})
    write_json(OUT / proof_name, {
        'schema': 'hepta.runtime.task-pump.observer-source-delta.v1',
        'base_commit': '427fb43a668900ada7921b5f1bdb774981eb517f',
        'base_prefix': 'tests/hia_native/public_task_pump_development_v1/source',
        'author_sha256': SHA(Path(__file__).read_bytes()), 'changes': changes,
        'hia_owner_bytes_changed': False, 'fixed_private_journal_fd': 3,
        'separate_trace_fixture_fixed_fd': 4,
        'production_chooses_private_fixture_fds': False,
        'notification_cancel_drops_future': False,
        'public_async_qualified': False, 'fresh_ci_qualified': False})
    binding = json.loads((BASE / 'native/runtime_mcp_sources.json').read_bytes())
    binding['sources'] = {}
    for path in sorted(OUT.rglob('*')):
        if not path.is_file() or path == OUT / 'native/runtime_mcp_sources.json':
            continue
        data = path.read_bytes()
        binding['sources'][path.relative_to(OUT).as_posix()] = {'bytes': len(data), 'sha256': SHA(data)}
    write_json(OUT / 'native/runtime_mcp_sources.json', binding)
    print(json.dumps({'changed_files': len(changes), 'bound_files': len(binding['sources']),
        'binding_sha256': SHA((OUT / 'native/runtime_mcp_sources.json').read_bytes()),
        'all_hia_unchanged': all((BASE / p.relative_to(OUT)).read_bytes() == p.read_bytes()
                               for p in (OUT / 'native').glob('*.hepta'))}))


if __name__ == '__main__':
    main()
