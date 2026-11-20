"""Physical source and complete DATA rejection controls for two installed owners."""
from pathlib import Path
import argparse, copy, gzip, hashlib, importlib.util, json, struct, sys
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from read_resource_capture import read_memory, read_trace, pin


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def rejected(operation):
    try:
        operation()
    except (AssertionError, ValueError, OSError, KeyError, struct.error) as error:
        return {'rejected': True, 'exception': type(error).__name__, 'reason': str(error)}
    raise AssertionError('corrupt complete evidence accepted')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    a = parser.parse_args()
    work = a.root.resolve()
    source = work / 'candidate'
    a.output.mkdir(parents=True, exist_ok=False)
    recipe = source / 'qualification/public124_default_entry_v1/source'
    entry = module('current_default126_reader', recipe / 'entry.py')
    checked = entry.check_source(source)
    assert checked['source_files'] == 544 and checked['binary_owners_integrated'] is True
    entry.prepare(source, a.output / 'physical-source')
    root = a.output / 'physical-source/source'
    cases = [
        ('typed-hia-byte', 'native/binary_write_params.hepta', lambda b: b + b'\n'),
        ('plan-hia-byte', 'native/binary_call_plan.hepta', lambda b: b + b'\n'),
        ('typed-abi-byte', 'native/binary_write_params_abi.md', lambda b: b + b'\n'),
        ('plan-composition-byte', 'native/binary_call_plan_composition.json', lambda b: b + b'\n'),
        ('high-work-bitmap-overlap', 'scripts/runtime_mcp_extra_engine.S', lambda b: b.replace(b'.equ RG_WORK_HIGH, 12736', b'.equ RG_WORK_HIGH, 12608')),
        ('high-output-bitmap-overlap', 'scripts/runtime_mcp_extra_engine.S', lambda b: b.replace(b'.equ RG_OUTPUT_HIGH, 12744', b'.equ RG_OUTPUT_HIGH, 12616')),
        ('slot-count-truncation', 'scripts/runtime_mcp_extra_engine.S', lambda b: b.replace(b'.equ RG_SLOTS, 71', b'.equ RG_SLOTS, 69')),
        ('exact-root-owner-byte', 'native/config_directory_owner_span.hepta', lambda b: b + b'\n'),
        ('old-public-frontend-byte', 'native/runtime_mcp.hepta', lambda b: b + b'\n'),
        ('complete-binding-byte', 'native/runtime_mcp_sources.json', lambda b: b + b'\n'),
        ('whole-inverse-proof-byte', 'native/runtime_mcp_binary_owners_integration.json', lambda b: b + b'\n'),
    ]
    controls = []
    for name, relative, mutate in cases:
        path = root / relative
        original = path.read_bytes()
        changed = mutate(original)
        assert changed != original
        try:
            path.write_bytes(changed)
            result = rejected(lambda: entry.check_source(root))
        finally:
            path.write_bytes(original)
        assert entry.check_source(root) == checked
        controls.append({'name': name, 'path': relative, 'original': pin(original), 'changed': pin(changed),
                         'exact_restoration_verified': True, **result})
    for relative in ('native/binary_write_params.hepta', 'native/binary_call_plan.hepta',
                     'native/runtime_mcp_binary_owners_integration.json'):
        path = root / relative
        original = path.read_bytes()
        try:
            path.unlink()
            result = rejected(lambda: entry.check_source(root))
        finally:
            path.write_bytes(original)
        assert entry.check_source(root) == checked
        controls.append({'name': 'missing-' + path.name, 'path': relative, 'exact_restoration_verified': True, **result})

    profile_path = source / 'tests/hia_native/historical_public58/PROFILE.json'
    before = json.loads((work / 'before/historical-PROFILE.json').read_bytes())
    current = json.loads(profile_path.read_bytes())
    inverse = copy.deepcopy(current)
    inverse['schema'] = before['schema']
    inverse['current_default_images'] = 124
    inverse['current_default_graph_binding_sha256'] = before['current_default_graph_binding_sha256']
    added = json.loads((work / 'SOURCE_FREEZE.json').read_bytes())['added_paths']
    for name in added:
        inverse['remove_current_public_only'].remove(name)
        del inverse['current_graph_files'][name]
    for name in before['current_graph_files']:
        inverse['current_graph_files'][name] = before['current_graph_files'][name]
    assert inverse == before and current['restore'] == before['restore'] and len(before['restore']) == 120
    ci = json.loads((work / 'CI_PROFILE_SUCCESSOR.json').read_bytes())
    materializer_path = profile_path.parent / 'materialize.py'
    raw = materializer_path.read_text()
    for old, new, count in reversed(ci['materializer_replacements']):
        assert raw.count(new) == count
        raw = raw.replace(new, old)
    assert raw.encode() == (work / 'before/historical-materialize.py').read_bytes()
    workflow = (source / '.github/workflows/hia-public-current.yml').read_text()
    assert workflow.count(ci['new_manifest_sha256']) == 2
    assert workflow.replace(ci['new_manifest_sha256'], ci['old_manifest_sha256']).encode() == (work / 'before/hia-public-current.yml').read_bytes()
    historical = module('current_historical58_materializer', materializer_path)
    historical.check(source)
    positive = historical.verify_materialized(work / 'historical-source')
    hpath = work / 'historical-source/native/config_directory_owner_span.hepta'
    original = hpath.read_bytes()
    try:
        hpath.write_bytes(original + b'\n')
        historical_negative = rejected(lambda: historical.verify_materialized(work / 'historical-source'))
    finally:
        hpath.write_bytes(original)
    assert historical.verify_materialized(work / 'historical-source') == positive

    folder = work / 'rog-evidence/source/capture-v2/installed-controls/installed'
    raw = gzip.decompress((folder / 'stderr.bin.gz').read_bytes())
    memory = (folder / 'memory.strace').read_text()
    trace_positive, memory_positive = read_trace(raw), read_memory(memory)
    ack = raw.index(b'HRCNAK02')
    changed_slot = bytearray(raw)
    struct.pack_into('<Q', changed_slot, 16, 71)
    trace_mutations = [('unknown-record-tag', b'XXXXXXXX' + raw[8:]), ('truncated-trace', raw[:-1]),
                       ('omitted-ack', raw[:ack] + raw[ack + 128:]), ('slot-out-of-range', bytes(changed_slot)),
                       ('unbound-trace-suffix', raw + b'X')]
    trace_controls = [{'name': name, **rejected(lambda data=data: read_trace(data))} for name, data in trace_mutations]
    lines = memory.splitlines(keepends=True)
    last_unmap = max(i for i, row in enumerate(lines) if ' munmap(' in row)
    first_clone = next(row for row in lines if ' clone(' in row)
    complete_wait = next(row for row in lines if 'WEXITSTATUS' in row)
    root_pid = memory_positive['application_pid']
    child_pid = memory_positive['shared_vm_children'][0]
    memory_mutations = [
        ('one-leaked-graph-allocation', ''.join(lines[:last_unmap] + lines[last_unmap + 1:])),
        ('missing-final-exit', ''.join(lines[:-1])),
        ('changed-process-map-size', memory.replace('3707834368', '3707838464', 1)),
        ('unknown-process-memory-event', memory.replace(str(root_pid) + ' mmap(', '999999999 mmap(', 1)),
        ('missing-shared-vm-clone', memory.replace(first_clone, '', 1)),
        ('non-shared-vm-clone', memory.replace('CLONE_VM|CLONE_FILES|SIGCHLD', 'CLONE_FILES|SIGCHLD', 1)),
        ('missing-successful-reap', memory.replace(complete_wait, '', 1)),
        ('child-unsuccessful-exit', memory.replace(str(child_pid) + ' exit(0)', str(child_pid) + ' exit(1)', 1)),
        ('unbound-memory-suffix', memory + str(root_pid) + ' munmap(0x1000, 4096) = 0\n'),
    ]
    memory_controls = []
    for name, text in memory_mutations:
        assert text != memory
        memory_controls.append({'name': name, **rejected(lambda text=text: read_memory(text))})
    assert read_trace(raw) == trace_positive and read_memory(memory) == memory_positive
    report = {'status': 'SOURCE_RESOURCE_CONTROLS_PASS', 'source': checked, 'physical_source_controls': controls,
              'historical_original_120_pins_unchanged': True, 'historical_profile_whole_inverse': True,
              'materializer_whole_inverse': True, 'workflow_exact_two_pin_inverse': True,
              'workflow_commands_and_budgets_unchanged': True, 'historical': positive,
              'historical_corruption': historical_negative, 'trace_controls': trace_controls,
              'memory_controls': memory_controls, 'original_application_or_compiler_or_rust_or_ssh_executions': 0}
    (a.output / 'RESULT.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({k: v for k, v in report.items() if not k.endswith('controls')}, sort_keys=True))


if __name__ == '__main__':
    main()
