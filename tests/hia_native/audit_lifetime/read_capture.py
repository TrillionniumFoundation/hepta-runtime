"""Read complete lifetime evidence without loading or executing native code."""
from pathlib import Path
from common import ROOT, encoded, envelope, files, loads, pin, read, require, sha, source
from emission_contract import refs_contract, callable_contract
from read_build import check_build, check_emission
from read_journal import check_journal, actor, map_entries, word_at
from recipes import recipes


def check_original():
    raw = read(ROOT / 'reference/request_audit.rs.txt')
    owner = read(ROOT / 'reference/registry.rs.txt')
    require(pin(raw) == dict(bytes=68414, sha256='b5189f2923153ffa83d0b45a7cdf89873b0f17ebbe6ec1b174c05bab291d73da'),
            'exact target audit source')
    begin = raw.index(b'fn active_registry()')
    end = raw.index(b'\n#[cfg(unix)]\nfn name(', begin)
    require(raw[begin:end] == owner and pin(owner) == dict(bytes=973, sha256='cc946d12475a33ecd0a4b47dd5ad1c85acf6d21dd3baa63f355066083b677e8f'),
            'four byte-exact original registry functions')
    return dict(target=pin(raw), registry=pin(owner))


def buffers(folder, row):
    result = {}
    for label, item in row['buffers'].items():
        require(item['file'] == row['name'] + '.' + label + '.bin', 'fixed physical buffer member path')
        raw = read(folder / item['file'])
        require(pin(raw) == {k: item[k] for k in ('bytes', 'sha256')}, 'complete physical buffer identity')
        result[label] = raw
    return result


def emission(folder, manifest, image, cases):
    report = loads(read(folder / 'EMISSION.json'))
    require(report['schema'] == 'hepta.audit-lifetime.emission.v1' and report['image'] == pin(image)
            and report['module_manifest'] == pin(read(manifest)) and report['native_calls'] == len(cases)
            and report['refusals'] == len(cases) - 1 and len(report['calls']) == len(cases),
            'complete HIA emission identity and case domain')
    require(read(folder / 'image.bin') == image, 'every composed instruction equals the frozen sources and actual HIA modules')
    physical = 0
    for row, (name, request, capacity, returned) in zip(report['calls'], cases, strict=True):
        require(row['name'] == name and row['returned'] == returned and row['output_capacity'] == capacity
                and row['workspace_capacity'] == 64, 'exact HIA emission case')
        raw = buffers(folder, row)
        require(set(raw) == {'input', 'output-before', 'output-after', 'workspace-before', 'workspace-after'},
                'whole emitter physical buffer set')
        require(raw['input'] == request and raw['output-before'] == b'\xa5' * (capacity + 16)
                and raw['workspace-before'] == raw['workspace-after'] == b'\xa5' * 64 + b'\x5a' * 16,
                'exact emitter input and unused workspace')
        wanted = image + raw['output-before'][len(image):] if name == 'valid' else raw['output-before']
        require(raw['output-after'] == wanted, 'complete emitted code, unused output and refusal preservation')
        physical += sum(map(len, raw.values()))
    return dict(image=pin(image), calls=len(cases), refusals=len(cases) - 1, physical_bytes=physical)


def check_composed(root, identity):
    folder = root / 'lifetime-emission'
    report = loads(read(folder / 'EMISSION.json'))
    require(report['source_manifest_sha256'] == identity and report['runtime_python_required'] is False
            and report['runtime_rust_required'] is False and report['whole_runtime_replaced'] is False,
            'native-only lifetime emission scope')
    composition = loads(read(ROOT / 'native/audit_lifetime.composition.json'))
    _, refs, cases = refs_contract(composition)
    first = emission(folder / 'refs', root / 'build/modules/audit-refs/manifest.json', refs, cases)
    controller = read(root / 'build/modules/audit-lifetime/module.image.bin')
    sync = read(root / 'sync-emission/boundary.bin')
    pump = loads(read(ROOT / 'native/audit_lifetime_callable.composition.json'))
    require(pin(sync) == pump['synchronization'], 'exact qualified embedded native synchronization')
    _, image, cases = callable_contract(controller, refs, sync, pump)
    second = emission(folder / 'callable', root / 'build/modules/audit-lifetime-callable/manifest.json', image, cases)
    require(report['refs'] == loads(read(folder / 'refs/EMISSION.json'))
            and report['callable'] == loads(read(folder / 'callable/EMISSION.json'))
            and report['controller'] == pin(controller) and report['synchronization'] == pin(sync),
            'composed emission retains complete constituent reports')
    return dict(refs=first, callable=second)


def check_observer_free(root, identity, pid, domain):
    folder = root / 'observer-free'
    report = loads(read(folder / 'OBSERVER_FREE.json'))
    require(report['schema'] == 'hepta.audit-lifetime.observer-free.v1'
            and report['source_manifest_sha256'] == identity and report['pid'] == pid
            and report['observer_pointer'] == report['foreign_effect_calls'] == 0
            and report['runtime_rust_required'] is False and report['whole_runtime_replaced'] is False,
            'observer-free actual native process and scope')
    require(report['callable'] == pin(read(root / 'lifetime-emission/callable/image.bin'))
            and report['references'] == pin(read(root / 'lifetime-emission/refs/image.bin')),
            'actual observer-free executable images')
    require([row['name'] for row in report['calls']] == domain['observer_free_cases'], 'frozen observer-free call domain')
    physical = refusals = 0
    for row in report['calls']:
        raw = buffers(folder, row)
        physical += sum(map(len, raw.values()))
        require(raw['before-input'] == raw['after-input'] and raw['after-input'][-16:] == b'\xa5' * 16
                and len(raw['after-input']) == row['request_bytes'] + 16, 'complete unchanged observer-free input')
        if row['returned'] > 0xfffffff0:
            refusals += 1
            require(all(raw['before-' + key[6:]] == raw[key] for key in raw if key.startswith('after-')),
                    'observer-free refusal changes no complete physical buffer')
            require(row['returned'] == domain['observer_free_refusals'][row['name']], 'exact native refusal code')
        if row['kind'] == 'callable':
            require(set(raw) == {phase + '-' + name for phase in ('before', 'after')
                                for name in ('input', 'actor', 'context', 'kernel', 'active', 'pins')},
                    'whole observer-free callable physical domain')
            for label, size in (('actor', 512), ('context', 128), ('kernel', 64)):
                require(len(raw['after-' + label]) == size + 16 and raw['after-' + label][size:] == b'\xa5' * 16,
                        'complete observer-free context/actor/kernel guard')
            require(word_at(raw['after-context'], 80) == word_at(raw['after-context'], 88) == 0,
                    'optional observer remains disabled throughout')
            if row['returned'] == 512:
                a = actor(raw['after-actor'])
                require(a[1] == 0 and a[2] == row['expected_result'] == domain['observer_free_results'][row['name']],
                        'actual observer-free HIA completion')
                for number, label in ((0, 'active'), (1, 'pins')):
                    if raw['after-' + label]:
                        map_entries(raw['after-' + label], number)
                if row['name'] == 'destroy':
                    require(all(word_at(raw['after-context'], i * 8) == 0 for i in (0, 1, 4, 5, 6, 7, 8, 9))
                            and not raw['after-active'] and not raw['after-pins'], 'observer-free actual map disposal')
        else:
            require(row['kind'] == 'reference' and set(raw) == {phase + '-' + name for phase in ('before', 'after')
                                                               for name in ('input', 'output', 'workspace')},
                    'whole observer-free reference physical domain')
            require(raw['before-output'] == b'\xa5' * 80 and raw['after-output'][64:] == b'\xa5' * 16
                    and raw['before-workspace'] == raw['after-workspace'] == b'\x5a' * 16,
                    'reference caller-owned output guard and workspace')
            if row['returned'] == 64:
                q, r = raw['before-input'][:64], raw['after-output'][:64]
                require(r[:8] == b'HARRES01' and word_at(r, 8) == word_at(q, 8)
                        and word_at(r, 48) == word_at(q, 16), 'actual observer-free reference operation')
                if row['name'] == 'outliving-marker-drop':
                    require(word_at(r, 16) == 2 and word_at(r, 32) == word_at(r, 40) == 0,
                            'strong outlives map and final object is actually unmapped')
    require(report['native_calls'] == len(report['calls']) and report['refusals'] == refusals == len(domain['observer_free_refusals']),
            'complete observer-free call totals')
    return dict(calls=len(report['calls']), refusals=refusals, physical_bytes=physical, foreign_effect_calls=0)


def check_processes(root, capture, domain):
    rows = loads(read(root / 'processes/processes.json'))
    expected = recipes(capture['source_root'], capture['producer_root'], capture['python'],
                       capture['rust_bin'], capture['compiler_root'], capture['sync_source_root'], domain)
    require(len(rows) == len(expected), 'complete semantic process domain')
    pids, seen = {}, set()
    for row, (name, argv) in zip(rows, expected, strict=True):
        require(row['name'] == name and row['argv'] == argv and row['cwd'] == capture['source_root']
                and row['timeout_seconds'] == domain['process_budgets'][name], 'actual command and frozen process budget')
        require(row['exit_code'] == 0 and row['timed_out'] is False and row['completed'] is True
                and 0 < row['elapsed_seconds'] < row['timeout_seconds'], 'completed bounded actual process')
        require(type(row['pid']) is int and row['pid'] > 1 and row['pid'] == row['pgid']
                and row['pid'] != row['parent_pid'] and row['pid'] not in seen, 'isolated process identity')
        seen.add(row['pid'])
        pids[name] = row['pid']
        require(row['stdin'] is None, 'no hidden semantic input stream')
        for label in ('stdout', 'stderr'):
            member = row[label]
            require(member['file'] == name + '.' + label
                    and pin(read(root / 'processes' / member['file'])) == {key: member[key] for key in ('bytes', 'sha256')},
                    'complete actual stdout and stderr')
    version = read(root / 'processes/compiler-version.stdout').decode()
    require('\nrelease: 1.95.0\n' in version and '\nhost: x86_64-unknown-linux-gnu\n' in version, 'fixed Rust release/host')
    for name in ('original-tests', 'native-tests'):
        require(read(root / 'threads' / name).startswith(b'\x7fELF'), 'retained actual Rust test executable')
    for case in domain['cases']:
        pair = []
        for implementation in ('original', 'native'):
            name = implementation + '-' + case.replace('_', '-')
            raw = read(root / 'processes' / (name + '.stdout'))
            require(raw.endswith(b'\n'), 'complete test stdout')
            values = [loads(line) for line in raw.splitlines()]
            require(values[-1] == dict(case=case, status='PASS'), 'actual scenario completed')
            deterministic = [row for row in values[:-1] if 'label' in row]
            races = [row for row in values[:-1] if 'race' in row]
            require(len(deterministic) == domain['checks_per_case'][case]
                    and len(deterministic) + len(races) == len(values) - 1
                    and len({row['label'] for row in deterministic}) == len(deterministic), 'complete shared scenario assertion domain')
            require([row['race'] for row in races] == (list(range(64)) if case == 'weak_upgrade_race' else [])
                    and all(type(row['upgraded']) is bool for row in races), 'complete actual race observations')
            require(read(root / 'processes' / (name + '.stderr')).count(b'panicked at') == domain['unwind_cases'].get(case, 0),
                    'actual standard unwind observations')
            pair.append(deterministic)
        require(pair[0] == pair[1], 'all exact original/native deterministic observations agree')
    return pids


def semantic(root):
    root = Path(root).resolve(strict=True)
    identity = source()
    capture = envelope(root)
    domain = loads(read(ROOT / 'DOMAIN.json'))
    require(capture['schema'] == 'hepta.audit-lifetime.capture.v1' and capture['status'] == 'PASS'
            and capture['source_manifest_sha256'] == identity and capture['domain'] == pin(read(ROOT / 'DOMAIN.json')),
            'complete same-source lifetime capture')
    require(capture['scope'] == domain['scope'] and capture['public_handler_qualified'] is False
            and capture['whole_runtime_replaced'] is False, 'exact private lifetime qualification scope')
    original = check_original()
    build = check_build(root, identity)
    synchronization = check_emission(root, identity)
    composed = check_composed(root, identity)
    pids = check_processes(root, capture, domain)
    observer_free = check_observer_free(root, identity, pids['observer-free'], domain)
    journals = {}
    for case in domain['cases']:
        journals[case] = check_journal(root / 'threads' / (case + '.jsonl'),
                                      pids['native-' + case.replace('_', '-')], case)
        require(journals[case]['allocations'] == domain['allocations_per_case'][case], 'frozen allocation domain')
    return dict(schema='hepta.audit-lifetime.read.v1', status='COMPLETE_PRIVATE_HIA_AUDIT_LIFETIME_PASS',
                source_manifest_sha256=identity, original=original, build=build, synchronization=synchronization,
                composed=composed, observer_free=observer_free, journals=journals, paired_cases=len(domain['cases']),
                scope=domain['scope'], public_handler_qualified=False, whole_runtime_replaced=False, semantic_reexecutions=0)


def verify(output, require_controls=False):
    output = Path(output).resolve(strict=True)
    result = semantic(output / 'semantic')
    if require_controls:
        import reader_controls
        result['controls'] = reader_controls.verify(output, result)
    return result
