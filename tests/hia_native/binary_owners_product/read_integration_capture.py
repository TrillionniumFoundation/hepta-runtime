"""Re-read all integration journals using the frozen component DATA readers.

No application, compiler, Rust oracle, dynamic library, or remote command is
executed. The old planner reader's two literal corrections are exactly those
already qualified in FINAL_HANDOFF; the original reader remains unchanged.
"""
from pathlib import Path
import argparse, collections, functools, gzip, hashlib, importlib.util, json, math, re, struct, sys, types
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from read_resource_capture import pin, require, word, PACK, queries, responses, read_capture as read_resources

SHA = lambda b: hashlib.sha256(b).hexdigest()
load_json = lambda p: json.loads(p.read_bytes())
jsonl = lambda p: [json.loads(line) for line in p.read_bytes().splitlines()]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@functools.lru_cache(maxsize=2)
def readers(qualified):
    params = qualified / 'qualification/binary_params/v1/source'
    planner = qualified / 'qualification/binary_call_plan/v1/source'
    sys.path[:0] = [str(params / 'scripts')]
    oldparams = load('frozen_read_params', params / 'scripts/read_params.py')
    oldparams.source_evidence(params)
    sys.path[:0] = [str(planner / 'scripts')]
    sys.modules.pop('common', None)
    sys.modules.pop('plan_cases', None)
    handoff = load_json(planner.parent / 'FINAL_HANDOFF.json')
    corrections = handoff['data_only_recovery']['exact_reader_changes'] if 'data_only_recovery' in handoff else next(
        v['exact_reader_changes'] for v in handoff.values() if isinstance(v, dict) and 'exact_reader_changes' in v)
    recipe = next(r for r in corrections if r['path'] == 'scripts/read_plan.py')
    original = (planner / recipe['path']).read_bytes()
    require(SHA(original) == recipe['original_sha256'], 'exact original plan DATA reader')
    text = original.decode()
    for change in recipe['replacements']:
        require(text.count(change['before']) == 1, 'exact handoff reader splice')
        text = text.replace(change['before'], change['after'])
    require(SHA(text.encode()) == recipe['patched_sha256'], 'exact already-qualified plan DATA recovery')
    newplan = types.ModuleType('frozen_recovered_plan_reader')
    newplan.__file__ = str(planner / recipe['path'])
    exec(compile(text, newplan.__file__, 'exec'), newplan.__dict__)
    newplan.source_evidence(planner)
    return oldparams, newplan, recipe


def read_reference_build(work, qualified):
    origin = load_json(work / 'CAPTURE_ORIGINS.json')
    oldroot, newroot = Path(origin['runtime_audit_root']), work.parent
    def relocated(name):
        original = Path(name)
        require(original.is_absolute() and original.is_relative_to(oldroot), 'bound captured artifact location')
        return newroot / original.relative_to(oldroot)
    refs = load_json(work / 'reference-build/REFERENCES.json')
    require(set(refs) == set(map(str, range(1, 8))), 'all seven actual reference images')
    names = ['serde_json_span', 'file_info_params', 'binary_read_params', 'binary_write_params',
             'binary_upload_params', 'binary_patch_inode_params', 'binary_call_plan']
    compiler = 'd3e2c90173cf733e42b299d0c4274df4b593a12f'
    b3 = 'bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'
    compiler_source = relocated(origin['compiler_source'])
    dependency = None
    rows, files = [], set()
    for number, name in enumerate(names, 1):
        ref = refs[str(number)]
        manifest = relocated(ref['manifest'])
        require(SHA(manifest.read_bytes()) == ref['sha256'], 'actual reference manifest bytes')
        md = load_json(manifest)
        p = manifest.parent
        source = p / md['source']
        image = p / md['image']
        request, receipt, build = [load_json(p / n) for n in ('module.request.json', 'module.receipt.json', 'build.json')]
        frozen = qualified / ('qualification/binary_call_plan/v1/source' if number == 7 else 'qualification/binary_params/v1/source') / 'native' / (name + '.hepta')
        raw_source, raw_image, output = source.read_bytes(), image.read_bytes(), (p / 'module.output.bin').read_bytes()
        require(raw_source == frozen.read_bytes() == (p / 'module.input.bin').read_bytes(), 'qualified original HIA input bytes')
        require(SHA(raw_source) == md['source_sha256'] and SHA(raw_image) == md['image_sha256'], 'complete source and compiled native image')
        require(md['compiler_commit'] == compiler and md['compiler_sha256'] == b3
                and md['buffer_profile'] == 'history.v1' and md['standalone'] is None
                and [md[k] for k in ('input_capacity', 'output_capacity', 'workspace_capacity')] == [128 << 20, 128 << 20, 256 << 20], 'original reference ABI and compiler')
        require(receipt['status'] == 'returned' and type(receipt['abi_status']) is int and receipt['abi_status'] == 0
                and receipt['source_unchanged'] is True and receipt['forbidden_compiler_modules_loaded'] == [], 'actual compiler receipt completed')
        require(receipt['core_u32'] == receipt['result_u64'] == receipt['produced_bytes'] == len(raw_image)
                and raw_image == output[:len(raw_image)] and receipt['output_sha256'] == SHA(output)
                and receipt['produced_sha256'] == SHA(raw_image) and receipt['artifact_sha256'] == b3
                and receipt['input_sha256'] == SHA(raw_source) and receipt['input_bytes'] == len(raw_source), 'entire compiler buffers and receipt')
        require(request['format'] == 'flat-x86-64' and request['source_sha256'] == SHA(raw_source)
                and request['image_sha256'] == b3 and SHA(relocated(request['image']).read_bytes()) == b3, 'actual B3 compiler input')
        require(build['compile_receipt'] == receipt and build['whole_runtime_replaced'] is False, 'build custody and limited scope')
        dep = build['compiler_dependency']
        require(dep['commit'] == compiler and dep['tree'] == '8d8b0fb8d015fb7edab302498bb9ed4c74ab6f49', 'original compiler source identity')
        require(dependency is None or dep == dependency, 'all reference compiler sources identical')
        dependency = dep
        files.update([manifest, source, image, *[p / n for n in ('module.request.json', 'module.receipt.json', 'build.json', 'module.input.bin', 'module.output.bin')], relocated(request['image'])])
        rows.append({'owner': number, 'name': name, 'source': pin(raw_source), 'image': pin(raw_image), 'manifest': pin(manifest.read_bytes())})
    for name, digest in dependency['files'].items():
        require(SHA((compiler_source / name).read_bytes()) == digest, 'complete original compiler source byte: ' + name)
    return {'status': 'REFERENCE_BUILD_DATA_PASS', 'compiler_commit': compiler, 'compiler_sha256': b3,
            'compiler_source_files': len(dependency['files']), 'members': rows}


def process_streams(folder, budget, public=False):
    metadata = load_json(folder / ('capture-process.json' if public else 'process.json'))
    require(metadata['exit_code'] == 0 and metadata['timed_out'] is False
            and metadata['timeout_seconds'] == budget and 0 <= metadata['elapsed_seconds'] <= budget,
            'actual process exit and original budget: ' + str(folder))
    require(metadata.get('failure_cleanup_requested', False) is False and not metadata.get('errors'), 'no failed process cleanup')
    streams = {name: gzip.decompress((folder / (name + '.bin.gz')).read_bytes()) for name in ('stdin', 'stdout', 'stderr')}
    for name, data in streams.items():
        require(pin(data) == metadata[name], 'complete native stream: ' + str(folder / name))
    return metadata, streams


def private(folder, budget):
    _, streams = process_streams(folder, budget)
    q, a = queries(streams['stdin']), responses(streams['stdout'])
    require(len(q) == len(a), 'complete private request/response count')
    if (folder / 'responses.json').exists():
        index = load_json(folder / 'responses.json')
        require(len(index) == len(q), 'complete private index')
        if index and 'header_hex' in index[0]:
            for i, ((session, slot, wire), (header, body), row) in enumerate(zip(q, a, index), 1):
                require(row['sequence'] == i and row['session'] == session and row['slot'] == slot
                        and row['input'] == pin(wire) and row['header_hex'] == header.hex() and row['body'] == pin(body),
                        'private complete wire/index binding')
    return list(zip(q, a))


def check_public(capture):
    pairs = 0
    times = []
    for profile in ('configured', 'absent'):
        for era in ('legacy', 'modern'):
            left = capture / 'public' / (profile + '-' + era + '-baseline')
            right = capture / 'public' / (profile + '-' + era + '-candidate')
            _, old = process_streams(left, 60, True)
            _, new = process_streams(right, 60, True)
            require(old['stdin'] == new['stdin'] and old['stderr'] == new['stderr'] == b'', 'public input and stderr unchanged')
            oa, na = old['stdout'].splitlines(keepends=True), new['stdout'].splitlines(keepends=True)
            require(len(oa) == len(na) == 29, 'entire public route response domain')
            for index, (a, b) in enumerate(zip(oa, na)):
                if index != 26:
                    require(a == b, 'complete public wire changed')
                    continue
                normalized = []
                for raw in (a, b):
                    obj = json.loads(raw)
                    require(obj['id'] == 34 and obj['result']['isError'] is False and len(obj['result']['content']) == 1,
                            'only successful Bellman response permits one measured duration')
                    elapsed = json.loads(obj['result']['content'][0]['text'])['native_operation_wall_seconds']
                    require(type(elapsed) in (int, float) and math.isfinite(elapsed) and 0 <= elapsed < 60, 'original Bellman duration budget')
                    pattern = rb'(\\"native_operation_wall_seconds\\":)([0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)'
                    found = list(re.finditer(pattern, raw))
                    require(len(found) == 1 and float(found[0][2]) == elapsed, 'single exact elapsed token')
                    normalized.append(re.sub(pattern, rb'\g<1>0', raw, count=1))
                    times.append(elapsed)
                require(normalized[0] == normalized[1], 'Bellman complete bytes beyond measured duration')
            cases = load_json(right / 'cases.json')
            require(len(cases) == 27 and cases[-1]['tool'] == 'binary_write' and cases[-1]['response']['error'] ==
                    {'code': -32602, 'message': 'Unknown tool'}, 'public binary_write remains unregistered')
            pairs += len(oa)
    return {'response_pairs': pairs, 'actual_processes': 8, 'routed_tools': 13, 'retained_bellman_seconds': times}


def read_all(capture, source, qualified, rog, inputs):
    oldparams, oldplan, recovery = readers(qualified)
    typed = load_json(capture / 'typed/results.json')
    planned = load_json(capture / 'planner/results.json')
    controls = jsonl(capture / 'reference/controls.jsonl')
    index = jsonl(capture / 'reference/calls.jsonl')
    require(len(typed) == 1388 and len(planned) == 433 and len(controls) == 197 and len(index) == 12350, 'whole integration domains')
    require((capture / 'typed/input.jsonl').read_bytes() == oldparams.params_cases.encoded(), 'exact 1388 frozen parameter inputs')
    domain = oldparams.params_cases.cases()
    # The integration producer runs one complete persistent session per kind;
    # retain each kind's original case order instead of zipping the interleaved
    # frozen domain with the grouped execution journal.
    execution_domain = [case for kind in range(1, 6) for case in domain if case['kind'] == kind]
    require([row['case_id'] for row in typed] == [case['case_id'] for case in execution_domain],
            'exact complete grouped parameter execution order')
    origins = load_json(capture.parent / 'CAPTURE_ORIGINS.json')
    groups = oldplan.plan_cases.groups(Path(origins['integration_capture']) / 'planner')
    require(len(groups) == 24 and sum(len(g['cases']) for g in groups) == 433, 'exact original planner domains')
    for group in groups:
        require((capture / 'planner' / group['name'] / 'input.json').read_bytes() == oldplan.plan_cases.encoded(group), 'exact whole planner group')
    chains, attributed = {}, {}
    def register(calls, owner, cid, label):
        require(calls and len(calls) <= 12 and calls == list(range(calls[0], calls[-1] + 1)), 'complete ordered continuation')
        key = tuple(calls)
        require(key not in chains, 'duplicate continuation')
        chains[key] = {'owner': owner, 'case_id': cid, 'label': label}
        for pos, number in enumerate(calls):
            require(number not in attributed, 'duplicate semantic call')
            attributed[number] = (key, pos)
    for row in typed + planned:
        register(row['value_calls'], 1, row['case_id'], 'semantic')
        if row['params_calls']:
            register(row['params_calls'], row['kind'] + 1, row['case_id'], 'semantic')
        for stage in row.get('stages', []):
            register(stage['plan_calls'], 7, row['case_id'], 'plan')
    control_calls = set()
    for row in controls:
        for call in ([row['call']] if 'call' in row else row.get('calls', [])) + row.get('resume_calls', []):
            require(call not in attributed and call not in control_calls, 'control identity duplicated')
            control_calls.add(call)
    require(set(attributed) | control_calls == set(range(1, len(index) + 1)), 'no unbound or missing native calls')
    full, completed, pending = {}, {}, {}
    first_plan_call = next(r for r in planned if r['stages'])['stages'][0]['plan_calls'][0]
    total_bytes = 0
    for ordinal, row, arrays in oldplan.full_records(capture / 'reference', index):
        wire, before, old, output, after = arrays
        total_bytes += row['bytes']
        if ordinal in control_calls or ordinal == first_plan_call:
            full[ordinal] = (row, arrays)
        if ordinal not in attributed:
            if row['return_code'] in (0xffffffff, 0xfffffffe):
                require(before == after and output == old, 'physical refusal preserves all caller bytes')
            elif row['owner'] == 7:
                oldplan.plan_frame(row['return_code'], output)
            else:
                oldparams.frame(row['owner'], row['return_code'], output)
            continue
        key, position = attributed[ordinal]
        declaration = chains[key]
        owner = declaration['owner']
        require(all(row[k] == declaration[k] for k in ('owner', 'case_id', 'label')), 'native semantic call source identity')
        if position == 0:
            require(before == bytes(16512 if owner == 1 else 512 if owner == 7 else 65536)
                    and len(output) == (32 if owner == 1 else 64 if owner == 7 else 256), 'original first-call setup')
        else:
            old_wire, expected_before, expected_capacity = pending.pop(key)
            require(wire == old_wire and before == expected_before and len(output) == expected_capacity,
                    'actual full mutable continuation preserved')
        if owner == 7:
            state, published = oldplan.plan_frame(row['return_code'], output)
            growth, which, needed = state[0] == 'growth', state[1], state[2]
        else:
            status, needed, published = oldparams.frame(owner, row['return_code'], output)
            growth, which = status in (2, 3), 1 if status == 2 else 2
        if growth:
            require(position + 1 < len(key) and needed > (len(before) if which == 1 else len(output)), 'growth continuation exists')
            pending[key] = (wire, after + bytes(needed - len(after)) if which == 1 else after,
                            len(output) if which == 1 else needed)
        else:
            require(position + 1 == len(key), 'completed owner not replayed')
            completed[key] = wire, published
    require(not pending and len(completed) == len(chains) and total_bytes == 1627490313,
            'all 1.627 GB complete buffer records accounted for')
    require(load_json(capture / 'reference/capture.json') == {'calls': 12350, 'controls': 197, 'logical_bytes': total_bytes}, 'capture totals')
    semantic_params = {}
    typed_installed = 0
    def finished(calls, wire):
        actual_wire, result = completed[tuple(calls)]
        require(actual_wire == wire, 'semantic input binds actual predecessor full output')
        return result
    def check_exchange(exchange, session, slot, wire, code, body):
        (actual_session, actual_slot, actual_wire), (header, actual_body) = exchange
        require((actual_session, actual_slot, actual_wire) == (session, slot, wire)
                and word(header, 8) == session and word(header, 16) == slot and word(header, 24) == code
                and actual_body == body, 'installed owner exact complete request/response differs')
    for kind in range(1, 6):
        installed = iter(private(capture / 'typed' / ('kind' + str(kind)) / 'installed', 60))
        for case, row in [(c, r) for c, r in zip(execution_domain, typed) if c['kind'] == kind]:
            require([row[k] for k in ('case_id', 'kind', 'name')] == [case[k] for k in ('case_id', 'kind', 'name')], 'parameter case identity')
            cid, raw = case['case_id'], case['raw_json'].encode()
            vwire = b'HJSMS002' + PACK(1, len(raw)) + raw
            value = finished(row['value_calls'], vwire)
            check_exchange(next(installed), cid % 2, 10, vwire, 32, value)
            admitted = word(value, 8) == 0
            require(row['admitted'] == admitted and row['input_sha256'] == SHA(raw), 'complete Map outcome')
            if admitted:
                twire = b'HBPRQ001' + PACK(len(value) - 32, kind) + value[32:]
                result = finished(row['params_calls'], twire)
                require(row['typed_frame_hex'] == result.hex() and row['typed_success'] == (word(result, 8) == 0), 'typed full output declaration')
                semantic_params[kind + 1, value[32:].decode()] = result
                if kind == 3:
                    check_exchange(next(installed), cid % 2, 69, twire, 256, result)
                    typed_installed += 1
            else:
                require(not row['params_calls'] and row['typed_frame_hex'] is None and row['typed_success'] is False, 'rejected Map cannot reach typed owner')
        require(next(installed, None) is None, 'unattributed installed typed exchange')
    params_controls = {n: (row, arrays[0], arrays[1], arrays[3], arrays[4]) for n, (row, arrays) in full.items() if row['owner'] != 7}
    oldparams.control_evidence(controls[:170], params_controls, semantic_params)
    config_exchanges = 0
    terminals = collections.Counter()
    for group in groups:
        folder = capture / 'planner' / group['name']
        installed, prior = iter(private(folder / 'installed', 45)), iter(private(folder / 'prior-root', 45))
        rows = [row for row in planned if row['group'] == group['name']]
        require(len(rows) == len(group['cases']), 'planner group complete')
        for case, row in zip(group['cases'], rows):
            require([row[k] for k in ('case_id', 'kind', 'name')] == [case[k] for k in ('case_id', 'kind', 'name')], 'planner case identity')
            cid, kind, raw = case['case_id'], case['kind'], case['raw_json'].encode()
            vwire = b'HJSMS002' + PACK(1, len(raw)) + raw
            value = finished(row['value_calls'], vwire)
            check_exchange(next(installed), cid % 2, 10, vwire, 32, value)
            require(word(value, 8) == 0, 'planner Map admission')
            twire = b'HBPRQ001' + PACK(len(value) - 32, kind) + value[32:]
            typed_frame = finished(row['params_calls'], twire)
            require(row['typed_frame_hex'] == typed_frame.hex(), 'planner typed predecessor')
            if kind == 3:
                check_exchange(next(installed), cid % 2, 69, twire, 256, typed_frame)
            phase, feedback = 0, b''
            terminal = None
            if word(typed_frame, 8) == 0:
                require(1 <= len(row['stages']) <= 4, 'planner bounded stages')
                for stage in row['stages']:
                    wire = b'HBPLQ001' + PACK(phase, int(case['pool']), len(typed_frame), len(feedback), 0) + typed_frame + feedback
                    result = finished(stage['plan_calls'], wire)
                    require(stage['phase'] == phase and stage['frame_hex'] == result.hex(), 'planner complete stage identity')
                    check_exchange(next(installed), cid % 2, 70, wire, len(result), result)
                    if word(result, 8) == 2:
                        phase, query = word(result, 24), result[64:]
                        old, actual = next(prior), next(installed)
                        feedback = bytes.fromhex(stage['root_hex'])
                        check_exchange(old, cid % 2, 11, query, len(feedback), feedback)
                        check_exchange(actual, cid % 2, 11, query, len(feedback), feedback)
                        config_exchanges += 1
                    else:
                        require(stage is row['stages'][-1] and word(result, 8) in (1, 3) and stage['root_hex'] is None, 'planner exact terminal position')
                        terminal = result
                require(terminal is not None, 'planner terminated')
            else:
                require(not row['stages'], 'typed refusal cannot reach planner')
            require(row['terminal_hex'] == (None if terminal is None else terminal.hex()), 'complete terminal bytes')
            terminals['typed-error' if terminal is None else str(word(terminal, 8))] += 1
        require(next(installed, None) is None and next(prior, None) is None, 'no unbound planner/root exchange')
    declared = [{**r, 'stages': [{**s, 'calls': s['plan_calls']} for s in r['stages']]} for r in planned]
    used = set(attributed)
    oldplan.check_controls(controls[170:], full, used, declared, [])
    require(used | {n for n in control_calls if index[n - 1]['owner'] != 7} == set(range(1, len(index) + 1)), 'all planner physical controls checked')
    root_queries = 0
    for folder in sorted((capture / 'root').iterdir()):
        _, old = process_streams(folder / 'baseline', 60)
        _, new = process_streams(folder / 'candidate', 60)
        require(old['stdin'] == new['stdin'] and old['stdout'] == new['stdout'], 'all original root wire/counter/capacity bytes unchanged')
        root_queries += len(queries(new['stdin']))
    require(root_queries == 68 and config_exchanges == 381, 'root/planner complete domain counts')
    resources = read_resources(rog, source, inputs)
    prior_report = load_json(capture / 'RESULT.json')
    require(prior_report['status'] == 'FAIL' and prior_report['error'] == 'Empty()', 'original cloud ptrace failure retained')
    require(prior_report['whole_runtime_qualified'] is False and prior_report['public_binary_write_registered'] is False, 'scope unchanged')
    return {'status': 'INTEGRATION_DATA_PASS', 'actual_application_reexecutions': 0,
            'typed_inputs': 1388, 'installed_write_input_cases': 196, 'installed_admitted_write_calls': typed_installed,
            'plan_inputs': 433, 'plan_groups': 24, 'plan_terminal_counts': dict(terminals),
            'reference_calls': len(index), 'complete_reference_bytes': total_bytes,
            'reference_build': read_reference_build(capture.parent, qualified),
            'original_typed_controls': 170, 'original_plan_controls': 27, 'original_plan_reader_recovery': recovery,
            'public': check_public(capture), 'root_queries': root_queries, 'composed_root_exchanges': config_exchanges,
            'resources': resources, 'retained_cloud_overall_result': 'FAIL',
            'whole_runtime_qualified': False, 'public_binary_write_registered': False, 'remote_writer_effects_qualified': False}


def main():
    p = argparse.ArgumentParser()
    for n in ('capture', 'source', 'qualified', 'rog', 'inputs', 'output'):
        p.add_argument('--' + n, required=True, type=Path)
    a = p.parse_args()
    report = read_all(a.capture.resolve(), a.source.resolve(), a.qualified.resolve(), a.rog.resolve(), a.inputs.resolve())
    a.output.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
