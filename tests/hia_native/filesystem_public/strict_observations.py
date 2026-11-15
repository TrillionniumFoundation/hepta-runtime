"""Read complete native observations without executing or restoring a fixture.

This layer checks streams, exact responses and state. HIA build graph admission
and interpretation of the complete syscall/continuation traces are separate.
"""
from pathlib import Path
from collections import Counter
import argparse
import importlib.util
import json
import os
import struct
import sys
sys.dont_write_bytecode = True


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value


def states(q, raw):
    q.need(len(raw) >= 64 and raw[:8] == b'HFSOBS02', 'actual observer header')
    n, m, c, s, l, z0, z1 = struct.unpack_from('<7Q', raw, 8)
    q.need((c, s, l, z0, z1) == (64, 256, 256, 0, 0) and n >= 64 and m >= 64 and len(raw) == 640+n+m,
           'actual observer exact five owned spans')
    sections = {}; at = 64
    for name, size in (('session', n), ('cache', m), ('context', c), ('scope', s), ('lease', l)):
        sections[name] = raw[at:at+size]; at += size
    session, cache = sections['session'], sections['cache']
    q.need(session[:8] == b'HRSWST02', 'actual session magic')
    r, w, present, poisoned, applied, version, zero = struct.unpack_from('<7Q', session, 8)
    q.need(present in (0, 1) and poisoned in (0, 1) and applied in (0, 1) and version == 1 and zero == 0,
           'actual session typed flags/version')
    q.need(r+w == n-64 and (present or w == 0), 'actual session full path extents')
    root, current = session[64:64+r], session[64+r:]
    q.need(cache[:8] == b'HVCSTA01' and struct.unpack_from('<2Q', cache, 8) == (1, m), 'actual cache header/version/extent')
    cache_poisoned = struct.unpack_from('<Q', cache, 32)[0]
    q.need(cache_poisoned in (0, 1) and cache[40:64] == bytes(24), 'actual cache poison/reserved fields')
    count = struct.unpack_from('<Q', cache, 24)[0]
    q.need(count <= (m-64)//16, 'actual cache count exceeds records')
    entries = {}; at = 64
    for _ in range(count):
        q.need(m-at >= 16, 'short cache record')
        kn, vn = struct.unpack_from('<2Q', cache, at); at += 16
        q.need(kn <= m-at and vn <= m-at-kn, 'actual cache record extents')
        key, value = cache[at:at+kn].decode('utf-8'), cache[at+kn:at+kn+vn].decode('utf-8'); at += kn+vn
        q.need(key not in entries, 'duplicate cache key'); entries[key] = value
    q.need(at == m, 'unclaimed cache tail')
    context = sections['context']
    if context != bytes(64):
        q.need(context[:8] == b'HRCXST01', 'context magic')
        words = struct.unpack_from('<7Q', context, 8)
        q.need(words[0] == 1 and words[3:] == (0, 0, 0, 0), 'task context not restored after request')
    scope = sections['scope']
    if scope != bytes(256):
        q.need(scope[:8] == b'HRSCST01' and struct.unpack_from('<Q', scope, 8)[0] == 1, 'scope magic/version')
        q.need(struct.unpack_from('<Q', scope, 24)[0] == 0, 'scope remains active/suspended/tombstoned')
    lease = sections['lease']
    if lease != bytes(256):
        q.need(lease[:8] == b'HRCLST01' and struct.unpack_from('<Q', lease, 8)[0] == 1, 'lease magic/version')
        # CREATE retains the session's initial lease. Per-request clones must
        # retire while that one real owner remains live until process cleanup.
        q.need(struct.unpack_from('<2Q', lease, 24) == (1, 1), 'per-request lease not restored to sole session owner')
    state = {'root_hex': root.hex(), 'current_hex': current.hex() if present else None,
             'effective_hex': (root if poisoned or not present else current).hex(), 'poisoned': bool(poisoned),
             'session_applied': bool(applied), 'cache': {'poisoned': bool(cache_poisoned), 'entries': entries}}
    projection = {name: state[name] for name in ('root_hex', 'current_hex', 'effective_hex', 'poisoned', 'session_applied')}
    projection['cache_entries'] = entries
    projection['section_pins'] = {name: {'bytes': len(value), 'sha256': q.sha(value)} for name, value in sections.items()}
    return state, projection, sections


def wire(action):
    if 'wire_hex' in action: return bytes.fromhex(action['wire_hex'])
    return json.dumps(action['message'], sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()+b'\n'


def seed(entries):
    body = struct.pack('<Q', len(entries))
    for entry in entries:
        path, content = bytes.fromhex(entry['path_hex']), entry['content'].encode()
        body += struct.pack('<2Q', len(path), len(content))+path+content
    return b'HFSSE002'+struct.pack('<5Q', 4, len(body), 0, 0, 0)+body


def plan(scene, private):
    requests = []; selectors = {session['id']: index for index, session in enumerate(scene['sessions'])}
    def append(identifier, slot, payload):
        index = len(requests)
        if private: requests.append({'session': selectors[identifier], 'slot': slot, 'payload': payload})
        else: requests.append({'wire': payload, 'response_count': int('id' in json.loads(payload))})
        return index
    def observers():
        return {name: append(name, 33, b'') for name in selectors} if private else {}
    handshakes = []
    for session in scene['sessions']:
        indexes = []
        for message in session['initial_messages']:
            raw = wire({'message': message}); indexes.append(append(session['id'], 34, raw[:-1] if private else raw))
        handshakes.append({'session': session['id'], 'exchanges': indexes})
    initial = observers(); cases = []
    for step in scene['steps']:
        before = observers(); action = step['action']; kind = action['kind']; index = None
        if kind == 'public':
            raw = wire(action); index = append(step['session'], 34, raw[:-1] if private else raw)
        elif kind == 'cache_seed':
            if not private: raise ValueError('ordinary stdio cannot seed cache')
            index = append(step['session'], 23, seed(action['entries']))
        elif kind != 'filesystem': raise ValueError('unknown declared action')
        cases.append({'step': step, 'before': before, 'action': index, 'after': observers()})
    return requests, {'selectors': selectors, 'handshakes': handshakes, 'initial': initial, 'cases': cases, 'terminal': observers()}


def actions(q, actual, expected):
    q.need(type(actual) is list and len(actual) == len(expected), 'all actual owned fixture actions')
    for row, action in zip(actual, expected, strict=True):
        q.fields(row, ('action', 'status', 'elapsed_seconds'), 'actual fixture action receipt')
        q.same(row['action'], action, 'exact fixture action'); q.same(row['status'], 'EXECUTED', 'actual fixture execution')
        q.positive(row['elapsed_seconds'], 'actual fixture action elapsed')


def descriptors(q, value):
    q.fields(value, ('wrapper_pid', 'child_pid', 'entries', 'process_exited'), 'complete FD observation')
    q.need(q.uint(value['wrapper_pid'], 'trace PID') > 0 and type(value['process_exited']) is bool, 'FD process identity')
    if value['child_pid'] is not None: q.need(q.uint(value['child_pid'], 'child PID') > 0, 'child PID')
    q.need(type(value['entries']) is list, 'actual FD list'); numbers = []
    for entry in value['entries']:
        q.fields(entry, ('fd', 'target_hex', 'device', 'inode', 'mode'), 'complete FD entry')
        numbers.append(q.uint(entry['fd'], 'actual descriptor')); q.hex_bytes(entry['target_hex'], 'descriptor target')
        for field in ('device', 'inode', 'mode'): q.uint(entry[field], 'descriptor '+field)
    q.same(numbers, sorted(set(numbers)), 'FD uniqueness/order')
    if numbers: q.same(numbers[:3], [0, 1, 2], 'standard descriptors')


def observation_evidence(original_reader, reference_source, producer_source, native_capture):
    here = Path(__file__).absolute().parent; ref = load(here/'strict_original.py', '_fs_observation_original')
    q = ref.bootstrap(original_reader)
    source, producer, capture = [q.Binder(path) for path in (reference_source, producer_source, native_capture)]
    for name, (size, digest) in q.SOURCES.items(): source.file(name, {'bytes': size, 'sha256': digest})
    factory = q.load(source.file('cases.py'), '_fs_observation_cases')
    report, binding = capture.json('NATIVE.json'), capture.json('SOURCE.json')
    q.same(report['schema'], 'hepta.runtime.filesystem-sdk-native-capture.v1', 'native capture schema')
    q.same(report['status'], 'NATIVE_EXECUTION_COMPLETE', 'native capture complete')
    q.need(report['original_replayed'] is False and report['original_comparison_complete'] is False and report['all_processes_terminated'] is True,
           'native-first execution boundary')
    q.same(report['semantic_parity_status'], 'NOT_RUN', 'producer self-asserted original parity')
    old_fixture = ref.absolute(q, report['fixture_root'], 'owned fixture'); old_capture = old_fixture.parent
    q.need(old_fixture.name == 'fixtures', 'native fixture ownership layout')
    corpus = factory.materialized(old_fixture); q.same(capture.json('INPUTS.json'), corpus, 'full native input regeneration')
    q.same(report['counts'], ref.COUNTS, 'all native domains'); q.same(sorted(report['completed_case_ids']), list(range(70000, 70332)), 'all native IDs')
    for name, pin in report['artifacts'].items(): capture.file(name, pin)
    q.same(binding['reference_source_files'], source.artifacts, 'frozen reference input source')
    q.same(sorted(binding['driver_sources']), ['capture_common.py', 'capture_fixture.py', 'native_capture.py'], 'producer closure')
    for name, pin in binding['driver_sources'].items(): producer.file(name, pin)
    q.same(binding['original_response_inputs'], [], 'no response oracle before native'); q.same(binding['original_executions'], 0, 'no Rust before native')
    q.same(binding['reference_reader']['sha256'], ref.FROZEN_READER['sha256'], 'frozen reference reader')
    public_reader = load(here/'strict_transport.py', '_fs_observation_stdio')
    private_reader = load(here/'strict_fixture.py', '_fs_observation_private')
    common = load(producer.file('capture_common.py'), '_fs_observation_common')
    scenes = [scene for group in corpus['groups'] for scene in group['scenarios']]
    declared_processes = capture.json('processes.json'); expected_processes = []; summaries = []; cases = {}; proofs = []; totals = Counter()
    for scene in scenes:
        for layer in ('observed', 'public'):
            if layer == 'public' and len(scene['sessions']) != 1: continue
            private = layer == 'observed'; name = layer+'/scenario-%03d'%scene['scenario_id']; path = capture.root/name
            rows = [q.strict_json(line) for line in capture.data(name+'/records.jsonl').split(b'\n') if line]
            expected = [('scenario_start', None), *[('case', step['case_id']) for step in scene['steps']], ('scenario_end', None)]
            q.same([(row['kind'], row.get('case_id')) for row in rows], expected, 'full record order '+name)
            for row in rows: q.same(row['scenario_id'], scene['scenario_id'], 'scenario identity')
            q.need(capture.data(name+'/policy.json') == factory.canonical(corpus['policies'][scene['policy_id']]), 'full native configuration')
            actions(q, capture.json(name+'/setup.json'), scene['setup'])
            reset = capture.json(name+'/reset.json')
            q.same(reset['scope'], 'only this scenario owned fixture roots; earlier native processes have terminated', 'owned reset scope')
            ref.reset_evidence(q, dict(reset, scope='only this scenario owned native fixture roots; native processes have terminated'), scene)
            requests, indexes = plan(scene, private)
            binary = binding['binaries']['fixture' if private else 'public']; argv = [binary['path']]
            if corpus['policies'][scene['policy_id']] is not None: argv += ['--runtime-config', str(old_capture/name/'policy.json')]
            cwd = os.fsdecode(bytes.fromhex(scene['sessions'][0]['root_hex']))
            kwargs = dict(binary=binary, argv=argv, cwd=cwd, fence=corpus['fence_environments'][scene['fence_id']], requests=requests, strace_path=binding['strace']['path'], trace=True)
            proof, bodies = (private_reader.fixture_evidence if private else public_reader.stdio_evidence)(q, path/'process', **kwargs)
            proofs.append({'layer': layer, 'scenario_id': scene['scenario_id'], 'evidence': proof})
            receipt = capture.json(name+'/process/process.json')
            expected_processes.append({'layer': layer, 'scenario_id': scene['scenario_id'], 'path': name+'/process', 'receipt': receipt})
            totals[layer+'_processes'] += 1; totals[layer+'_exchanges'] += len(requests)
            def observe(actual, expected_indexes):
                q.same(sorted(actual), sorted(expected_indexes), 'all Session observations')
                result = {}; decoded_sections = {}
                for identifier, index in expected_indexes.items():
                    row = actual[identifier]; q.fields(row, ('exchange', 'body', 'projection'), 'observer binding')
                    q.same(row['exchange'], index, 'observer order'); q.same(row['body'], proof['exchanges'][index]['body'], 'observer raw span')
                    decoded, projection, sections = states(q, bodies[index]); q.same(row['projection'], projection, 'observer bytes/projection')
                    result[identifier] = decoded; decoded_sections[identifier] = sections
                return result, decoded_sections
            start = rows[0]
            q.same({key: start[key] for key in ('name', 'policy_id', 'fence_id')}, {key: scene[key] for key in ('name', 'policy_id', 'fence_id')}, 'scene identity')
            q.same(start['layer'], layer, 'layer identity')
            if private:
                q.same(start['selectors'], indexes['selectors'], 'selector mapping'); q.same(start['handshakes'], indexes['handshakes'], 'initialization calls')
                initial, initial_sections = observe(start['states'], indexes['initial'])
            else:
                q.same(start['session'], scene['sessions'][0]['id'], 'ordinary Session')
                q.same(start['handshakes'], indexes['handshakes'][0]['exchanges'], 'ordinary initialization calls')
                initial = {}; initial_sections = {}
            q.filesystem(start['filesystem'], scene['observed_roots']); descriptors(q, start['fds'])
            trees = [start['filesystem']]; previous_tree = start['filesystem']; previous_states = initial; previous_sections = initial_sections
            scene_cases = []
            for row, item in zip(rows[1:-1], indexes['cases'], strict=True):
                step = item['step']; q.same({key: row[key] for key in ('case_id', 'name', 'domain', 'session')},
                    {key: step[key] for key in ('case_id', 'name', 'domain', 'session')}, 'native case identity')
                q.same(row['filesystem_before'], previous_tree, 'filesystem continuity')
                for field in ('filesystem_before', 'filesystem_after'): q.filesystem(row[field], scene['observed_roots'])
                for field in ('fds_before', 'fds_after'): descriptors(q, row[field])
                if private:
                    q.same(row['fds_before'], row['fds_after'], 'per-request FD cleanup')
                    before, before_sections = observe(row['states_before'], item['before'])
                    after, after_sections = observe(row['states_after'], item['after'])
                    q.same(before, previous_states, 'same-Session continuity')
                    for identifier in before:
                        for field in before_sections[identifier]:
                            q.need(before_sections[identifier][field] == previous_sections[identifier][field], 'raw state changed between requests')
                        if identifier != step['session']:
                            q.same(before[identifier], after[identifier], 'other Session state changed')
                            for field in before_sections[identifier]:
                                q.need(before_sections[identifier][field] == after_sections[identifier][field], 'other Session raw state changed')
                    previous_states, previous_sections = after, after_sections
                else: before = {}; after = {}
                action = step['action']; index = item['action']; outcome = row['result']; response = None; transport = None
                if action['kind'] == 'public':
                    q.same(outcome['exchange'], index, 'public exchange')
                    if private:
                        q.fields(outcome, ('kind', 'exchange', 'mode', 'closed', 'public_stdio_transport'), 'observed outcome')
                        q.same(outcome['kind'], 'actual_frontend_publisher', 'frontend branch'); header = proof['exchanges'][index]['header']
                        q.same(outcome['mode'], header['mode'], 'public mode'); q.same(outcome['closed'], header['closed'], 'closed mode')
                        q.same(outcome['public_stdio_transport'], False, 'carrier is not ordinary stdio')
                        response = bodies[index]; transport = 'private-closed' if header['mode'] == 3 else 'response' if header['mode'] in (1, 2) else 'notification'
                    else:
                        q.fields(outcome, ('kind', 'exchange', 'transport'), 'ordinary outcome'); q.same(outcome['kind'], 'actual_public_stdio', 'ordinary branch')
                        transport = proof['exchanges'][index]['transport']; q.same(outcome['transport'], transport, 'OS transport'); response = b''.join(bodies[index])
                    totals[layer+'_public_attempts'] += 1; totals[layer+'_reply_bytes'] += len(response); totals[layer+'_'+transport] += 1
                elif action['kind'] == 'cache_seed':
                    q.same(outcome, {'kind': 'actual_scope_cache_seed', 'exchange': index}, 'cache seed branch')
                    q.need(bodies[index] == b'HRCFGM01'+bytes(24) and proof['exchanges'][index]['header']['native_return'] == 32, 'seed completion')
                    totals[layer+'_cache_controls'] += 1
                else:
                    q.fields(outcome, ('kind', 'actions'), 'private action outcome'); q.same(outcome['kind'], 'private_owned_fixture_actions', 'owned action branch')
                    actions(q, outcome['actions'], action['actions']); totals[layer+'_filesystem_controls'] += 1
                previous_tree = row['filesystem_after']; trees += [row['filesystem_before'], row['filesystem_after']]
                scene_cases.append({'case_id': step['case_id'], 'step': step, 'response': response, 'transport': transport, 'before': before, 'after': after})
            terminal = rows[-1]; q.same(terminal['filesystem'], previous_tree, 'final filesystem continuity')
            if private:
                ending, ending_sections = observe(terminal['states'], indexes['terminal']); q.same(ending, previous_states, 'final state continuity')
                for identifier in ending_sections:
                    for field in ending_sections[identifier]: q.need(ending_sections[identifier][field] == previous_sections[identifier][field], 'final observer mutated state')
            else: ending = {}
            descriptors(q, terminal['fds']); trees.append(terminal['filesystem']); normalized = common.structural_snapshots(trees)
            cases[(layer, scene['scenario_id'])] = {'cases': scene_cases, 'initial': initial, 'terminal': ending,
                'tree_sequence': normalized, 'handshakes': indexes['handshakes'], 'exchange_bodies': bodies}
            summaries.append({'layer': layer, 'scenario_id': scene['scenario_id'], 'records': len(rows), 'steps': len(scene['steps']), 'exchanges': len(requests),
                              'filesystem_sequence_sha256': q.sha(q.canonical(normalized))})
    q.same(declared_processes, expected_processes, 'all complete native process receipts')
    q.same(report['actual_native_processes'], len(expected_processes), 'actual process count')
    q.same(totals['observed_public_attempts'], 323, 'all observed attempts'); q.same(totals['public_public_attempts'], 317, 'all ordinary attempts')
    for binder in (source, producer, capture):
        for name, pin in list(binder.artifacts.items()): q.same(q.pin(q.inside(binder.root, name)), pin, 'observation artifact changed')
    proof = {'schema': 'hepta.runtime.filesystem-sdk-native-observation-evidence.v1', 'status': 'PASS', 'counts': dict(totals),
        'scenarios': summaries, 'actual_processes': proofs, 'source_graph_admitted': False, 'syscall_trace_admitted': False,
        'original_comparison_complete': False, 'new_native_calls': 0, 'new_rust_processes': 0, 'live_fixture_required': False,
        'native_capture': capture.artifacts['NATIVE.json'], 'artifact_sha256': {name: pin['sha256'] for name, pin in sorted(capture.artifacts.items())}}
    return q, proof, cases, corpus


def compare_original(original_reader, reference_source, producer_source, native_capture, original_capture, original_driver_source):
    q, native, cases, corpus = observation_evidence(original_reader, reference_source, producer_source, native_capture)
    here = Path(__file__).absolute().parent; ref = load(here/'strict_original.py', '_fs_compare_original')
    original = ref.reference_evidence(reference_source, original_reader, original_driver_source, native_capture, original_capture)
    capture = q.Binder(original_capture); common = load(Path(producer_source)/'capture_common.py', '_fs_compare_structure')
    totals = Counter(); complete = []
    for scene in [scene for group in corpus['groups'] for scene in group['scenarios']]:
        raw = capture.data('scenario-%03d.stdout'%scene['scenario_id']); rows = q.parse_output(raw)
        initial = {entry['session']: entry['state'] for entry in rows[0]['metadata']['sessions']}
        for layer in ('observed', 'public'):
            if (layer, scene['scenario_id']) not in cases: continue
            values = cases[(layer, scene['scenario_id'])]; previous = dict(initial)
            if layer == 'observed': q.same(values['initial'], initial, 'actual initial native/original Sessions')
            original_trees = [rows[0]['metadata']['filesystem']]
            for actual, row in zip(values['cases'], rows[1:-1], strict=True):
                meta = row['metadata']; step = actual['step']; q.same(actual['case_id'], meta['case_id'], 'whole original/native case order')
                label = '%s case %d %s'%(layer, step['case_id'], step['name'])
                if layer == 'observed':
                    q.same(actual['before'], previous, label+' complete before state')
                    previous[step['session']] = meta['state_after']; q.same(actual['after'], previous, label+' complete after state')
                original_trees += [meta['filesystem_before'], meta['filesystem_after']]
                if step['action']['kind'] == 'public':
                    _, _, expected = q.exchange(meta['result'], step['action'], raw, row)
                    q.need(actual['response'] == expected, label+' whole reply bytes differ: native='+q.sha(actual['response'])+' original='+q.sha(expected))
                    original_transport = meta['result']['transport']; observed_transport = actual['transport']
                    q.need(observed_transport == original_transport or layer == 'observed' and original_transport == 'write-error' and observed_transport == 'private-closed',
                           label+' actual transport outcome differs')
                    totals[layer+'_public_attempts'] += 1; totals[layer+'_reply_bytes'] += len(expected)
                else: totals[layer+'_private_controls'] += 1
            original_trees.append(rows[-1]['metadata']['filesystem'])
            q.same(values['tree_sequence'], common.structural_snapshots(original_trees), layer+' complete filesystem state/identity sequence scenario '+str(scene['scenario_id']))
            if layer == 'observed':
                q.same(values['terminal'], {identifier: value['state'] for identifier, value in rows[-1]['metadata']['sessions'].items()}, 'actual terminal complete Sessions')
            complete.append({'layer': layer, 'scenario_id': scene['scenario_id'], 'cases': [item['case_id'] for item in values['cases']]})
    return {'schema': 'hepta.runtime.filesystem-sdk-native-original-observation-comparison.v1', 'status': 'PASS',
        'counts': dict(totals), 'complete_scenarios': complete, 'native_observations': native, 'original_evidence': original,
        'complete_response_path_substitutions': 0, 'same_absolute_fixture_and_cwd': True,
        'source_graph_admitted': False, 'syscall_trace_admitted': False, 'full_native_qualification': False,
        'new_native_calls': 0, 'new_rust_processes': 0, 'live_fixture_required': False}


def main():
    p = argparse.ArgumentParser()
    for name in ('original-reader', 'reference-source', 'producer-source', 'native-capture', 'original-capture', 'original-driver-source', 'output'):
        p.add_argument('--'+name, type=Path, required=True)
    a = p.parse_args(); result = compare_original(a.original_reader, a.reference_source, a.producer_source, a.native_capture, a.original_capture, a.original_driver_source)
    with a.output.open('x') as stream: json.dump(result, stream, sort_keys=True, ensure_ascii=True, allow_nan=False); stream.write('\n')
    print(json.dumps({key: result[key] for key in ('status', 'counts', 'source_graph_admitted', 'syscall_trace_admitted', 'full_native_qualification')}, sort_keys=True))


if __name__ == '__main__': main()
