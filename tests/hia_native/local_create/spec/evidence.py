"""Read complete Local Create captures without executing either implementation.

Every fixed input, cache byte, file, owned task, scheduling barrier and actual
process receipt is consumed. Native observations keep their native meaning.
"""
from pathlib import Path
from collections import Counter
import gzip
import hashlib
import importlib.util
import json
import os
import posixpath
import struct

import cases
import observations
import run_ordinary
import run_held

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location('_create_leaf_evidence_for_spec', HERE.parent / 'async/held_evidence.py')
leaf = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(leaf)
Evidence = leaf.Evidence
sha = leaf.sha; pin = leaf.pin; compact = leaf.compact; decode = leaf.decode
require = leaf.require; owned = leaf.owned
integer = leaf.integer; finite = leaf.finite; absolute = leaf.absolute
Q = lambda value: struct.pack('<Q', value)
U = lambda raw, offset: struct.unpack_from('<Q', raw, offset)[0]


def exact(actual, expected, message):
    if type(expected) in (bytes, set):
        require(type(actual) is type(expected) and actual == expected, message)
    elif type(expected) in (list, tuple):
        require(type(actual) is type(expected) and len(actual) == len(expected), message)
        for left, right in zip(actual, expected, strict=True): exact(left, right, message)
    elif type(expected) is dict:
        require(type(actual) is dict and set(actual) == set(expected), message)
        for key in expected: exact(actual[key], expected[key], message)
    else:
        leaf.exact(actual, expected, message)


def request(spec, work):
    """Reconstruct the fixed fixture input without recreating its filesystem."""
    require(absolute(work), 'fixture origin is not a canonical absolute path')
    directory = os.fsencode(work); suffix = bytes.fromhex(spec['path_hex'])
    path = directory + b'/' + suffix if spec['absolute'] else suffix
    body = bytes.fromhex(spec['body_hex']) * spec['repeat']; body.decode('utf-8')
    raw_key = path.decode('utf-8', 'replace').encode()
    if b'\0' in path:
        canonical = b'no-success-nul-key'
    else:
        full = path if spec['absolute'] else directory + b'/' + suffix
        canonical = posixpath.normpath(full)
        aliases = {'dangling_leaf_symlink': b'absent-target', 'existing_leaf_symlink': b'existing-target',
                   'parent_symlink': b'real/created.bin', 'dangling_parent_symlink': b'absent-parent/created.bin'}
        if spec['setup'] in aliases:
            canonical = directory + b'/' + aliases[spec['setup']]
        canonical = canonical.decode('utf-8', 'replace').encode()
    seeds = {b'unrelated\0key': b'untouched\r\ntext', b'present-empty': b'',
             raw_key: b'stale raw-path entry', canonical: b'stale canonical entry'}
    frames = [cases.cache_frame(0)]
    frames.extend(cases.cache_frame(2, key, value) for key, value in sorted(seeds.items()))
    if spec['poison']:
        frames.append(cases.cache_frame(9))
    create_index = len(frames)
    frames.append(struct.pack('<8s7Q', b'HLCSPQ01', 1, spec['context'], len(path), len(body), 1, 0, 0) + path + body)
    keys = sorted(seeds); frames.extend(cases.cache_frame(1, key) for key in keys)
    return dict(wire=b''.join(cases.framed(frame) for frame in frames), frames=frames,
        create_index=create_index, inspection_keys=keys, path=path, content=body,
        canonical_key=canonical, seeds=seeds)


def initial_fixture(spec):
    setup, suffix = spec['setup'], bytes.fromhex(spec['path_hex'])
    rows, contents = [], {}

    def file(path, data):
        rows.append(dict(path_hex=path.hex(), kind='file', mode=0o644, content=pin(data))); contents[path.hex()] = data

    def directory(path, mode=0o755):
        rows.append(dict(path_hex=path.hex(), kind='directory', mode=mode))

    def symlink(path, target):
        rows.append(dict(path_hex=path.hex(), kind='symlink', mode=0o777, target_hex=target.hex()))

    if setup == 'existing_file': file(suffix, b'original file must remain\n')
    elif setup == 'existing_directory': directory(suffix)
    elif setup == 'dangling_leaf_symlink': symlink(suffix, b'absent-target')
    elif setup == 'existing_leaf_symlink':
        file(b'existing-target', b'original symlink target\n'); symlink(suffix, b'existing-target')
    elif setup == 'parent_regular_file': file(b'parent', b'parent is a regular file\n')
    elif setup == 'parent_symlink': directory(b'real'); symlink(b'alias', b'real')
    elif setup == 'dangling_parent_symlink': symlink(b'alias', b'absent-parent')
    elif setup == 'dot_parent_alias': directory(b'dir')
    elif setup == 'readonly_parent': directory(b'protected', 0o500)
    elif setup == 'leaf_symlink_loop': symlink(suffix, suffix)
    elif setup == 'parent_symlink_loop': symlink(b'loop', b'loop')
    else: require(setup == 'none', 'undeclared initial fixture setup')
    return sorted(rows, key=lambda row: bytes.fromhex(row['path_hex'])), contents


def filesystem(evidence, prefix, phase, rows, *, initial=None):
    require(type(rows) is list, 'full filesystem inventory absent')
    seen, content, total = set(), {}, 0
    for row in rows:
        require(type(row) is dict and type(row.get('path_hex')) is str, 'filesystem path entry differs')
        path = bytes.fromhex(row['path_hex'])
        require(path and not path.startswith(b'/') and b'\0' not in path and b'..' not in path.split(b'/'), 'fixture path escapes its owned directory')
        require(path not in seen and type(row.get('mode')) is int and 0 <= row['mode'] <= 0o7777, 'duplicate or invalid filesystem entry')
        seen.add(path)
        if row['kind'] == 'file':
            exact(set(row), {'path_hex', 'kind', 'mode', 'content'}, 'regular file receipt fields differ')
            name = phase + '-file-' + sha(path) + '.bin.gz'
            raw = evidence.compressed(prefix + name)
            exact(pin(raw), row['content'], 'complete regular file bytes differ from receipt')
            content[row['path_hex']] = raw; total += len(raw)
        elif row['kind'] == 'directory':
            exact(set(row), {'path_hex', 'kind', 'mode'}, 'directory receipt fields differ')
        else:
            require(row['kind'] == 'symlink', 'undeclared filesystem object type')
            exact(set(row), {'path_hex', 'kind', 'mode', 'target_hex'}, 'symlink receipt fields differ')
            require(b'\0' not in bytes.fromhex(row['target_hex']), 'symlink target contains NUL')
    if initial is not None:
        expected, expected_contents = initial_fixture(initial)
        exact(rows, expected, 'initial owned filesystem differs from fixed source fixture')
        require(content == expected_contents, 'initial complete fixture file content differs')
    return dict(rows=rows, complete_bytes=total, content=content)


def snapshots(raw, mode, *, held):
    if mode == 'native':
        return observations.observations(raw)
    return run_held.cache_frames(raw) if held else run_ordinary.observations(raw)


def semantic(spec, invocation, stdout, stderr, mode, *, held=None):
    frames = run_ordinary.frames(stdout); before = invocation['create_index']
    require(len(frames) == len(invocation['frames']), 'complete fixture response count differs')
    exact(frames[:before], [run_ordinary.cache_response(None)] * before, 'cache setup responses differ')
    response = frames[before]
    outcome = dict(outcome='cancelled') if response == 0xfffffff7 else None
    if outcome is None:
        require(type(response) is bytes and len(response) >= 32 and response[:8] == b'HLCSPR01', 'complete Create result absent')
        require(U(response, 8) == 1 and U(response, 16) in (0, 1) and U(response, 24) == len(response) - 32, 'typed Create response fields differ')
        message = response[32:]; message.decode('utf-8')
        outcome = dict(outcome='result', kind=U(response, 16), message_hex=message.hex())
    expected_outcome = held['expected_outcome'] if held else 'result'
    require(outcome['outcome'] == expected_outcome, 'fixed cancellation/normal result domain differs')
    expected = dict(invocation['seeds'])
    if outcome['outcome'] == 'result':
        require(outcome['kind'] == (1 if spec['error_class'] else 0), 'original semantic error class differs')
        message = bytes.fromhex(outcome['message_hex'])
        if outcome['kind'] == 0:
            exact(message, f"File created successfully with {len(invocation['content'])} bytes".encode(), 'success used a wrong UTF-8 byte length')
            if spec['context'] == 1 and not spec['poison']:
                value = invocation['content'].replace(b'\r\n', b'\n')
                if len(value) <= 1 << 20: expected[invocation['canonical_key']] = value
                else: expected.pop(invocation['canonical_key'], None)
        elif spec['error_class'] == 'exists':
            exact(message, b'File already exists: ' + invocation['path'].decode('utf-8', 'replace').encode() +
                  b'. Edit it with str_replace or batch_edit instead of create.', 'existing path guidance differs')
        elif spec['error_class'] == 'write':
            require(message.startswith(b'Permission denied. Cannot write to file: '), 'write error wrapper differs')
        else:
            require(spec['error_class'] == 'mkdir' and message.startswith(b"Permission denied. Cannot create directories: Failed to create dirs for '"), 'both original mkdir error wrappers must remain')
    cache, markers = snapshots(stderr, mode, held=held is not None)
    require(cache == [dict(phase=0, poisoned=spec['poison'], entries=invocation['seeds']),
                      dict(phase=1, poisoned=spec['poison'], entries=expected)], 'complete cache, poison, normalization or retention differs')
    require(frames[before + 1:] == [run_ordinary.cache_response(None if spec['poison'] else expected.get(key))
            for key in invocation['inspection_keys']], 'actual cache get responses differ')
    if mode == 'native':
        children = [row['child'] for row in markers if row['magic'] == 'HLCSPFX1']
        require(children and children[0] == 1, 'initial synchronous exists was omitted')
        if spec['error_class'] == 'exists':
            exact(children, [1], 'existing-file refusal performed later Create steps')
            require(all(row['magic'] == 'HLCSPFX1' for row in markers), 'existing-file refusal dispatched an async effect')
        elif outcome['outcome'] == 'result' and outcome['kind'] == 0:
            exact(children[-2:], [5, 6], 'canonical key and note_create were omitted or reordered')
            require(children.count(4) == 1, 'successful Create did not use one segmented writer')
        else: require(5 not in children and 6 not in children, 'error or cancellation mutated the cache')
    return dict(outcome=outcome, cache=cache, marker_count=len(markers),
        cache_bytes=sum(len(key) + len(value) for row in cache for key, value in row['entries'].items()))


def source_binding(source, origin, names, leaf_source=None):
    result = {str(Path(origin) / name): pin(owned(source, name).read_bytes()) for name in names}
    if leaf_source is not None:
        result[leaf_source] = pin(owned(Path(source).parent / 'async', 'owned_trace.py').read_bytes())
    return result


def normalized_cache(cache):
    return [dict(phase=row['phase'], poisoned=row['poisoned'], entries=[dict(key_hex=key.hex(), value=pin(value))
        for key, value in sorted(row['entries'].items())]) for row in cache]


def ordinary_capture(output, source, mode, *, binary_identity, execution, fixtures):
    evidence = Evidence(output); summary = evidence.object('summary.json')
    require(mode in ('native', 'rust') and all(absolute(value) for value in execution.values()), 'ordinary execution origin differs')
    exact(summary.get('execution'), execution, 'ordinary capture moved its declared process origin')
    sources = source_binding(source, execution['source'], ('run_ordinary.py', 'cases.py', 'observations.py'))
    expected = dict(schema='hepta.runtime.local-create-spec-ordinary.v1', status='SPEC_ORDINARY_CAPTURE_PASS', mode=mode,
        source_before=sources, source_after=sources, binary_before=binary_identity, binary_after=binary_identity,
        cases=cases.CASES, process_deadline_seconds=60, qualifier_deadline_seconds=180,
        actual_root_processes=38, retired_fixtures=38, public_handler_qualified=False,
        full_create_file_spec_qualified=False, whole_runtime_replaced=False)
    exact({key: summary.get(key) for key in expected}, expected, 'ordinary complete domain/source/deadline differs')
    require('error' not in summary and finite(summary.get('elapsed_seconds'), 180), 'ordinary capture failed or exceeded deadline')
    require(type(summary.get('rows')) is list and len(summary['rows']) == len(cases.CASES) == 38, 'ordinary case rows missing or duplicated')
    rows, pids, complete_bytes = [], set(), 0
    for spec, declared in zip(cases.CASES, summary['rows'], strict=True):
        prefix = spec['name'] + '/'; row = evidence.object(prefix + 'result.json')
        exact(row, declared, 'ordinary summary did not bind the actual case receipt')
        work = str(Path(execution['fixtures']) / spec['name']); invocation = request(spec, work)
        require(row.get('name') == spec['name'] and row.get('status') == 'PASS', 'ordinary case did not complete')
        expected_process = dict(command=[execution['binary']], cwd=work, environment={'PATH': '', 'LC_ALL': 'C'}, umask=0o022,
            timeout_seconds=60, timed_out=False, exit_code=0, binary_before=binary_identity)
        exact({key: row.get(key) for key in expected_process}, expected_process, 'ordinary actual child process contract differs')
        require(integer(row.get('actual_pid'), 2) and row['actual_pid'] not in pids, 'ordinary child PID missing or repeated')
        pids.add(row['actual_pid']); require(finite(row.get('elapsed_seconds'), 60) and 'error' not in row, 'ordinary child failed or timed out')
        streams = {name: evidence.compressed(prefix + name + '.bin.gz') for name in ('stdin', 'stdout', 'stderr')}
        for name, raw in streams.items(): exact(pin(raw), row.get(name), 'ordinary complete stream identity differs: ' + name)
        require(streams['stdin'] == invocation['wire'], 'ordinary input differs from complete fixed source fixture')
        found = semantic(spec, invocation, streams['stdout'], streams['stderr'], mode)
        initial = filesystem(evidence, prefix, 'initial', row['initial_filesystem'], initial=spec)
        final = filesystem(evidence, prefix, 'final', row['final_filesystem'])
        expected_files = dict(initial['content'])
        if spec['outcome'] == 'success':
            target = posixpath.normpath(bytes.fromhex(spec['path_hex']))
            if spec['setup'] == 'parent_symlink': target = b'real/created.bin'
            expected_files[target.hex()] = invocation['content']
            created = [item for item in final['rows'] if item['path_hex'] == target.hex()]
            require(len(created) == 1 and created[0]['kind'] == 'file' and created[0]['mode'] == 0o644,
                    'successful ordinary Create lost its exclusive regular file or mode')
        require(final['content'] == expected_files, 'complete ordinary file bytes differ from the fixed source body')
        final_rows = {item['path_hex']: item for item in final['rows']}
        require(all(final_rows.get(item['path_hex']) == item for item in initial['rows']),
                'ordinary Create changed an existing filesystem object')
        require(not (Path(fixtures) / spec['name']).exists(), 'ordinary live fixture was not retired')
        expected_capture = dict(outcome=spec['outcome'], message_hex=found['outcome']['message_hex'], context=spec['context'],
            initial_cache_entries=len(invocation['seeds']), final_cache_entries=len(found['cache'][1]['entries']), poisoned=spec['poison'],
            cache_before=[dict(key_hex=key.hex(), value=pin(value)) for key, value in sorted(invocation['seeds'].items())],
            cache_after=[dict(key_hex=key.hex(), value=pin(value)) for key, value in sorted(found['cache'][1]['entries'].items())],
            marker_count=found['marker_count'])
        exact(row.get('semantic_capture'), expected_capture, 'ordinary semantic receipt disagrees with complete retained bytes')
        count = len(streams['stdin']) + len(streams['stdout']) + found['cache_bytes'] + initial['complete_bytes'] + final['complete_bytes']
        complete_bytes += count
        rows.append(dict(name=spec['name'], outcome=found['outcome'], cache=normalized_cache(found['cache']),
            initial_filesystem=initial['rows'], final_filesystem=final['rows'], complete_bytes=count,
            actual_pid=row['actual_pid'], elapsed_seconds=row['elapsed_seconds']))
    expected_artifacts = set(evidence.artifacts)
    actual_artifacts = {str(path.relative_to(evidence.root)) for path in evidence.root.rglob('*') if path.is_file()}
    exact(actual_artifacts, expected_artifacts, 'ordinary capture has an unconsumed artifact')
    return dict(schema='hepta.runtime.local-create-spec-ordinary-capture.v1', status='PASS', mode=mode,
        actual_root_processes=38, complete_bytes=complete_bytes, rows=rows,
        artifact_sha256=dict(sorted(evidence.artifacts.items())))


def journal_frames(raw, mode):
    at, frames = 0, []
    while at < len(raw):
        require(len(raw) - at >= 16, 'truncated complete journal header')
        magic = raw[at:at + 8]
        if magic in (b'HLCSCS01', b'HLCSNA01'):
            size = U(raw, at + 8)
        else:
            require(magic in (b'HLCARP01', b'HLCASR01', b'HLCREF01', b'HSHMKFX1', b'HLCSPFX1'), 'unknown full-spec journal')
            size = {b'HLCARP01': 128, b'HLCASR01': 128, b'HLCREF01': 96, b'HSHMKFX1': 96, b'HLCSPFX1': 64}[magic]
        require(16 <= size <= len(raw) - at, 'truncated complete journal payload')
        frame = raw[at:at + size]; frames.append(frame); at += size
    return frames


def expected_leaf_calls(case):
    scene, name = case['scenario'], case['name']
    if case['fixture']['error_class']:
        return dict(open=0, write=0, close=0)
    if case['expected_outcome'] == 'cancelled':
        opened = name in ('exists_missing_sync_cancel', 'parent_exists_sync_cancel', 'mkdir_ready_poll_cancel')
        return dict(open=int(opened), write=0, close=int(opened))
    body = bytes.fromhex(case['fixture']['body_hex']) * case['fixture']['repeat']
    return dict(open=1, write=int(bool(body)), close=1)


def expected_held_filesystem(case):
    spec = case['fixture']; rows, content = initial_fixture(spec)
    if b'one/two/' in bytes.fromhex(spec['path_hex']):
        rows += [dict(path_hex=path.hex(), kind='directory', mode=0o755) for path in (b'one', b'one/two')]
    calls = expected_leaf_calls(case)
    if calls['open'] and case['scenario'] != 'canonical_unlink':
        body = bytes.fromhex(spec['body_hex']) * spec['repeat'] if case['expected_outcome'] == 'result' else b''
        path = bytes.fromhex(spec['path_hex']); content[path.hex()] = body
        rows.append(dict(path_hex=path.hex(), kind='file', mode=0o644, content=pin(body)))
    return sorted(rows, key=lambda row: bytes.fromhex(row['path_hex'])), content


def trace_events(evidence, prefix, result, origin, binary_identity, invocation, initial, final):
    raw = evidence.read(prefix + 'events.jsonl')
    require(raw.endswith(b'\n'), 'owned event stream is not complete')
    events = [decode(line) for line in raw.splitlines()]
    require(events and len(events) == result.get('events'), 'owned event count differs')
    previous, owned_pids, reaped, pending = 0, set(), {}, {}
    root = result.get('root_pid'); require(integer(root, 2), 'actual owned root PID absent')
    allowed = {'profile', 'owned_fixture_setup_before_spawn', 'owned_root', 'owned_descendant', 'child_first_syscall',
        'process_event', 'process_reaped', 'syscall_entry', 'syscall_exit', 'mechanism_syscall_entry', 'mechanism_syscall_exit',
        'marker_entry', 'spec_syscall_entry', 'spec_syscall_exit', 'runtime_statx_probe_entry', 'runtime_statx_probe_exit',
        'spec_child_entry', 'stdout_write_entry', 'stdout_read', 'hold', 'release', 'cancel_signal_sent', 'forced_wake_signal',
        'signal_delivery', 'owned_fixture_mutation'}
    for index, event in enumerate(events):
        exact(event.get('index'), index, 'owned event ordinal differs')
        require(finite(event.get('elapsed_seconds'), result['elapsed_seconds']) and event['elapsed_seconds'] >= previous,
                'owned event time regressed or exceeded the retained process')
        previous = event['elapsed_seconds']; kind = event.get('kind'); require(kind in allowed, 'undeclared owned trace event')
        if kind == 'owned_root':
            require(not owned_pids and event['pid'] == root, 'owned root admission differs'); owned_pids.add(root)
        elif kind == 'owned_descendant':
            require(event['parent'] in owned_pids and integer(event['pid'], 2) and event['pid'] not in owned_pids
                    and event['ptrace_event'] in (1, 2, 3), 'descendant was not admitted by its owned parent')
            owned_pids.add(event['pid'])
        if 'tid' in event: require(event['tid'] in owned_pids, 'event names an unowned process')
        if kind == 'process_reaped':
            require(event['tid'] not in reaped and event['exit_code'] == 0, 'owned process exited unsuccessfully or was reaped twice')
            reaped[event['tid']] = event['exit_code']
        if kind == 'profile': require(index == 0, 'owned process profile was not first and unique')
        if kind in ('spec_syscall_entry', 'runtime_statx_probe_entry'):
            require(event['tid'] not in pending, 'overlapping observed path syscalls')
            pending[event['tid']] = event
        elif kind in ('spec_syscall_exit', 'runtime_statx_probe_exit'):
            require(event['tid'] in pending, 'path syscall completion has no actual entry')
            entry = pending.pop(event['tid']); require(entry['index'] < index and entry['nr'] == event['nr'], 'path syscall identity changed')
            if kind == 'runtime_statx_probe_exit':
                require(entry['kind'] == 'runtime_statx_probe_entry' and entry['nr'] == 332 and
                        entry['arguments'][:5] == [0, 0, 0, 4095, 0] and event['kernel_return'] == -14,
                        'actual Linux statx availability probe differs')
            else:
                require(entry['kind'] == 'spec_syscall_entry', 'path syscall completion type differs')
                exact((event['operation'], event['call'], event['path_hex']),
                      (entry['operation'], entry['call'], entry['path_hex']), 'path syscall completion identity differs')
                require(type(event['kernel_return']) is int and event['completion'] == event['kernel_return']
                        and event['target_syscall_executed'] is True, 'path syscall completion was synthesized')
                returned = bytes.fromhex(event['returned_hex']); exact(pin(returned), event['returned_bytes'], 'complete returned path metadata differs')
                operation = entry['operation']; value = event['kernel_return']
                if operation == 'metadata':
                    require(entry['nr'] in (4, 6, 262, 332), 'metadata observation used an unexpected syscall')
                    require(len(returned) == (entry['result_extent'] if value == 0 else 0), 'full stat structure was not retained')
                elif operation == 'readlink':
                    require(entry['nr'] in (89, 267) and len(returned) == max(0, value), 'full actual readlink result differs')
                else:
                    require(operation == 'mkdir' and entry['nr'] in (83, 258) and not returned and entry['mode'] == 0o777,
                            'whole mkdir used an unexpected syscall or mode')
    require(not pending and owned_pids == set(reaped), 'owned process or path syscall did not finish')
    exact(sorted(owned_pids), result['owned_pids'], 'reported owned PID inventory differs')
    exact({str(pid): 0 for pid in owned_pids}, result['exit_codes'], 'actual process exit inventory differs')
    profile = events[0]
    wanted = dict(mode=result['mode'], binary=origin['binary'], binary_identity=binary_identity,
        target_hex=invocation['path'].hex(), timeout_seconds=60, injected_completions=[], fd0_setup=False,
        command=[origin['binary']], cwd=origin['work'], umask=0o022, environment={'PATH': '', 'LC_ALL': 'C'},
        initial_directory_entries=[])
    exact({key: profile.get(key) for key in wanted}, wanted, 'actual process profile/source/executable differs')
    setups = [event for event in events if event['kind'] == 'owned_fixture_setup_before_spawn']
    require(len(setups) == 1 and setups[0]['index'] < next(event['index'] for event in events if event['kind'] == 'owned_root'),
            'post-construction owned fixture setup was hidden or reordered')
    exact(setups[0]['entries'], initial['rows'], 'actual fixture setup inventory differs')
    exact(setups[0]['contents'], {key: pin(value) for key, value in initial['content'].items()}, 'actual setup file bytes differ')
    shallow = []
    for row in final['rows']:
        name = bytes.fromhex(row['path_hex'])
        if b'/' in name: continue
        shallow.append(dict(name=os.fsdecode(name), kind='file' if row['kind'] == 'file' else 'other',
                            mode=row['mode'], content=row.get('content') if row['kind'] == 'file' else None))
    exact(result['filesystem'], dict(initial_entries=[], final_entries=shallow), 'low-level trace filesystem disagrees with complete wrapper snapshot')
    return events


def journal_interleaving(observed, expected):
    """Bind atomic pipe records without confusing syscall entry with commit.

    A held write has not entered the kernel yet. Another owned task can write
    first. Each task's write order remains fixed; every complete record must
    still appear exactly once. Retain all admissible assignments when two
    tasks happen to write identical records rather than choosing one greedily.
    """
    require(Counter(event['raw_hex'] for event in observed) == Counter(expected),
            'complete journals differ from actual stopped-process writes')
    tids = sorted({event['tid'] for event in observed})
    queues = [[event['raw_hex'] for event in observed if event['tid'] == tid] for tid in tids]
    states = {tuple(0 for _ in queues)}
    for frame in expected:
        following = set()
        for state in states:
            for index, queue in enumerate(queues):
                if state[index] < len(queue) and queue[state[index]] == frame:
                    cursor = list(state); cursor[index] += 1; following.add(tuple(cursor))
        require(following, 'pipe journals reversed an owned task write order')
        require(len(following) <= 65536, 'journal attribution exceeds the declared reader resource')
        states = following
    require(tuple(map(len, queues)) in states, 'an owned task journal write was not consumed')


def marker_custody(events, stderr, mode):
    raw_frames = journal_frames(stderr, mode)
    expected = [frame.hex() for frame in raw_frames if frame[:8] == (b'HLCARP01' if mode == 'rust' else b'HLCASR01')]
    observed = [event for event in events if event['kind'] == 'marker_entry']
    journal_interleaving(observed, expected)
    for event in observed:
        raw = bytes.fromhex(event['raw_hex'])
        if mode == 'rust':
            require(event['owner'] == 'rust' and U(raw, 48) == event['reported_tid'] == event['tid'], 'Rust marker TID changed')
            fields = dict(event=U(raw, 16), serial=U(raw, 24), poll=U(raw, 32), wake=U(raw, 40), details=[U(raw, 56), U(raw, 64)])
        else:
            require(event['owner'] == 'native', 'native marker was relabeled as a Rust poll')
            fields = dict(zip(('action', 'life', 'generation', 'sequence', 'accepted', 'completed', 'result_kind', 'error',
                'ticket_start', 'ticket_end', 'phase', 'token', 'flags'), struct.unpack_from('<13Q', raw, 16), strict=True))
        exact({key: event.get(key) for key in fields}, fields, 'actual marker fields differ from full retained bytes')
    children = [event for event in events if event['kind'] == 'spec_child_entry']
    child_frames = [frame for frame in raw_frames if frame[:8] == b'HLCSPFX1']
    exact([event['raw_hex'] for event in children], [frame.hex() for frame in child_frames], 'native child-call descriptors were not fully observed')
    for event, frame in zip(children, child_frames, strict=True):
        require(event['child'] == U(frame, 16) and event['sequence'] == U(frame, 24) and event['generation'] == U(frame, 32)
                and event['flags'] == U(frame, 40) and event['request_bytes'] == U(frame, 48), 'native child descriptor fields differ')
    return observed, [frame for frame in raw_frames if frame[:8] == b'HLCREF01'], [frame for frame in raw_frames if frame[:8] == b'HSHMKFX1']


def mkdir_custody(events, frames, mode, root):
    entries = [event for event in events if event['kind'] == 'spec_syscall_entry' and event['operation'] == 'mkdir']
    workers = {event['tid'] for event in entries}
    require(root not in workers and len(workers) <= 1, 'one complete mkdir algorithm escaped its one actual worker')
    if mode == 'rust':
        require(not frames, 'Rust capture contains native mkdir effect frames'); return
    observed = [event for event in events if event['kind'] in ('spec_syscall_entry', 'runtime_statx_probe_entry') and event['tid'] in workers]
    require(len(observed) == len(frames), 'native whole-mkdir effect stream omitted an actual syscall')
    exits = {event['tid']: [] for event in observed}
    for event in events:
        if event['kind'] in ('spec_syscall_exit', 'runtime_statx_probe_exit') and event['tid'] in exits: exits[event['tid']].append(event)
    for index, (entry, frame) in enumerate(zip(observed, frames, strict=True)):
        candidates = [event for event in exits[entry['tid']] if event['index'] > entry['index']]
        require(candidates, 'mkdir effect has no actual syscall completion'); end = candidates[0]
        ordinal, action, start, length, flags, ready, value, error, file_mode, zero, zero2 = struct.unpack_from('<11Q', frame, 8)
        expected_action = 3 if entry['kind'] == 'runtime_statx_probe_entry' else 1 if entry['operation'] == 'mkdir' else 2 if entry['nr'] == 332 else 4
        require(ordinal == index + 1 and action == expected_action and ready == 1 and zero == zero2 == 0, 'native mkdir effect ordinal/action differs')
        completion = end['kernel_return']
        exact((value, error), (completion & ((1 << 64) - 1), -completion if completion < 0 else 0), 'mkdir effect changed actual kernel result')
        if action == 3: exact((start, length, flags, file_mode), (0, 0, 4095, 0), 'mkdir statx probe effect differs')
        else:
            require(length == len(bytes.fromhex(entry['path_hex'])) and start >= 513, 'mkdir effect lost its actual pathname length')
            expected_flags = 0o777 if action == 1 else 4095 if action == 2 else 0
            require(flags == expected_flags, 'mkdir effect syscall flags differ')
            metadata = bytes.fromhex(end['returned_hex'])
            observed_mode = (struct.unpack_from('<H', metadata, 28)[0] if action == 2 else struct.unpack_from('<I', metadata, 24)[0]) if metadata else 0
            require(file_mode == observed_mode, 'mkdir effect changed the actual file kind/mode')


def held_boundaries(case, invocation, events, markers, result, stdout):
    mode, root, scene = result['mode'], result['root_pid'], case['scenario']
    lookup = {event['index']: event for event in events}; active, barriers = {}, []
    cancels = [event for event in events if event['kind'] == 'cancel_signal_sent']
    wakes = [event for event in events if event['kind'] == 'forced_wake_signal']
    writes = [event for event in events if event['kind'] == 'stdout_write_entry']
    reads = [event for event in events if event['kind'] == 'stdout_read']
    require(writes and reads, 'actual stdout publication or visibility is absent')
    require(b''.join(bytes.fromhex(event['raw_hex']) for event in writes) == stdout, 'full stdout actual write stream differs')
    require(b''.join(bytes.fromhex(event['raw_hex']) for event in reads) == stdout, 'full stdout actual read stream differs')
    offset = 0
    for event in reads:
        raw = bytes.fromhex(event['raw_hex']); exact((event['offset'], event['bytes'], event['payload']), (offset, len(raw), pin(raw)), 'stdout read custody differs'); offset += len(raw)
    create_start = invocation['create_index'] * 40
    outcome = run_held.visible(stdout, invocation['create_index']); require(outcome is not None, 'Create result not visible')
    create_end, offset, publication = outcome['consumed'], 0, None
    for event in writes:
        raw = bytes.fromhex(event['raw_hex']); exact((event['length'], event['payload']), (len(raw), pin(raw)), 'stdout write custody differs')
        if offset + len(raw) > create_start and publication is None: publication = event['index']
        offset += len(raw)
    visible = next(event['index'] for event in reads if event['offset'] + event['bytes'] >= create_end)
    require(publication is not None, 'Create result publication was omitted')
    require(len(cancels) == (0 if scene == 'mkdir_before_wait' else 1), 'actual cancellation request inventory differs')
    if cancels:
        cancel = cancels[0]; require(cancel['tid'] == root and cancel['index'] < publication, 'cancel was requested after the Create result')
        signals = [event for event in events if event['kind'] == 'signal_delivery' and event['signal'] == 10]
        if mode == 'native':
            require(len(signals) == 1 and signals[0]['tid'] == root and signals[0]['index'] > cancel['index'], 'actual cancellation signal delivery differs')
        else:
            # The frozen Rust observer blocks SIGUSR1 and consumes it with
            # sigwait in its owned control thread. Its actual AbortHandle
            # before/after markers below bind consumption and completion.
            require(not signals, 'Rust sigwait control unexpectedly delivered a signal handler')
    for event in events:
        if event['kind'] == 'hold':
            require(event['tid'] not in active and event['event_index'] < event['index'], 'invalid or overlapping owned hold')
            observed = lookup[event['event_index']]; require(observed['tid'] == event['tid'], 'held observation belongs to another process')
            active[event['tid']] = (event, observed)
        elif event['kind'] == 'release':
            require(event['tid'] in active, 'release has no actual hold'); hold, observed = active.pop(event['tid'])
            require(hold['index'] < event['index'], 'release preceded hold')
            exact((event.get('held_event'), event.get('held_reason')), (hold['event_index'], hold['reason']), 'release changed its held observation')
            barriers.append((hold, event, observed))
    require(not active, 'an owned hold never resumed')
    by_reason = {}
    for hold, release, observed in barriers: by_reason.setdefault(hold['reason'], []).append((hold, release, observed))
    deferred = scene in ('exists_sync', 'parent_sync', 'mkdir_ready_poll') and outcome['outcome'] == 'cancelled'
    required = set()
    if scene in ('exists_sync', 'parent_sync', 'canonical_sync', 'canonical_unlink'): required.add('sync')
    if scene in ('mkdir_inflight', 'mkdir_repeat'): required.add('mkdir_effect')
    if scene in ('mkdir_ready', 'mkdir_ready_poll', 'mkdir_before_wait'): required.add('bootstrap_mkdir')
    if scene == 'mkdir_ready': required.add('ready')
    if scene == 'mkdir_ready_poll': required.add('poll')
    if scene == 'mkdir_before_wait': required.add('pending_gate')
    if deferred:
        required.add('open_effect' if expected_leaf_calls(case)['open'] else 'mkdir_effect')
        gates = set(by_reason) & {'pending_gate', 'cancel_publication_gate'}
        require(bool(gates) and (mode == 'native' or gates == {'pending_gate'}),
                'same-turn cancellation lacks its actual admitted-effect boundary')
        required.update(gates)
        if len(gates) == 2:
            require(mode == 'native' and by_reason['pending_gate'][0][1]['index']
                    < by_reason['cancel_publication_gate'][0][0]['index'],
                    'native cancellation publication preceded its actual pending admission')
    exact(set(by_reason), required, 'held fixed scenario added or omitted an actual barrier')
    require(all(len(rows) == 1 for rows in by_reason.values()), 'an actual held boundary was repeated')
    if scene in ('mkdir_inflight', 'mkdir_repeat'):
        states = [event for event in markers if event['tid'] == root and event['index'] < cancels[0]['index'] and
                  (event['event'] in (1, 2, 3) if mode == 'rust' else event['life'] == 2 or event['action'] == 3 and event['life'] == 3)]
        require(states and (states[-1]['event'] == 2 if mode == 'rust' else states[-1]['action'] == 3 and states[-1]['life'] == 3),
                'whole mkdir cancellation was not requested after an actual Pending return')
    if scene in ('exists_sync', 'parent_sync', 'canonical_sync', 'canonical_unlink'):
        require(len(by_reason.get('sync', [])) == 1, 'synchronous same-poll barrier absent')
        hold, release, observed = by_reason['sync'][0]
        require(observed['kind'] == 'spec_syscall_entry' and observed['tid'] == root and hold['index'] < cancels[0]['index'] < release['index'], 'sync cancellation was not inside the real owned operation')
        if scene in ('exists_sync', 'parent_sync'):
            expected_path = invocation['path'] if scene == 'exists_sync' else posixpath.dirname(invocation['path'])
            require(observed['operation'] == 'metadata' and bytes.fromhex(observed['path_hex']) == expected_path, 'wrong exists syscall was held')
        else:
            close = [event for event in events if event['kind'] == 'syscall_exit' and event['operation'] == 'close']
            require(len(close) == 1 and close[0]['tid'] == root and close[0]['index'] < hold['index'], 'canonical key ran before actual inline close')
            require(not any(event['index'] > hold['index'] and (event['event'] == 2 if mode == 'rust' else event['action'] in (3, 6)) for event in markers if event['tid'] == root), 'canonical key/cache tail added a cancellation point')
    if scene == 'mkdir_ready':
        require(len(by_reason.get('ready', [])) == 1, 'mkdir ready-before-poll barrier absent')
    if scene == 'mkdir_ready_poll':
        require(len(by_reason.get('poll', [])) == 1, 'mkdir ready poll was not actually held')
    if scene == 'mkdir_before_wait':
        require(len(by_reason.get('pending_gate', [])) == 1, 'mkdir completion-before-wait barrier absent')
    for hold, release, observed in barriers:
        reason = hold['reason']
        if reason in ('mkdir_effect', 'open_effect', 'ready'):
            require(outcome['outcome'] == 'cancelled' and visible < release['index'], 'held worker was released before complete cancellation was readable')
        if reason in ('mkdir_effect', 'bootstrap_mkdir'):
            require(observed['kind'] == 'spec_syscall_entry' and observed['operation'] == 'mkdir' and observed['tid'] != root,
                    'whole mkdir boundary did not hold its actual worker syscall')
            if scene in ('mkdir_inflight', 'mkdir_repeat'):
                require(hold['index'] < cancels[0]['index'] < release['index'], 'mkdir cancellation preceded its declared in-flight hold')
        if reason == 'open_effect':
            require(observed['kind'] == 'syscall_entry' and observed['operation'] == 'open' and observed['tid'] != root,
                    'deferred cancellation did not hold the admitted exclusive-open worker')
        if reason == 'ready':
            require(observed['event'] == 4 if mode == 'rust' else observed['action'] == 9 and observed['life'] == 3,
                    'ready barrier is not an actual published completion')
        elif reason == 'poll':
            require(observed['tid'] == root and hold['index'] < cancels[0]['index'] < release['index'], 'cancel was not requested during the ready poll')
            require(observed['event'] == 1 if mode == 'rust' else observed['action'] == 11 and observed['life'] == 2 and (observed['flags'] >> 16) & 255 == 6,
                    'held native turn was not the actual mkdir ready poll')
        elif reason == 'cancel_publication_gate':
            require(mode == 'native' and observed['action'] == 6 and observed['life'] == 4, 'cancel-publication barrier was mislabeled as a running poll')
            require(release['index'] < publication, 'cancel-publication gate was released after publication')
        elif reason == 'pending_gate' and scene == 'mkdir_before_wait':
            completed = [event for event in markers if event.get('event') == 5] if mode == 'rust' else [event for event in events if event['kind'] == 'process_reaped' and event['tid'] != root]
            require(any(hold['index'] < event['index'] < release['index'] for event in completed), 'worker did not actually complete before wait was released')
        if reason == 'pending_gate':
            require(observed['tid'] == root and (observed['event'] == 2 if mode == 'rust' else observed['action'] == 3 and observed['life'] == 3),
                    'pending gate was not an actual original Pending or native WAIT')
        if deferred and reason in ('pending_gate', 'cancel_publication_gate'):
            effect = by_reason['open_effect' if expected_leaf_calls(case)['open'] else 'mkdir_effect'][0]
            require(effect[0]['index'] < release['index'] < publication, 'next admitted worker did not actually start before cancellation publication')
        if reason == 'bootstrap_mkdir':
            require(any(event['tid'] == root and event['index'] < release['index'] and
                    (event['event'] == 2 if mode == 'rust' else event['action'] == 3 and event['life'] == 3) for event in markers),
                    'bootstrap whole mkdir continued before the original parent returned Pending')
    if mode == 'rust':
        aborts = [event for event in markers if event['event'] in (8, 9)]
        exact([event['event'] for event in aborts], [8, 9] if cancels else [], 'actual AbortHandle call did not return exactly once')
        if cancels:
            require(cancels[0]['index'] < aborts[0]['index'] < aborts[1]['index']
                    and aborts[0]['index'] < publication and aborts[0]['tid'] == aborts[1]['tid'] != root,
                    'actual AbortHandle order or owned control thread differs')
            for hold, release, observed in barriers:
                if hold['reason'] in ('sync', 'poll'):
                    require(hold['index'] < aborts[1]['index'] < release['index'], 'Rust abort did not return during the held same poll')
        normal = outcome['outcome'] == 'result'
        require(sum(event['event'] == 3 for event in markers) == int(normal), 'the actual original Ready/Pending result domain differs')
        joins = [event for event in markers if event['event'] in (11, 12)]
        exact([event['event'] for event in joins], [12 if normal else 11], 'actual Tokio JoinHandle outcome differs')
        require(joins[0]['tid'] == root and joins[0]['index'] < publication, 'actual JoinHandle result was not obtained before publication')
        drops = [event for event in markers if event['event'] in (6, 7)]
        exact([event['event'] for event in drops], [6, 7], 'the actual original future was not dropped once')
        require(all(event['tid'] == root for event in drops) and drops[1]['index'] < joins[0]['index'],
                'original future cleanup was deferred beyond its JoinHandle result')
        drains = [event for event in markers if event['event'] == 13]
        require(len(drains) == 1 and publication < drains[0]['index'], 'Runtime drain replaced result visibility')
        starts = [event for event in markers if event['event'] == 16]; stops = [event for event in markers if event['event'] == 17]
        exact(sorted(event['tid'] for event in starts), sorted(event['tid'] for event in stops), 'blocking runtime workers were not fully drained')
        require(len(starts) <= 1 and all(event['index'] < drains[0]['index'] for event in stops), 'whole Local profile gained an undrained worker')
    else:
        children = {event['pid'] for event in events if event['kind'] == 'owned_descendant'}
        waits = [event for event in events if event['kind'] == 'mechanism_syscall_exit' and event['nr'] == 61 and event['kernel_return'] > 0]
        exact(sorted(event['kernel_return'] for event in waits), sorted(children), 'native wait4 did not reap each actual worker once')
        require(all(event['tid'] == root for event in waits), 'native worker reap escaped the owned parent')
    repeated = scene == 'mkdir_repeat'
    require(len(wakes) == (3 if repeated else 0), 'actual explicit-wake domain differs')
    if repeated:
        signals = [event for event in events if event['kind'] == 'signal_delivery' and event['signal'] == 12]
        if mode == 'native':
            require(len(signals) == 3 and all(event['tid'] == root for event in signals), 'three actual wake signals were not delivered')
        else:
            require(not signals and sum(event['event'] == 10 for event in markers) == 3, 'actual Rust sigwait/task waker was not invoked three times')
        for index, wake in enumerate(wakes):
            end = wakes[index + 1]['index'] if index < 2 else cancels[0]['index']
            require(any(wake['index'] < event['index'] < end and event['tid'] == root and
                        (event['event'] == 2 if mode == 'rust' else event['action'] == 3 and event['life'] == 3) for event in markers),
                    'explicit wake did not produce another real Pending/WAIT turn')
    mutations = [event for event in events if event['kind'] == 'owned_fixture_mutation']
    require(len(mutations) == (1 if scene == 'canonical_unlink' else 0), 'unexpected external fixture mutation')
    if mutations:
        event = mutations[0]
        exact((event['operation'], event['path_hex'], event['removed_content']),
              ('unlink-after-successful-close', invocation['path'].hex(), pin(invocation['content'])), 'post-close unlink changed another resource')
    return dict(barriers=len(barriers), cancellations=len(cancels), forced_wakes=len(wakes), outcome=outcome)


def held_capture(output, source, mode, *, binary_identity, execution, fixtures):
    evidence = Evidence(output); summary = evidence.object('summary.json')
    require(mode in ('native', 'rust') and all(absolute(value) for value in execution.values()), 'held execution origin differs')
    exact(summary.get('execution'), execution, 'held capture moved its declared process origin')
    sources = source_binding(source, execution['source'], ('run_held.py', 'cases.py', 'owned_trace.py', 'observations.py'), execution['leaf_source'])
    expected = dict(schema='hepta.runtime.local-create-spec-held.v1', status='SPEC_HELD_CAPTURE_PASS', mode=mode,
        cases=run_held.CASES, source_before=sources, source_after=sources,
        binary_before=binary_identity, binary_after=binary_identity, process_deadline_seconds=60,
        qualifier_deadline_seconds=180, actual_root_processes=15, public_handler_qualified=False,
        full_create_file_spec_qualified=False, whole_runtime_replaced=False, old_stack_removal_qualified=False)
    exact({key: summary.get(key) for key in expected}, expected, 'held complete source/domain/deadline differs')
    require('error' not in summary and finite(summary.get('elapsed_seconds'), 180), 'held corpus failed or exceeded deadline')
    require(type(summary.get('checks')) is list and len(summary['checks']) == len(run_held.CASES) == 15, 'held case rows missing or duplicated')
    rows, root_pids, owned_count, complete_bytes = [], set(), 0, 0
    for case, declared in zip(run_held.CASES, summary['checks'], strict=True):
        spec = case['fixture']; prefix = case['name'] + '/'; row = evidence.object(prefix + 'result.json')
        exact(row, declared, 'held wrapper row differs from full summary')
        require(row.get('name') == case['name'] and row.get('status') == 'PASS' and row.get('fixture_retired') is True,
                'held case did not finish or retire its fixture')
        trace_bytes = evidence.read(prefix + 'trace/result.json'); exact(pin(trace_bytes), row['leaf_trace'], 'held wrapper changed its actual child trace')
        result = decode(trace_bytes)
        expected_trace = dict(schema='hepta.runtime.owned-create-trace.v2', status='PASS', error=None, mode=mode,
            timed_out=False, timeout_seconds=60, unreaped_owned_pids=[], raw_syscall_results_preserved=True,
            all_injections_explicit=True, public_handler_qualified=False, whole_runtime_replaced=False)
        exact({key: result.get(key) for key in expected_trace}, expected_trace, 'held actual process completion or scope differs')
        require(finite(result.get('elapsed_seconds'), 60), 'held actual root exceeded its original deadline')
        exact((row['actual_root_pid'], row['actual_owned_pids'], row['elapsed_seconds'], row['full_result']),
              (result['root_pid'], result['owned_pids'], result['elapsed_seconds'], result['policy']), 'held wrapper process/observer custody differs')
        require(result['root_pid'] not in root_pids, 'held root process was reused as a fresh invocation'); root_pids.add(result['root_pid'])
        work = str(Path(execution['fixtures']) / case['name']); invocation = request(spec, work)
        streams = {name: evidence.read(prefix + 'trace/' + name + '.bin') for name in ('stdout', 'stderr')}
        streams['stdin'] = evidence.compressed(prefix + 'trace/stdin.bin.gz')
        for name, raw in streams.items(): exact(pin(raw), result.get(name), 'held complete stream identity differs: ' + name)
        require(streams['stdin'] == invocation['wire'] and result['input_delivered_bytes'] == len(invocation['wire']),
                'held input was changed or only partially delivered')
        found = semantic(spec, invocation, streams['stdout'], streams['stderr'], mode, held=case)
        initial = filesystem(evidence, prefix, 'initial', row['filesystem_before_spawn'], initial=spec)
        final = filesystem(evidence, prefix, 'final', row['filesystem_after_drain'])
        expected_rows, expected_contents = expected_held_filesystem(case)
        exact(final['rows'], expected_rows, 'held completion changed its complete expected filesystem')
        require(final['content'] == expected_contents, 'held complete file bytes differ from fixed source expectations')
        origin = dict(binary=execution['binary'], work=work)
        events = trace_events(evidence, prefix + 'trace/', result, origin, binary_identity, invocation, initial, final)
        markers, effects, mkdir_effects = marker_custody(events, streams['stderr'], mode)
        entries = [event for event in events if event['kind'] == 'syscall_entry']
        exits = [event for event in events if event['kind'] == 'syscall_exit']
        calls = expected_leaf_calls(case)
        exact(result['syscall_counts'], calls, 'held target operation domain differs')
        exact(row['leaf_syscall_counts'], calls, 'held wrapper syscall domain differs')
        path_counts = Counter(event['operation'] for event in events if event['kind'] == 'spec_syscall_entry')
        exact(row['spec_syscall_counts'], {name: path_counts[name] for name in ('metadata', 'mkdir', 'readlink')}, 'actual path syscall inventory differs')
        payload_bytes = evidence.compressed(prefix + 'trace/write-payloads.bin.gz')
        syscall_capture = leaf.check_syscalls(dict(size=len(invocation['content']), expected_calls=calls, options={}),
            mode, invocation['content'], invocation['path'], result['root_pid'], entries, exits, [], effects, payload_bytes)
        completed = sum(event['completion'] for event in exits if event['operation'] == 'write' and event['completion'] > 0)
        require(result['completed_kernel_bytes'] == completed, 'actual completed kernel byte total differs')
        mkdir_custody(events, mkdir_effects, mode, result['root_pid'])
        boundaries = held_boundaries(case, invocation, events, markers, result, streams['stdout'])
        exact(row['full_result']['semantic_result'], boundaries['outcome'], 'held policy result disagrees with actual complete result bytes')
        target_suffix = bytes.fromhex(spec['path_hex']).hex()
        target_bytes = final['content'].get(target_suffix)
        if target_bytes is None:
            require(result['file'] is None and not (evidence.root / prefix / 'trace/file.bin.gz').exists(), 'held trace retained a nonexistent target file')
        else:
            actual = evidence.compressed(prefix + 'trace/file.bin.gz')
            require(actual == target_bytes and result['file'] == pin(actual), 'trace target file differs from complete filesystem snapshot')
        require(not (Path(fixtures) / case['name']).exists(), 'held live fixture was not retired')
        count = len(streams['stdin']) + len(streams['stdout']) + found['cache_bytes'] + initial['complete_bytes'] + final['complete_bytes'] + len(payload_bytes)
        owned_count += len(result['owned_pids']); complete_bytes += count
        rows.append(dict(name=case['name'], outcome=found['outcome'], cache=normalized_cache(found['cache']),
            initial_filesystem=initial['rows'], final_filesystem=final['rows'], syscall_counts=calls,
            syscall_projection=syscall_capture['syscall_projection'], actual_owned_processes=len(result['owned_pids']),
            actual_root_pid=result['root_pid'], elapsed_seconds=result['elapsed_seconds'], complete_bytes=count,
            boundary_counts={key: boundaries[key] for key in ('barriers', 'cancellations', 'forced_wakes')}))
    exact(summary.get('actual_owned_processes'), owned_count, 'held actual owned process total differs')
    actual_artifacts = {str(path.relative_to(evidence.root)) for path in evidence.root.rglob('*') if path.is_file()}
    exact(actual_artifacts, set(evidence.artifacts), 'held capture has an unconsumed artifact')
    return dict(schema='hepta.runtime.local-create-spec-held-capture.v1', status='PASS', mode=mode,
        actual_root_processes=15, actual_owned_processes=owned_count, complete_bytes=complete_bytes,
        rows=rows, artifact_sha256=dict(sorted(evidence.artifacts.items())))


def capture(output, source, mode, *, binary_identity, execution, fixtures):
    output, source = Path(output), Path(source)
    ordinary_origin = dict(source=execution['source'], binary=execution['binary'], output=execution['output'] + '/ordinary',
                           fixtures=execution['fixtures'] + '/ordinary')
    held_origin = dict(source=execution['source'], binary=execution['binary'], output=execution['output'] + '/held',
                       fixtures=execution['fixtures'] + '/held', leaf_source=execution['leaf_source'])
    ordinary_result = ordinary_capture(output / 'ordinary', source, mode, binary_identity=binary_identity,
        execution=ordinary_origin, fixtures=Path(fixtures) / 'ordinary')
    held_result = held_capture(output / 'held', source, mode, binary_identity=binary_identity,
        execution=held_origin, fixtures=Path(fixtures) / 'held')
    artifacts = {'ordinary/' + name: value for name, value in ordinary_result['artifact_sha256'].items()}
    artifacts.update({'held/' + name: value for name, value in held_result['artifact_sha256'].items()})
    return dict(status='PASS', mode=mode, actual_root_processes=53, ordinary=ordinary_result, held=held_result,
        complete_bytes=ordinary_result['complete_bytes'] + held_result['complete_bytes'],
        artifact_sha256=dict(sorted(artifacts.items())))


def compare(native_output, original_output, source, *, native_identity, original_identity,
            native_execution, original_execution, fixtures):
    native = capture(native_output, source, 'native', binary_identity=native_identity, execution=native_execution, fixtures=fixtures)
    original = capture(original_output, source, 'rust', binary_identity=original_identity, execution=original_execution, fixtures=fixtures)
    compared = 0
    for domain, definitions in (('ordinary', cases.CASES), ('held', run_held.CASES)):
        for spec, left, right in zip(definitions, native[domain]['rows'], original[domain]['rows'], strict=True):
            for field in ('name', 'outcome', 'cache', 'initial_filesystem', 'final_filesystem'):
                exact(left[field], right[field], 'complete native/original Local result differs: ' + field)
            folders = [Path(base) / domain / spec['name'] for base in (native_output, original_output)]
            if domain == 'ordinary':
                for leaf_name in ('stdin', 'stdout'):
                    values = [gzip.decompress((folder / (leaf_name + '.bin.gz')).read_bytes()) for folder in folders]
                    require(values[0] == values[1], 'complete paired ordinary stream differs'); compared += len(values[0])
                errors = [gzip.decompress((folder / 'stderr.bin.gz').read_bytes()) for folder in folders]
            else:
                for leaf_name in ('stdin.bin.gz', 'stdout.bin', 'write-payloads.bin.gz'):
                    values = [(gzip.decompress if leaf_name.endswith('.gz') else lambda raw: raw)((folder / 'trace' / leaf_name).read_bytes()) for folder in folders]
                    require(values[0] == values[1], 'complete paired held stream differs'); compared += len(values[0])
                errors = [(folder / 'trace/stderr.bin').read_bytes() for folder in folders]
                exact(left['syscall_counts'], right['syscall_counts'], 'paired actual target syscall counts differ')
                def projection(value):
                    projected = []
                    for item in value:
                        item = dict(item)
                        if item['operation'] == 'open' and item['completion'] >= 0: item['completion'] = 'owned-open-descriptor'
                        projected.append(item)
                    return projected
                exact(projection(left['syscall_projection']), projection(right['syscall_projection']), 'paired actual syscall returns differ')
            left_cache, _ = snapshots(errors[0], 'native', held=domain == 'held')
            right_cache, _ = snapshots(errors[1], 'rust', held=domain == 'held')
            require(left_cache == right_cache, 'complete paired cache keys/values/poison differ')
            compared += sum(len(key) + len(value) for row in left_cache for key, value in row['entries'].items())
            for phase in ('initial', 'final'):
                names = {path.name for path in folders[0].glob(phase + '-file-*.bin.gz')}
                exact(names, {path.name for path in folders[1].glob(phase + '-file-*.bin.gz')}, 'paired complete filesystem artifact set differs')
                for name in names:
                    values = [gzip.decompress((folder / name).read_bytes()) for folder in folders]
                    require(values[0] == values[1], 'complete paired filesystem bytes differ'); compared += len(values[0])
    return dict(status='PASS', ordinary_cases=38, held_cases=15, actual_native_root_processes=53,
        actual_original_root_processes=53, complete_compared_bytes=compared, native=native, original=original,
        public_handler_qualified=False, full_create_file_spec_qualified=False,
        whole_runtime_replaced=False, old_stack_removal_qualified=False)
