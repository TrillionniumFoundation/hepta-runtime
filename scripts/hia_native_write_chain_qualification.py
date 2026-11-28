"""Validate complete write-chain artifacts, native captures and original runs.

These functions inspect retained bytes only. Their results never stand in for
an aggregate's actual completed subprocess, a fresh Rust build, or a cold gate.
"""
from __future__ import annotations
import gzip
import hashlib
import json
import math
import os
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / 'scripts', ROOT / 'tests/hia_native'):
    if str(path) not in sys.path: sys.path.insert(0, str(path))
import hia_native_write_chain_build as build
import prepare_chain_original as original
from hia_native_write_chain_build import exact, require, read, obj, sha, file_record

NATIVE_SUITES = ('test_shared_atomic.py', 'test_write_chain_controller.py',
    'test_write_chain_files.py', 'test_write_chain_kernel.py', 'test_write_chain_concurrency.py')
SUITES = (*NATIVE_SUITES, 'test_write_chain_evidence.py')
SOURCE_NAMES = (
    'scripts/hia_native_write_chain_qualification.py', 'scripts/prepare_chain_original.py',
    'scripts/hia_native_write_chain_pipeline.py',
    *('tests/hia_native/' + name for name in SUITES),
    'tests/hia_native/write_chain_supervisor.py', 'tests/hia_native/oracle_write_chain.rs',
    'tests/hia_native/compare_write_chain_original.py', 'tests/hia_native/write_chain_file_plan.json',
    'tests/hia_native/atomic_write_rust_io_properties.txt',
    *original.QUALIFICATION_PINS,
)
FILE_COUNTS = dict(save=63, undo=84, success=98, original_error=49, invalid_frames=0,
    large_boundary_calls=26, observed_file_bytes=787555659)
PLAN_SHA = '8cbb195da8b6a97a8c791cbfac84b51958c0e39eaa1a1f7a2652947e2db61558'
TRACE_SHA = '79c0ae9ee55f2d26aaf766552fe0413a33473bc7d0f74fa512cbdbdabb1589dc'
TRANSITION_SHA = 'ccb380b2362ca41cac8994d5dfddeacf0a38834d393e0bd4e29d1ed813a6cb6e'


def duration(value, message):
    require(type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 180, message)


def pins(root=ROOT):
    root = Path(root)
    result = build.source_pins(root)
    exact(read(root / 'scripts/hia_native_write_chain_qualification.py'), read(__file__), 'loaded write-chain evidence inspector differs')
    exact(read(root / 'scripts/prepare_chain_original.py'), read(original.__file__), 'loaded write-chain original owner extractor differs')
    for name in SOURCE_NAMES: result[name] = file_record(root / name)
    for name, digest in original.QUALIFICATION_PINS.items(): exact(result[name]['sha256'], digest, 'write-chain reference dependency differs')
    for name, digest in original.PINS.items(): exact(result[name]['sha256'], digest, 'write-chain original source differs')
    exact(result['tests/hia_native/write_chain_file_plan.json']['sha256'], PLAN_SHA, 'write-chain file domain plan differs')
    return result


def process_stdout(path, expected):
    exact(obj(path), expected, 'write-chain actual completed stdout differs')
    return file_record(path)


def stream_record(path, *, compressed=False):
    digest = hashlib.sha256(); size = 0
    with (gzip.open(path, 'rb') if compressed else Path(path).open('rb')) as handle:
        while raw := handle.read(1 << 20): digest.update(raw); size += len(raw)
    return dict(bytes=size, sha256=digest.hexdigest())


def project_evidence(project, root=ROOT, *, recorded_root=None):
    project, root = Path(project), Path(root).resolve(strict=True)
    files, report = original.inputs(root, root)
    if recorded_root is not None:
        require(type(recorded_root) is str and Path(recorded_root).is_absolute(), 'original source root identity differs')
        report['runtime'] = report['source'] = recorded_root
        files['inputs.json'] = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode()
    exact({str(path.relative_to(project)) for path in project.rglob('*') if path.is_file()}, set(files),
          'write-chain original project file set differs')
    for name, raw in files.items(): exact(read(project / name), raw, 'actual original owner source differs: ' + name)
    return dict(inputs=report, files={name: file_record(project / name) for name in files})


def shared_evidence(folder, manifest, stdout, root=ROOT):
    folder, manifest, root = Path(folder), Path(manifest), Path(root)
    report = obj(folder / 'result.json')
    meta = obj(manifest.parent / 'atomic_write_shared.json')
    expected = dict(schema='hepta.runtime.shared-atomic-transition.v1', status='PASS',
        actual_filesystem_effects=0, native_calls=45280, synthetic_transition_cases=7978, refusals=12,
        original_rust_replay='PENDING', source_sha256=meta['source_sha256'], image_sha256=meta['image_sha256'],
        manifest_sha256=sha(read(manifest.parent / 'atomic_write_shared.json')),
        test_sha256=sha(read(root / 'tests/hia_native/test_shared_atomic.py')),
        loader_sha256=sha(read(root / 'scripts/hia_native_loader.py')),
        errno_properties_sha256=sha(read(root / 'tests/hia_native/atomic_write_rust_io_properties.txt')),
        transitions_bytes=2397334, transitions_sha256=TRANSITION_SHA)
    for key, wanted in expected.items(): exact(report.get(key), wanted, 'write-chain shared-cache evidence differs: ' + key)
    exact(set(report), set(expected) | {'elapsed_seconds'}, 'write-chain shared-cache result shape differs')
    duration(report['elapsed_seconds'], 'write-chain shared-cache test exceeded its deadline')
    actual = stream_record(folder / 'transitions.jsonl.gz', compressed=True)
    exact(actual, dict(bytes=2397334, sha256=TRANSITION_SHA), 'write-chain complete shared-cache corpus differs')
    count = 0
    with gzip.open(folder / 'transitions.jsonl.gz', 'rb') as incoming:
        for raw in incoming:
            row = json.loads(raw); count += 1
            require(set(row) == {'plan', 'events', 'result_hex', 'cache'} and len(row['plan']) == 7,
                    'write-chain shared-cache row is incomplete')
    exact(count, 7978, 'write-chain shared-cache state domain omitted')
    return dict(result=file_record(folder / 'result.json'), stdout=process_stdout(stdout, report),
        corpus=dict(gzip=file_record(folder / 'transitions.jsonl.gz'), raw=actual),
        native_calls=45280, synthetic_transition_cases=7978, refusals=12, actual_filesystem_effects=0)


def controller_evidence(folder, manifest, stdout, root=ROOT):
    folder, manifest, root = Path(folder), Path(manifest), Path(root)
    report = obj(folder / 'result.json')
    expected = dict(schema='hepta.runtime.local-write-controller-test.v1', status='PASS',
        native_controller_calls=214, native_leaf_calls=302, synthetic_filesystem_completions=31,
        trusted_buffer_growths=27, completed_requests=26, actual_filesystem_effects=0,
        original_rust_execution='PENDING', trace_calls=516, trace_bytes=126529918, trace_sha256=TRACE_SHA,
        test_sha256=sha(read(root / 'tests/hia_native/test_write_chain_controller.py')),
        loader_sha256=sha(read(root / 'scripts/hia_native_loader.py')),
        registry_sha256=sha(read(manifest.parent / 'registry.json')),
        trace_gzip_sha256=sha(read(folder / 'calls.jsonl.gz')))
    for key, wanted in expected.items(): exact(report.get(key), wanted, 'write-chain controller evidence differs: ' + key)
    duration(report['elapsed'], 'write-chain controller test exceeded its deadline')
    modules = {}
    for name in ('write_chain', 'file_lock_service', 'file_lock_state', 'history', 'view_cache'):
        meta = obj(manifest.parent / (name + '.json'))
        modules[name] = dict(manifest_sha256=sha(read(manifest.parent / (name + '.json'))),
            source_sha256=meta['source_sha256'], image_sha256=meta['image_sha256'])
    exact(report['loaded_modules'], modules, 'write-chain direct test loaded another actual image')
    exact(set(report), set(expected) | {'elapsed', 'loaded_modules'}, 'write-chain controller result shape differs')
    counts = dict.fromkeys(modules, 0); digest = hashlib.sha256(); size = 0
    with gzip.open(folder / 'calls.jsonl.gz', 'rb') as incoming:
        for raw in incoming:
            digest.update(raw); size += len(raw); row = json.loads(raw)
            exact(set(row), {'module', 'input_hex', 'code', 'output_capacity', 'output_hex', 'output_sha256',
                'workspace_before_hex', 'workspace_after_hex'}, 'write-chain actual controller invocation row differs')
            require(row['module'] in counts, 'write-chain trace invoked an undeclared image')
            counts[row['module']] += 1
            source = bytes.fromhex(row['input_hex']); output = bytes.fromhex(row['output_hex'])
            before, after = [bytes.fromhex(row[key]) for key in ('workspace_before_hex', 'workspace_after_hex')]
            require(source and type(row['code']) is int and 0 <= row['code'] < 1 << 32
                    and len(before) == len(after) and len(before) >= 4608
                    and type(row['output_capacity']) is int and 0 <= len(output) <= row['output_capacity'],
                    'write-chain actual borrowed buffers are incomplete')
            exact(len(output), row['code'] if row['code'] < 0xffff0000 else 0, 'write-chain actual returned bytes are truncated')
    exact(counts['write_chain'], 214, 'write-chain root call domain omitted')
    exact(sum(counts.values()) - 214, 302, 'write-chain actual leaf call domain omitted')
    exact(dict(bytes=size, sha256=digest.hexdigest()), dict(bytes=126529918, sha256=TRACE_SHA),
          'write-chain complete stateful borrowed-buffer history differs')
    return dict(result=file_record(folder / 'result.json'), stdout=process_stdout(stdout, report),
        corpus=dict(gzip=file_record(folder / 'calls.jsonl.gz'), bytes=size, sha256=digest.hexdigest()),
        loaded_modules=modules, native_controller_calls=214, native_leaf_calls=302,
        synthetic_filesystem_completions=31, completed_requests=26, actual_filesystem_effects=0)


def requests(raw):
    rows, cancellations = [], []; at = 0
    while at < len(raw):
        require(len(raw) - at >= 16, 'write-chain actual stdin header is truncated')
        size, tag = struct.unpack_from('<QQ', raw, at); at += 16
        if size == (1 << 64) - 1:
            cancellations.append(tag); continue
        require(64 <= size <= len(raw) - at, 'write-chain actual stdin frame is truncated')
        frame = raw[at:at + size]; at += size
        require(frame[:8] == b'HFWRT001' and frame[32:64] == bytes(32), 'write-chain actual request frame differs')
        op, context, length = struct.unpack_from('<3Q', frame, 8)
        require(op in (1, 2) and context in (1, 2) and length == len(frame) - 64, 'write-chain actual request fields differ')
        rows.append(dict(tag=tag, op=op, context=context, path_hex=frame[64:].hex()))
    exact([row['tag'] for row in rows], list(range(1, len(rows) + 1)), 'write-chain invocation IDs are incomplete')
    return rows, cancellations


def responses(raw, count, *, ordered):
    rows = []; at = 0; normalized = bytearray()
    while at < len(raw):
        require(len(raw) - at >= 20, 'write-chain actual stdout header is truncated')
        tag, tid, code = struct.unpack_from('<QQI', raw, at); at += 20
        require(tid > 0 and (32 <= code < 0xffff0000 or code == 0xfffffff7), 'write-chain actual response code differs')
        size = code if code < 0xffff0000 else 0
        require(size <= len(raw) - at, 'write-chain actual stdout body is truncated')
        output = raw[at:at + size]; at += size
        if size:
            require(output[:8] == b'HFWTR001' and struct.unpack_from('<Q', output, 16)[0] in (0, 1)
                    and struct.unpack_from('<Q', output, 24)[0] == len(output) - 32, 'write-chain actual response shape differs')
        rows.append(dict(tag=tag, tid=tid, code=code, output_hex=output.hex()))
        normalized.extend(struct.pack('<QI', tag, code) + output)
    actual = [row['tag'] for row in rows]
    exact(actual if ordered else sorted(actual), list(range(1, count + 1)), 'write-chain actual response domain omitted')
    return rows, bytes(normalized)


def filesystem_evidence(path, inventories, ordinals=None):
    """Read every retained content byte, then reconstruct every snapshot row."""
    digest = hashlib.sha256(); total = body_total = 0; completed = []; current = []
    ordinals = list(range(1, len(inventories) + 1)) if ordinals is None else ordinals
    exact(len(ordinals), len(inventories), 'write-chain snapshot ordinal domain differs')
    with gzip.open(path, 'rb') as incoming:
        def take(count):
            nonlocal total
            raw = incoming.read(count)
            require(len(raw) == count, 'write-chain full filesystem observation is truncated')
            digest.update(raw); total += len(raw); return raw
        while True:
            header = incoming.read(16)
            if not header: break
            require(len(header) == 16, 'write-chain snapshot header is truncated')
            digest.update(header); total += 16
            size, count = struct.unpack('<QQ', header)
            if size == 0:
                require(len(completed) < len(ordinals) and count == ordinals[len(completed)], 'write-chain snapshot ordinal differs')
                exact(current, inventories[len(completed)], 'write-chain complete filesystem state differs from captured inventory')
                completed.append(count); current = []; continue
            require(size <= 65536, 'write-chain retained filesystem header exceeds the fixture domain')
            row = json.loads(take(size), object_pairs_hook=atomic_pairs)
            require(len(completed) < len(ordinals), 'write-chain extra snapshot after completion')
            exact(row.pop('ordinal'), ordinals[len(completed)], 'write-chain snapshot row ordinal differs')
            body = hashlib.sha256(); left = count
            while left:
                raw = take(min(left, 1 << 20)); body.update(raw); left -= len(raw)
            if row.get('kind') == 0o100000 and 'read_errno' not in row:
                exact(row['bytes'], count, 'write-chain full file body size differs')
                row['sha256'] = body.hexdigest(); body_total += count
            else: exact(count, 0, 'write-chain non-file observation contains hidden data')
            current.append(row)
    exact(len(completed), len(inventories), 'write-chain complete snapshot domain omitted')
    exact(current, [], 'write-chain unterminated final snapshot')
    return dict(bytes=total, sha256=digest.hexdigest(), observed_file_bytes=body_total, snapshots=len(completed))


def atomic_pairs(items):
    value = {}
    for key, item in items:
        require(key not in value, 'duplicate write-chain retained JSON field'); value[key] = item
    return value


def file_process_evidence(folder, binary_sha, *, root=ROOT, original_side=False):
    folder, root = Path(folder), Path(root)
    report = obj(folder / 'result.json')
    expected = dict(schema='hepta.runtime.write-chain-files.v1', status='PASS', failure=None,
        binary_sha256=binary_sha, exit_code=0, actual_processes=1, actual_requests=147,
        counts=FILE_COUNTS, full_size_domain=True, raw_stdout_includes_tids=True,
        normalized_excludes_only_tid=True, reaped=True, timeout_seconds=180)
    for key, wanted in expected.items(): exact(report.get(key), wanted, 'write-chain actual file process differs: ' + key)
    require(type(report['pid']) is int and report['pid'] > 0, 'write-chain file process identity missing')
    duration(report['elapsed_seconds'], 'write-chain file process exceeded its original deadline')
    names = ('requests.bin', 'stdout.bin', 'normalized.bin', 'events.jsonl', 'filesystem.bin.gz', 'stderr.bin')
    exact(set(report['files']), set(names), 'write-chain complete file-process captures differ')
    for name in names: exact(report['files'][name], file_record(folder / name), 'write-chain actual file-process bytes differ')
    incoming, canceled = requests(read(folder / 'requests.bin')); exact(len(incoming), 147, 'write-chain complete file request domain omitted')
    exact(canceled, [], 'write-chain serial file corpus contains cancellation controls')
    outgoing, normalized = responses(read(folder / 'stdout.bin'), 147, ordered=True)
    exact(read(folder / 'normalized.bin'), normalized, 'write-chain normalization changed more than TIDs')
    events = [json.loads(raw, object_pairs_hook=atomic_pairs) for raw in read(folder / 'events.jsonl').splitlines()]
    exact(len(events), 147, 'write-chain complete file event domain omitted')
    plan = obj(root / 'tests/hia_native/write_chain_file_plan.json')
    exact(plan['case_source_sha256'], sha(read(root / 'tests/hia_native/test_write_chain_files.py')), 'write-chain case plan source differs')
    exact(plan['execution_evidence'], False, 'write-chain static plan cannot claim an execution')
    base = os.fsencode(report['fixture']); inventories = []
    for expected_row, request, response, event in zip(plan['rows'], incoming, outgoing, events):
        path = (base if expected_row['path_kind'] == 'fixture' else b'') + bytes.fromhex(expected_row['path_hex'])
        exact(request, dict(tag=expected_row['ordinal'], op=expected_row['operation'], context=expected_row['context'], path_hex=path.hex()),
              'write-chain complete current file domain differs')
        output = bytes.fromhex(response['output_hex'])
        exact(struct.unpack_from('<Q', output, 8)[0], request['op'], 'write-chain response belongs to another operation')
        exact(struct.unpack_from('<Q', output, 16)[0], expected_row['outcome'], 'write-chain original file outcome differs')
        expected_event = dict(ordinal=request['tag'], label=expected_row['label'], operation=request['op'],
            context=request['context'], path_hex=path.hex(), response_sha256=sha(output), response_bytes=len(output),
            outcome=expected_row['outcome'], filesystem=event['filesystem'])
        exact(event, expected_event, 'write-chain actual full result/event link differs')
        bodies = [{key: item[key] for key in ('path_hex', 'bytes', 'sha256', 'read_errno') if key in item}
            for item in event['filesystem'] if item['kind'] == 0o100000]
        links = [{key: item[key] for key in ('path_hex', 'link_hex')}
            for item in event['filesystem'] if item['kind'] == 0o120000]
        exact(bodies, expected_row['file_bodies'], 'write-chain complete file content domain differs from the original owner')
        exact(links, expected_row['symlink_targets'], 'write-chain original symlink target domain differs')
        inventories.append(event['filesystem'])
    filesystem = filesystem_evidence(folder / 'filesystem.bin.gz', inventories)
    exact(filesystem['observed_file_bytes'], FILE_COUNTS['observed_file_bytes'], 'write-chain full large-file domain shortened')
    if original_side:
        exact(obj(folder / 'stderr.bin'), dict(status='PASS', original_owner_calls=147, responses=147, canceled=0),
              'write-chain actual original file owner summary differs')
    else: exact(read(folder / 'stderr.bin'), b'', 'write-chain native file process emitted diagnostics')
    return dict(result=file_record(folder / 'result.json'), captures={name: file_record(folder / name) for name in names},
        filesystem=filesystem, actual_processes=1, actual_requests=147, counts=FILE_COUNTS)


def files_evidence(folder, stdout, *, root=ROOT, original_sha=None):
    folder, root = Path(folder), Path(root)
    report = obj(folder / 'result.json')
    exact(report.get('test_sha256'), sha(read(root / 'tests/hia_native/test_write_chain_files.py')), 'write-chain file suite source differs')
    exact(report['status'], 'PASS' if original_sha else 'NATIVE_PASS', 'write-chain file suite did not finish')
    exact(report['original_status'], 'PASS' if original_sha else 'PENDING', 'write-chain file original status differs')
    native = file_process_evidence(folder / 'native', build.ELF_SHA, root=root)
    exact(report['native'], obj(folder / 'native/result.json'), 'write-chain file suite native report changed')
    compared, reference = {}, None
    if original_sha:
        reference = file_process_evidence(folder / 'original', original_sha, root=root, original_side=True)
        exact(report['original'], obj(folder / 'original/result.json'), 'write-chain file suite original report changed')
        from test_write_chain_files import equal_streams
        for name in ('requests.bin', 'normalized.bin', 'events.jsonl', 'filesystem.bin.gz'):
            compared[name] = equal_streams(folder / 'native' / name, folder / 'original' / name, name.endswith('.gz'))
        exact(report['compared'], compared, 'write-chain full original file comparison differs')
    else: require('original' not in report and 'compared' not in report, 'write-chain native suite invented original evidence')
    summary = {key: value for key, value in report.items() if key not in ('native', 'original')}
    return dict(result=file_record(folder / 'result.json'), stdout=process_stdout(stdout, summary), native=native,
        original=reference, compared=compared)


def kernel_process_evidence(folder, config, binary_sha, *, original_side=False, concurrent=False):
    folder = Path(folder); report = obj(folder / 'result.json')
    for key, wanted in dict(schema='hepta.runtime.write-chain-kernel-process.v1', status='PASS', failure=None,
            binary_sha256=binary_sha, config=config, exit_code=0, actual_requests=len(config['steps'])).items():
        exact(report.get(key), wanted, 'write-chain actual kernel process differs: ' + key)
    duration(report['elapsed_seconds'], 'write-chain kernel process exceeded its deadline')
    names = ('requests.bin', 'stdout.bin', 'stderr.bin', 'normalized.bin')
    for name in names: exact(report[name], file_record(folder / name), 'write-chain complete kernel process bytes differ')
    incoming, cancels = requests(read(folder / 'requests.bin'))
    base = os.fsencode(report['fixture'])
    expected = [dict(tag=i + 1, op=step['op'], context=step.get('context', 1),
        path_hex=(base + b'/' + bytes.fromhex(step.get('path_hex', b'target'.hex()))).hex()) for i, step in enumerate(config['steps'])]
    exact(incoming, expected, 'write-chain complete kernel request domain differs')
    cancel_tag = config.get('cancel', {}).get('tag')
    if concurrent: cancel_tag = config['parallel'].get('cancel_tag')
    exact(cancels, [cancel_tag] if cancel_tag is not None else [], 'write-chain actual cancel input differs')
    outgoing, normalized = responses(read(folder / 'stdout.bin'), len(incoming), ordered=not concurrent)
    exact(outgoing, report['frames'], 'write-chain kernel report omitted actual returned bytes')
    exact(read(folder / 'normalized.bin'), normalized, 'write-chain kernel normalization changed more than TIDs')
    for response in outgoing:
        if response['code'] != 0xfffffff7:
            exact(struct.unpack_from('<Q', bytes.fromhex(response['output_hex']), 8)[0], incoming[response['tag'] - 1]['op'],
                  'write-chain kernel result belongs to another operation')
    events, raw = report['events'], report['raw_events']; require(events and raw, 'write-chain kernel trace is empty')
    roots = {row['pid'] for row in raw}; require(len(roots) == 1 and all(type(x) is int and x > 0 for x in roots), 'write-chain raw process identity differs')
    root_pid = next(iter(roots)); tree = report['verified_process_tree']
    for tid, identity in tree.items():
        require(str(int(tid)) == tid and (identity['tgid'] == root_pid or identity['ppid'] == root_pid), 'write-chain kernel process escaped the owned tree')
    controlled = {}
    for event in events:
        require(type(event['raw_index']) is int and 0 <= event['raw_index'] < len(raw), 'write-chain owner trace lost its original syscall')
        syscall = raw[event['raw_index']]
        for key in ('pid', 'tid', 'ip', 'args'): exact(event[key], syscall[key], 'write-chain normalized event detached from its raw syscall')
        exact({key: event[key] for key in ('tgid', 'ppid')}, tree[str(event['tid'])], 'write-chain owner trace identity differs')
        if 'control_index' in event:
            index = event['control_index']; require(index not in controlled, 'write-chain completion control executed twice'); controlled[index] = event
            control = event['control']
            exact(event['kind'], control['kind'], 'write-chain actual effect control kind differs')
            if control['type'] == 'fault':
                exact(syscall['completion'], dict(value=0, error=-control.get('errno', 0), flags=0, held=False), 'write-chain actual injected completion differs')
            else: exact(syscall['completion']['held'], True, 'write-chain cancellation did not hold a real syscall')
    controls = [dict(type='fault', **row) for row in config.get('faults', [])]
    if config.get('cancel'): controls.append(dict(type='cancel', **config['cancel']))
    if concurrent: controls.append(dict(type='hold', **config['parallel']['hold']))
    exact(set(controlled), set(range(len(controls))), 'write-chain required real kernel controls omitted')
    for index, control in enumerate(controls): exact(controlled[index]['control'], control, 'write-chain kernel control domain differs')
    from write_chain_supervisor import normalized as normalized_events
    exact(report['normalized_events'], normalized_events(events), 'write-chain syscall normalization changed its declared domain')
    exact(report['injected_completions'], len(config.get('faults', [])), 'write-chain injected effects mislabeled')
    exact(report['actual_kernel_effects'], len(events) - len(config.get('faults', [])), 'write-chain kernel effect count differs')
    if config.get('cancel'):
        held = controlled[len(controls) - 1]; cancel = config['cancel']; ack = report['cancel_ack']
        exact(ack['effect_still_held'], True, 'write-chain cancel was not observed against a held syscall')
        if cancel.get('synchronous'):
            exact(ack['no_early_response'], True, 'write-chain synchronous section was interrupted')
            exact(held['release_reason'], 'synchronous-section-must-finish', 'write-chain synchronous cancellation order differs')
            require(held['held_seconds'] >= 0.05, 'write-chain synchronous hold was shortened')
        else:
            exact(ack['code'], 0xfffffff7, 'write-chain actual cancellation did not finish')
            exact(held['release_reason'], 'completed-response-' + str(cancel['release_after_tag']), 'write-chain guard/drop completion order differs')
            exact(held['cancellation_ack_before_effect_release'], True, 'write-chain cancellation waited for the blocked I/O')
    if concurrent:
        held = controlled[len(controls) - 1]; parallel = config['parallel']; mode = parallel['mode']
        if mode == 'serialized':
            exact(held['release_reason'], 'all-other-callers-reached-held-lock', 'write-chain shared lock was not exercised')
            require(held['queued_key_completions'] >= 3 and held['held_seconds'] >= 0.05, 'write-chain simultaneous caller domain shortened')
        elif mode == 'queued-cancel':
            exact(held['release_reason'], 'canceled-waiter-removed-before-guard-release', 'write-chain concurrent cancel ordering differs')
            exact(held['queued_cancel_sent'], parallel['cancel_tag'], 'write-chain canceled another request')
            exact(held['queued_cancel_ack'], parallel['cancel_tag'], 'write-chain concurrent cancellation did not finish')
            require(held['held_seconds'] >= 0.10 and report['cancel_ack']['effect_still_held'] is True,
                    'write-chain canceled caller did not finish before releasing the held guard')
        else:
            exact(mode, 'cache-race', 'write-chain undefined concurrent domain')
            exact(held['release_reason'], 'other-cache-transition-complete', 'write-chain statx race did not reach the required order')
            exact(held['other_request_completed_before_release'], 2, 'write-chain late statx success race omitted')
            require(any(row['kind'] == 'path_statx' and row['admission_epoch'] == 3 for row in events)
                    and any(row['kind'] == 'fd_stat' and row['admission_epoch'] == 2 for row in events), 'write-chain actual shared cache transitions omitted')
    filesystem = filesystem_evidence(folder / 'filesystem.bin.gz', [report['final_files']], [len(incoming)])
    # The supervisor's final snapshot uses the total request ordinal, unlike
    # the serial suite's one snapshot after each request.
    if original_side:
        summary = obj(folder / 'stderr.bin')
        expected_canceled = sum(row['code'] == 0xfffffff7 for row in outgoing)
        exact(summary, dict(status='PASS', original_owner_calls=len(incoming), responses=len(incoming), canceled=expected_canceled),
              'write-chain actual original kernel owner summary differs')
    else: exact(read(folder / 'stderr.bin'), b'', 'write-chain native kernel process emitted diagnostics')
    return dict(result=file_record(folder / 'result.json'), captures={name: file_record(folder / name) for name in names},
        filesystem=dict(gzip=file_record(folder / 'filesystem.bin.gz'), raw=filesystem),
        requests=len(incoming), kernel_effects=report['actual_kernel_effects'], injected_completions=report['injected_completions'])


def kernel_evidence(folder, stdout, *, root=ROOT, original_sha=None, concurrent=False):
    folder, root = Path(folder), Path(root)
    if concurrent:
        from test_write_chain_concurrency import cases, by_tag
        name, schema, count, request_count = 'test_write_chain_concurrency.py', 'hepta.runtime.write-chain-concurrency.v1', 4, 34
    else:
        from test_write_chain_kernel import cases
        name, schema, count, request_count = 'test_write_chain_kernel.py', 'hepta.runtime.write-chain-kernel-comparison.v1', 53, 162
    domain = cases(); report = obj(folder / 'result.json')
    exact(len(domain), count, 'write-chain declared kernel domain differs')
    exact(json.loads(read(folder / 'cases.json')), domain, 'write-chain actual kernel case definitions differ')
    expected = dict(schema=schema, status='PASS' if original_sha else 'NATIVE_PASS', original_status='PASS' if original_sha else 'PENDING',
        native_sha256=build.ELF_SHA, original_sha256=original_sha, cases=count, declared_cases=count,
        native_processes=count, original_processes=count if original_sha else 0,
        native_requests=request_count, original_requests=request_count if original_sha else 0,
        sources={n: sha(read(root / 'tests/hia_native' / n)) for n in (name, 'write_chain_supervisor.py', 'test_write_chain_files.py')})
    for key, wanted in expected.items(): exact(report.get(key), wanted, 'write-chain complete kernel suite differs: ' + key)
    duration(report['elapsed_seconds'], 'write-chain kernel suite exceeded the original 180-second deadline')
    if concurrent:
        exact(report['concurrent_response_order_claimed'], False, 'write-chain invented a deterministic thread schedule')
        exact(report['public_session_dispatch_qualified'], False, 'write-chain internal caller overclaimed public dispatch')
    else:
        exact(report['exact_trace_comparisons'], 38 if original_sha else 0, 'write-chain complete original syscall trace domain omitted')
        exact(report['cancellation_partial_order_comparisons'], 15 if original_sha else 0, 'write-chain original cancellation domain omitted')
    exact(len(report['observations']), count, 'write-chain kernel observations omitted')
    observations = []
    from test_write_chain_files import equal_streams
    for index, (config, captured) in enumerate(zip(domain, report['observations'])):
        entry = folder / (('%02d-' if concurrent else '%03d-') % index + config['name'])
        native = kernel_process_evidence(entry / 'native', config, build.ELF_SHA, concurrent=concurrent)
        exact(captured['name'], config['name'], 'write-chain observation belongs to another case')
        exact(captured['native_result_sha256'], native['result']['sha256'], 'write-chain native kernel report changed')
        reference, compared = None, {}
        if original_sha:
            reference = kernel_process_evidence(entry / 'original', config, original_sha, original_side=True, concurrent=concurrent)
            exact(captured['original_result_sha256'], reference['result']['sha256'], 'write-chain original kernel report changed')
            n, r = obj(entry / 'native/result.json'), obj(entry / 'original/result.json')
            exact(captured['original_summary'], obj(entry / 'original/stderr.bin'), 'write-chain retained original summary differs from actual stderr')
            if concurrent:
                exact(by_tag(n), by_tag(r), 'write-chain complete original concurrent outcomes differ')
                exact(captured['tagged_response_bytes'], len(by_tag(n)), 'write-chain concurrent response bytes omitted')
                exact(captured['tagged_response_sha256'], sha(by_tag(n)), 'write-chain concurrent response digest differs')
            else:
                compared['normalized.bin'] = equal_streams(entry / 'native/normalized.bin', entry / 'original/normalized.bin')
                if 'cancel' not in config: exact(n['normalized_events'], r['normalized_events'], 'write-chain complete original syscall trace differs')
            compared['requests.bin'] = equal_streams(entry / 'native/requests.bin', entry / 'original/requests.bin')
            compared['filesystem.bin.gz'] = equal_streams(entry / 'native/filesystem.bin.gz', entry / 'original/filesystem.bin.gz', True)
            exact(n['final_files'], r['final_files'], 'write-chain complete original final state differs')
            if concurrent:
                exact(captured['filesystem'], compared['filesystem.bin.gz'], 'write-chain concurrent file comparison differs')
                exact(captured['requests'], compared['requests.bin'], 'write-chain concurrent request comparison differs')
            else: exact(captured['compared'], compared, 'write-chain kernel complete-byte comparisons differ')
        else:
            exact(captured['original_result_sha256'], None, 'write-chain native evidence contains an invented original invocation')
            exact(captured['original_summary'], None, 'write-chain native evidence contains an invented original result')
        observations.append(dict(name=config['name'], native=native, original=reference, compared=compared))
    return dict(result=file_record(folder / 'result.json'), cases=file_record(folder / 'cases.json'),
        stdout=process_stdout(stdout, {key: value for key, value in report.items() if key != 'observations'}),
        observations=observations, cases_completed=count, native_requests=request_count,
        original_requests=request_count if original_sha else 0)


def native_evidence(manifest, folder, stdout_dir, *, root=ROOT):
    manifest, folder, stdout_dir, root = Path(manifest), Path(folder), Path(stdout_dir), Path(root)
    before = pins(root); artifact = build.inspect_bundle(manifest, source_root=root)
    domains = dict(shared_atomic=shared_evidence(folder / 'shared', manifest, stdout_dir / 'test_shared_atomic.py.stdout', root),
        controller=controller_evidence(folder / 'controller', manifest, stdout_dir / 'test_write_chain_controller.py.stdout', root),
        files=files_evidence(folder / 'files', stdout_dir / 'test_write_chain_files.py.stdout', root=root),
        kernel=kernel_evidence(folder / 'kernel', stdout_dir / 'test_write_chain_kernel.py.stdout', root=root),
        concurrency=kernel_evidence(folder / 'concurrency', stdout_dir / 'test_write_chain_concurrency.py.stdout', root=root, concurrent=True))
    exact(pins(root), before, 'write-chain source closure changed during evidence inspection')
    return dict(schema='hepta.runtime.write-chain-native-evidence.v1', status='PASS', source_files=before,
        artifact=artifact, domains=domains, borrowed_controller_calls=214, borrowed_leaf_calls=302,
        shared_atomic_calls=45280, actual_elf_processes=58, actual_elf_requests=343,
        synthetic_filesystem_completions=31, synthetic_statx_transitions=7978,
        original_rust_execution='PENDING', production_activated=False, whole_runtime_replaced=False)


def controls_evidence(folder, native, stdout, *, root=ROOT):
    """Inspect the actual negative-control process; execute no semantic owner."""
    from test_write_chain_evidence import CONTROLS
    folder, root = Path(folder), Path(root)
    report = obj(folder / 'result.json')
    expected = dict(schema='hepta.runtime.write-chain-evidence-controls.v1', status='PASS',
        source_files=pins(root), native_evidence_sha256=sha(build.canonical(native)),
        accepted_controls=2, rejected_controls=len(CONTROLS), new_native_calls=0,
        new_original_calls=0, production_activated=False)
    exact(set(report), set(expected) | {'controls', 'elapsed_seconds'}, 'write-chain controls result shape differs')
    for key, value in expected.items(): exact(report.get(key), value, 'write-chain actual control evidence differs: ' + key)
    duration(report['elapsed_seconds'], 'write-chain evidence control process exceeded its deadline')
    exact(len(report['controls']), len(CONTROLS), 'write-chain control domain omitted')
    for row, (name, reason) in zip(report['controls'], CONTROLS):
        exact(set(row), {'name', 'status', 'error', 'changed_files'}, 'write-chain refusal result shape differs')
        exact(row['name'], name, 'write-chain control domain differs')
        exact(row['status'], 'REJECTED', 'write-chain required refusal was not observed')
        exact(row['error'], reason, 'write-chain control did not reach its declared guard')
        require(type(row['changed_files']) is dict and row['changed_files'], 'write-chain control did not alter actual retained files')
        for path, change in row['changed_files'].items():
            require(type(path) is str and not Path(path).is_absolute() and '..' not in Path(path).parts,
                    'write-chain control mutation escaped its private snapshot')
            exact(set(change), {'before', 'after'}, 'write-chain mutation identity is incomplete')
            require(change['before'] != change['after'], 'write-chain control mutation was empty')
            for record in change.values():
                require(set(record) == {'bytes', 'sha256'} and type(record['bytes']) is int and record['bytes'] >= 0
                        and type(record['sha256']) is str and len(bytes.fromhex(record['sha256'])) == 32,
                        'write-chain mutation file identity differs')
    summary = {key: value for key, value in report.items() if key not in ('source_files', 'controls')}
    summary['result'] = file_record(folder / 'result.json')
    return dict(schema='hepta.runtime.write-chain-controls-evidence.v1', status='PASS',
        result=file_record(folder / 'result.json'), stdout=process_stdout(stdout, summary),
        accepted_controls=2, rejected_controls=len(CONTROLS), new_native_calls=0, new_original_calls=0,
        retained_inspection_only=True)


def original_evidence(folder, manifest, native_corpus, native_stdout_dir, stdout, *, root=ROOT):
    """Recheck a completed original recipe; this function executes no owner."""
    folder, manifest, root = Path(folder), Path(manifest), Path(root)
    report = obj(folder / 'result.json')
    expected = dict(schema='hepta.runtime.write-chain-original-comparison.v1', status='PASS',
        source_files=pins(root), artifacts=build.inspect_bundle(manifest, source_root=root),
        native=native_evidence(manifest, native_corpus, native_stdout_dir, root=root),
        original_build_is_fresh=True, original_replay_is_fresh=True, outer_timeout_seconds=180,
        inherits_outer_process_group=True, original_processes=58, original_requests=343,
        exact_trace_comparisons=38, cancellation_partial_order_comparisons=15, concurrent_cases=4,
        full_file_observation_bytes_per_side=787555659, production_activated=False,
        whole_runtime_replaced=False, remote_sftp_closed=False)
    for key, wanted in expected.items(): exact(report.get(key), wanted, 'write-chain retained original recipe differs: ' + key)
    duration(report['elapsed_seconds'], 'write-chain original recipe exceeded the unchanged deadline')
    for key in ('source_root', 'directory', 'manifest', 'native_corpus', 'native_stdout_dir'):
        require(type(report[key]) is str and Path(report[key]).is_absolute(), 'write-chain original path identity missing')
    exact(report['project'], project_evidence(folder / 'project', root, recorded_root=report['source_root']),
          'write-chain actual compiled original project differs')
    from compare_write_chain_original import CLEARED, cleared
    tools = report['tools']; exact(set(tools), {'rustc', 'cargo', 'rustfmt'}, 'write-chain selected Rust tool set differs')
    for entry in [*tools.values(), report['python']]:
        require(set(entry) == {'path', 'resolved_path', 'bytes', 'sha256'}
                and all(type(entry[key]) is str and Path(entry[key]).is_absolute() for key in ('path', 'resolved_path'))
                and type(entry['bytes']) is int and entry['bytes'] > 0
                and type(entry['sha256']) is str and len(bytes.fromhex(entry['sha256'])) == 32,
                'write-chain retained compiler/interpreter identity is incomplete')
    actual_root, actual_output = Path(report['source_root']), Path(report['directory'])
    policy = report['environment_policy']
    exact(policy['cleared_names'], list(CLEARED), 'write-chain original compiler environment policy differs')
    exact(policy['clear_hia_prefix'], True, 'write-chain original inherited a development override')
    exact(policy['clear_target_rustflags'], True, 'write-chain original inherited a target flag override')
    require(type(policy['removed_names']) is list and policy['removed_names'] == sorted(set(policy['removed_names']))
            and all(type(name) is str and cleared(name) for name in policy['removed_names']), 'write-chain environment clearing record differs')
    exact(policy['selected'], dict(RUSTC=tools['rustc']['path'], CARGO_TARGET_DIR=str(actual_output / 'target'),
        TMPDIR=str(actual_output / 'tmp')), 'write-chain selected build environment differs')
    binary = report['original_binary']
    exact(binary['path'], str(actual_output / 'target/release/hia-write-chain-callers-original'), 'write-chain actual original binary path differs')
    exact({key: binary[key] for key in ('bytes', 'sha256')}, file_record(folder / 'target/release/hia-write-chain-callers-original'),
          'write-chain complete executed original binary changed')
    records = report['records']
    exact([row['name'] for row in records], ['rustc-version', 'format-check', 'cargo-build', 'files', 'kernel', 'concurrency'],
          'write-chain fresh original compilation/replay stages omitted')
    commands = {
        'rustc-version': [tools['rustc']['path'], '-Vv'],
        'format-check': [tools['rustfmt']['path'], '--edition', '2024', '--config-path',
            str(actual_root / 'rustfmt.toml'), '--check', str(actual_root / 'tests/hia_native/oracle_write_chain.rs')],
        'cargo-build': [tools['cargo']['path'], 'build', '--release', '--locked', '--manifest-path', str(actual_output / 'project/Cargo.toml')],
    }
    for name in ('files', 'kernel', 'concurrency'):
        commands[name] = [report['python']['path'], '-I', '-B', str(actual_root / 'tests/hia_native' / ('test_write_chain_' + name + '.py')),
            '--native', str(Path(report['manifest']).parent / 'write-chain.elf'), '--original', binary['path'],
            '--output', str(actual_output / name)] + (['--large'] if name == 'files' else [])
    require(type(report['outer_process_group']) is int and report['outer_process_group'] > 0,
            'write-chain original process group identity is missing')
    for row in records:
        command = commands[row['name']]
        if row['name'] == 'cargo-build' and row['command'][-1:] == ['--offline']: command += ['--offline']
        exact(row['command'], command, 'write-chain actual original command differs')
        exact(row['cwd'], str(actual_output / ('project' if row['name'] == 'cargo-build' else 'empty-cwd')), 'write-chain actual original working directory differs')
        for key, wanted in dict(exit_code=0, reaped=True, inherits_outer_process_group=True,
                outer_timeout_seconds=180, process_group=report['outer_process_group'], stdin=dict(bytes=0, sha256=sha(b''))).items():
            exact(row.get(key), wanted, 'write-chain original process did not complete in the owned group')
        require(type(row['pid']) is int and row['pid'] > 0, 'write-chain actual original process identity missing')
        duration(row['elapsed_seconds'], 'write-chain actual original child exceeded its deadline')
        for channel in ('stdout', 'stderr'):
            exact(row[channel], file_record(folder / (row['name'] + '.' + channel)), 'write-chain actual original process stream changed')
    version = read(folder / 'rustc-version.stdout')
    require(version.startswith(b'rustc 1.95.0 ') and b'release: 1.95.0\n' in version
            and b'commit-hash: 59807616e1fa2540724bfbac14d7976d7e4a3860\n' in version,
            'write-chain actual original compiler version differs')
    for name in ('rustc-version.stderr', 'format-check.stdout', 'format-check.stderr', 'files.stderr', 'kernel.stderr', 'concurrency.stderr'):
        exact(read(folder / name), b'', 'write-chain original qualification emitted unexpected diagnostics')
    comparisons = dict(files=files_evidence(folder / 'files', folder / 'files.stdout', root=root, original_sha=binary['sha256']),
        kernel=kernel_evidence(folder / 'kernel', folder / 'kernel.stdout', root=root, original_sha=binary['sha256']),
        concurrency=kernel_evidence(folder / 'concurrency', folder / 'concurrency.stdout', root=root, original_sha=binary['sha256'], concurrent=True))
    exact(report['comparisons'], comparisons, 'write-chain complete original comparisons changed')
    summary = {key: report[key] for key in ('status', 'original_processes', 'original_requests',
        'exact_trace_comparisons', 'cancellation_partial_order_comparisons', 'concurrent_cases',
        'full_file_observation_bytes_per_side', 'elapsed_seconds')}
    summary['result'] = file_record(folder / 'result.json')
    return dict(schema='hepta.runtime.write-chain-original-evidence.v1', status='PASS',
        result=file_record(folder / 'result.json'), stdout=process_stdout(stdout, summary),
        tools=tools, original_binary={key: binary[key] for key in ('bytes', 'sha256')},
        actual_project=report['project'], records=records, comparisons=comparisons,
        original_processes=58, original_requests=343, retained_inspection_only=True,
        new_native_calls=0, new_original_calls=0, production_activated=False, whole_runtime_replaced=False)
