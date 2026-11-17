"""Native full body order and persistent state with explicit synthetic I/O."""
from __future__ import annotations
import argparse
import gzip
import importlib.util
import json
from pathlib import Path
import random
import struct
import sys
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
from batch_write_harness import NativeWorld, Q, frame, sha, CANCELED, INVALID, CAPACITY, STATE
import batch_render_reference as render


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def root_packet(plan, ops, path='file.txt', resolved=b'/fixture', context=1):
    raw = plan.packet(ops, path=path, mode=0)
    display = path.encode() if isinstance(path, str) else b''
    records = raw[80 + len(display):]
    actual = resolved if isinstance(path, str) else b''
    return frame(b'HFBWT001', [context, len(actual), len(display), len(ops), len(records),
                              int(isinstance(path, str)), 0], actual + display + records)


def planned_operations(data):
    count = struct.unpack_from('<Q', data, 16)[0]
    at, rows = 48, []
    for _ in range(count):
        index, kind, same, first, last, size = struct.unpack_from('<6Q', data, at)
        assert index == len(rows) and kind == same
        at += 48
        rows.append((kind, first, last, data[at:at + size]))
        at += size
    assert at == len(data)
    return rows


def response(kind, text):
    return frame(b'HFBWR001', [kind, len(text), 0], text)


def expected(plan, apply, raw, ops, path='file.txt'):
    admitted = plan.reference(ops, path=path, mode=0)
    if struct.unpack_from('<Q', admitted, 8)[0] == 1:
        return response(1, admitted[48:]), None
    before = apply.Editable(raw).normalized()
    planned = plan.reference(ops, [v.decode() for v in render.lines(before)], path)
    if struct.unpack_from('<Q', planned, 8)[0] == 1:
        return response(1, planned[48:]), None
    rows = planned_operations(planned)
    applied = apply.response(raw, rows, 2)
    if struct.unpack_from('<Q', applied, 8)[0] == 1:
        return response(1, applied[80:]), None
    normal, amount = struct.unpack_from('<QQ', applied, 48)
    after, written = applied[80:80 + normal], applied[80 + normal:80 + normal + amount]
    rendered = render.response(before, after, rows)
    return response(0, rendered[32:]), (before, after, written)


def cases(plan, apply):
    for path in (None, '', 'file.txt', '空间/\npath'):
        for count in (0, 1, 50, 51):
            yield 'early_admission', b'before', [None] * count, path
    raws = [b'', b'\n', b'a', b'a\n', b'a\r\n', b'\r\r\n', b'a\r\nb\nc\nlast',
            'α\nβ\n😀\n\x00\n'.encode()]
    contents = ['', 'x', '\n', 'x\n', '\r', '\r\n', 'x\r\r\ny\r', '😀\n漢\x00']
    for raw in raws:
        lines = render.lines(apply.Editable(raw).normalized())
        for content in contents:
            for anchor in (0, -1):
                yield 'original_endings', raw, [{'operation': 'insert', 'start': anchor, 'content': content}], 'file.txt'
            for start in range(1, len(lines) + 1):
                target = render.line_id(start, lines[start - 1]).decode()
                yield 'original_endings', raw, [{'operation': 'replace', 'start': target, 'content': content}], 'file.txt'
    for index, (domain, case) in enumerate(plan.random_cases()):
        if index >= 260: break
        raw = b'\n'.join(v.encode() for v in case['lines'])
        yield 'ordered_validation', raw, case['operations'], case['path']
    rng = random.Random(0x425752495445)
    for _ in range(400):
        raw = b'\n'.join(rng.choice([b'a', b'b', b'', b'\r', 'é😀'.encode()]) + str(i).encode()
                         for i in range(rng.randrange(1, 25)))
        if rng.randrange(2): raw += b'\n'
        if rng.randrange(2): raw = raw.replace(b'\n', b'\r\n')
        lines = render.lines(apply.Editable(raw).normalized())
        operations = []
        for _ in range(rng.randrange(1, 7)):
            kind = rng.choice(['replace', 'insert'])
            first = rng.randrange(1, len(lines) + 1)
            item = {'operation': kind, 'start': render.line_id(first, lines[first - 1]).decode(),
                    'content': rng.choice(contents)}
            if kind == 'replace' and rng.randrange(2):
                last = rng.randrange(first, len(lines) + 1)
                item['end'] = render.line_id(last, lines[last - 1]).decode()
            operations.append(item)
        yield 'resolved_conflict_apply', raw, operations, 'file.txt'
    raw = b''.join(f'old-{i}\r\n'.encode() for i in range(50))
    lines = render.lines(apply.Editable(raw).normalized())
    yield 'all_fifty', raw, [{'operation': 'replace', 'start': render.line_id(i + 1, line).decode(),
                             'content': f'changed-{i}'} for i, line in enumerate(lines)], 'file.txt'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--registry', type=Path, required=True)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--controller-source', type=Path)
    parser.add_argument('--profiles-dir', type=Path)
    parser.add_argument('--render-source', type=Path)
    args = parser.parse_args()
    reference = args.reference.resolve(strict=True)
    sys.path.insert(0, str(reference / 'tests/hia_native'))
    plan = load('_write_test_plan_reference', reference / 'tests/hia_native/test_batch_plan.py')
    apply = render.load_apply(reference)
    args.output.mkdir(exist_ok=False, parents=True)
    report = {'schema': 'hepta.runtime.batch-write-controller-observation.v1', 'status': 'RUNNING',
              'domains': {}, 'completed_cases': 0, 'actual_filesystem_effects': 0,
              'original_rust_body_replay': 'PENDING', 'controls': [], 'source_root': str(ROOT),
              'test_sha256': sha(Path(__file__).read_bytes()),
              'harness_sha256': sha((HERE / 'batch_write_harness.py').read_bytes())}
    trace = gzip.open(args.output / 'calls.jsonl.gz', 'xb', compresslevel=1)
    stream = gzip.open(args.output / 'cases.jsonl.gz', 'xb', compresslevel=1)
    def record(row): trace.write(json.dumps(row, sort_keys=True, separators=(',', ':')).encode() + b'\n')
    world = None
    started = time.monotonic()
    try:
        world = NativeWorld(args.registry, reference, ROOT, record, args.controller_source, args.profiles_dir, args.render_source)
        for domain, raw, operations, path in cases(plan, apply):
            want, success = expected(plan, apply, raw, operations, path)
            world.io = {'content': raw}; world.written = None
            wire = root_packet(plan, operations, path)
            code, actual, events, work = world.root(wire)
            assert actual == want and code == len(want), (domain, raw, operations, code, actual, want, events)
            if success:
                assert world.written == success[2]
                children = [row[1:] for row in events if row[0] == 'child']
                assert children == [(9, 0), (6, 1), (1, 1), (1, 3), (6, 2), (8, 1), (9, 1),
                                    (12, 2), (6, 1), (6, 2), (2, 1), (3, 1), (4, 1), (2, 1),
                                    (5, 1), (5, 3), (13, len(success[0])), (1, 5), (1, 6)], children
            else:
                assert world.written is None
            stream.write(json.dumps({'ordinal': report['completed_cases'], 'domain': domain,
                                     'raw_hex': raw.hex(), 'input_hex': wire.hex(), 'output_hex': actual.hex(),
                                     'written_hex': world.written.hex() if world.written is not None else None,
                                     'events': events}, sort_keys=True, separators=(',', ':')).encode() + b'\n')
            report['domains'][domain] = report['domains'].get(domain, 0) + 1
            report['completed_cases'] += 1
        ops = [{'operation': 'insert', 'start': 0, 'content': 'new'}]
        wire = root_packet(plan, ops)
        world.io = {'exists': 0}
        assert world.root(wire)[1] == response(1, b'File not found: file.txt')
        report['controls'].append('first_exists_missing')
        world.io = {'read_error': b"Failed to read '/fixture': injected"}
        assert world.root(wire)[1] == response(1, b"Failed to read file 'file.txt': Failed to read '/fixture': injected")
        report['controls'].append('first_read_error_wrapper')
        world.io = {'content': b'before', 'read_sequence': [b'before', (1, b'history read failure')]}
        assert world.root(wire)[1] == response(1, b'history read failure')
        report['controls'].append('second_read_error_unwrapped')
        for how in ('read_cancel', 'write_cancel', 'write_error'):
            world.io = {'content': b'before'}
            if how == 'read_cancel': world.io['read_sequence'] = [CANCELED]
            elif how == 'write_cancel': world.io['write_cancel'] = True
            else: world.io['write_error'] = b'rename injected'
            code, actual, events, work = world.root(wire)
            assert work.word(0) == 201 and work.read(8, work.size - 8) == bytes(work.size - 8)
            if how.endswith('cancel'): assert code == CANCELED and actual == b''
            else: assert actual == response(1, b"Atomic write failed for 'file.txt': rename injected")
            assert [event[1:] for event in events if event[0] == 'child'][-2:] == [(1, 5), (1, 6)]
            report['controls'].append(how + '_releases_guard')
        world.io = {'content': b'before', 'read_sequence': [b'before', b'fresh second snapshot']}
        assert world.root(wire)[1] == expected(plan, apply, b'before', ops)[0]
        popped = world.invoke(3, frame(b'HHISTQ01', [2, 0, len(world.key), 0, 0, 0, 0], world.key), world.history)[1]
        assert popped[64:] == b'fresh second snapshot'
        report['controls'].append('history_uses_fresh_second_read')
        before = b'a\r\r\n'
        old_normal = apply.Editable(before).normalized()
        world.invoke(5, frame(b'HVCACH01', [2, 0, len(world.key), len(old_normal.replace(b'\r\n', b'\n')), 0],
                              world.key + old_normal.replace(b'\r\n', b'\n')), world.cache)
        world.io = {'content': before}
        want, success = expected(plan, apply, before, ops)
        code, actual, events, work = world.root(wire)
        assert actual == want
        cached = world.invoke(5, frame(b'HVCACH01', [1, 0, len(world.key), 0, 0], world.key), world.cache)[1]
        assert cached[32:] == success[1].replace(b'\r\n', b'\n')
        assert (5, 1) in [e[1:] for e in events if e[0] == 'child']
        assert (5, 2) in [e[1:] for e in events if e[0] == 'child']
        report['controls'].append('separate_cache_get_set_with_second_normalize')
        before_cached = cached
        world.io = {'content': b'else'}
        _, actual, events, _ = world.root(root_packet(plan, ops, context=2))
        assert not any(e[0] == 'child' and e[1] == 5 for e in events)
        assert world.invoke(5, frame(b'HVCACH01', [1, 0, len(world.key), 0, 0], world.key), world.cache)[1] == before_cached
        assert sum(e[0] == 'canonical' for e in events) == 3
        report['controls'].append('no_context_still_computes_fresh_key')
        assert world.root(wire, cancel=1)[0] == CANCELED
        report['controls'].append('cancel_before_first_dispatch')
        for n in range(64):
            assert world.root(wire[:n])[0] == INVALID
        report['controls'].append('truncated_outer_frame_64_cases')
        assert world.root(wire, workspace=8191)[0] == CAPACITY
        report['controls'].append('short_workspace_no_output')
        report['status'] = 'PASS'
    except BaseException as error:
        report.update(status='FAIL', failure=repr(error))
        raise
    finally:
        trace.close(); stream.close()
        if world is not None: world.close()
        report['counts'] = world.counts if world is not None else None
        report['loaded_modules'] = world.loaded if world is not None else None
        report['elapsed_seconds'] = time.monotonic() - started
        for name in ('calls.jsonl.gz', 'cases.jsonl.gz'):
            report[name] = {'bytes': (args.output / name).stat().st_size, 'sha256': sha((args.output / name).read_bytes())}
        (args.output / 'result.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
