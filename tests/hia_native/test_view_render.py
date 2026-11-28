#!/usr/bin/env python3
"""Exact native view range/render decisions, with independent read snapshots.

This is a component qualification. It does not install a view MCP handler,
perform filesystem reads, or invent session-cache identity or eviction policy.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib.util
import itertools
import json
import os
from pathlib import Path
import random
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
U64 = (1 << 64) - 1
FILE_LIMIT = 5 << 20
RESULT_LIMIT = 8 << 20
CACHE_LIMIT = 1 << 20
AUTO = object()
DELTA = TEXT = None
COUNTS = {}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def packet(current='', *, start=None, end=None, first=AUTO, first_failed=False,
           first_stat=AUTO, current_stat=AUTO, previous=None, context=True,
           full=False, operation=2):
    encoded = lambda value: value.encode() if isinstance(value, str) else value
    current = encoded(current)
    ranged = start is not None or end is not None
    if first is AUTO:
        first = current if ranged and not first_failed else b''
    first = encoded(first)
    if first_stat is AUTO:
        first_stat = len(first) if ranged else None
    if current_stat is AUTO:
        current_stat = len(current)
    flags = ((start is not None) | ((end is not None) << 1) | (full << 2)
             | (context << 3) | ((previous is not None) << 4)
             | (first_failed << 5) | ((first_stat is not None) << 6))
    previous = b'' if previous is None else encoded(previous)
    return struct.pack('<8s11Q', b'HVIEW001', operation, flags,
                       (start or 0) & U64, (end or 0) & U64,
                       len(first), len(current), len(previous), first_stat or 0,
                       current_stat, 0, 0) + first + current + previous


def fields(wire):
    values = struct.unpack('<8s11Q', wire[:96])
    _, operation, flags, start, end, a, b, c, first_stat, current_stat, _, _ = values
    first = wire[96:96 + a].decode()
    current = wire[96 + a:96 + a + b].decode()
    previous = wire[96 + a + b:].decode()
    assert len(previous.encode()) == c
    signed = lambda value: value if value < 1 << 63 else value - (1 << 64)
    return operation, flags, signed(start), signed(end), first, current, previous, first_stat, current_stat


def reference(wire):
    operation, flags, start, end, first, current, previous, first_stat, current_stat = fields(wire)
    status = kind = ranged = begin = finish = first_count = current_count = normalized_size = hints = action = 0
    normalized = ''
    if flags & 3:
        if flags & 64 and first_stat > FILE_LIMIT:
            status, kind = 1, 5
        else:
            first_count = 0 if flags & 32 else len(DELTA.rust_lines(first))
            if first_count:
                left = start if flags & 1 else 1
                right = end if flags & 2 else -1
                if left == 0 or right == 0:
                    status, kind = 1, 6
                else:
                    def resolve(value):
                        position = value if value > 0 else first_count + value + 1
                        return max(1, min(first_count, position)), not 1 <= position <= first_count
                    begin, clamped1 = resolve(left)
                    finish, clamped2 = resolve(right)
                    ranged = 1
                    if begin > finish:
                        begin, finish = finish, begin
                        hints |= 1
                    if clamped1 or clamped2:
                        hints |= 2
    if status == 0:
        if current_stat > FILE_LIMIT:
            status, kind = 1, 5
        else:
            current_count = len(DELTA.rust_lines(current))
            normalized = current.replace('\r\n', '\n')
            normalized_size = len(normalized.encode())
            if ranged:
                kind = 4
            else:
                if flags & 8:
                    action = 1 if normalized_size <= CACHE_LIMIT else 2
                if flags & 24 == 24 and not flags & 4:
                    kind = 1 if previous == normalized else 2
    if not flags & 8 or status:
        hints = 0
    body = b''
    if operation == 2 and status == 0:
        if kind == 0:
            lines = DELTA.rust_lines(normalized)
            body = TEXT.render(lines, 1) if lines else b'[empty file, 0 lines]'
        elif kind == 1:
            body = f'[unchanged since you last viewed or edited it: {current_count} lines. Pass full: true to re-read.]'.encode()
        elif kind == 2:
            delta = DELTA.render(DELTA.rust_lines(previous), DELTA.rust_lines(normalized))
            if struct.unpack('<Q', delta[:8])[0]:
                body = delta[8:]
            else:
                kind = 3
                body = (b'[changed since your last view: too many changes for a delta, full content follows]\n'
                        + TEXT.render(DELTA.rust_lines(normalized), 1))
        elif kind == 4:
            body = TEXT.render(DELTA.rust_lines(current), 1, (begin, finish))
            if body.startswith(b'Start line'):
                status, hints = 1, 0
        if len(body) > RESULT_LIMIT:
            status, kind, hints = 1, 7, 0
            body = (f'Result is {len(body) / (1024 * 1024):.1f} MB, too large to return in one tool result (limit 8.0 MB). '
                    'Narrow `path`, `pattern` or `content`, or read the file in `start`/`end` ranges.').encode()
    if kind == 5:
        body = b'File is too large (>5MB)'
    if kind == 6:
        body = b'Invalid lines parameter: Line numbers are 1-indexed, use 1 for first line'
    body_size = len(body)
    if operation == 2 and status == 0 and hints:
        body += b'\n\n'
        if hints & 1:
            body += f'⚠️ start was after end, so the range was read as [{begin}, {finish}].\n'.encode()
        if hints & 2:
            body += (f'⚠️ Range clamped to [{begin}, {finish}]: the file has {first_count} lines '
                     '(negative indices count from the end).\n').encode()
    cached = normalized.encode() if action == 1 else b''
    return struct.pack('<8s15Q', b'HVIEWR01', status, len(body), action, len(cached),
                       ranged, begin, finish, first_count, current_count, hints, kind,
                       normalized_size, body_size, 0, 0) + body + cached


def unpack(raw):
    header = struct.unpack('<8s15Q', raw[:128])
    assert header[0] == b'HVIEWR01' and header[-2:] == (0, 0)
    assert len(raw) == 128 + header[2] + header[4]
    return header, raw[128:128 + header[2]], raw[128 + header[2]:]


def cases():
    texts = ['', '\n', '\r', '\r\n', '\r\r\n', '\n\n', 'a', 'a\n', 'a\r\n',
             'a\r\r\n', 'a\r\r\r\n', 'a\n\r', 'é\n漢\r\n😀', '\0\u2028\u0085\u2029', 'a\nb\nc\n']
    for current in texts:
        for context in [False, True]:
            for full in [False, True]:
                yield 'whole', packet(current, context=context, full=full)
        for previous in texts:
            yield 'cache_delta', packet(current, previous=previous)
            yield 'full_refresh', packet(current, previous=previous, full=True)
    for count in range(7):
        text = ''.join(f'row{i}\r\n' for i in range(count))
        endpoints = [None, -(1 << 63), -100, -7, -2, -1, 0, 1, 2, 7, 100, (1 << 63) - 1]
        for start, end in itertools.product(endpoints, repeat=2):
            yield 'endpoint_bounds', packet(text, start=start, end=end)
    for first in ['', 'a\nb\nc\n', '\n\n', 'a\r\r\n']:
        for current in ['', 'a', 'different\r\ntext\n', '\r\r\n', '1\n2\n3\n4\n5\n']:
            for start, end in [(1, None), (2, 3), (100, -100), (-1, 1), (0, 0)]:
                for failed in [False, True]:
                    yield 'separate_read_snapshots', packet(current, first='' if failed else first,
                        first_failed=failed, first_stat=None, start=start, end=end, previous='old\n')
    for first_stat in [None, 0, FILE_LIMIT - 1, FILE_LIMIT, FILE_LIMIT + 1, U64]:
        for current_stat in [0, FILE_LIMIT, FILE_LIMIT + 1, U64]:
            for start in [None, 0, 1]:
                yield 'metadata_order', packet('a\nb\n', first='x\ny\n' if start is not None else '',
                    start=start, first_stat=first_stat if start is not None else None,
                    current_stat=current_stat, previous='old')
    rng = random.Random(0x56494557)
    pool = ['a', 'b', 'é', '漢', '😀', '\n', '\r', '\r\n', '\0', '\u2028', '']
    for _ in range(900):
        first = ''.join(rng.choice(pool) for _ in range(rng.randrange(40)))
        current = ''.join(rng.choice(pool) for _ in range(rng.randrange(40)))
        previous = ''.join(rng.choice(pool) for _ in range(rng.randrange(40)))
        context = bool(rng.randrange(2))
        start, end = rng.choice([None, -20, -1, 0, 1, 20]), rng.choice([None, -20, -1, 0, 1, 20])
        ranged = start is not None or end is not None
        yield 'random_snapshots', packet(current, first=first if ranged else '', start=start, end=end,
            first_stat=None, previous=previous if context and rng.randrange(2) else None,
            full=bool(rng.randrange(2)), context=context)
    for count in [499, 500, 501]:
        for previous, current in [('', 'x\n' * count), ('x\n' * count, '')]:
            yield 'exact_myers_ceiling', packet(current, previous=previous)
    for current, previous in [('x\n' * 251, 'y\n' * 250), ('a\r\n', 'a\n'), ('a\r\r\n', 'a\r\n'),
                              ('a\n', 'a'), ('a', 'a\n'), ('', '\n'), ('\n', '')]:
        yield 'normalization_and_terminators', packet(current, previous=previous)


def boundary_cases():
    for size in [CACHE_LIMIT - 1, CACHE_LIMIT, CACHE_LIMIT + 1]:
        yield 'cache_byte_cap', packet('x' * size)
        yield 'cache_byte_cap_with_previous', packet('x' * size, previous='before')
    yield 'normalization_at_cache_cap', packet(('x\r\n' * (CACHE_LIMIT // 2)) + '\r\n')
    for size in [FILE_LIMIT - 1, FILE_LIMIT]:
        yield 'file_byte_cap', packet('é' * (size // 2) + 'x' * (size % 2))
    yield 'file_stat_refusal', packet('not read', current_stat=FILE_LIMIT + 1, previous='old')
    # At fixed line count the hash remains two characters, so one payload byte
    # changes the complete formatted body by exactly one byte.
    count = 760000
    digits = sum(len(str(i)) for i in range(1, count + 1))
    empty_size = digits + 5 * count - 1
    padding = RESULT_LIMIT - empty_size
    for adjustment in [-1, 0, 1]:
        text = 'x' * (padding + adjustment) + '\n' * count
        yield 'body_budget', packet(text)
        if adjustment == 1:
            yield 'cache_after_oversize', packet(text, previous=text)
        if adjustment == 0:
            yield 'hints_after_body_budget', packet(text, start=10000000, end=-10000000,
                                                   first='\n' * count)
    # Both independent read snapshots can reach the original 5 MiB limit.
    yield 'independent_large_snapshots', packet('y' * FILE_LIMIT, start=1, end=1,
        first='x' * FILE_LIMIT, previous='z' * CACHE_LIMIT)
    # 40 bytes per old/new line plus original lazy Myers snapshots exceed the
    # old 32 MiB transport profile but fit the explicit 256 MiB view workspace.
    yield 'maximum_line_workspace', packet('\n' * FILE_LIMIT, previous='\n' * CACHE_LIMIT)
    # A stat/read race may grow the first snapshot independently. The component
    # declares its own 16 MiB frame bound rather than pretending stat is a lock.
    yield 'declared_input_capacity', packet('x', start=1, first='\n' * ((16 << 20) - 97),
                                           first_stat=0, current_stat=1)


def invalid_frames():
    valid = packet('a\nb\n', start=1, end=-1)
    for size in range(96):
        yield valid[:size]
    yield b'BADVIEW1' + valid[8:]
    for offset, value in [(8, 0), (8, 3), (16, 128), (40, U64), (48, U64),
                          (56, U64), (80, 1), (88, 1)]:
        yield valid[:offset] + struct.pack('<Q', value) + valid[offset + 8:]
    yield valid + b'x'
    yield valid[:-1]
    yield packet('x', first='x')
    yield packet('x', first_stat=1)
    yield packet('x', first_failed=True)
    yield packet('x', previous='x', context=False)
    yield packet('x', start=1, first='x', first_failed=True)
    yield packet('x', previous=b'x' * (CACHE_LIMIT + 1))
    for bad in [b'\xff', b'\xc0\xaf', b'\xed\xa0\x80', b'\xf4\x90\x80\x80', b'\xf0\x9f\x98', b'\xc2a']:
        yield packet(bad)
        yield packet('x', first=bad, start=1)
        yield packet('x', previous=bad)
    for at, value in [(24, 1), (32, 1), (56, 1), (64, 1)]:
        plain = packet('x')
        yield plain[:at] + struct.pack('<Q', value) + plain[at + 8:]


def check_composition(repo, source, document, hepta):
    sys.path.insert(0, str(hepta))
    from hepta.hia_agent_assembly import assemble_program
    import copy
    assert document['source_sha256'] == sha(source.read_bytes())
    compiled = assemble_program(source.read_bytes()).as_dict()
    actual = {function['name']: function for function in compiled['functions']}
    for record in document['imports']:
        original_raw = (repo / record['path']).read_bytes()
        assert sha(original_raw) == record['sha256']
        originals = {f['name']: f for f in assemble_program(original_raw).as_dict()['functions']}
        reverse = {v: k for k, v in record['function_relocation'].items()}
        for old, new in record['function_relocation'].items():
            function = copy.deepcopy(actual[new])
            function['name'] = old
            for block in function['blocks']:
                for operation in block['ops']:
                    if operation['op'] == 'call':
                        operation['attrs']['function'] = reverse[operation['attrs']['function']]
            assert function == originals[old], (record['namespace'], old)
            canonical = json.dumps(originals[old], sort_keys=True, separators=(',', ':')).encode()
            assert sha(canonical) == record['functions'][old]
    for relative, identity in document['original_sources'].items():
        raw = (repo / relative).read_bytes()
        assert sha(raw) == identity['sha256']
        assert hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == identity['blob']
    return compiled


def main():
    global DELTA, TEXT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, default=os.environ.get('HIA_VIEW_MANIFEST'))
    parser.add_argument('--source', type=Path, default=ROOT / 'native/view_render.hepta')
    parser.add_argument('--composition', type=Path, default=ROOT / 'native/view_render_composition.json')
    parser.add_argument('--loader', type=Path, default=ROOT / 'scripts/hia_native_loader.py')
    parser.add_argument('--repo', type=Path, default=ROOT)
    parser.add_argument('--hepta', type=Path, default=os.environ.get('HIA_HEPTA_DIR'))
    parser.add_argument('--corpus-dir', type=Path, default=os.environ.get('HIA_VIEW_CORPUS_DIR'))
    parser.add_argument('--report', type=Path)
    parser.add_argument('--small-only', action='store_true', help='development only; omit complete byte-bound checks')
    args = parser.parse_args()
    if not args.manifest or not args.hepta:
        parser.error('the compiled manifest and pinned Hepta directory are required')
    started = time.monotonic()
    DELTA = load_module('original_delta_reference', args.repo / 'tests/hia_native/test_delta.py')
    TEXT = load_module('original_text_reference', args.repo / 'tests/hia_native/test_text_budget.py')
    loader = load_module('view_native_loader', args.loader)
    raw = args.manifest.read_bytes()
    metadata = json.loads(raw)
    assert metadata['source_sha256'] == sha(args.source.read_bytes())
    composition = json.loads(args.composition.read_bytes())
    document = check_composition(args.repo, args.source, composition, args.hepta)
    oracle_builder = load_module('view_original_oracle_source', Path(__file__).with_name('view_oracle_source.py'))
    oracle = Path(__file__).with_name('oracle_view_render.rs')
    assert oracle.read_bytes() == oracle_builder.oracle_source(args.repo).encode()
    corpus_requests = corpus_outputs = None
    if args.corpus_dir:
        args.corpus_dir.mkdir(parents=True, exist_ok=False)
        corpus_requests = gzip.open(args.corpus_dir / 'requests.hex.gz', 'wb')
        corpus_outputs = gzip.open(args.corpus_dir / 'native-output.txt.gz', 'wb')
    native_cases = 0
    examples = []
    def record(label, wire, actual):
        COUNTS[label] = COUNTS.get(label, 0) + 1
        if corpus_requests:
            corpus_requests.write(wire.hex().encode() + b'\n')
            corpus_outputs.write(b'OK ' + actual.hex().encode() + b'\n')

    with loader.NativeModule(args.manifest, manifest_sha256=sha(raw)) as module:
        with module.session(output_capacity=1 << 20, workspace_capacity=8 << 20) as session:
            for label, wire in cases():
                expected = reference(wire)
                actual = session.invoke(wire)
                assert actual == expected, (label, fields(wire), unpack(actual), unpack(expected))
                record(label, wire, actual)
                native_cases += 1
                if len(examples) < 3 or label == 'exact_myers_ceiling':
                    examples.append((wire, actual))
                if native_cases % 7 == 0:
                    prepared = wire[:8] + struct.pack('<Q', 1) + wire[16:]
                    value = session.invoke(prepared)
                    assert value == reference(prepared), (label, 'prepare')
                    record('prepare', prepared, value)
        if not args.small_only:
            assert metadata.get('buffer_profile') == 'view-render.v1'
            assert (metadata['input_capacity'], metadata['output_capacity'], metadata['workspace_capacity']) == (
                16 << 20, 16 << 20, 256 << 20)
            with module.session() as session:
                for label, wire in boundary_cases():
                    expected = reference(wire)
                    actual = session.invoke(wire)
                    assert actual == expected, (label, sha(actual), sha(expected))
                    record(label, wire, actual)
                    native_cases += 1
                    prepared = wire[:8] + struct.pack('<Q', 1) + wire[16:]
                    value = session.invoke(prepared)
                    assert value == reference(prepared), (label, 'prepare')
                    record('prepare', prepared, value)
                    if label in {'body_budget', 'cache_after_oversize'}:
                        header, text, cached = unpack(actual)
                        assert header[3] == 1 and cached
                        if header[11] == 7:
                            assert header[1] == 1 and text.startswith(b'Result is ')
                    if label == 'hints_after_body_budget':
                        header, _, _ = unpack(actual)
                        assert header[13] == RESULT_LIMIT and header[2] > RESULT_LIMIT and header[1] == 0
            maximum = packet('\n' * FILE_LIMIT, previous='\n' * CACHE_LIMIT)
            code, output, _ = module.invoke_raw(maximum, output_capacity=512,
                workspace_capacity=32 << 20, output_fill=0xA7)
            assert code == 0xFFFFFFFE and output == bytes([0xA7]) * 512
            COUNTS['workspace_refusal_is_not_semantic_none'] = 1
        for wire in invalid_frames():
            code, output, _ = module.invoke_raw(wire, output_capacity=128, workspace_capacity=512,
                                               output_fill=0xA7, workspace_fill=0xBD)
            assert code == U64 & 0xffffffff and output == bytes([0xA7]) * 128, (len(wire), code)
            COUNTS['invalid_abi'] = COUNTS.get('invalid_abi', 0) + 1
        capacity_wire = packet('first\nsecond\n', previous='before\nsecond\n')
        expected = reference(capacity_wire)
        for output_size, workspace_size in [(0, 8 << 20), (127, 8 << 20), (len(expected) - 1, 8 << 20),
                                            (len(expected), 0), (len(expected), 287), (len(expected), 288)]:
            code, output, _ = module.invoke_raw(capacity_wire, output_capacity=output_size,
                                               workspace_capacity=workspace_size, output_fill=0xA7)
            assert code == 0xFFFFFFFE and output == bytes([0xA7]) * output_size, (output_size, workspace_size, code)
            COUNTS['capacity'] = COUNTS.get('capacity', 0) + 1
        assert module.invoke(capacity_wire, output_capacity=len(expected), workspace_capacity=8 << 20) == expected
        COUNTS['exact_output_capacity'] = 1
    if not args.small_only:
        standalone = metadata['standalone']
        executable = args.manifest.parent / standalone['path']
        assert sha(executable.read_bytes()) == standalone['sha256']
        assert standalone['runtime_python_required'] is False and standalone['runtime_libc_required'] is False
        standalone_wires = [packet('a\r\r\n'),
            packet('y' * FILE_LIMIT, start=1, end=1, first='x' * FILE_LIMIT),
            next(wire for label, wire in boundary_cases() if label == 'hints_after_body_budget')]
        for wire in standalone_wires:
            actual = subprocess.run([str(executable)], input=wire, capture_output=True,
                env={'PATH': '/no-runtime-interpreter'}, timeout=60)
            assert actual.returncode == 0 and actual.stderr == b'' and actual.stdout == reference(wire)
            COUNTS['standalone_elf'] = COUNTS.get('standalone_elf', 0) + 1
        too_large = packet('x', start=1, first='\n' * ((16 << 20) - 96), first_stat=0)
        actual = subprocess.run([str(executable)], input=too_large, capture_output=True,
            env={'PATH': '/no-runtime-interpreter'}, timeout=60)
        assert actual.returncode == 3 and actual.stdout == actual.stderr == b''
        COUNTS['standalone_frame_capacity'] = 1
    if corpus_requests:
        corpus_requests.close()
        corpus_outputs.close()
        def digest_gzip(path):
            digest, count = hashlib.sha256(), 0
            with gzip.open(path, 'rb') as handle:
                while chunk := handle.read(1 << 20):
                    digest.update(chunk)
                    count += len(chunk)
            return digest.hexdigest(), count
        request_sha, request_bytes = digest_gzip(args.corpus_dir / 'requests.hex.gz')
        output_sha, output_bytes = digest_gzip(args.corpus_dir / 'native-output.txt.gz')
        info = {'schema': 'hepta.runtime.view-render-native-corpus.v1',
                'cases': native_cases + COUNTS.get('prepare', 0),
                'requests_file': 'requests.hex.gz', 'native_output_file': 'native-output.txt.gz',
                'requests_sha256': request_sha, 'requests_bytes': request_bytes,
                'native_output_sha256': output_sha, 'native_output_bytes': output_bytes,
                'source_sha256': sha(args.source.read_bytes()), 'manifest_sha256': sha(raw),
                'image_sha256': metadata['image_sha256'], 'oracle_sha256': sha(oracle.read_bytes())}
        (args.corpus_dir / 'native-corpus.json').write_text(json.dumps(info, sort_keys=True, indent=2) + '\n')
    result = {'status': 'PASS', 'scope': 'typed view range/render/cache plan only',
              'whole_view_migrated': False, 'seconds': time.monotonic() - started,
              'complete_byte_bounds': not args.small_only,
              'counts': COUNTS, 'source_sha256': sha(args.source.read_bytes()),
              'composition_sha256': sha(args.composition.read_bytes()),
              'manifest_sha256': sha(raw), 'image_sha256': metadata['image_sha256'],
              'test_sha256': sha(Path(__file__).read_bytes()), 'oracle_sha256': sha(oracle.read_bytes()),
              'functions': len(document['functions'])}
    if args.report:
        args.report.write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
