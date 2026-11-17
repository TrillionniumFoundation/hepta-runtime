"""Actual HIA line verification, exact diagnostics and signed-index parity."""
from __future__ import annotations
import argparse
import copy
import gzip
import hashlib
import importlib.util
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


def hashed(raw):
    if isinstance(raw, str):
        raw = raw.encode()
    value = 2166136261
    for byte in raw:
        value = ((value ^ byte) * 16777619) & 0xffffffff
    value = (value >> 16) ^ (value & 0xffff)
    return f'{((value >> 8) ^ (value & 255)):02x}'


def varint(value):
    out = bytearray()
    while value >= 128:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)
    return bytes(out)


def packet(operation, number=0, total=0, expected='', lines=()):
    expected = expected.encode() if isinstance(expected, str) else expected
    payload = bytearray(expected)
    if operation == 1:
        total = 0
        for raw in lines:
            raw = raw.encode() if isinstance(raw, str) else raw
            payload.extend(varint(len(raw)))
            payload.extend(raw)
            total += 1
    return struct.pack('<8s7Q', b'HLINE001', operation, number & U64, total,
        len(expected), len(payload), 0, 0) + payload


def response(value=0, clamped=False, error=None):
    error_raw = b'' if error is None else error.encode()
    return struct.pack('<8s4Q', b'HLINER01', int(error is not None),
        value, int(clamped), len(error_raw)) + error_raw


def reference(operation, number=0, total=0, expected='', lines=()):
    if operation != 1:
        index = number if number < (1 << 63) else number - (1 << 64)
        if index == 0:
            return response(error='Line numbers are 1-indexed, use 1 for first line')
        if index > 0:
            if index <= total:
                return response(index)
            if operation == 3:
                return response(total, True)
            return response(error=f'Line {index} exceeds file length ({total} lines)')
        distance = U64 if index == -(1 << 63) else -index
        if distance <= total:
            return response(total - distance + 1)
        if operation == 3:
            return response(1, True)
        return response(error=f'Negative index {index} exceeds file length ({total} lines)')
    lines = [raw if isinstance(raw, str) else raw.decode() for raw in lines]
    total = len(lines)
    identifier = lambda n: f'{n}:{hashed(lines[n - 1])}'
    if 0 < number <= total and hashed(lines[number - 1]) == expected:
        return response(number)
    candidates = [n for n, raw in enumerate(lines, 1) if hashed(raw) == expected]
    candidates.sort(key=lambda n: abs(n - number))
    relocation = '' if not candidates else (
        f'Hash {expected} now matches ' + ', '.join(identifier(n) for n in candidates[:3])
        + ' (content moved, or hash paired with the wrong line).')
    if number == 0 or number > total:
        return response(error=f'Line id "{number}:{expected}" is out of range: the file has {total} lines.'
            + relocation + '\nRe-view the file for fresh ids.')
    first, last = max(1, number - 2), min(total, number + 2)
    error = f'Line id "{number}:{expected}" does not match: line {number} is now "{identifier(number)}". Current content:\n'
    error += ''.join(f'{identifier(n)}|{lines[n - 1]}\n' for n in range(first, last + 1))
    error += relocation + f'\nRetry with these ids, or view start={first} end={last} for more.'
    return response(error=error)


def cases():
    alphabet = ['', 'a', 'z', 'same', 'changed', '\r', '\r\n', 'a\nb', '\0', 'é', '😀', '\u2028', '"|\\']
    documents = [[], ['only'], ['first', 'CHANGED', 'third'],
        ['first', 'inserted', 'also inserted', 'target'],
        ['target', 'target', 'target', 'CHANGED', 'target', 'target', 'target'], alphabet]
    for lines in documents:
        for number in [0, 1, 2, 3, 4, 5, len(lines), len(lines) + 1, U64]:
            for expected in ['', '00', 'ff', 'AB', 'xx', '0', '000', '\n"', 'é', '😀', hashed('target'), hashed(''), hashed('same')]:
                yield 'context_and_relocation', packet(1, number, expected=expected, lines=lines), reference(1, number, expected=expected, lines=lines)
    lines = [str(index) for index in range(16)]
    for value in range(256):
        for number in [0, 1, 8, 16, 17, U64]:
            expected = f'{value:02x}'
            yield 'all_expected_hashes', packet(1, number, expected=expected, lines=lines), reference(1, number, expected=expected, lines=lines)
    target = hashed('target')
    collisions = [str(index) for index in range(10000) if hashed(str(index)) == target][:9]
    assert len(collisions) == 9
    for position in range(9):
        lines = list(collisions)
        lines[position] = 'CHANGED'
        assert hashed(lines[position]) != target
        yield 'stable_collision_order', packet(1, position + 1, expected=target, lines=lines), reference(1, position + 1, expected=target, lines=lines)
    for total in [0, 1, 2, 3, 9, 65536, (1 << 31) - 1, 1 << 32, (1 << 63) - 1, 1 << 63, U64 - 1, U64]:
        for index in [-(1 << 63), -(1 << 63) + 1, -(1 << 32), -65537, -65536, -10, -3, -2, -1,
                      0, 1, 2, 3, 9, 10, 65536, 65537, (1 << 31) - 1, 1 << 32, (1 << 63) - 1]:
            for operation in [2, 3]:
                yield 'full_lp64_index_domain', packet(operation, index, total), reference(operation, index, total)
    rng = random.Random(0x11DECAFE)
    for _ in range(1600):
        lines = [''.join(rng.choice(alphabet) for _ in range(rng.randrange(8))) for _ in range(rng.randrange(20))]
        number = rng.randrange(len(lines) + 4)
        expected = hashed(rng.choice(lines)) if lines and rng.randrange(4) else f'{rng.randrange(256):02x}'
        yield 'ordered_random', packet(1, number, expected=expected, lines=lines), reference(1, number, expected=expected, lines=lines)
    for raw in ['x' * size for size in [0, 1, 126, 127, 128, 129, 16383, 16384]]:
        for expected in [hashed(raw), 'unmatched']:
            yield 'line_encoding_boundaries', packet(1, 1, expected=expected, lines=[raw]), reference(1, 1, expected=expected, lines=[raw])


def large_cases():
    count = 5 << 20
    expected = hashed('')
    def empty_packet(number):
        data = expected.encode() + bytes(count)
        return struct.pack('<8s7Q', b'HLINE001', 1, number, count, 2, len(data), 0, 0) + data
    yield 'maximum_empty_lines', empty_packet(count), response(count)
    moved = ', '.join(f'{n}:{expected}' for n in [count, count - 1, count - 2])
    error = f'Line id "{U64}:{expected}" is out of range: the file has {count} lines.Hash {expected} now matches {moved} (content moved, or hash paired with the wrong line).\nRe-view the file for fresh ids.'
    yield 'maximum_empty_lines', empty_packet(U64), response(error=error)
    raw = '😀' * ((5 << 20) // 4)
    yield 'maximum_utf8_line', packet(1, 1, expected='unmatched', lines=[raw]), reference(1, 1, expected='unmatched', lines=[raw])


def invalid_frames():
    good = packet(1, 1, expected='ab', lines=['x'])
    for count in range(64):
        yield good[:count]
    yield b'BADLINE1' + good[8:]
    for offset, value in [(8, 0), (8, 4), (24, U64), (32, U64), (40, U64), (48, 1), (56, 1)]:
        raw = bytearray(good)
        struct.pack_into('<Q', raw, offset, value)
        yield bytes(raw)
    yield good + b'x'
    yield good[:-1]
    for invalid in [b'\xff', b'\xc0\xaf', b'\xed\xa0\x80', b'\xf4\x90\x80\x80', b'\xf0\x9f\x98']:
        yield packet(1, 1, expected=invalid, lines=['x'])
        yield packet(1, 1, expected='ab', lines=[invalid])
    for encoded in [b'\x80\x00', b'\x81\x00x', b'\x80', b'\xff' * 9 + b'\x02', b'\xff' * 9 + b'\x01', b'\x80' * 10 + b'\x00']:
        data = b'ab' + encoded
        yield struct.pack('<8s7Q', b'HLINE001', 1, 1, 1, 2, len(data), 0, 0) + data
    yield packet(2, 1, 2, expected='x')
    yield packet(3, 1, 2, expected='x')


def function_source(text, name):
    marker = 'fn ' + name + '('
    start = text.index(marker)
    start = text.rfind('\n', 0, start) + 1
    brace = text.index('{', start)
    at, depth = brace + 1, 1
    while depth:
        if text[at] == '{':
            depth += 1
        if text[at] == '}':
            depth -= 1
        at += 1
    return text[start:at]


def oracle_source(repo):
    original = (repo / 'src/utils/line_hash.rs').read_text()
    names = ['fnv1a_8', 'line_hash', 'line_id', 'line_id_at', 'verify_line_id', 'push_relocation',
             'resolve_line_index', 'resolve_line_index_clamped']
    return ('// Copyright 2026 Muvon Un Limited\n// SPDX-License-Identifier: Apache-2.0\n'
        + '\n\n'.join(function_source(original, name) for name in names) + '\n'
        + Path(__file__).with_name('line_verify_oracle_transport.rs').read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_composition(source, repo, hepta):
    sys.path.insert(0, str(hepta))
    from hepta.hia_agent_assembly import assemble_program
    proof = json.loads(source.with_name('line_verify_composition.json').read_bytes())
    assert proof['schema'] == 'hepta.runtime.line-verify-source-composition.v1'
    assert proof['source_sha256'] == sha(source)
    assert proof['original_runtime_commit'] == 'a0dcdda1991ec536d5e2d252c006a778993fa566'
    assert set(proof['original_sources']) == {'src/utils/line_hash.rs'}
    for name, record in proof['original_sources'].items():
        raw = (repo / name).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == record['sha256']
        assert hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == record['blob']
    actual = {fn['name']: fn for fn in assemble_program(source.read_bytes()).as_dict()['functions']}
    assert len(proof['imports']) == 1
    record = proof['imports'][0]
    assert record['path'] == 'native/text_budget.hepta'
    assert record['sha256'] == sha(repo / record['path'])
    original = {fn['name']: fn for fn in assemble_program((repo / record['path']).read_bytes()).as_dict()['functions']}
    relocation = record['function_relocation']
    assert set(relocation) == {'f2', 'f9', 'f14', 'f15', 'f16'}
    assert len(set(relocation.values())) == 5
    reverse = {new: old for old, new in relocation.items()}
    for old, new in relocation.items():
        fn = copy.deepcopy(actual[new])
        fn['name'] = old
        for block in fn['blocks']:
            for operation in block['ops']:
                if operation['op'] == 'call':
                    operation['attrs']['function'] = reverse[operation['attrs']['function']]
        assert fn == original[old]
        assert hashlib.sha256(json.dumps(original[old], sort_keys=True, separators=(',', ':')).encode()).hexdigest() == record['functions'][old]
    return len(relocation)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, default=os.environ.get('HIA_LINE_VERIFY_MANIFEST'))
    parser.add_argument('--source', type=Path, default=ROOT / 'native/line_verify.hepta')
    parser.add_argument('--repo', type=Path, default=ROOT)
    parser.add_argument('--loader', type=Path, default=ROOT / 'scripts/hia_native_loader.py')
    parser.add_argument('--hepta', type=Path, default=os.environ.get('HIA_HEPTA_DIR'))
    parser.add_argument('--corpus-dir', type=Path, default=os.environ.get('HIA_LINE_VERIFY_CORPUS_DIR'))
    parser.add_argument('--emit-oracle', type=Path)
    args = parser.parse_args()
    if args.emit_oracle:
        args.emit_oracle.write_text(oracle_source(args.repo))
        print(json.dumps({'oracle_sha256': sha(args.emit_oracle)}))
        return
    assert args.manifest and args.hepta
    imports = check_composition(args.source, args.repo, args.hepta)
    spec = importlib.util.spec_from_file_location('line_verify_loader', args.loader)
    loader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loader)
    metadata = json.loads(args.manifest.read_bytes())
    assert metadata['source_sha256'] == sha(args.source)
    counts = {}
    rows = 0
    request_stream = output_stream = None
    request_hash = hashlib.sha256()
    output_hash = hashlib.sha256()
    request_bytes = output_bytes = 0
    if args.corpus_dir:
        args.corpus_dir.mkdir(parents=True, exist_ok=False)
        request_stream = gzip.open(args.corpus_dir / 'requests.hex.gz', 'wb')
        output_stream = gzip.open(args.corpus_dir / 'native-output.txt.gz', 'wb')
    start = time.monotonic()
    with loader.NativeModule(args.manifest, manifest_sha256=sha(args.manifest)) as native:
        with native.session(output_capacity=8 << 20, workspace_capacity=192) as session:
            for generator in [cases, large_cases]:
                for kind, wire, wanted in generator():
                    actual = session.invoke(wire)
                    if actual != wanted:
                        raise AssertionError({'kind': kind, 'row': rows, 'wire': wire[:100].hex(),
                            'actual': actual[:1024].hex(), 'expected': wanted[:1024].hex()})
                    request_row = wire.hex().encode() + b'\n'
                    output_row = b'OK ' + actual.hex().encode() + b'\n'
                    request_hash.update(request_row)
                    output_hash.update(output_row)
                    request_bytes += len(request_row)
                    output_bytes += len(output_row)
                    if request_stream:
                        request_stream.write(request_row)
                        output_stream.write(output_row)
                    counts[kind] = counts.get(kind, 0) + 1
                    rows += 1
        for wire in invalid_frames():
            code, actual, _ = native.invoke_raw(wire, output_capacity=4096, workspace_capacity=192,
                output_fill=0xa5, workspace_fill=0x5a)
            assert code == 0xffffffff and actual == b'\xa5' * 4096, (code, wire[:100].hex())
            counts['invalid'] = counts.get('invalid', 0) + 1
        wire = packet(1, 3, expected=hashed('target'), lines=['target', 'target', 'CHANGED', 'target', 'target'])
        wanted = reference(1, 3, expected=hashed('target'), lines=['target', 'target', 'CHANGED', 'target', 'target'])
        for capacity, workspace in [(0, 192), (len(wanted) - 1, 192), (4096, 0), (4096, 191)]:
            code, actual, _ = native.invoke_raw(wire, output_capacity=capacity, workspace_capacity=workspace,
                output_fill=0xa5, workspace_fill=0x5a)
            assert code == 0xfffffffe and actual == b'\xa5' * capacity, (capacity, workspace, code)
            counts['capacity'] = counts.get('capacity', 0) + 1
        code, actual, _ = native.invoke_raw(wire, output_capacity=len(wanted), workspace_capacity=192,
            output_fill=0xa5, workspace_fill=0x5a)
        assert code == len(wanted) and actual == wanted
        counts['exact_output'] = 1
        executable = args.manifest.parent / metadata['standalone']['path']
        image = (args.manifest.parent / metadata['image']).read_bytes()
        from tools.generate_hia_native_filter import template
        prefix, hole = template(output_bytes=8 << 20, workspace_bytes=32 << 20)
        prefix = bytearray(prefix)
        for offset in (96, 104):
            prefix[offset:offset + 8] = (len(prefix) + len(image)).to_bytes(8, 'little')
        prefix[hole:hole + 4] = (len(prefix) - hole - 4).to_bytes(4, 'little')
        assert executable.read_bytes() == prefix + image
        counts['exact_elf_image_binding'] = 1
        for wire, wanted in [(wire, wanted), (packet(2, -(1 << 63), U64), response(1)),
                             (packet(3, -1, 0), response(1, True))]:
            completed = subprocess.run([str(executable)], input=wire, capture_output=True, timeout=10)
            assert completed.returncode == 0 and completed.stdout == wanted and completed.stderr == b''
            counts['standalone_elf'] = counts.get('standalone_elf', 0) + 1
        completed = subprocess.run([str(executable)], input=b'bad', capture_output=True, timeout=10)
        assert completed.returncode != 0 and completed.stdout == b''
        counts['standalone_invalid'] = 1
    if request_stream:
        request_stream.close()
        output_stream.close()
        oracle = oracle_source(args.repo)
        assert Path(__file__).with_name('oracle_line_verify.rs').read_text() == oracle
        corpus = {'schema': 'hepta.runtime.native-corpus.v1', 'component': 'line_verify', 'cases': rows,
            'counts': counts, 'source_sha256': sha(args.source), 'image_sha256': metadata['image_sha256'],
            'composition_sha256': sha(args.source.with_name('line_verify_composition.json')),
            'requests_file': 'requests.hex.gz', 'requests_bytes': request_bytes,
            'requests_sha256': request_hash.hexdigest(), 'native_output_file': 'native-output.txt.gz',
            'native_output_bytes': output_bytes, 'native_output_sha256': output_hash.hexdigest(),
            'original_line_hash_sha256': sha(args.repo / 'src/utils/line_hash.rs'),
            'oracle': 'tests/hia_native/oracle_line_verify.rs',
            'oracle_sha256': hashlib.sha256(oracle.encode()).hexdigest(),
            'imported_helper_functions': imports}
        (args.corpus_dir / 'native-corpus.json').write_text(json.dumps(corpus, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'status': 'passed', 'counts': counts, 'source_sha256': sha(args.source),
        'elapsed_seconds': time.monotonic() - start, 'captured_cases': rows, 'imported_helper_functions': imports,
        'test_sha256': sha(Path(__file__)), 'manifest_sha256': sha(args.manifest),
        'image_sha256': metadata['image_sha256'], 'loader_sha256': sha(args.loader),
        'oracle_sha256': sha(Path(__file__).with_name('oracle_line_verify.rs')),
        'composition_sha256': sha(args.source.with_name('line_verify_composition.json'))}, sort_keys=True))


if __name__ == '__main__':
    main()
