"""Native EditableContent parity; actual original Rust owns the final comparison."""
from __future__ import annotations
import argparse
import copy
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
RUNTIME = ROOT.parent / 'hepta-runtime'
U64 = (1 << 64) - 1


def parts(raw):
    start = 0
    for at, value in enumerate(raw):
        if value == 10:
            yield raw[start:at + 1]
            start = at + 1
    if start < len(raw):
        yield raw[start:]


def incoming(raw):
    return [line.removesuffix(b'\n').rstrip(b'\r') for line in parts(raw)]


class Editable:
    def __init__(self, raw):
        self.lines = []
        for line in parts(raw):
            if line.endswith(b'\r\n'):
                self.lines.append([line[:-2], b'\r\n'])
            elif line.endswith(b'\n'):
                self.lines.append([line[:-1], b'\n'])
            else:
                self.lines.append([line, b''])
        crlf = sum(end == b'\r\n' for _, end in self.lines)
        lf = sum(end == b'\n' for _, end in self.lines)
        self.dominant = b'\r\n' if crlf > lf else b'\n'
        self.had = raw.endswith(b'\n')

    def normalized(self):
        return b''.join(text + (b'\n' if end else b'') for text, end in self.lines)

    def rendered(self):
        return b''.join(text + end for text, end in self.lines)

    def new_lines(self, raw):
        return [[line[:-1], self.dominant] if line.endswith(b'\n') else [line, b''] for line in parts(raw)]

    def insert(self, position, trailing, raw):
        if position > len(self.lines):
            return f'Invalid internal insertion position {position}'
        new = [[line, self.dominant] for line in incoming(raw)]
        if not new:
            return None
        if position > 0 and self.lines[position - 1][1] == b'':
            self.lines[position - 1][1] = self.dominant
        if position == len(self.lines) and not trailing:
            new[-1][1] = b''
        self.lines[position:position] = new
        self.had = bool(trailing)
        return None

    def replace(self, start, end, replacement):
        content = self.normalized()
        boundary = lambda at: at == len(content) or content[at] & 192 != 128
        if start > end or end > len(content) or not boundary(start) or not boundary(end):
            return f'Invalid internal replacement range {start}..{end}'
        if not self.lines:
            self.lines = self.new_lines(replacement)
            return None
        last_offset = end - 1 if end > start else min(start, max(0, len(content) - 1))
        offset = 0
        start_line = end_line = None
        region_start = region_end = 0
        for index, (text, ending) in enumerate(self.lines):
            next_offset = offset + len(text) + bool(ending)
            if start_line is None and (start < next_offset or (start == len(content) and index + 1 == len(self.lines))):
                start_line = index
                region_start = offset
            if last_offset < next_offset:
                end_line = index
                region_end = next_offset
                break
            offset = next_offset
        if start_line is None:
            return 'Replacement start is out of bounds'
        if end_line is None:
            return 'Replacement end is out of bounds'
        changed = content[region_start:start] + replacement + content[end:region_end]
        suffix = self.lines[end_line + 1:]
        changed_lines = self.new_lines(changed)
        if changed and not changed.endswith(b'\n') and suffix:
            changed_tail = changed_lines.pop()
            suffix_head = suffix.pop(0)
            changed_lines.append([changed_tail[0] + suffix_head[0], self.dominant])
        self.lines = self.lines[:start_line] + changed_lines + suffix
        return None

    def preserve(self):
        if not self.lines:
            if self.had:
                self.lines.append([b'', self.dominant])
            return None
        for line in self.lines[:-1]:
            if not line[1]:
                line[1] = self.dominant
        if self.had:
            if not self.lines[-1][1]:
                self.lines[-1][1] = self.dominant
        elif self.lines[-1][0]:
            self.lines[-1][1] = b''
        return None


def packet(raw, operations=(), mode=0):
    if isinstance(raw, str):
        raw = raw.encode()
    out = struct.pack('<8s5Q', b'HEDIT001', mode, len(raw), len(operations), 0, 0) + raw
    for op, a, b, data in operations:
        if isinstance(data, str):
            data = data.encode()
        out += struct.pack('<4Q', op, a, b, len(data)) + data
    return out


def expected(raw, operations=(), mode=0):
    if isinstance(raw, str):
        raw = raw.encode()
    owner = Editable(raw)
    error = None
    done = 0
    for op, a, b, data in operations:
        if isinstance(data, str):
            data = data.encode()
        if op == 1:
            error = owner.insert(a, b, data)
        elif op == 2:
            error = owner.replace(a, b, data)
        else:
            error = owner.preserve()
        if error:
            break
        done += 1
    normalized, rendered = owner.normalized(), owner.rendered()
    body = rendered if mode == 0 else normalized
    message = error.encode() if error else b''
    return struct.pack('<8s9Q', b'HEDRES01', bool(error), done, len(owner.dominant),
        owner.had, len(owner.lines), len(normalized), len(rendered), len(body), len(message)) + body + message


def cases():
    texts = [b''.join(value) for size in range(4) for value in itertools.product([b'a', b'\r', b'\n'], repeat=size)]
    texts += [s.encode() for s in ['é😀', 'é\r\n漢\n', 'a\r\nb\nc', 'a\r\r\nb\n\n', 'a\x00b', '\U0010ffff\n']]
    contents = [b'', b'x', b'x\n', b'\r', b'\n', b'x\r\r\ny\r', 'é😀\n'.encode()]
    for raw in texts:
        owner = Editable(raw)
        for mode in range(2):
            yield 'roundtrip', packet(raw, mode=mode), expected(raw, mode=mode)
            for position in range(len(owner.lines) + 2):
                for trailing in range(2):
                    for content in contents:
                        ops = [(1, position, trailing, content), (3, 0, 0, b'')]
                        yield 'insert_preserve', packet(raw, ops, mode), expected(raw, ops, mode)
            normalized = owner.normalized()
            for start in range(len(normalized) + 2):
                for end in range(len(normalized) + 2):
                    content = contents[(start * 17 + end * 11) % len(contents)]
                    ops = [(2, start, end, content), (3, 0, 0, b'')]
                    yield 'replace_preserve', packet(raw, ops, mode), expected(raw, ops, mode)
            for a, b in [(U64, 0), (0, U64), (U64, U64)]:
                ops = [(2, a, b, b'x')]
                yield 'full_u64_error', packet(raw, ops, mode), expected(raw, ops, mode)
            ops = [(1, U64, 1, b'x')]
            yield 'full_u64_error', packet(raw, ops, mode), expected(raw, ops, mode)
    for raw in [b'', b'a', b'\n', b'a\r\n']:
        count = len(Editable(raw).lines)
        for initial in [b'\r', b'\n']:
            for second in [(1, count + 1, 0, b'x'), (1, count, 1, b'x'),
                           (2, len(Editable(raw).normalized()), len(Editable(raw).normalized()), b'x'),
                           (2, 0, 0, b'x'), (3, 0, 0, b'')]:
                ops = [(1, count, 0, initial), second, (3, 0, 0, b'')]
                for mode in range(2):
                    yield 'empty_unterminated_line', packet(raw, ops, mode), expected(raw, ops, mode)
    rng = random.Random(0x45444954)
    alphabet = ['a', 'b', 'é', '😀', '\r', '\n', '\x00', '漢']
    for _ in range(1400):
        raw = ''.join(rng.choice(alphabet) for _ in range(rng.randrange(30))).encode()
        model = Editable(raw)
        ops = []
        for __ in range(rng.randrange(1, 9)):
            op = rng.randrange(1, 4)
            data = ''.join(rng.choice(alphabet) for _ in range(rng.randrange(10))).encode()
            if op == 1:
                a, b = rng.randrange(len(model.lines) + 2), rng.randrange(2)
                error = model.insert(a, b, data)
            elif op == 2:
                length = len(model.normalized())
                a, b = sorted([rng.randrange(length + 2), rng.randrange(length + 2)])
                error = model.replace(a, b, data)
            else:
                a, b, data = 0, 0, b''
                error = model.preserve()
            ops.append((op, a, b, data))
            if error:
                break
        mode = rng.randrange(2)
        yield 'ordered_random', packet(raw, ops, mode), expected(raw, ops, mode)


def invalid_frames():
    good = packet(b'a', [(1, 0, 0, b'x')])
    for size in range(48):
        yield good[:size]
    yield b'BADEDIT1' + good[8:]
    yield packet(b'\xff')
    yield packet(b'a', [(1, 0, 0, b'\xc0\xaf')])
    yield packet(b'a', [(1, 0, 2, b'x')])
    yield packet(b'a', [(0, 0, 0, b'')])
    yield packet(b'a', [(4, 0, 0, b'')])
    yield packet(b'a', [(3, 1, 0, b'')])
    yield packet(b'a', [(3, 0, 1, b'')])
    yield packet(b'a', [(3, 0, 0, b'x')])
    yield good + b'\0'
    yield good[:-1]
    for offset in [8, 16, 24, 32, 40, 49 + 24]:
        value = bytearray(good)
        struct.pack_into('<Q', value, offset, U64)
        yield bytes(value)


def large_cases():
    # Closed-form expectations avoid retaining a second five-million-line vector.
    # The unchanged original Rust methods replay these complete same packets.
    limit = 5 << 20
    raw = b'\n' * limit
    ops = [(2, 0, 1, b'x\n'), (3, 0, 0, b'')]
    body = b'x' + raw
    out = struct.pack('<8s9Q', b'HEDRES01', 0, 2, 1, 1, limit,
        len(body), len(body), len(body), 0) + body
    yield 'full_file_domain', packet(raw, ops), out
    raw = b'A' * (limit - 4) + '😀'.encode()
    ops = [(2, limit - 4, limit, 'é\n'.encode()), (3, 0, 0, b'')]
    body = b'A' * (limit - 4) + 'é'.encode()
    out = struct.pack('<8s9Q', b'HEDRES01', 0, 2, 1, 0, 1,
        len(body), len(body), len(body), 0) + body
    yield 'full_file_domain', packet(raw, ops), out
    count = limit // 3
    raw = b'a\r\n' * count
    ops = [(1, 8192, 1, b'\r\nx\r\r\n'), (3, 0, 0, b'')]
    body = b'a\r\n' * 8192 + b'\r\nx\r\n' + b'a\r\n' * (count - 8192)
    out = struct.pack('<8s9Q', b'HEDRES01', 0, 2, 2, 1, count + 2,
        count * 2 + 3, len(body), len(body), 0) + body
    yield 'full_file_domain', packet(raw, ops), out


def oracle_source(repo):
    source = (repo / 'src/mcp/fs/text_editing.rs').read_text()
    start = source.index('const LF_ENDING:')
    stop = source.index('\nfn sanitize_incoming_content(', start)
    original = source[start:stop]
    return ('// Copyright 2026 Muvon Un Limited\n// SPDX-License-Identifier: Apache-2.0\n'
            'use anyhow::{anyhow, bail, Result};\n' + original
            + Path(__file__).with_name('editable_oracle_transport.rs').read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_source_composition(source, repo, hepta):
    sys.path.insert(0, str(hepta))
    from hepta.hia_agent_assembly import assemble_program
    proof = json.loads(source.with_name('editable_content_composition.json').read_bytes())
    assert proof['schema'] == 'hepta.runtime.editable-source-composition.v1'
    assert proof['source_sha256'] == sha(source)
    assert proof['original_runtime_commit'] == 'a0dcdda1991ec536d5e2d252c006a778993fa566'
    for name, record in proof['original_sources'].items():
        raw = (repo / name).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == record['sha256']
        assert hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == record['blob']
    assert set(proof['original_sources']) == {'src/mcp/fs/text_editing.rs'}
    actual = {fn['name']: fn for fn in assemble_program(source.read_bytes()).as_dict()['functions']}
    assert len(proof['imports']) == 1
    record = proof['imports'][0]
    assert record['path'] == 'native/text_budget.hepta'
    upstream = repo / record['path']
    assert record['sha256'] == sha(upstream)
    original = {fn['name']: fn for fn in assemble_program(upstream.read_bytes()).as_dict()['functions']}
    relocation = record['function_relocation']
    assert set(relocation) == {'f2', 'f14', 'f15', 'f16'}
    assert len(set(relocation.values())) == 4
    reverse = {new: old for old, new in relocation.items()}
    for old, new in relocation.items():
        fn = copy.deepcopy(actual[new])
        fn['name'] = old
        for block in fn['blocks']:
            for operation in block['ops']:
                if operation['op'] == 'call':
                    operation['attrs']['function'] = reverse[operation['attrs']['function']]
        assert fn == original[old]
        canonical = json.dumps(original[old], sort_keys=True, separators=(',', ':')).encode()
        assert hashlib.sha256(canonical).hexdigest() == record['functions'][old]
    return len(relocation)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, default=os.environ.get('HIA_EDITABLE_MANIFEST'))
    parser.add_argument('--source', type=Path, default=ROOT / 'native/editable_content.hepta')
    parser.add_argument('--loader', type=Path, default=RUNTIME / 'scripts/hia_native_loader.py')
    parser.add_argument('--repo', type=Path, default=RUNTIME)
    parser.add_argument('--corpus-dir', type=Path, default=os.environ.get('HIA_EDITABLE_CORPUS_DIR'))
    parser.add_argument('--hepta', type=Path, default=os.environ.get('HIA_HEPTA_DIR'))
    parser.add_argument('--rust-oracle', type=Path)
    parser.add_argument('--emit-oracle', type=Path)
    args = parser.parse_args()
    if args.emit_oracle:
        args.emit_oracle.write_text(oracle_source(args.repo))
        print(json.dumps({'oracle_sha256': sha(args.emit_oracle)}))
        return
    assert args.manifest
    assert args.hepta, '--hepta or HIA_HEPTA_DIR required for exact source composition validation'
    imported = check_source_composition(args.source, args.repo, args.hepta)
    start = time.monotonic()
    metadata = json.loads(args.manifest.read_bytes())
    assert metadata['source_sha256'] == sha(args.source)
    spec = importlib.util.spec_from_file_location('editable_native_loader', args.loader)
    loader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loader)
    counts = {}
    output = request = None
    if args.corpus_dir:
        args.corpus_dir.mkdir(parents=True, exist_ok=False)
        request = (args.corpus_dir / 'requests.hex').open('x')
        output = (args.corpus_dir / 'native-output.txt').open('x')
    with loader.NativeModule(args.manifest, manifest_sha256=sha(args.manifest)) as native:
        with native.session(output_capacity=65536, workspace_capacity=131072) as session:
            for index, (kind, wire, wanted) in enumerate(cases()):
                actual = session.invoke(wire)
                if request:
                    request.write(wire.hex() + '\n')
                    output.write('OK ' + actual.hex() + '\n')
                if actual != wanted:
                    raise AssertionError({'index': index, 'kind': kind, 'wire': wire.hex(), 'actual': actual.hex(), 'expected': wanted.hex()})
                counts[kind] = counts.get(kind, 0) + 1
        with native.session(output_capacity=8 << 20, workspace_capacity=32 << 20) as session:
            for kind, wire, wanted in large_cases():
                actual = session.invoke(wire)
                if request:
                    request.write(wire.hex() + '\n')
                    output.write('OK ' + actual.hex() + '\n')
                assert actual == wanted, (kind, hashlib.sha256(wire).hexdigest(),
                    hashlib.sha256(actual).hexdigest(), hashlib.sha256(wanted).hexdigest())
                counts[kind] = counts.get(kind, 0) + 1
        for wire in invalid_frames():
            code, actual, work = native.invoke_raw(wire, output_capacity=4096, workspace_capacity=4096, output_fill=0xa5, workspace_fill=0x5a)
            assert code == 0xffffffff and actual == b'\xa5' * 4096, (code, wire.hex())
            counts['invalid'] = counts.get('invalid', 0) + 1
        wire = packet(b'a\r\nb', [(1, 1, 1, b'x\r\n'), (3, 0, 0, b'')])
        wanted = expected(b'a\r\nb', [(1, 1, 1, b'x\r\n'), (3, 0, 0, b'')])
        for output_capacity, workspace_capacity in [(len(wanted) - 1, 4096), (0, 4096), (4096, 259), (4096, 260)]:
            code, actual, work = native.invoke_raw(wire, output_capacity=output_capacity, workspace_capacity=workspace_capacity, output_fill=0xa5, workspace_fill=0x5a)
            assert code == 0xfffffffe and actual == b'\xa5' * output_capacity, (code, output_capacity, workspace_capacity)
            counts['capacity'] = counts.get('capacity', 0) + 1
        code, actual, work = native.invoke_raw(wire, output_capacity=len(wanted), workspace_capacity=4096, output_fill=0xa5, workspace_fill=0x5a)
        assert code == len(wanted) and actual == wanted
        counts['exact_output'] = 1
        executable = args.manifest.parent / metadata['standalone']['path']
        from tools.generate_hia_native_filter import template
        prefix, hole = template(output_bytes=8 << 20, workspace_bytes=32 << 20)
        image = (args.manifest.parent / metadata['image']).read_bytes()
        prefix = bytearray(prefix)
        for offset in (96, 104):
            prefix[offset:offset + 8] = (len(prefix) + len(image)).to_bytes(8, 'little')
        prefix[hole:hole + 4] = (len(prefix) - hole - 4).to_bytes(4, 'little')
        assert executable.read_bytes() == prefix + image
        counts['exact_elf_image_binding'] = 1
        for raw, ops in [(b'a\r\nb', []), (b'\n', [(1, 1, 0, b'\r'), (2, 1, 1, b'x')]),
                         ('é😀'.encode(), [(2, 1, 2, b'x')])]:
            run = subprocess.run([str(executable)], input=packet(raw, ops), stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=10, env={'PATH': '/does-not-exist', 'LANG': 'C'})
            assert run.returncode == 0 and run.stderr == b'' and run.stdout == expected(raw, ops), (run.returncode, run.stdout, run.stderr)
            counts['standalone_elf'] = counts.get('standalone_elf', 0) + 1
        _, wire, wanted = next(large_cases())
        run = subprocess.run([str(executable)], input=wire, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=30, env={'PATH': '/does-not-exist', 'LANG': 'C'})
        assert run.returncode == 0 and run.stderr == b'' and run.stdout == wanted
        counts['standalone_elf'] += 1
    if request:
        request.close()
        output.close()
        oracle = Path(__file__).with_name('oracle_editable_content.rs')
        assert oracle.read_text() == oracle_source(args.repo)
        manifest = {'schema': 'hepta.runtime.native-corpus.v1', 'component': 'editable_content',
            'source_sha256': metadata['source_sha256'], 'image_sha256': metadata['image_sha256'],
            'cases': sum(value for key, value in counts.items() if key not in {'invalid', 'capacity', 'exact_output', 'standalone_elf', 'exact_elf_image_binding'}),
            'counts': counts, 'oracle': 'tests/hia_native/oracle_editable_content.rs', 'oracle_sha256': sha(oracle),
            'requests_file': 'requests.hex', 'requests_sha256': sha(args.corpus_dir / 'requests.hex'),
            'requests_bytes': (args.corpus_dir / 'requests.hex').stat().st_size,
            'native_output_file': 'native-output.txt', 'native_output_sha256': sha(args.corpus_dir / 'native-output.txt'),
            'native_output_bytes': (args.corpus_dir / 'native-output.txt').stat().st_size,
            'composition_sha256': sha(args.source.with_name('editable_content_composition.json')),
            'imported_helper_functions': imported,
            'original_text_editing_sha256': sha(args.repo / 'src/mcp/fs/text_editing.rs')}
        (args.corpus_dir / 'native-corpus.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    if args.rust_oracle:
        all_cases = list(itertools.chain(cases(), large_cases()))
        result = subprocess.run([str(args.rust_oracle)], input=''.join(wire.hex() + '\n' for _, wire, _ in all_cases).encode(),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=True)
        actual = result.stdout.decode().splitlines()
        wanted = ['OK ' + out.hex() for _, _, out in all_cases]
        assert actual == wanted, next(((index, a, b) for index, (a, b) in enumerate(zip(actual, wanted)) if a != b), ('length', len(actual), len(wanted)))
        counts['original_rust_cases'] = len(all_cases)
    print(json.dumps({'status': 'passed', 'counts': counts, 'source_sha256': metadata['source_sha256'],
        'imported_helper_functions': imported,
        'elapsed_seconds': time.monotonic() - start}, sort_keys=True))


if __name__ == '__main__':
    main()
