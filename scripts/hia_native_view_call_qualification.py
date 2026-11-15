"""Read complete view evidence; native execution and fresh Rust parity are separate.

The reader never invokes an owner, interprets HIA, or generates view output.
It binds retained borrowed buffers and actual ELF streams to the frozen images,
then the separate original recipe compares full bytes with fresh original Rust.
All paths in the returned artifact map are relative to the qualification output.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import contextlib
import gzip
import hashlib
import importlib.util
import io
import json
import math
import os
from pathlib import Path
import stat
import struct
import sys
import tempfile

ORACLE_OUTPUT_FOLDER = 'view-call-original'
ORIGINAL_CHECK = 'view_call_original'
TESTS = ('test_view_call_read.py', 'test_view_call_params.py',
         'test_view_call_sync.py', 'test_view_call_wide.py')
MAX = (1 << 64) - 1
INVALID, CAPACITY, GROW, PENDING, CANCEL_WAIT, CANCELLED = (
    0xffffffff, 0xfffffffe, 0xffffffd0, 0xfffffff0, 0xffffffef, 0xffffffcf)
MEMBERS = (('view-call', 'view_call'), ('view-read', 'view_read'),
           ('view-endpoint', 'line_endpoint'), ('view-key', 'file_lock_key'),
           ('view-scope', 'request_scope_lifecycle'), ('view-lease', 'request_cache_lease'),
           ('view-cache', 'view_cache'), ('view-render', 'view_render'),
           ('view-context', 'request_context'), ('view-error', 'view_error'),
           ('view-raw-regex', 'view_regex'), ('view-regex-syntax', 'regex_syntax'),
           ('view-regex-hir', 'regex_hir'), ('view-regex-nfa', 'regex_nfa'),
           ('view-regex-match', 'regex_match'), ('view-regex-data', 'regex_unicode_data'),
           ('view-regex-diagnostic', 'view_regex_diagnostic'))
SLOTS = [0, 1, 1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
EVENTS = {1: 'exists', 2: 'is_dir', 3: 'is_file', 4: 'metadata', 5: 'read'}
READER_FIELDS = ('generation', 'operation', 'outcome', 'errno', 'mode',
                 'metadata_size', 'snapshot_offset', 'snapshot_length', 'read_attempts')


def require(condition, message):
    if not condition:
        raise ValueError('view qualification: ' + message)


def integer(value, label, minimum=0, maximum=MAX):
    require(type(value) is int and minimum <= value <= maximum, label + ' must be an integer in range')
    return value


def duration(value, deadline, label):
    require(type(value) in (int, float) and math.isfinite(value) and 0 < value < deadline,
            label + ' elapsed time is not within the actual deadline')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode() + b'\n'


def same(left, right, label):
    require(canonical(left) == canonical(right), label + ' differs (including JSON types)')


def json_value(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON key ' + key)
            result[key] = value
        return result
    def constant(value):
        raise ValueError('view qualification: non-finite JSON ' + value)
    def floating(value):
        result = float(value)
        require(math.isfinite(result), 'non-finite JSON numeric exponent')
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant, parse_float=floating)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError('view qualification: malformed UTF-8 JSON') from error


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(path):
    result = hashlib.sha256(); size = 0
    with Path(path).open('rb') as stream:
        while block := stream.read(1 << 20):
            result.update(block); size += len(block)
    return dict(bytes=size, sha256=result.hexdigest())


def inside(root, name):
    require(type(name) is str and name != '', 'empty/non-string artifact path')
    path = Path(name)
    path = path if path.is_absolute() else root / path
    require('..' not in path.parts, 'parent traversal in artifact path')
    for part in (path, *path.parents):
        require(not part.is_symlink(), 'symlink in artifact path')
    path = path.resolve()
    require(path.is_relative_to(root.resolve()), 'artifact escapes its declared directory: ' + name)
    return path


def load_module(name, path):
    spec = importlib.util.spec_from_file_location('_view_evidence_' + name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def exact_read(stream, size):
    integer(size, 'binary span size')
    raw = stream.read(size)
    require(len(raw) == size, 'truncated binary span')
    return raw


def frame(stream):
    return exact_read(stream, struct.unpack('<Q', exact_read(stream, 8))[0])


def eof(stream):
    require(stream.read(1) == b'', 'unexpected trailing binary bytes')


class Evidence:
    def __init__(self, root, output):
        self.root, self.output = Path(root).resolve(), Path(output).resolve()
        self.artifacts, self.sources = {}, {}
        self.old_roots = []
        self.bootstraps = {}

    def path(self, name, base=None):
        return inside(base or self.output, str(name))

    def file(self, path):
        path = self.path(path)
        require(path.is_file(), 'missing artifact: ' + str(path))
        value = pin(path); self.artifacts[str(path.relative_to(self.output))] = value['sha256']
        return value

    def raw(self, path):
        self.file(path); return Path(path).read_bytes()

    def json(self, path):
        return json_value(self.raw(path))

    def rows(self, path):
        raw = self.raw(path)
        require(raw.endswith(b'\n'), 'JSONL lacks final LF')
        return [json_value(row) for row in raw.split(b'\n')[:-1]]

    def zipped(self, folder, name, expected=None):
        path = self.path(name, folder); compressed = self.file(path)
        with gzip.open(path, 'rb') as stream:
            raw = stream.read()
        if expected is not None:
            same({key: expected[key] for key in ('compressed_bytes', 'compressed_sha256')},
                 dict(compressed_bytes=compressed['bytes'], compressed_sha256=compressed['sha256']),
                 'compressed stream identity')
            same(dict(bytes=len(raw), sha256=digest(raw)),
                 {key: expected[key] for key in ('bytes', 'sha256')}, 'complete decompressed stream identity')
        return raw

    def source(self, relative):
        path = inside(self.root, relative); require(path.is_file(), 'missing source ' + relative)
        value = pin(path); self.sources[relative] = value['sha256']; return value

    def rebase(self, recorded):
        require(type(recorded) is str and Path(recorded).is_absolute(), 'recorded path is not absolute')
        path = Path(recorded)
        for old, new in sorted(self.old_roots, key=lambda pair: len(pair[0].parts), reverse=True):
            if path.is_relative_to(old):
                return inside(new, str(path.relative_to(old)))
        raise ValueError('view qualification: recorded path has no verified execution root: ' + recorded)

    def pins(self, recorded):
        require(type(recorded) is dict and recorded, 'empty execution source pins')
        for name, value in recorded.items():
            path = self.rebase(name)
            actual = self.source(str(path.relative_to(self.root))) if path.is_relative_to(self.root) else self.file(path)
            if type(value) is str:
                require(actual['sha256'] == value, 'executed source/image hash changed: ' + name)
            else:
                same(actual, value, 'executed source/image identity ' + name)


def _check(evidence, report, name, summary, script_relative, *, deadline=180):
    checks = [row for row in report.get('checks', []) if row.get('name') == name]
    require(len(checks) == 1, 'expected exactly one actual check ' + name)
    check = checks[0]; command = check.get('command')
    require(type(command) is list and len(command) == 4 and all(type(x) is str for x in command), 'check command shape')
    require(Path(command[0]).is_absolute() and command[1:3] == ['-I', '-B'], 'check did not execute isolated Python')
    suffix = Path(script_relative)
    recorded = Path(command[3]); require(recorded.is_absolute() and recorded.parts[-len(suffix.parts):] == suffix.parts,
                                        'check executed another test')
    old_root = recorded
    for _ in suffix.parts: old_root = old_root.parent
    if (old_root, evidence.root) not in evidence.old_roots: evidence.old_roots.append((old_root, evidence.root))
    same(check.get('exit_code'), 0, 'check exit')
    require(check.get('timed_out') is False, 'check timeout or missing timeout observation')
    require(check.get('start_error') is None, 'check failed to start')
    same(check.get('timeout_seconds'), deadline, 'check deadline')
    duration(check.get('elapsed_seconds'), deadline, 'check')
    directory = evidence.path(report.get('check_artifact_directories', {}).get(name, '.'))
    for extension in ('stdout', 'stderr'):
        raw = evidence.raw(directory / (name + '.' + extension))
        same(len(raw), check.get(extension + '_bytes'), 'check full ' + extension + ' length')
        require(digest(raw) == check.get(extension + '_sha256'), 'check full ' + extension + ' SHA')
        if extension == 'stdout': same(json_value(raw), summary, 'actual test stdout')
    same(check.get('summary'), summary, 'recorded parsed test summary')
    evidence.source(script_relative)
    return check


def _module(evidence, manifest_path, source, *, expected=None):
    metadata = evidence.json(manifest_path)
    require(metadata.get('schema') == 'hepta.runtime.native-module.v1' and
            metadata.get('target') == 'linux-x86_64' and
            metadata.get('abi') == 'hepta.runtime.borrowed-bytes.linux-x86_64.v1', 'native module ABI')
    require(metadata.get('compiler_commit') == 'd3e2c90173cf733e42b299d0c4274df4b593a12f', 'unqualified compiler commit')
    build = manifest_path.parent.parent.parent
    if build not in evidence.bootstraps:
        bootstrap = evidence.json(build / 'bootstrap/bootstrap.json')
        require(bootstrap.get('schema') == 'hepta.runtime.native-bootstrap.v1' and
                bootstrap.get('qualification') == 'development_fixed_point' and
                bootstrap.get('matching_source_cold_qualified') is False, 'bootstrap scope')
        require(bootstrap['dependency']['commit'] == 'd3e2c90173cf733e42b299d0c4274df4b593a12f' and
                bootstrap['dependency']['tree'] == '8d8b0fb8d015fb7edab302498bb9ed4c74ab6f49', 'bootstrap dependency identity')
        require(bootstrap['compiler_source_sha256'] == '388b182e42675f11435867dd99520e9452a4ff48e23c0766a3952b662acc7627',
                'bootstrap compiler source identity')
        generation = bootstrap['generation_sha256']
        require(generation == 'bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0', 'bootstrap compiler image identity')
        for label in ('B1', 'B2', 'B3'):
            require(evidence.file(build / 'bootstrap' / (label + '.image.bin'))['sha256'] == generation, 'bootstrap fixed point bytes')
        evidence.bootstraps[build] = bootstrap
    require(metadata.get('compiler_sha256') == evidence.bootstraps[build]['generation_sha256'], 'child compiled by a different compiler')
    profiles = {'standard': (8388608, 8388608, 33554432),
                'history.v1': (134217728, 134217728, 268435456),
                'serde-json.v1': (16777216, 67108864, 268435456)}
    profile = metadata.get('buffer_profile', 'standard')
    require(profile in profiles, 'native buffer profile')
    same(tuple(metadata.get(key) for key in ('input_capacity', 'output_capacity', 'workspace_capacity')),
         profiles[profile], 'native carrier capacities')
    for field in ('source', 'image'):
        path = evidence.path(metadata[field], manifest_path.parent)
        require(evidence.file(path)['sha256'] == metadata[field + '_sha256'], 'module ' + field + ' identity')
    require(evidence.source(source)['sha256'] == metadata['source_sha256'], 'compiled source differs from repository')
    if expected is not None:
        for key in ('source_sha256', 'image_sha256'):
            require(expected[key] == metadata[key], 'fixture member ' + key)
        require(expected['manifest_sha256'] == evidence.file(manifest_path)['sha256'], 'fixture member manifest')
    image = evidence.raw(evidence.path(metadata['image'], manifest_path.parent))
    _producer(evidence, manifest_path.parent, metadata, image, evidence.bootstraps[build])
    return metadata, image


def _producer(evidence, folder, metadata, image, bootstrap):
    request = evidence.json(folder / 'module.request.json')
    receipt = evidence.json(folder / 'module.receipt.json')
    build = evidence.json(folder / 'build.json')
    same(build['compile_receipt'], receipt, 'actual compile receipt/build binding')
    same(build['compiler_dependency'], bootstrap['dependency'], 'compile dependency/bootstrap binding')
    require(build.get('whole_runtime_replaced') is False, 'compile scope inflated')
    source = evidence.raw(folder / 'module.input.bin'); output = evidence.raw(folder / 'module.output.bin')
    require(digest(source) == metadata['source_sha256'] and output == image + b'\xa5' * (len(output) - len(image)),
            'actual compiler complete input/output differs from admitted source/image')
    require(request.get('format') == receipt.get('format') == 'flat-x86-64' and
            request.get('image_sha256') == receipt.get('artifact_sha256') == receipt.get('image_sha256') == metadata['compiler_sha256'],
            'actual producer compiler identity')
    require(request.get('source_sha256') == receipt.get('input_sha256') == receipt.get('source_sha256') == digest(source),
            'actual producer source identity')
    same(request.get('capacity'), len(output), 'compile borrowed output capacity')
    same(request.get('workspace_fill'), 0, 'compile initial workspace')
    same(receipt.get('input_bytes'), len(source), 'compile input extent')
    for key in ('core_u32', 'result_u64', 'produced_bytes'): same(receipt.get(key), len(image), 'compile ' + key)
    require(receipt.get('produced_sha256') == digest(image) and receipt.get('output_sha256') == digest(output), 'compile full output/image hashes')
    require(receipt.get('source_unchanged') is True and receipt.get('status') == 'returned' and
            receipt.get('return_encoding') == 'zero-extended-u32', 'compile execution result')
    same(receipt.get('abi_status'), 0, 'compile ABI status'); same(receipt.get('forbidden_compiler_modules_loaded'), [], 'host compiler fallback')
    same(receipt['limits']['output_capacity'], len(output), 'compile limit/output extent')
    same(receipt['limits']['workspace_bytes'], request['workspace_size'], 'compile workspace limit')
    old_folder = Path(request['source']).parent
    require(Path(request['source']).is_absolute() and Path(request['source']).name == 'module.input.bin' and
            Path(request['output']) == old_folder / 'module.output.bin' and
            Path(receipt['produced_image']) == old_folder / 'module.image.bin' and
            Path(request['image']) == old_folder.parent.parent / 'bootstrap/B3.image.bin', 'compile producer paths')
    stdout = json_value(evidence.raw(folder / 'module.stdout.log'))
    for key, value in stdout.items(): same(receipt.get(key), value, 'complete compiler stdout/receipt')
    require(evidence.raw(folder / 'module.stderr.log') == b'', 'compiler stderr')


def _builds(evidence, descriptor):
    require(type(descriptor) is dict and set(descriptor) == {
        'manifest', 'read_fixture_manifest', 'params_manifest', 'value_manifest', 'corpora'}, 'view descriptor fields')
    paths = {key: evidence.path(descriptor[key]) for key in (
        'manifest', 'read_fixture_manifest', 'params_manifest', 'value_manifest')}
    caller = evidence.json(paths['manifest']); build = paths['manifest'].parent.parent
    require(caller.get('schema') == 'hepta.runtime.view-call-build.v1', 'caller manifest schema')
    same(caller.get('slot_image_indices'), SLOTS, 'closed caller slot table')
    same(len(caller.get('members', [])), 17, 'caller image count')
    same(len(caller.get('image_offsets', [])), 17, 'caller image offsets')
    elf_path = evidence.path(caller['elf'], paths['manifest'].parent); elf = evidence.raw(elf_path)
    require(digest(elf) == caller['elf_sha256'], 'caller ELF identity')
    proof = json_value((evidence.root / 'native/view_call_adapter.json').read_bytes())
    evidence.source('native/view_call_adapter.json')
    same(caller['sources'], proof['sources'], 'boundary source set')
    for source, sha in caller['sources'].items(): require(evidence.source(source)['sha256'] == sha, 'boundary source changed')
    for key in ('prefix_bytes', 'prefix_sha256', 'table_offset'): same(caller[key], proof[key], 'boundary ' + key)
    size, table = integer(caller['prefix_bytes'], 'prefix bytes', 176), integer(caller['table_offset'], 'slot offset', 176)
    require(table + 152 <= size <= len(elf), 'prefix/slot containment')
    prefix = bytearray(elf[:size]); require(struct.unpack_from('<2Q', prefix, 96) == (len(elf), len(elf)), 'ELF extent')
    prefix[96:112] = bytes(16); prefix[table:table + 152] = bytes(152)
    require(digest(prefix) == proof['prefix_sha256'], 'actual ELF prefix/source proof')
    end = size; images = []
    for (name, source), member, offset in zip(MEMBERS, caller['members'], caller['image_offsets']):
        same(member['name'], name, 'member order'); same(member['source'], 'native/' + source + '.hepta', 'member source')
        metadata, image = _module(evidence, evidence.path(member['manifest'], build), member['source'], expected=member)
        integer(offset, 'image offset'); padded = end + (-end) % 16
        require(offset == padded and elf[end:offset] == bytes(offset - end), 'image alignment/padding')
        require(elf[offset:offset + len(image)] == image, 'actual ELF embedded HIA image')
        end = offset + len(image); images.append(image)
    require(end == len(elf), 'trailing caller ELF payload')
    same(list(struct.unpack_from('<19Q', elf, table)), [0x400000 + caller['image_offsets'][i] for i in SLOTS], 'actual ELF slot addresses')
    packer = evidence.path(caller['packer_manifest'], build)
    require(evidence.file(packer)['sha256'] == caller['packer_manifest_sha256'], 'caller packer manifest')
    _module(evidence, packer, 'native/view_call_packer.hepta')
    read = evidence.json(paths['read_fixture_manifest']); read_build = paths['read_fixture_manifest'].parent.parent
    require(read.get('schema') == 'hepta.runtime.view-read-build.v1', 'read fixture schema')
    owner = evidence.path(read['owner_manifest'], read_build)
    owner_meta, read_image = _module(evidence, owner, 'native/view_read.hepta', expected={
        'source_sha256': read['owner_source_sha256'], 'image_sha256': read['owner_image_sha256'],
        'manifest_sha256': read['owner_manifest_sha256']})
    require(read_image == images[1], 'standalone and caller read images differ')
    read_packer = evidence.path(read['packer_manifest'], read_build)
    require(evidence.file(read_packer)['sha256'] == read['packer_manifest_sha256'], 'read packer manifest')
    _module(evidence, read_packer, 'native/view_read_packer.hepta')
    require(evidence.source('scripts/view_read_adapter.S')['sha256'] == read['adapter_source_sha256'], 'read adapter source')
    read_elf_path = evidence.path(read['elf'], paths['read_fixture_manifest'].parent); read_elf = evidence.raw(read_elf_path)
    require(digest(read_elf) == read['elf_sha256'], 'read ELF hash')
    offset, hole = integer(read['image_offset'], 'read image offset', 176), integer(read['call_displacement_offset'], 'read call hole', 176)
    require(read_elf[offset:] == read_image and hole + 4 <= offset, 'actual read image and call bounds')
    require(read_elf[hole - 1:hole] == b'\xe8' and struct.unpack_from('<i', read_elf, hole)[0] == offset - hole - 4, 'actual read call target')
    require(struct.unpack_from('<2Q', read_elf, 96) == (len(read_elf), len(read_elf)), 'read ELF extent')
    for manifest in (caller, read):
        require(manifest['fixed_total_read_limit'] is None, 'invented whole-read quota')
        for key in ('whole_view_replaced', 'whole_runtime_replaced', 'public_mcp_route_replaced'):
            require(manifest[key] is False, 'fixture scope inflated')
    _module(evidence, paths['params_manifest'], 'native/view_params.hepta')
    _module(evidence, paths['value_manifest'], 'native/serde_json.hepta')
    for source in ('scripts/hia_native_view_call_build.py', 'scripts/hia_native_view_read_build.py',
                   'scripts/hia_native_loader.py', 'tests/hia_native/test_view_call_support.py'):
        evidence.source(source)
    return dict(paths=paths, caller_elf=elf_path, read_elf=read_elf_path, read_owner=owner)


def _reader_result(raw, *, private=False):
    require(len(raw) >= 80 and raw[:8] == b'HVRDR001', 'reader response magic/length')
    result = dict(zip(READER_FIELDS, struct.unpack_from('<9Q', raw, 8)))
    require(result['generation'] > 0 and result['operation'] in ((1, 2, 4) if private else (1, 2)), 'reader generation/operation')
    if result['operation'] == 4: require(result['outcome'] == 5, 'DROP operation/outcome')
    require(result['outcome'] in (range(6) if private else range(4)) and result['errno'] <= 4095,
            'reader outcome/errno')
    require(len(raw) == 80 + result['snapshot_length'], 'complete reader snapshot extent')
    if result['operation'] != 2 or result['outcome'] != 0:
        require(result['snapshot_offset'] == result['snapshot_length'] == 0, 'failed/stat reader leaked snapshot')
    else:
        require(result['snapshot_offset'] >= 8192, 'snapshot outside owned arena')
        raw[80:].decode('utf-8')
    return result


def _event(raw, ack, previous_sequence, generation, cancel):
    require(len(raw) >= 64 and raw[:8] == b'HVCLIO01', 'logical I/O frame')
    gen, seq, kind, slot, code, size, zero = struct.unpack_from('<7Q', raw, 8)
    require(gen > 0 and (generation is None or gen == generation), 'logical generation changed')
    require(seq > previous_sequence and kind in range(1, 7) and zero == 0 and size == len(raw) - 64,
            'logical sequence/kind/extent')
    if kind == 6: require(slot == 0 and code in (0, 1), 'render gate slot/status')
    else: require(slot in ((2, 3) if kind == 5 else (1,)) and code == 80, 'logical child slot/return')
    expected = struct.pack('<8s3Q', b'HVCLACK1', gen, seq, 1 if cancel and kind == 6 else 0)
    require(ack == expected, 'ACK generation/sequence/action does not acknowledge this event')
    return dict(generation=gen, sequence=seq, kind=kind, child_slot=slot, child_return=code), raw[64:]


def _receipt(raw):
    require(len(raw) == 128 and raw[:8] == b'HVRDACK1', 'kernel receipt length/magic')
    seq, gen, kind, a, b, c, d, actual, normalized, errno, mode, size, before, after, done = struct.unpack_from('<15Q', raw, 8)
    require(seq == done > 0 and gen > 0 and kind in (1, 2, 3, 4), 'kernel receipt sequence/generation/kind')
    signed = actual if actual < 1 << 63 else actual - (1 << 64)
    require(signed >= -4095, 'invalid raw syscall result')
    require(errno == (-signed if signed < 0 else 0), 'raw syscall errno differs')
    require(normalized == (actual if signed < 0 or kind == 3 else 0), 'normalized syscall result differs')
    if signed < 0: require(mode == size == 0, 'failed syscall retained metadata')
    if kind == 1:
        require(a == 4096 and c == 1024 and d == 144 and before == after == MAX, 'stat argument/descriptor ownership')
        require(signed <= 0, 'stat returned positive result')
    elif kind == 2:
        require(a == 4096 and c == os.O_CLOEXEC and d == 0 and before == MAX, 'open argument/descriptor ownership')
        require(after == (actual if signed >= 0 else MAX), 'opened descriptor not installed exactly once')
    elif kind == 3:
        require(a == 0 and c == 65536 and d == 0 and before == after != MAX and signed <= 65536,
                'read window/descriptor ownership')
        require(mode == size == 0 and b >= 8192, 'read receipt metadata/snapshot offset')
    else:
        require(a == b == c == d == 0 and before != MAX and after == MAX and signed <= 0,
                'close must retire its descriptor before completion')
    return dict(sequence=seq, generation=gen, kind=kind, a=a, b=b, c=c, d=d,
                result=signed, normalized=normalized, errno=errno, mode=mode, size=size, before=before, after=after)


def _kernel(raw, logical):
    require(len(raw) % 128 == 0, 'truncated kernel receipt')
    rows = []; key_sequence = 0; counts = dict(reader_effects=0, key_effects=0,
        stat_attempts=0, open_attempts=0, read_attempts=0, close_attempts=0, read_bytes=0)
    for at in range(0, len(raw), 128):
        part = raw[at:at + 128]
        if part[:8] == b'HFLKEYFX':
            seq, kind, a, b, c, d, value, errno, mode, dev, ino, complete, r0, r1, r2 = struct.unpack_from('<15Q', part, 8)
            require(seq == 1 or seq == key_sequence + 1, 'canonical-key effect sequence')
            require(kind in range(1, 14) and errno <= 4095 and complete == 1 and r0 == r1 == r2 == 0,
                    'canonical-key completion fields')
            if errno: require(value == mode == dev == ino == 0, 'canonical-key failed completion payload')
            key_sequence = seq; counts['key_effects'] += 1; continue
        row = _receipt(part); rows.append(row); counts['reader_effects'] += 1
        counts[{1: 'stat_attempts', 2: 'open_attempts', 3: 'read_attempts', 4: 'close_attempts'}[row['kind']]] += 1
        if row['kind'] == 3: counts['read_bytes'] += max(0, row['result'])
    at = 0; sequences = defaultdict(int); generations = defaultdict(int)
    for slot, result, path_len in logical:
        gen = result['generation']; require(gen == generations[slot] + 1, 'reader slot generation reuse/skip')
        generations[slot] = gen
        if result['outcome'] == 2:
            require(result['read_attempts'] == 0, 'NUL rejection performed a read'); continue
        owned = MAX
        def take(kind):
            nonlocal at, owned
            require(at < len(rows), 'logical I/O lacks actual syscall receipt')
            row = rows[at]; at += 1
            require(row['kind'] == kind and row['generation'] == gen, 'kernel effect/logical operation mismatch')
            require(row['sequence'] == sequences[slot] + 1 and row['before'] == owned,
                    'per-slot kernel sequence or retained FD changed')
            sequences[slot] = row['sequence']; owned = row['after']; return row
        if result['operation'] == 1:
            row = take(1); require(row['b'] == path_len, 'stat path extent differs')
            same((result['outcome'], result['errno'], result['mode'], result['metadata_size']),
                 (1 if row['errno'] else 0, row['errno'], row['mode'], row['size']), 'stat completion/result')
            require(result['read_attempts'] == 0, 'stat has read attempts')
        else:
            opened = take(2); require(opened['b'] == path_len, 'open path extent differs')
            attempts = total = 0; error = opened['errno']
            if not error:
                while True:
                    row = take(3); attempts += 1
                    require(row['b'] == 8192 + total, 'read append offset skips/duplicates bytes')
                    if row['result'] > 0: total += row['result']; continue
                    if row['errno'] == 4: continue
                    error = row['errno']; break
                take(4)
            require(result['read_attempts'] == attempts and owned == MAX, 'read attempt count/descriptor retirement')
            if error: same((result['outcome'], result['errno']), (1, error), 'read errno result')
            else:
                require(result['outcome'] in (0, 3) and result['errno'] == 0, 'read EOF UTF-8 outcome')
                require(result['snapshot_length'] == (total if result['outcome'] == 0 else 0), 'read snapshot/actual byte count')
    require(at == len(rows), 'unaccounted actual reader syscall receipts')
    return counts


def _process(evidence, folder, row, elf, timeout):
    require(type(row.get('command')) is list and len(row['command']) == 2 and row['command'][1] == '--sync', 'actual ELF command')
    require(evidence.rebase(row['command'][0]) == elf, 'actual ELF command not the qualified image')
    same(row.get('timeout_seconds'), timeout, 'ELF deadline'); duration(row.get('elapsed_seconds'), timeout, 'ELF')
    same(row.get('exit_code'), 0, 'ELF exit')
    for key in ('timed_out', 'forced_termination'): require(row.get(key) is False, 'ELF ' + key)
    require(row.get('capture_error') is None and row.get('stderr_capture_complete') is True, 'incomplete ELF capture')
    require(evidence.rebase(row['cwd']).is_relative_to(folder), 'ELF fixture working directory')
    raw = {}
    require(set(row['streams']) == {'input', 'stdout', 'stderr'}, 'missing actual ELF stream')
    for key, value in row['streams'].items(): raw[key] = evidence.zipped(folder, value['path'], value)
    standalone = evidence.json(folder / (row['name'] + '.process.json'))
    same(standalone, {k: v for k, v in row.items() if k != 'observed_kernel_receipts'}, 'independent process receipt file')
    return raw


def _control(stdin, stdout, operation, value, payload=b''):
    expected = struct.pack('<8s3Q', b'HVCFIX01', operation, value, len(payload)) + payload
    require(frame(stdin) == expected, 'actual fixture control input differs')
    result = frame(stdout)
    require(len(result) >= 32 and result[:8] == b'HVCFXR01', 'fixture control response')
    require(struct.unpack_from('<3Q', result, 8) == (operation, 0, len(result) - 32), 'fixture control response fields')
    return result[32:]


def _cache(evidence, folder, metadata, rows, stdin, stdout):
    require(len(rows) == len(metadata['cache_probes']), 'complete cache probe count')
    total = 0
    for row, path_hex in zip(rows, metadata['cache_probes']):
        same(row['path_hex'], path_hex, 'cache probe input path')
        raw = _control(stdin, stdout, 3, 0, bytes.fromhex(path_hex))
        require(raw == evidence.zipped(folder, row['probe_path']), 'actual full cache response differs')
        require(len(raw) >= 64 and raw[:8] == b'HRLKY001', 'cache key response')
        tag, length, zero = struct.unpack_from('<3Q', raw, 8); at = 32 + length
        require(tag == 1 and zero == 0 and at + 32 <= len(raw) and raw[at:at + 8] == b'HVCAR001', 'canonical cache key extent')
        present, size, zero = struct.unpack_from('<3Q', raw, at + 8)
        require(present in (0, 1) and zero == 0 and size == len(raw) - at - 32, 'cache value extent')
        same(row['present'], bool(present), 'cache presence'); same(row['content_bytes'], size, 'cache content length')
        if present:
            require(evidence.zipped(folder, row['content_path']) == raw[at + 32:], 'complete retained cache value differs')
            total += size
        else: require(size == 0 and row['content_path'] is None, 'absent cache has value')
    return total


def _caller_case(evidence, folder, row, case, stdin, stdout, expected_wire, expected_input):
    meta = case['metadata']; cid = meta['case_id']; path = bytes.fromhex(meta['path_hex'])
    for key in ('case_id', 'name', 'session'): same(row[key], meta[key], 'case identity ' + key)
    require(evidence.zipped(folder, row['input_path']) == expected_input, 'complete original logical input differs')
    require(evidence.zipped(folder, row['call_path']) == expected_wire, 'actual HIA request differs from original input/projection')
    require(row['cache_observations_complete'] is True, 'incomplete cache observation flag')
    require(_control(stdin, stdout, 1, int(meta['context'])) == b'', 'context selection payload')
    if meta['reset_cache']: require(_control(stdin, stdout, 2, 0) == b'', 'cache reset payload')
    counts = dict(body_bytes=0, cache_bytes=0, read_snapshot_bytes=0, cancelled_base_bytes=0)
    counts['cache_bytes'] += _cache(evidence, folder, meta, row['cache_before'], stdin, stdout)
    require(frame(stdin) == expected_wire, 'actual stdin does not contain the exact RUN frame')
    previous = 0; generation = None; logical = []; occurrence = Counter(); gates = 0; io_index = 0
    event_gates = {}
    for saved in row['events']:
        payload = frame(stdout); ack = exact_read(stdin, 32)
        require(payload == evidence.zipped(folder, saved['payload_path']) and ack == evidence.zipped(folder, saved['ack_path']),
                'event/ACK artifact differs from actual complete process streams')
        fields, body = _event(payload, ack, previous, generation, meta['cancel_after_render'])
        for key, value in fields.items(): same(saved[key], value, 'saved logical ' + key)
        previous, generation = fields['sequence'], fields['generation']; kind = fields['kind']
        if kind == 6:
            gates += 1; require(gates == 1 and saved is row['events'][-1], 'render gate must be unique and last')
            require(body == evidence.zipped(folder, row['after_render_path']), 'complete render gate body')
            same(row['after_render_bytes'], len(body), 'render gate body length')
            same(row['after_render_status'], fields['child_return'], 'render gate status')
        else:
            require(gates == 0, 'I/O after render gate')
            result = _reader_result(body); require(result['operation'] == (2 if kind == 5 else 1), 'reader/logical operation')
            observation = row['io'][io_index]; io_index += 1; occurrence[EVENTS[kind]] += 1
            same(observation['event'], EVENTS[kind], 'I/O name'); same(observation['occurrence'], occurrence[EVENTS[kind]], 'I/O occurrence')
            same(observation['native_reader'], result, 'complete typed reader result')
            require(evidence.zipped(folder, observation['reader_result_path']) == body, 'retained reader bytes')
            if kind <= 3:
                value = result['outcome'] == 0
                if kind == 2: value = value and stat.S_ISDIR(result['mode'])
                if kind == 3: value = value and stat.S_ISREG(result['mode'])
                same(observation['ok'], True, 'boolean I/O result'); same(observation['value'], value, 'boolean I/O value')
            else:
                same(observation['ok'], result['outcome'] == 0, 'I/O success')
                if result['outcome'] == 0 and kind == 4:
                    for key, value in (('size', result['metadata_size']), ('is_file', stat.S_ISREG(result['mode'])), ('is_dir', stat.S_ISDIR(result['mode']))):
                        same(observation[key], value, 'metadata ' + key)
                if result['outcome'] == 0 and kind == 5:
                    require(evidence.zipped(folder, observation['snapshot_path']) == body[80:], 'complete successful read snapshot')
            logical.append((fields['child_slot'], result, len(path)))
            counts['read_snapshot_bytes'] += result['snapshot_length']
            event_gates[(EVENTS[kind], occurrence[EVENTS[kind]])] = (generation, previous)
    require(gates == 1 and io_index == len(row['io']), 'render/I/O count')
    result = frame(stdout); require(result == evidence.zipped(folder, row['result_path']), 'actual final response bytes')
    require(len(result) >= 32 and result[:8] == b'HVCLOR01', 'final response header')
    code, size, zero = struct.unpack_from('<3Q', result, 8)
    require(zero == 0 and size == len(result) - 32, 'final response extent')
    same(row['native_return'], code, 'final native return'); same(row['cancelled'], meta['cancel_after_render'], 'actual cancellation')
    body = evidence.zipped(folder, row['body_path']); same(row['body_bytes'], len(body), 'complete published body length')
    if meta['cancel_after_render']:
        require(code == CANCELLED and size == len(body) == 0, 'cancel published output')
        counts['cancelled_base_bytes'] = row['after_render_bytes']
    else:
        require(code == size >= 32 and result[32:40] == b'HRCFGM01', 'final owner response')
        status, reserved, length = struct.unpack_from('<3Q', result, 40)
        require(status in (0, 1) and reserved == 0 and length == len(body) == size - 32 and body == result[64:], 'actual complete visible body')
        body.decode('utf-8'); same(row['ok'], status == 0, 'visible result status'); counts['body_bytes'] = len(body)
    counts['cache_bytes'] += _cache(evidence, folder, meta, row['cache_after'], stdin, stdout)
    require(len(row['mutations']) == len(meta['hooks']), 'missing actual filesystem mutation hook')
    for mutation, hook in zip(row['mutations'], meta['hooks']):
        require(mutation['when'] == hook['when'] and mutation['event'] == hook['event'] and mutation['occurrence'] == hook['occurrence'], 'mutation hook identity')
        same(mutation['actions'], hook['actions'], 'complete filesystem mutation actions')
        gate = mutation['actual_gate']; key = (gate['event'], gate['occurrence'])
        require(event_gates.get(key) == (gate['generation'], gate['sequence']), 'mutation not at observed ACK gate')
        if hook['when'] == 'before':
            same((gate['event'], gate['occurrence'], gate.get('next_observation')), ('is_dir', 1, ['metadata', 1]), 'before-metadata synchronization')
            names = [(x['event'], x['occurrence']) for x in row['io']]
            require(names[names.index(key) + 1] == ('metadata', 1), 'I/O intervened before metadata mutation')
        else: same(key, (hook['event'], hook['occurrence']), 'after-I/O mutation synchronization')
    return counts, logical


def _caller(evidence, folder, summary, elf, oracle, *, wide_wire=None):
    cases = load_module('cases', oracle / 'cases.py')
    support = load_module('support', evidence.root / 'tests/hia_native/test_view_call_support.py')
    wide = load_module('wide', oracle / 'wide_endpoint_case.py') if wide_wire is not None else None
    rows = evidence.rows(folder / 'native-cases.jsonl'); processes = evidence.json(folder / 'processes.json')
    require(len(rows) == (1 if wide else 58) and len(processes) == (1 if wide else 46), 'complete caller case/process domain')
    if not wide: same(evidence.json(folder / 'failures.json'), [], 'caller failures')
    totals = Counter(); kernel = Counter(); row_at = 0; process_at = 0; current = None; logical = []
    generated = hashlib.sha256(cases.INPUT_MAGIC + struct.pack('<Q', 58)); generated_size = 16
    generation_by_context = {}; retained_streams = None
    def finish():
        nonlocal logical
        if retained_streams is None: return
        eof(stdin); eof(stdout)
        values = _kernel(retained_streams['stderr'], logical)
        same(values, process['observed_kernel_receipts'], 'recounted actual kernel receipts')
        kernel.update(values); logical = []
    for case in ([wide.case()] if wide else cases.iter_cases()):
        meta = case['metadata']; row = rows[row_at]; row_at += 1
        if wide:
            encoded = wide.original_input(); wire = wide_wire
            same(row['domain'], 'additional_public_prelude_wide_endpoint', 'wide domain')
        else:
            encoded = cases.encode_cases([case]); record = cases.blob_record(meta, case['blobs'])
            generated.update(record); generated_size += len(record)
            raw = bytes.fromhex(meta['path_hex']); shown = raw.decode('utf-8', errors='replace').encode() if meta['raw_path'] else raw
            wire = support.call_frame(shown, raw, meta['params'])
            if meta['raw_path']: wire = b'HVCPI001' + wire[8:]
            same(row['domain'], 'raw_path_source_private' if meta['raw_path'] else 'public_prelude_fixture', 'caller original entry domain')
        if current != meta['session']:
            finish(); process = processes[process_at]; process_at += 1
            current = meta['session']; generation_by_context = {}
            same(process['name'], 'wide-endpoint' if wide else 'session-' + str(current), 'actual session process identity')
            require(evidence.rebase(process['cwd']) == folder / ('files' if wide else 'files-' + str(current)), 'actual caller fixture directory identity')
            retained_streams = _process(evidence, folder, process, elf, 90 if wide else 60)
            stdin, stdout = io.BytesIO(retained_streams['input']), io.BytesIO(retained_streams['stdout'])
        values, observations = _caller_case(evidence, folder, row, case, stdin, stdout, wire, encoded)
        context = bool(meta['context']); gen = row['events'][0]['generation']
        require(gen == generation_by_context.get(context, 0) + 1, 'bound/unbound controller generation isolation')
        generation_by_context[context] = gen
        totals.update(values); logical.extend(observations)
    finish(); require(row_at == len(rows) and process_at == len(processes), 'extra/missing actual session')
    if not wide:
        same(summary['independent_input'], dict(bytes=generated_size, sha256=generated.hexdigest()), 'regenerated complete 58 inputs')
        same(summary['observed_output_bytes'], dict(totals), 'actual complete output recount')
        same(summary['observed_kernel_receipts'], dict(kernel), 'actual complete kernel recount')
        same([row['case_id'] for row in rows if row['session'] == 1000], list(range(45, 58)), 'shared cache session coverage')
        same([row['case_id'] for row in rows if row['cancelled']], [52], 'actual after-render cancellation case')
    else:
        require([x['event'] for x in rows[0]['io']] == ['exists', 'is_dir'] and kernel['read_attempts'] == 0, 'wide error performed file read')
        same(summary['complete_error_bytes'], rows[0]['body_bytes'], 'wide complete error bytes')
    return dict(cases=len(rows), actual_elf_processes=len(processes), output_bytes=dict(totals), kernel=dict(kernel))


def _projection(raw):
    require(len(raw) >= 96 and raw[:8] == b'HVPRR001', 'typed projection header')
    status, flags, plen, slen, elen, patlen, clen, context, depth, presence, errorlen = struct.unpack_from('<11Q', raw, 8)
    require(status in (0, 1), 'typed projection status')
    if status:
        require(raw[16:88] == bytes(72) and errorlen == len(raw) - 96, 'typed error extent/fields')
        raw[96:].decode('utf-8'); return
    require(flags & ~28 == 0 and presence & ~127 == 0 and errorlen == 0 and
            len(raw) == 96 + plen + slen + elen + patlen + clen, 'typed success extents/flags')
    at = 96; raw[at:at + plen].decode('utf-8'); at += plen
    for size in (slen, elen):
        if size:
            endpoint = raw[at:at + size]
            require(size >= 32 and endpoint[:8] == b'HIAEP001', 'typed endpoint frame')
            kind, length, scalar = struct.unpack_from('<3Q', endpoint, 8)
            require(kind in (0, 1, 2, 3) and length == size - 32, 'typed endpoint tag/extent')
            require(kind not in (0, 1) or length == 0, 'numeric endpoint payload')
            require(kind == 0 or scalar == 0, 'non-integer endpoint scalar')
            if kind == 2: endpoint[32:].decode('utf-8')
            if kind == 3: json_value(endpoint[32:])
        at += size
    raw[at:at + patlen].decode('utf-8'); raw[at + patlen:].decode('utf-8')


def _params(evidence, folder, summary, oracle):
    rows = evidence.rows(folder / 'semantic-cases.jsonl'); require(len(rows) == 63, 'complete typed semantic domain')
    sdk = load_module('sdk_inputs', oracle / 'sdk_cases.py'); extra = load_module('parameter_inputs', oracle / 'parameter_sdk_cases.py')
    inputs = []
    for source, selected in ((sdk.encode_cases(), set(range(24))), (extra.encoded_cases(), set(range(200, 239)))):
        for line in source.split(b'\n'):
            if not line: continue
            item = json_value(line)
            if item['case_id'] in selected:
                text = line.decode(); at = text.index('"arguments":') + len('"arguments":')
                _, end = json.JSONDecoder().raw_decode(text, at)
                inputs.append((item['case_id'], item['name'], text[at:end].encode()))
    plan, sessions = [], []; next_sid = 2
    def create(sid, module, output=8192, workspace=65536):
        sessions.append(dict(kind='session_create', session=sid, module=module, output=output, workspace=workspace))
    def close(sid): sessions.append(dict(kind='session_close', session=sid))
    create(1, 'value', workspace=1048576); create(2, 'projection')
    for row, (cid, name, raw) in zip(rows, inputs):
        same((row['case_id'], row['name']), (cid, name), 'typed semantic identity')
        require(row['original_typed'] is None and bytes.fromhex(row['input_hex']) == raw, 'typed input/original-scope claim')
        canonical_raw, projection = bytes.fromhex(row['canonical_hex']), bytes.fromhex(row['output_hex'])
        json_value(canonical_raw); _projection(projection)
        plan += [(1, 1, b'HSJVAL01' + struct.pack('<2Q', 1, len(raw)) + raw, 1048576, 8192, len(canonical_raw), canonical_raw),
                 (2, 2, b'HVPRQ001' + struct.pack('<2Q', len(canonical_raw), 0) + canonical_raw, 65536, 8192, len(projection), projection)]
    close(2); close(1)
    for row in rows:
        expected = bytes.fromhex(row['output_hex']); raw = bytes.fromhex(row['canonical_hex'])
        wire = b'HVPRQ001' + struct.pack('<2Q', len(raw), 0) + raw
        for capacity in (0, len(expected) - 1, len(expected)):
            next_sid += 1; create(next_sid, 'projection', output=capacity)
            plan.append((2, next_sid, wire, 65536, capacity, CAPACITY if capacity < len(expected) else len(expected),
                         None if capacity < len(expected) else expected)); close(next_sid)
    valid = b'HVPRQ001' + struct.pack('<2Q', 2, 0) + b'{}'
    bad = [valid[:n] for n in (0, 7, 8, 15, 16, 23, 24, 25)] + [b'badmagic' + valid[8:],
        valid[:16] + struct.pack('<Q', 1) + valid[24:], valid[:8] + struct.pack('<Q', 0) + valid[16:],
        valid[:8] + struct.pack('<Q', MAX) + valid[16:], valid + b'x',
        b'HVPRQ001' + struct.pack('<2Q', 2, 0) + b'[]', b'HVPRQ001' + struct.pack('<2Q', 4, 0) + b'null']
    next_sid += 1; create(next_sid, 'projection')
    for wire in bad: plan.append((2, next_sid, wire, 65536, 8192, INVALID, None))
    close(next_sid)
    for capacity in (0, 1, 32767):
        next_sid += 1; create(next_sid, 'projection', workspace=capacity)
        plan.append((2, next_sid, valid, capacity, 8192, CAPACITY, None)); close(next_sid)
    same(evidence.json(folder / 'sessions.json'), sessions, 'complete typed session lifecycle')
    path = folder / 'raw-calls.bin.gz'; require(evidence.file(path)['sha256'] == summary['raw_calls_sha256'], 'typed raw-call archive hash')
    seen = Counter()
    with gzip.open(path, 'rb') as stream:
        for number, (module, sid, wire, workspace, output, code, expected) in enumerate(plan, 1):
            fields = struct.unpack('<8Q', exact_read(stream, 64))
            same(fields, (number, module, sid, len(wire), workspace, output, code, output), 'actual typed borrowed call header')
            require(exact_read(stream, len(wire)) == wire, 'actual typed input bytes')
            raw, state = exact_read(stream, output), exact_read(stream, workspace)
            require(raw == (b'\xa5' * output if expected is None else expected + b'\xa5' * (output - len(expected))),
                    'typed full output/sentinel buffer differs')
            if workspace < 32768: require(state == bytes(workspace), 'short workspace mutated')
            seen[module] += 1
        eof(stream)
    values = dict(value_calls=seen[1], projection_calls=seen[2], sessions=next_sid, semantic_cases=len(rows),
                  output_capacity_controls=3 * len(rows), closed_frame_controls=len(bad), workspace_controls=3)
    same(summary['counts'], values, 'actual typed call/control recount')
    return values


def _read_frame(operation, generation=0, path=b'', reserved=(0, 0, 0, 0)):
    return struct.pack('<8s7Q', b'HVRDQ001', operation, generation, len(path), *reserved) + path


def _refusal(before, after, output, code):
    require(code in (INVALID, CAPACITY) and output == b'\xa5' * len(output), 'refusal modified output or returned another code')
    require(before == after, 'refusal consumed a completion or mutated retained workspace')


def _read_direct(evidence, folder, summary):
    events = summary['events']; require(type(events) is list, 'reader event list')
    by_call = defaultdict(list); last_event_call = 0
    for event in events:
        at = integer(event.get('after_call'), 'reader event call', 0, 98)
        require(at >= last_event_call, 'reader events reordered'); last_event_call = at; by_call[at].append(event)
    path = folder / 'read-direct-calls.bin.gz'; evidence.file(path)
    live = {}; seen = set(); called = set(); counters = Counter(); admitted = None; previous_code = {}
    fault_controls = []
    def apply_events(number, next_state):
        nonlocal admitted
        for event in by_call.pop(number, []):
            sid, kind = integer(event.get('session'), 'reader session', 1, 34), event['kind']
            if kind == 'session_create':
                require(sid not in seen, 'reader session reused before/after close'); seen.add(sid)
                workspace = integer(event['workspace'], 'reader arena', 0, 147456)
                output = integer(event['output'], 'reader output', 0, 80)
                live[sid] = dict(state=bytearray(workspace), output=output); counters['direct_sessions'] += 1
                continue
            require(sid in live, 'reader event on closed/unknown session'); state = live[sid]['state']
            if kind == 'session_close':
                require(sid in called, 'unused reader session'); del live[sid]; continue
            if kind == 'private_counter_fault':
                expected = {'initial-generation': [[8, MAX]], 'initial-effect-sequence': [[32, MAX]],
                            'initial-growth-sequence': [[136, MAX]], 'completed-read-count': [[152, MAX]],
                            'closing-effect-sequence': [[32, MAX], [520, MAX]], 'next-window-growth-sequence': [[136, MAX]]}
                require(event['control'] in expected, 'unknown private fault control')
                same(event['writes'], expected[event['control']], 'private fault exact writes')
                for offset, value in event['writes']: struct.pack_into('<Q', state, offset, value)
                fault_controls.append(event['control']); counters['private_counter_faults'] += 1; continue
            if kind == 'relocation':
                require(previous_code[sid] == GROW and state[640:648] == b'HVRDG001', 'relocation without actual grow request')
                sequence, required = struct.unpack_from('<2Q', state, 648)
                same((event['sequence'], event['required'], event['capacity']),
                     (sequence, required, max(required, len(state) * 2)), 'exact actual driver relocation')
                require(required > len(state) and sequence == struct.unpack_from('<Q', state, 136)[0], 'grow request monotonicity')
                state.extend(bytes(event['capacity'] - len(state))); counters['driver_relocations'] += 1; continue
            require(kind == 'private_completion_control' and state[512:520] == b'HVRDFX01', 'unknown event/not pending completion')
            seq, gen, effect_kind, a, offset, capacity, d = struct.unpack_from('<7Q', state, 520)
            same((event['sequence'], event['generation'], event['effect_kind']), (seq, gen, effect_kind), 'private completion pending identity')
            require(struct.unpack_from('<Q', state, 576)[0] == 0, 'private completion overwrite')
            size = integer(event['data_bytes'], 'completion data bytes', 0, 65536)
            if size:
                require(effect_kind == 3 and size == event['result'] <= capacity and offset + size <= len(state), 'completion data span')
                data = next_state[offset:offset + size]
                require(digest(data) == event['data_sha256'], 'private injected full data hash')
                state[offset:offset + size] = data
            else: require(event['data_sha256'] == digest(b''), 'empty private data identity')
            errno = integer(event['errno'], 'private errno', 0, 4095)
            require(errno == 0 or event['result'] == (-errno) & MAX, 'private signed error completion')
            struct.pack_into('<8Q', state, 576, seq, gen, event['result'], errno, event['mode'], event['size'], 0, 0)
            if sid == 22: admitted = bytes(state)
            counters['private_completion_controls'] += 1
    valid = _read_frame(1, path=b'file')
    malformed = [valid[:n] for n in (0, 7, 8, 16, 24, 32, 63)] + [b'badmagic' + valid[8:], _read_frame(0),
        _read_frame(5), _read_frame(1, 1, b'file'), _read_frame(3), _read_frame(4), valid + b'x']
    malformed += [_read_frame(1, path=b'file', reserved=tuple(int(j == i) for j in range(4))) for i in range(4)]
    with gzip.open(path, 'rb') as stream:
        for number in range(1, 99):
            n, sid, ilen, workspace, capacity, code, olen = struct.unpack('<7Q', exact_read(stream, 56))
            require(n == number and sid in range(1, 35) and ilen <= 69 and workspace <= 147456 and capacity <= 80 and olen == capacity,
                    'reader actual borrowed call header')
            wire, out, state = exact_read(stream, ilen), exact_read(stream, olen), exact_read(stream, workspace)
            apply_events(number - 1, state)
            require(sid in live and len(live[sid]['state']) == workspace and live[sid]['output'] == capacity,
                    'call outside admitted session/capacities')
            before = bytes(live[sid]['state']); called.add(sid)
            if number <= 18: require(wire == malformed[number - 1] and code == INVALID, 'closed reader frame control')
            if 19 <= number <= 21: require(wire == valid and code == CAPACITY, 'reader borrowed capacity control')
            if 28 <= number <= 34:
                require(sid == 22 and admitted is not None and wire == valid, 'private malformed-completion scope')
                before = bytearray(admitted)
                if number < 34:
                    offset, value = ((576, 2), (584, 2), (624, 1), (632, 1), (536, 3), (544, 4097))[number - 28]
                    struct.pack_into('<Q', before, offset, value)
                before = bytes(before)
            if code in (INVALID, CAPACITY): _refusal(before, state, out, code)
            elif code == 80:
                require(out[:8] == b'HVRDR001' and len(out) == 80, 'reader actual output header')
                offset, size = struct.unpack_from('<2Q', out, 56)
                require(offset <= len(state) and size <= len(state) - offset, 'reader snapshot workspace containment')
                result = _reader_result(out + state[offset:offset + size], private=True)
                if number in (39, 74, 83): require(result['outcome'] == 4 and size == 0, 'late cancel did not discard retained result')
                if number in (36, 40, 59, 75, 84): require(result['outcome'] == 5 and size == 0, 'DROP result')
                if number in (35, 58): require(state == before, 'retained result reread changed state')
                if number == 56: require(state[offset:offset + size] == b'a\0\r\n' + '🙂中'.encode() and result['read_attempts'] == 8, 'split UTF-8/EINTR complete snapshot')
                if number == 59: require(state[8192:8205] == bytes(13), 'DROP retained snapshot not cleared')
                if number == 64: require((result['outcome'], result['errno']) == (3, 0), 'invalid UTF-8 final outcome')
                if number == 69: require((result['outcome'], result['errno']) == (1, 5), 'late I/O error must precede UTF-8 error')
            else:
                require(code in (PENDING, CANCEL_WAIT, GROW) and out == b'\xa5' * capacity, 'pending/grow/cancel output')
                if code in (PENDING, CANCEL_WAIT):
                    require(state[512:520] == b'HVRDFX01', 'pending effect owner record')
                if number == 23: require(state == before, 'pending replay mutated request')
            live[sid]['state'] = bytearray(state); previous_code[sid] = code; counters['direct_calls'] += 1
        eof(stream)
    apply_events(98, b''); require(not live and not by_call and len(seen) == 34, 'unclosed/missing reader lifecycle')
    same(fault_controls, ['initial-generation', 'initial-effect-sequence', 'initial-growth-sequence',
                         'completed-read-count', 'closing-effect-sequence', 'next-window-growth-sequence'], 'six distinct private counter faults')
    return dict(counters)


def _read(evidence, folder, summary, elf):
    counters = Counter(_read_direct(evidence, folder, summary)); processes = summary['processes']
    require(len(processes) == 14, 'reader actual ELF process domain')
    content = b'alpha\r\n\0' + '中🙂'.encode()
    values = [(b'empty', b''), (b'text', content), (b'split', b'a' * 65535 + '🙂\n中'.encode()),
              (b'invalid', b'a' * 65535 + b'\xf0\x9f\x99'),
              (b'big', b'first\n' + b'q' * ((17 << 20) + 3) + b'\nlast\n'),
              (b'raw-\xff', b'raw\n'), (b'symlink', content), (b'hardlink', content)]
    errors = [(b'absent', 1, 1, 2), (b'absent', 2, 1, 2), (b'dir', 2, 1, 21),
              (b'a\0b', 1, 2, 0), (b'a\0b', 2, 2, 0), (b'x' * 300, 1, 1, 36)]
    for index, row in enumerate(processes):
        name = 'file-' + str(index) if index < 8 else 'error-' + str(index - 8)
        same(row['name'], name, 'reader fixture order/name')
        require(type(row['command']) is list and len(row['command']) == 1 and evidence.rebase(row['command'][0]) == elf,
                'reader actual executable command')
        same(row['timeout_seconds'], 45, 'reader ELF deadline'); duration(row['elapsed_seconds'], 45, 'reader ELF'); same(row['exit_code'], 0, 'reader ELF exit')
        raw = {}
        for key in ('input', 'stdout', 'stderr'):
            raw[key] = evidence.zipped(folder, name + '.' + key + '.bin.gz')
            same(len(raw[key]), row[key + '_bytes'], 'reader complete stream length')
            require(digest(raw[key]) == row[key + '_sha256'], 'reader complete stream SHA')
        if index < 8:
            path, content = values[index]; wires = [_read_frame(1, path=path), _read_frame(4, 1), _read_frame(2, path=path), _read_frame(4, 2)]
        else:
            path, operation, outcome, errno = errors[index - 8]; wires = [_read_frame(operation, path=path), _read_frame(4, 1)]
        require(raw['input'] == b''.join(struct.pack('<Q', len(wire)) + wire for wire in wires), 'reader actual exact input frames')
        stdout = io.BytesIO(raw['stdout']); logical = []
        for pos, wire in enumerate(wires):
            code, size = struct.unpack('<2Q', exact_read(stdout, 16)); payload = exact_read(stdout, size)
            require(code == 80, 'reader fixture unexpected native refusal'); result = _reader_result(payload, private=True)
            operation, gen = struct.unpack_from('<2Q', wire, 8)
            if operation == 4:
                require(result['outcome'] == 5 and result['generation'] == gen and len(payload) == 80, 'actual reader DROP result'); continue
            logical.append((1, result, len(path)))
            if index < 8:
                require(result['generation'] == (1 if operation == 1 else 2), 'reader reuse generation')
                if operation == 1: require(result['metadata_size'] == len(content) and stat.S_ISREG(result['mode']), 'actual file metadata')
                elif path == b'invalid': require(result['outcome'] == 3 and len(payload) == 80, 'actual truncated UTF-8')
                else: require(result['outcome'] == 0 and payload[80:] == content, 'actual entire read content')
            else: same((result['outcome'], result['errno'], result['snapshot_length']), (outcome, errno, 0), 'actual OS/NUL error')
        eof(stdout); counts = _kernel(raw['stderr'], logical)
        counters.update(elf_processes=1, actual_effect_receipts=counts['reader_effects'],
                        actual_read_attempts=counts['read_attempts'], actual_read_bytes=counts['read_bytes'],
                        actual_opens=counts['close_attempts'], actual_closes=counts['close_attempts'])
    same(dict(counters), summary['counts'], 'reader full native/actual-kernel recount')
    return dict(counters)


def _uniform(stream, size, byte):
    while size:
        count = min(size, 65536)
        require(exact_read(stream, count) == bytes([byte]) * count, 'borrowed output tail changed')
        size -= count


def _discard(stream, size):
    while size:
        count = min(size, 65536); exact_read(stream, count); size -= count


def _wide(evidence, folder, summary, elf, oracle):
    wide = load_module('wide_input', oracle / 'wide_endpoint_case.py')
    arguments = evidence.zipped(folder, summary['arguments']['path'], summary['arguments'])
    require(arguments == wide.arguments() and len(arguments) < 8 << 20, 'wide independent original argument bytes')
    require(len(summary['owner_calls']) == 2, 'wide actual owner call count')
    expected_input = b'HSJVAL01' + struct.pack('<2Q', 1, len(arguments)) + arguments
    for number, record in enumerate(summary['owner_calls'], 1):
        same(evidence.json(folder / ('owner-' + str(number) + '.json')), record, 'wide owner receipt')
        require(record['number'] == number and record['error'] is None, 'wide owner execution result')
        duration(record['elapsed_seconds'], 180, 'wide owner')
        raw_input = evidence.zipped(folder, record['input']['path'], record['input'])
        output = evidence.zipped(folder, record['output']['path'], record['output'])
        require(raw_input == expected_input and record['code'] == len(output), 'wide actual owner input/return')
        workspace = 128 << 20 if number == 1 else 65536
        same((record['workspace'], record['output_capacity']), (workspace, 32 << 20), 'wide owner capacities')
        path = evidence.path(record['raw_path'], folder)
        same(evidence.file(path), record['raw_compressed'], 'wide complete raw owner archive')
        with gzip.open(path, 'rb') as stream:
            header = struct.unpack('<8s6Q', exact_read(stream, 56))
            require(header == (b'HVWDR001', number, len(raw_input), 32 << 20, workspace, len(output), len(output)), 'wide raw owner header')
            require(exact_read(stream, len(raw_input)) == raw_input and exact_read(stream, len(output)) == output,
                    'wide raw owner complete input/output bytes')
            _uniform(stream, (32 << 20) - len(output), 165); _discard(stream, workspace); eof(stream)
        if number == 1:
            require(len(output) == summary['canonical_bytes'] and len(output) > 16 << 20, 'actual canonical expansion extent')
            expected_input = b'HVPRQ001' + struct.pack('<2Q', len(output), 0) + output
        else:
            _projection(output); words = struct.unpack_from('<11Q', output, 8)
            require(words[0:3] == (0, 0, 4) and words[4:] == (0, 0, 0, 0, 0, 0, 0) and output[96:100] == b'file',
                    'wide actual typed projection fields')
            endpoint = output[100:]
            require(len(endpoint) == words[3] and endpoint[:8] == b'HIAEP001' and struct.unpack_from('<3Q', endpoint, 8) == (3, len(endpoint) - 32, 0),
                    'wide endpoint complete projection')
            wire = struct.pack('<8s7Q', b'HVCLQ001', 0, 4, 4, len(endpoint), 0, 0, 0) + b'filefile' + endpoint
    result = _caller(evidence, folder, summary, elf, oracle, wide_wire=wire)
    result.update(owner_calls=2, canonical_bytes=summary['canonical_bytes'])
    return result


def _domain(summary, kind):
    schemas = {'read': 'hepta.runtime.view-read-native-tests.v1', 'params': 'hepta.runtime.view-params-native.v1',
               'caller': 'hepta.runtime.view-call-native.v1', 'wide': 'hepta.runtime.view-call-wide-native.v1'}
    require(summary.get('schema') == schemas[kind], 'native summary schema')
    require(summary.get('status') == ('PASS' if kind == 'read' else 'NATIVE_COMPLETE_RUST_REPLAY_REQUIRED'), 'native execution status/scope')
    for field in ('whole_runtime_replaced', 'whole_view_replaced'):
        require(summary.get(field) is False, 'native fixture whole-scope claim')
    if kind != 'params': require(summary.get('public_mcp_route_replaced') is False, 'private caller called public route')
    expected = {
        'read': dict(test_groups=9, expected_groups=9, skipped=0, errors=0, failures=0, original_rust_comparison='separate recipe'),
        'params': dict(groups=3, errors=0, failures=0, formal_sdk_typed_cases=24, additional_typed_cases=39,
                       fresh_rust_processes=0, real_serde_value_owner=True, optional_existing_original_comparison=False,
                       actual_router_qualification=False),
        'caller': dict(groups=1, failures=0, requested_cases=58, completed_cases=58, public_prelude_cases=56,
                       raw_path_source_cases=2, full_58_case_domain_complete=True, actual_elf_processes=46,
                       actual_io_comparison=None, reference_report=None, after_render_cancelled=1,
                       common_cache_session=1000, unbound_context_kept_same_process=True),
        'wide': dict(groups=1, additional_wide_cases=1, ordinary_58_cases_counted=0, case_id=1000,
                     actual_elf_processes=1, ordinary_file_reads=0, original_reference_comparison=False, failure=None)}[kind]
    for key, value in expected.items(): same(summary.get(key), value, 'native scope/count ' + key)


def native_evidence(root, output, report):
    """Validate four actual native suites; do not claim original parity here."""
    evidence = Evidence(root, output); descriptor = report.get('view_call')
    build = _builds(evidence, descriptor)
    require(type(descriptor['corpora']) is dict and set(descriptor['corpora']) == {'read', 'params', 'caller', 'wide'}, 'native corpus descriptor')
    folders = {key: evidence.path(value) for key, value in descriptor['corpora'].items()}
    require(len(set(folders.values())) == 4, 'aliased native corpus directories')
    summaries = {kind: evidence.json(folder / ('read-native-result.json' if kind == 'read' else 'result.json'))
                 for kind, folder in folders.items()}
    manifest_relative = build['paths']['manifest'].relative_to(evidence.output)
    manifest_pin = evidence.file(build['paths']['manifest'])
    candidates = [Path(path) for path, value in summaries['caller']['pinned_inputs'].items()
                  if value == manifest_pin and Path(path).parts[-len(manifest_relative.parts):] == manifest_relative.parts]
    require(len(candidates) == 1, 'cannot bind executed output root to actual caller manifest')
    old_output = candidates[0]
    for _ in manifest_relative.parts: old_output = old_output.parent
    evidence.old_roots.append((old_output, evidence.output))
    for kind, name in zip(('read', 'params', 'caller', 'wide'), TESTS):
        summary = summaries[kind]; _domain(summary, kind)
        _check(evidence, report, name, summary, 'tests/hia_native/' + name)
        pins = summary['identities' if kind == 'read' else 'qualification_inputs' if kind == 'params' else 'pinned_inputs']
        evidence.pins(pins)
        if kind == 'read': require(summary['test_sha256'] == evidence.source('tests/hia_native/' + name)['sha256'], 'reader test source pin')
    oracle = evidence.root / 'tests/hia_native/view_call_oracle'
    for path in sorted(oracle.rglob('*')):
        if path.is_file() and '__pycache__' not in path.parts: evidence.source(str(path.relative_to(evidence.root)))
    read = _read(evidence, folders['read'], summaries['read'], build['read_elf'])
    params = _params(evidence, folders['params'], summaries['params'], oracle)
    caller = _caller(evidence, folders['caller'], summaries['caller'], build['caller_elf'], oracle)
    wide = _wide(evidence, folders['wide'], summaries['wide'], build['caller_elf'], oracle)
    evidence.source('scripts/hia_native_view_call_qualification.py')
    return dict(schema='hepta.runtime.view-call-native-evidence.v1', status='PASS',
        native_execution_complete=True, fresh_original_comparison=False,
        complete_input_output_buffers_retained=True, actual_kernel_receipts_recounted=True,
        public_prelude_cases=56, private_raw_path_cases=2, typed_cases=63, additional_wide_cases=1,
        native_suites=4, native_groups=14, actual_elf_processes=61, direct_native_calls=433,
        read=read, params=params, caller=caller, wide=wide,
        corpora={key: str(path.relative_to(evidence.output)) for key, path in folders.items()},
        transient_fixture_directories=[str((folders['caller'] / ('files-' + str(i))).relative_to(evidence.output))
            for i in list(range(45)) + [1000]] + [str((folders['wide'] / 'files').relative_to(evidence.output))],
        artifact_sha256=dict(sorted(evidence.artifacts.items())), source_sha256=dict(sorted(evidence.sources.items())),
        standalone_fixture_is_public_mcp=False, whole_view_replaced=False, whole_runtime_replaced=False)


ORIGINAL_PROCESSES = ('rust-version', 'build', 'original', 'sdk', 'parameter',
                      'wide', 'router', 'public-schema', 'info')
ORIGINAL_BINARIES = ('hepta-view-call-original-oracle', 'view_call_sdk', 'view_call_router_sdk',
                     'view_call_public_schema', 'view_call_info_sdk')


def _original_process(row, expected_command):
    same(row.get('command'), expected_command, 'actual original process command')
    same(row.get('timeout_seconds'), 180, 'original actual deadline')
    same(row.get('exit_code'), 0, 'original process exit')
    require(row.get('timed_out') is False and 'spawn_error' in row and row['spawn_error'] is None,
            'original process timeout/spawn error')
    duration(row.get('elapsed_seconds'), 180, 'original process')


def _strict_blob_file(path, magic, count):
    """Check all metadata with the strict JSON decoder without retaining blobs."""
    extent = path.stat().st_size
    with path.open('rb') as stream:
        require(exact_read(stream, 16) == magic + struct.pack('<Q', count), 'complete original binary domain')
        for _ in range(count):
            size, blobs = struct.unpack('<2Q', exact_read(stream, 16))
            require(size <= extent - stream.tell() and blobs <= extent // 8, 'original record bounds')
            require(type(json_value(exact_read(stream, size))) is dict, 'original metadata object')
            for _ in range(blobs):
                size, = struct.unpack('<Q', exact_read(stream, 8))
                require(size <= extent - stream.tell(), 'original blob bounds'); _discard(stream, size)
        eof(stream)


def _original_outer(evidence, report, result):
    rows = [check for check in report.get('checks', []) if check.get('name') == ORIGINAL_CHECK]
    require(len(rows) == 1, 'exactly one shared original recipe must have actually executed')
    check = rows[0]; command = check.get('command')
    require(type(command) is list and len(command) == 18 and all(type(item) is str for item in command), 'original recipe command shape')
    require(Path(command[0]).is_absolute() and command[1:3] == ['-I', '-B'], 'original recipe isolated Python')
    expected_keys = ['--runtime-root', '--output', '--cargo', '--rustc', '--native-corpus', '--params-corpus', '--wide-corpus']
    same(command[4::2], expected_keys, 'original recipe options/order')
    options = dict(zip(command[4::2], command[5::2]))
    require(all(Path(value).is_absolute() for value in options.values()), 'original recipe recorded relative paths')
    require(Path(command[3]) == Path(options['--runtime-root']) / 'tests/hia_native/view_call_oracle/run.py', 'original actual harness command')
    require(Path(options['--output']).name == ORACLE_OUTPUT_FOLDER, 'original output folder identity')
    require(len(set(options[key] for key in ('--native-corpus', '--params-corpus', '--wide-corpus'))) == 3,
            'aliased original replay corpora')
    same(check.get('exit_code'), 0, 'original recipe exit'); same(check.get('timeout_seconds'), 180, 'original recipe deadline')
    require(check.get('timed_out') is False and check.get('start_error') is None, 'original recipe timeout/start error')
    duration(check.get('elapsed_seconds'), 180, 'original recipe')
    for kind in ('stdout', 'stderr'):
        raw = evidence.raw(evidence.output / (ORIGINAL_CHECK + '.' + kind))
        same(len(raw), check.get(kind + '_bytes'), 'original recipe complete stream extent')
        require(digest(raw) == check.get(kind + '_sha256'), 'original recipe complete stream identity')
        if kind == 'stdout': same(json_value(raw), result, 'actual original recipe stdout')
        else: require(raw == b'', 'original recipe stderr')
    if 'summary' in check: same(check['summary'], result, 'original parsed recipe summary')
    return options


def _original_evidence(root, output, report, native):
    evidence = Evidence(root, output); original = evidence.output / ORACLE_OUTPUT_FOLDER
    require(native.get('status') == 'PASS' and native.get('native_execution_complete') is True and
            native.get('fresh_original_comparison') is False, 'missing prior native-only evidence')
    for name, sha in native['artifact_sha256'].items(): require(evidence.file(evidence.path(name))['sha256'] == sha, 'previously admitted native artifact changed')
    for name, sha in native['source_sha256'].items(): require(evidence.source(name)['sha256'] == sha, 'previously admitted native source changed')
    result = evidence.json(original / 'result.json')
    require(result.get('schema') == 'hepta.runtime.view-call-original-reference.v1' and result.get('status') == 'PASS' and
            result.get('harness_unchanged') is True and result.get('whole_view_migrated') is False and result.get('whole_runtime_replaced') is False,
            'fresh original completion/scope')
    options = _original_outer(evidence, report, result)
    receipts = evidence.json(original / 'process-receipts.json')
    same(receipts, result['processes'], 'complete actual original process receipt list')
    same([row['name'] for row in receipts], list(ORIGINAL_PROCESSES), 'shared nine original process inventory')
    old = Path(options['--output']); cargo, rustc = options['--cargo'], options['--rustc']
    require(type(result.get('explicit_offline')) is bool, 'explicit original offline selection')
    build_command = [cargo, 'build', '--locked'] + (['--offline'] if result['explicit_offline'] else []) + ['--manifest-path', str(old / 'crate/Cargo.toml'), '--release']
    commands = [[rustc, '--version'], build_command,
        [str(old / 'target/release/hepta-view-call-original-oracle'), str(old / 'fixtures')],
        [str(old / 'target/release/view_call_sdk')], [str(old / 'target/release/view_call_sdk')],
        [str(old / 'target/release/hepta-view-call-original-oracle'), str(old / 'wide-fixtures')],
        [str(old / 'target/release/view_call_router_sdk')], [str(old / 'target/release/view_call_public_schema')],
        [str(old / 'target/release/view_call_info_sdk')]]
    for row, command in zip(receipts, commands):
        _original_process(row, command); same(row.get('cwd'), str(old / 'crate'), 'original process cwd')
        for stream in ('stdout', 'stderr'):
            same(evidence.file(original / (row['name'] + '.' + stream)), row[stream], 'complete original actual ' + stream)
    environment = result['build_environment']
    require(set(environment) <= {'RUSTC', 'CARGO_TARGET_DIR', 'CARGO_BUILD_JOBS', 'CARGO_NET_OFFLINE'}, 'unexpected original build environment overrides')
    same({key: environment.get(key) for key in ('RUSTC', 'CARGO_TARGET_DIR', 'CARGO_BUILD_JOBS')},
         dict(RUSTC=rustc, CARGO_TARGET_DIR=str(old / 'target'), CARGO_BUILD_JOBS='2'), 'fresh isolated original target/compiler')
    oracle = evidence.root / 'tests/hia_native/view_call_oracle'
    harness = {str(path.relative_to(oracle)): evidence.source(str(path.relative_to(evidence.root)))
               for path in sorted(oracle.rglob('*')) if path.is_file() and '__pycache__' not in path.parts}
    same(result['harness_inputs'], harness, 'all actually executed original harness inputs')
    run = load_module('original_recipe', oracle / 'run.py')
    source = run.source
    for relative in source.SOURCE_FILES: evidence.source(relative)
    with tempfile.TemporaryDirectory(prefix='view-original-materialization-') as temporary:
        expected_root = Path(temporary) / 'crate'
        expected_materialization = source.materialize(evidence.root, expected_root)
        same(result['materialization'], expected_materialization, 'fresh source extraction/materialization')
        expected_files = {str(path.relative_to(expected_root)) for path in expected_root.rglob('*') if path.is_file()}
        actual_files = {str(path.relative_to(original / 'crate')) for path in (original / 'crate').rglob('*') if path.is_file()}
        same(sorted(actual_files), sorted(expected_files), 'complete materialized crate inventory')
        for relative in sorted(expected_files):
            require(evidence.raw(original / 'crate' / relative) == (expected_root / relative).read_bytes(), 'materialized original source/lock differs')
    require(result['materialization']['registry_dependencies'] == 74, 'locked original dependency domain')
    same(sorted(result['binaries']), sorted(ORIGINAL_BINARIES), 'fresh original binary inventory')
    for name in ORIGINAL_BINARIES:
        path = original / 'target/release' / name
        same(evidence.file(path), result['binaries'][name], 'actual fresh original executable')
        with path.open('rb') as stream: require(exact_read(stream, 4) == b'\x7fELF', 'original executable is not ELF')
    pairs = [('input.bin', result['independent_input']), ('original.stdout', result['original_output']),
             ('sdk-input.jsonl', result['sdk_input']), ('sdk.stdout', result['sdk_output'])]
    pairs += list(result['additional_inputs'].items()) + list(result['additional_outputs'].items())
    require(set(result['additional_inputs']) == {'parameter-input.jsonl', 'wide-input.bin', 'router-input.jsonl', 'info-input.jsonl'} and
            set(result['additional_outputs']) == {'parameter.stdout', 'wide.stdout', 'router.stdout', 'public-schema.stdout', 'info.stdout'},
            'additional original input/output inventory')
    for name, expected in pairs: same(evidence.file(original / name), expected, 'original complete input/output identity')
    with (original / 'input.bin').open('rb') as stream:
        require(exact_read(stream, 16) == run.cases.INPUT_MAGIC + struct.pack('<Q', 58), 'original input domain')
        for case in run.cases.iter_cases():
            expected = run.cases.blob_record(case['metadata'], case['blobs'])
            require(exact_read(stream, len(expected)) == expected, 'fresh full independent 58-case input')
        eof(stream)
    generated = {'sdk-input.jsonl': run.sdk.encode_cases(), 'parameter-input.jsonl': run.parameter.encoded_cases(),
                 'wide-input.bin': run.wide.original_input(),
                 'router-input.jsonl': b''.join(canonical(row) for row in run.router.iter_router_sdk_cases()),
                 'info-input.jsonl': b''.join(canonical(row) for row in run.info.iter_info_sdk_cases())}
    for name, raw in generated.items(): require(evidence.raw(original / name) == raw, 'regenerated independent input ' + name)
    _strict_blob_file(original / 'original.stdout', run.cases.OUTPUT_MAGIC, 58)
    _strict_blob_file(original / 'wide.stdout', run.cases.OUTPUT_MAGIC, 1)
    for name in ('sdk', 'parameter', 'router', 'info'):
        raw = evidence.raw(original / (name + '.stdout')); require(raw.endswith(b'\n'), 'SDK output final LF')
        for line in raw.split(b'\n')[:-1]: require(type(json_value(line)) is dict, 'SDK output object')
    reference = run.reference_summary(original); same(result['reference'], reference, 'recounted original actual I/O/SDK results')
    additional = dict(parameter=run.sdk_reference(original, 'parameter', [json_value(line) for line in generated['parameter-input.jsonl'].split(b'\n') if line], 39),
                      router=run.sdk_reference(original, 'router', run.router.iter_router_sdk_cases(), 54),
                      info=run.sdk_reference(original, 'info', run.info.iter_info_sdk_cases(), 13))
    schema = evidence.raw(original / 'public-schema.stdout').split(b'\n')
    require(len(schema) == 3 and schema[-1] == b'', 'actual original schema output framing')
    for name, raw in zip(('raw-input-schema.json', 'public-input-schema.json'), schema[:2]):
        require(type(json_value(raw)) is dict and evidence.raw(original / name) == raw + b'\n', 'actual standalone schema bytes')
    additional['schema'] = dict(raw=evidence.file(original / 'raw-input-schema.json'), published=evidence.file(original / 'public-input-schema.json'),
                                original_functions_executed=True, original_full_list_tools_executed=False)
    with (original / 'wide.stdout').open('rb') as stream:
        iterator = run.cases.read_records(stream, run.cases.OUTPUT_MAGIC); wide = next(iterator)
        require(next(iterator, None) is None, 'extra wide original result')
    meta = wide['metadata']; require(meta['case_id'] == 1000 and meta['outcome']['ok'] is False and meta['io_counts'] == {'exists': 1, 'is_dir': 1}, 'wide original execution domain')
    body = wide['blobs'][meta['outcome']['blob']]; require(len(body) == meta['outcome']['bytes'] > 16 << 20, 'complete wide original error')
    additional['wide'] = dict(cases=1, case_id=1000, error_body=source.pin(body), actual_tokio_io=True, ordinary_58_cases_counted=0)
    same(result['additional_reference'], additional, 'recounted additional original execution')
    corpora = {key: evidence.path(value) for key, value in native['corpora'].items()}
    comparison = dict(caller=run.replay.compare_native(corpora['caller'], original),
                      params=run.replay.compare_params(corpora['params'], original),
                      wide=run.replay.compare_wide(corpora['wide'], original))
    same(result['native_comparison'], comparison, 'fresh full original/native byte comparison')
    return dict(schema='hepta.runtime.view-call-original-comparison.v1', status='PASS', original_output=ORACLE_OUTPUT_FOLDER,
        fresh_original_processes=9, shared_original_recipe=True, original_recipe_check=ORIGINAL_CHECK,
        comparisons=comparison, reference=reference, additional_reference=additional,
        every_original_input_output_byte_checked=True, source_and_lock_rebuilt_without_compilation=True,
        original_outer_view_handler_executed=False, original_full_tool_catalog_executed=False,
        artifact_sha256=dict(sorted(evidence.artifacts.items())), source_sha256=dict(sorted(evidence.sources.items())),
        whole_view_replaced=False, whole_runtime_replaced=False)


def compare_original(root, output, report, native, *, record_check=None, cargo=None, rustc=None, report_path=None):
    """One fresh shared nine-process recipe; subsequent components only reread it."""
    root, output = Path(root).resolve(), Path(output).resolve()
    checks = [row for row in report.get('checks', []) if row.get('name') == ORIGINAL_CHECK]
    require(len(checks) <= 1, 'duplicate shared original recipe')
    if not checks:
        require(record_check is not None and cargo is not None and rustc is not None, 'fresh original recipe has not executed')
        original = output / ORACLE_OUTPUT_FOLDER
        require(not original.exists(), 'unrecorded original output already exists')
        folders = {key: inside(output, value) for key, value in native['corpora'].items()}
        command = [sys.executable, '-I', '-B', str(root / 'tests/hia_native/view_call_oracle/run.py'),
            '--runtime-root', str(root), '--output', str(original), '--cargo', str(Path(cargo).absolute()),
            '--rustc', str(Path(rustc).absolute()), '--native-corpus', str(folders['caller']),
            '--params-corpus', str(folders['params']), '--wide-corpus', str(folders['wide'])]
        record_check(output, report, name=ORIGINAL_CHECK, command=command, timeout=180, report_path=report_path)
    return _original_evidence(root, output, report, native)


def qualification_evidence(root, output, report, native):
    """Require the actual rejection suite, after the native-only baseline read."""
    evidence = Evidence(root, output)
    summary = evidence.json(evidence.output / 'view-call-evidence/result.json')
    require(summary.get('schema') == 'hepta.runtime.view-call-evidence-tests.v1', 'evidence test schema')
    for key, value in dict(status='PASS', groups=8, expected_groups=8, controls=64, expected_controls=64,
        failures=0, errors=0, skipped=0, new_native_calls=0, new_original_processes=0,
        original_captures_modified=False, whole_view_replaced=False, whole_runtime_replaced=False).items():
        same(summary.get(key), value, 'evidence rejection suite ' + key)
    duration(summary.get('elapsed_seconds'), 180, 'evidence suite')
    controls = summary.get('rejection_controls')
    require(type(controls) is list and len(controls) == 64 and len({row['name'] for row in controls}) == 64,
            'evidence rejection control inventory')
    for control in controls:
        require(set(control) == {'name', 'rejected'} and type(control['name']) is str and control['name'] and
                control['rejected'] is True, 'failed/untyped rejection control')
    require(summary['reader_sha256'] == evidence.source('scripts/hia_native_view_call_qualification.py')['sha256'] and
            summary['test_sha256'] == evidence.source('tests/hia_native/test_view_call_evidence.py')['sha256'], 'evidence reader/test source identity')
    require(summary['baseline_native_sha256'] == digest(canonical(native)), 'evidence suite baseline is not current native evidence')
    same(summary['baseline_artifacts'], len(native['artifact_sha256']), 'evidence baseline artifact count')
    _check(evidence, report, 'test_view_call_evidence.py', summary, 'tests/hia_native/test_view_call_evidence.py')
    result = dict(native)
    result['evidence_controls'] = dict(schema='hepta.runtime.view-call-evidence-qualification.v1', status='PASS',
        groups=8, rejection_controls=64, baseline_native_sha256=summary['baseline_native_sha256'])
    result['artifact_sha256'] = dict(sorted({**native['artifact_sha256'], **evidence.artifacts}.items()))
    result['source_sha256'] = dict(sorted({**native['source_sha256'], **evidence.sources}.items()))
    return result
