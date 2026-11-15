"""Read the complete frozen native Text publication evidence, without execution.

This reader never creates fixtures, starts a child, loads native code or runs a
Rust reference. Logical execution paths remain in the original receipts. An
explicit origin map changes only where immutable files are read. The 99 normal
original cases and 20 original races are separate, still pending qualifications.
"""
from __future__ import annotations
import argparse, ast, base64, gzip, hashlib, json, math, os, stat, struct, sys, types
from pathlib import Path, PurePosixPath

U64 = (1 << 64) - 1
INVALID, CAPACITY, STATE, RESOURCE = 0xffffffff, 0xfffffffe, 0xfffffff9, 0xfffffffc
ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / 'native/text_publication_qualification_sources.json'

def require(value, message):
    if not value:
        raise ValueError(message)

def same(actual, expected, message):
    # bool is not an integer in any recorded counter or process return.
    def equal(a, b):
        if type(a) is not type(b): return False
        if type(a) is dict: return a.keys()==b.keys() and all(equal(a[k],b[k]) for k in a)
        if type(a) in (list,tuple): return len(a)==len(b) and all(equal(x,y) for x,y in zip(a,b))
        return a==b
    require(equal(actual,expected), message)

def sha(raw): return hashlib.sha256(raw).hexdigest()
def pin(raw): return {'bytes': len(raw), 'sha256': sha(raw)}
def unsigned(value): return type(value) is int and 0 <= value <= U64
def integer(value, lower=0): return type(value) is int and value >= lower
def number(value): return type(value) in (int, float) and math.isfinite(value) and value >= 0
def signed(value): return value - (1 << 64) if value >= 1 << 63 else value
def q(raw, at=0): return struct.unpack_from('<Q', raw, at)[0]
def b64(raw): return base64.b64encode(raw).decode('ascii')
def unb64(raw): return base64.b64decode(raw, validate=True)

def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON key: ' + key)
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))

def relative(name):
    require(type(name) is str and name and not name.startswith('/') and '\\' not in name,
            'non-relative artifact path')
    require(all(x not in ('', '.', '..') for x in name.split('/')), 'unsafe artifact component')
    return name

class Files:
    def __init__(self, roots, origins=None):
        require(set(roots) == {'native', 'boundary', 'faults', 'corpus', 'handoff'}, 'five explicit roots')
        self.roots = {k: str(Path(v).absolute()) for k, v in roots.items()}
        require(len(set(self.roots.values())) == 5, 'distinct execution roots')
        self.origins = {str(Path(k).absolute()): Path(v).absolute() for k, v in (origins or {}).items()}
        require(all(k.startswith('/') for k in self.origins), 'absolute origin map')
        self.artifacts, self.sources = {}, {}

    def physical(self, path):
        path = str(path)
        matches = [k for k in self.origins if path == k or path.startswith(k + '/')]
        if self.origins:
            require(matches, 'unmapped execution path: ' + path)
        if matches:
            key = max(matches, key=len)
            base = self.origins[key]
            tail = path[len(key):].lstrip('/')
        else:
            candidates = [v for v in self.roots.values() if path == v or path.startswith(v + '/')]
            require(candidates, 'path outside explicit evidence roots')
            key = max(candidates, key=len)
            base, tail = Path(key), path[len(key):].lstrip('/')
        require(not base.is_symlink(), 'symlink evidence root')
        cursor = base
        for part in PurePosixPath(tail).parts:
            require(part not in ('.', '..'), 'unsafe mapped path')
            cursor /= part
            require(not cursor.is_symlink(), 'symlink evidence component')
        require(stat.S_ISREG(cursor.lstat().st_mode), 'evidence is not a regular file')
        return cursor

    def read(self, group, name, expected=None, source=False):
        relative(name)
        key = group + '/' + name
        raw = self.physical(self.roots[group] + '/' + name).read_bytes()
        value = pin(raw)
        if expected is not None:
            same(value if type(expected) is dict else value['sha256'], expected, 'artifact pin: ' + key)
        if key in self.artifacts:
            same(value, self.artifacts[key], 'artifact changed while reading: ' + key)
        self.artifacts[key] = value
        if source:
            self.sources[key] = value
        return raw

    def obj(self, group, name, expected=None): return decode(self.read(group, name, expected))
    def absolute(self, group, name): return self.roots[group] + '/' + relative(name)

def clocks(row, deadline, *, timed=True, exit_code=0):
    require(integer(row.get('pid'), 1), 'real positive process PID')
    same(row.get('exit_code'), exit_code, 'actual process exit')
    require(number(row.get('elapsed_seconds')) and row['elapsed_seconds'] <= deadline,
            'finite process duration within unchanged deadline')
    if timed:
        same(row.get('timeout_seconds'), deadline, 'actual unchanged process deadline')
        same(row.get('timed_out'), False, 'process timed out')
        same(row.get('start_error'), None, 'process start error')
    if 'started_monotonic_ns' in row or 'finished_monotonic_ns' in row:
        a, b = row.get('started_monotonic_ns'), row.get('finished_monotonic_ns')
        require(integer(a, 1) and integer(b, a), 'real monotonic interval')
        require(abs(row['elapsed_seconds'] - (b - a) / 1e9) < 1e-9, 'monotonic duration binding')

def process_streams(f, group, folder, row, *, outer=False):
    streams = {}
    for name in (('stdout', 'stderr') if outer else ('stdin', 'stdout', 'stderr')):
        where = folder + '.' + name if outer else folder + '/' + name + '.bin'
        value = row[name] if outer else row['streams'][name]
        streams[name] = f.read(group, where, {k: value[k] for k in ('bytes', 'sha256')})
    return streams

def checked_process(f, group, record, command, cwd, prefix, *, outer=True, deadline=180,
                    timed=True, exit_code=0):
    same(record.get('command'), command, 'source-bound exact process command')
    same(record.get('cwd'), cwd, 'actual process cwd')
    clocks(record, deadline, timed=timed, exit_code=exit_code)
    return process_streams(f, group, prefix, record, outer=outer)

def load_generators(f):
    # These exact admitted source modules are loaded only to obtain their finite
    # input descriptions. None of their live snapshot/run/check functions run.
    names = ('hia_native_text_publication_fixtures', 'qualify_hia_text_publication_native',
             'qualify_hia_text_publication_races')
    old = {k: sys.modules.get(k) for k in names}
    old_path = list(sys.path)
    modules = []
    try:
        for name in names:
            module = types.ModuleType(name)
            module.__file__ = f.absolute('corpus', 'source/scripts/' + name + '.py')
            sys.modules[name] = module
            exec(compile(f.read('corpus', 'source/scripts/' + name + '.py'), module.__file__, 'exec'), module.__dict__)
            modules.append(module)
    finally:
        sys.path[:] = old_path
        for name, value in old.items():
            if value is None: sys.modules.pop(name, None)
            else: sys.modules[name] = value
    return modules[0], modules[2]

def admit_sources(f, contract):
    tables = contract['source_sets']
    for group in ('native', 'boundary', 'faults', 'corpus'):
        actual = f.obj(group, 'SOURCE-PINS.json' if group == 'corpus' else 'SOURCE-FILES.json')
        # Corpus uses complete byte/sha pins, the native stage source table uses
        # SHA strings. The recorded key set must be complete in either form.
        if group == 'corpus':
            actual = {k: v['sha256'] if type(v) is dict else v for k, v in actual.items()}
        same(actual, tables[group], 'complete exact frozen source closure: ' + group)
        for name, digest in actual.items():
            f.read(group, 'source/' + name, digest, source=True)
    files = f.obj('handoff', 'FILES.json')
    require(type(files) is dict and len(files) == 13, 'frozen 13-file source handoff')
    # FILES carries each real original source path and its exact byte pin.
    for name, item in files.items():
        f.read('handoff', 'source/' + name, {k: item[k] for k in ('bytes', 'sha256')}, source=True)
        require(any(tables[g].get(name) == item['sha256'] for g in tables), 'unbound handoff source')
        allowed = [f.absolute(g, 'source/' + name) for g in ('native', 'boundary', 'faults')
                   if tables[g].get(name) == item['sha256']]
        require(item['actual_source'] in allowed, 'actual source provenance')
    dependencies = f.obj('handoff', 'DEPENDENCIES.json')
    for name, digest in dependencies.items():
        value = digest['sha256'] if type(digest) is dict else digest
        same(tables['native'].get(name), value, 'frozen recursive dependency')
    return tables

def admit_artifact_inventory(f, contract):
    manifest = f.obj('handoff', 'ARTIFACTS.json')
    groups = {'native-v4': 'native', 'boundary-v1': 'boundary', 'faults-v1': 'faults'}
    same(set(manifest), set(groups), 'three complete mechanical capture groups')
    count = 0
    for label, group in groups.items():
        item = manifest[label]
        same(item['origin'], f.roots[group], 'original mechanical execution root')
        same(sorted(item['artifacts']), contract['mechanical_artifacts'][label], 'complete mechanical artifact set')
        for name, expected in item['artifacts'].items():
            f.read(group, name, expected)
            count += 1
    same(count, 553, 'all original mechanical artifacts read')

def native_build(f, contract, sources):
    m = f.obj('native', 'build/manifest.json')
    same(m['schema'], 'hepta.runtime.text-publication-build.v1', 'native build schema')
    same(m['slots'], [0, 1, 2], 'fixed image slots')
    for flag in ('runtime_python_required', 'runtime_rust_required', 'runtime_libc_required',
                 'public_handler_replaced', 'whole_runtime_replaced'):
        same(m[flag], False, 'build scope: ' + flag)
    same(m['builder_source'], 'scripts/hia_native_text_publication_build.py', 'actual builder source')
    same(m['builder_sha256'], sources['native'][m['builder_source']], 'builder source pin')
    f.read('native', 'build/builder.py', m['builder_sha256'])
    source_names = ['scripts/text_publication_fixture.S', 'scripts/text_publication_engine.S',
                    'scripts/text_publication_effects.S', 'scripts/text_publication_children.S',
                    'scripts/text_publication_transport.S']
    same(m['sources'], {x: sources['native'][x] for x in source_names}, 'all five native boundary sources')
    combined = b'\n'.join(f.read('native', 'source/' + x) for x in source_names)
    same(f.read('native', 'build/combined.S'), combined, 'exact assembled boundary input')
    same(f.read('native', 'authoring-boundary/combined.S'), combined, 'exact authoring boundary input')
    prefix = f.read('native', 'build/prefix.bin', {'bytes': m['prefix_bytes'], 'sha256': m['prefix_sha256']})
    same(f.read('native', 'authoring-boundary/prefix.bin'), prefix, 'original packer prefix')
    proof = f.obj('native', 'build/packer-composition.json', m['packer_composition_sha256'])
    same(f.read('native', 'source/' + m['packer_composition']), f.read('native', 'build/packer-composition.json'), 'exact packer contract')
    boundary = {'prefix_bytes': len(prefix), 'prefix_sha256': sha(prefix), 'table_offset': m['table_offset'],
                'slots': [0, 1, 2], 'sources': m['sources']}
    same(f.obj('native', 'build/boundary.json'), boundary, 'native boundary metadata')
    same(proof['boundary'], boundary, 'packer frozen native boundary')
    for imported in proof['imports']:
        same(imported['source_sha256'], sources['native'][imported['source']], 'packer imported bytes')
    require(prefix[:7] == b'\x7fELF\x02\x01\x01' and prefix[m['table_offset']:m['table_offset']+24] == bytes(24), 'static Linux image prefix')
    images = []
    members = [('text-publication', 'native/text_publication.hepta'),
               ('text-publication-codec', 'native/binary_codec.hepta'),
               ('text-publication-error', 'native/view_error.hepta')]
    same([(x['name'], x['source']) for x in m['members']], members, 'all source-owned child members')
    module_paths = [(x['name'], x['source'], 'build/' + x['manifest'], x['manifest_sha256']) for x in m['members']]
    module_paths.append(('text-publication-packer', 'native/text_publication_packer.hepta',
                         'build/' + m['packer_manifest'], m['packer_manifest_sha256']))
    for index, (name, source, path, digest) in enumerate(module_paths):
        member = f.obj('native', path, digest)
        same(member['name'], name, 'module name')
        same(member['compiler_commit'], contract['compiler_commit'], 'fixed compiler commit')
        same(member['compiler_sha256'], contract['compiler_image_sha256'], 'fixed B3 compiler')
        same(member['source_sha256'], sources['native'][source], 'actual module source pin')
        same(member['standalone'], None, 'borrowed callable module')
        folder = str(PurePosixPath(path).parent)
        image = f.read('native', folder + '/' + member['image'], member['image_sha256'])
        raw_source = f.read('native', 'source/' + source)
        same(f.read('native', folder + '/' + member['source']), raw_source, 'staged exact module source')
        same(f.read('native', folder + '/module.input.bin'), raw_source, 'actual compiler input')
        request = f.obj('native', folder + '/module.request.json')
        receipt = f.obj('native', folder + '/module.receipt.json')
        same(request['source'], f.absolute('native', folder + '/module.input.bin'), 'compiler actual source command')
        same(request['output'], f.absolute('native', folder + '/module.output.bin'), 'compiler actual output')
        same(request['image'], f.absolute('native', 'build/build/bootstrap/B3.image.bin'), 'actual B3 path')
        same(request['source_sha256'], sha(raw_source), 'compiler request source digest')
        same(request['image_sha256'], contract['compiler_image_sha256'], 'compiler request image digest')
        same(receipt['input_bytes'], len(raw_source), 'compiled source extent')
        same(receipt['input_sha256'], sha(raw_source), 'actual compiled input digest')
        for key in ('source_sha256',): same(receipt[key], sha(raw_source), 'compiler receipt source')
        same(receipt['status'], 'returned', 'actual compiler returned')
        same(receipt['abi_status'], 0, 'compiler ABI success')
        same(receipt['core_u32'], len(image), 'actual produced native length')
        same(receipt['produced_sha256'], sha(image), 'actual produced native bytes')
        same(receipt['produced_bytes'], len(image), 'receipt complete image extent')
        same(receipt['produced_image'], f.absolute('native', folder + '/module.image.bin'), 'receipt original image path')
        same(receipt['source_unchanged'], True, 'compiler source unchanged')
        same(receipt['forbidden_compiler_modules_loaded'], [], 'native compiler only')
        require(integer(receipt['native_elapsed_ns']) and integer(receipt['wall_elapsed_ns'], receipt['native_elapsed_ns']), 'compiler actual clocks')
        complete_output = f.read('native', folder + '/module.output.bin', receipt['output_sha256'])
        same(complete_output[:len(image)], image, 'compiler full output image prefix')
        if index < 3:
            same(m['members'][index]['image_bytes'], len(image), 'member exact image extent')
            same(m['members'][index]['image_sha256'], sha(image), 'member complete image fingerprint')
            images.append(image)
    f.read('native', 'build/build/bootstrap/B3.image.bin', contract['compiler_image_sha256'])
    frame = b'HTXTELF1' + struct.pack('<6Q', len(prefix), 3, m['table_offset'], *map(len, images)) + prefix + b''.join(images)
    same(f.read('native', 'build/packer.input.bin', m['input_frame_sha256']), frame, 'entire actual packer input')
    expected, positions = bytearray(prefix), []
    for image in images:
        expected.extend(bytes((-len(expected)) % 16)); positions.append(len(expected)); expected.extend(image)
    struct.pack_into('<QQ', expected, 96, len(expected), len(expected))
    for slot, pos in enumerate(positions): struct.pack_into('<Q', expected, m['table_offset'] + 8*slot, 0x400000 + pos)
    same(m['image_offsets'], positions, 'actual embedded image offsets')
    elf = f.read('native', 'build/' + m['elf'], m['elf_sha256'])
    same(elf, bytes(expected), 'whole actual static ELF byte equality')
    same(f.read('native', 'build/packer.output.bin'), elf, 'HIA packer complete output')
    return m

def result_record(raw):
    require(len(raw) >= 64 and raw[:8] == b'HTXTER01', 'complete native result envelope')
    code, gen, seq, size, live, phase, reserved = struct.unpack_from('<7Q', raw, 8)
    require(code <= INVALID and size == len(raw)-64 and live == reserved == 0, 'native terminal result fields')
    body = raw[64:]
    if code < 0xffff0000:
        require(code == len(body) and body[:8] == b'HTXTR001' and len(body) >= 64, 'native body and result length')
        tag, n, total, new, bodygen, bodyseq, zero = struct.unpack_from('<7Q', body, 8)
        require((gen, seq) == (bodygen, bodyseq) and zero == 0 and tag in (0, 1, 2), 'native body lifetime')
        if tag == 0:
            require(len(body) == 160 and n == 0 and new in (0, 1) and body[152:] == bytes(8) and phase == 100, 'success body')
        elif tag == 1:
            require(len(body) == 64+n and total == new == 0 and phase == 100, 'complete diagnostic body')
            body[64:].decode('utf-8')
        else:
            require(len(body) == 64 and n == total == new == phase == 0, 'DROP body')
    else:
        require(not body, 'private refusal has no result body')
    return {'code':code, 'generation':gen, 'sequence':seq, 'phase':phase, 'body':body}

def framed(raw):
    result, at = [], 0
    while at < len(raw):
        require(len(raw)-at >= 8, 'complete frame length')
        size = q(raw, at); at += 8
        require(size <= len(raw)-at, 'complete frame payload')
        result.append(raw[at:at+size]); at += size
    return result

def receipt_records(raw, *, terminal=True):
    require(len(raw) % 256 == 0, 'complete 256-byte effect stream')
    records, lastgen, state, opened, closed = [], 0, [(-1, 0)]*4, 0, 0
    for at in range(0, len(raw), 256):
        frame = raw[at:at+256]
        require(frame[:8] == b'HTXTEF01' and frame[64:72] == b'HTXTFX01', 'effect and completion magic')
        gen, seq, kind, phase, ret, capacity, reserved = struct.unpack_from('<7Q', frame, 8)
        fields = struct.unpack_from('<15Q', frame, 72)
        require(fields[:3] == (seq,gen,kind), 'effect/completion identity')
        args = list(fields[3:9]); value, error, aux, ready, flags, zero = fields[9:]
        require(seq == len(records)+1 and gen >= lastgen and gen > 0 and 1 <= kind <= 19,
                'strict complete effect sequence and generation')
        require(capacity >= 4096 and reserved == aux == flags == zero == 0 and ready == 1,
                'source-owned completion flags')
        ret = signed(ret)
        require(error <= 4095 and (not error or (value == 0 and ret == -error)), 'exact Linux errno normalization')
        current = [struct.unpack_from('<qQ', frame, 192+16*i) for i in range(4)]
        expected = list(state)
        if kind in (1,2,6,13):
            slot = args[0] if kind == 1 else args[1]
            require(1 <= slot <= 4 and state[slot-1] == (-1,0), 'open owns an empty exact slot')
            if kind != 1: require(1 <= args[0] <= 4 and state[args[0]-1][0] >= 0, 'openat parent is owned')
            if not error:
                require(value == 1 and 0 <= ret <= 0x7fffffff and ret not in [x[0] for x in state], 'actual open FD normalization')
                expected[slot-1] = (ret, seq); opened += 1
        elif kind == 3:
            slot, serial = args[:2]
            require(1 <= slot <= 4 and state[slot-1][0] >= 0 and state[slot-1][1] == serial,
                    'close consumes its own opening serial')
            expected[slot-1] = (-1, 0); closed += 1
        elif kind in (4,5,7,9,10,14,15,16,17,18):
            slot = args[0]
            require(1 <= slot <= 4 and state[slot-1][0] >= 0, 'filesystem effect borrows a live owned FD')
        same(current, expected, 'complete descriptor ownership after actual effect')
        if kind in (10,15) and not error: require(0 <= ret == value <= args[2], 'bounded actual transfer')
        records.append({'stream_offset':at, 'generation':gen, 'sequence':seq, 'kind':kind,
                        'phase':phase, 'raw_linux_return':ret, 'workspace_capacity':capacity,
                        'args':args, 'value':value, 'errno':error,
                        'slots':[{'slot':i+1,'fd':fd,'opening_sequence':serial} for i,(fd,serial) in enumerate(current)],
                        'frame_sha256':sha(frame)})
        state, lastgen = current, gen
    if terminal: require(state == [(-1,0)]*4 and opened == closed, 'all actual FD serials retired before terminal result')
    return records

def snapshot_tree(f, folder, rows):
    require(type(rows) is list and rows, 'full captured filesystem tree')
    seen, nodes = set(), {}
    for row in rows:
        path = unb64(row['path_base64'])
        require(path not in seen and not path.startswith(b'/') and b'\0' not in path
                and all(x not in (b'.',b'..') for x in path.split(b'/')), 'owned unique raw snapshot path')
        seen.add(path); nodes[path] = row
        require(row['kind'] in ('file','directory','symlink','fifo','socket','other'), 'actual snapshot node type')
        require(integer(row['mode']) and row['mode'] <= 0o7777 and integer(row['uid'])
                and integer(row['gid']) and integer(row['nlink']), 'snapshot POSIX metadata')
        require(type(row['identity']) is list and len(row['identity']) == 7
                and all(unsigned(x) for x in row['identity']) and row['identity'][4] < 10**9
                and row['identity'][6] < 10**9, 'seven complete Linux version fields')
        if 'xattrs' in row:
            require('xattr_errno' not in row and type(row['xattrs']) is dict, 'actual xattr result')
            for key, value in row['xattrs'].items(): unb64(key); unb64(value)
        else: require(integer(row.get('xattr_errno'),1), 'actual xattr error')
        if row['kind'] == 'file':
            if 'data' in row:
                item = row['data']; same(item['file'], item['sha256']+'.bin', 'content-addressed full file')
                raw = f.read('corpus', folder+'/blobs/'+item['file'], {k:item[k] for k in ('bytes','sha256')})
                same(len(raw), row['identity'][2], 'full file bytes match actual size')
                require('read_errno' not in row, 'exclusive actual file observation')
            else: require(integer(row.get('read_errno'),1), 'captured actual read failure')
        elif row['kind'] == 'symlink': unb64(row['target_base64'])
        else: require('data' not in row, 'only ordinary files have bytes')
    require(nodes.get(b'',{}).get('kind') == 'directory', 'complete tree includes owned root')
    for path in seen-{b''}:
        parent = path.rsplit(b'/',1)[0] if b'/' in path else b''
        require(nodes.get(parent,{}).get('kind') == 'directory', 'snapshot parent closure')
    return nodes

def tree_bytes(f, folder, node):
    item = node['data']
    return f.read('corpus', folder+'/blobs/'+item['file'], {k:item[k] for k in ('bytes','sha256')})

def setup_binding(f, folder, desc, before, materialize):
    nodes = snapshot_tree(f, folder, before)
    require(set(nodes) == {b''} | {unb64(x['path_base64']) for x in desc['setup']}, 'complete explicit initial fixture')
    same(nodes[b'']['mode'], 0o700, 'owned fixture directory mode')
    for item in desc['setup']:
        path = unb64(item['path_base64']); node = nodes[path]; kind = item['kind']
        same(node['kind'], 'file' if kind == 'hardlink' else kind, 'actual initial node kind')
        if kind == 'file':
            same(node['mode'], item['mode'], 'actual initial file mode')
            same(node['identity'][2], len(materialize(item['data'])), 'initial full data size')
            if 'data' in node: same(tree_bytes(f, folder, node), materialize(item['data']), 'actual complete initial file data')
            same(node.get('xattrs'), {b64(k.encode()):v for k,v in item['xattrs'].items()}, 'initial actual xattrs')
        elif kind == 'hardlink':
            original = nodes[unb64(item['target_base64'])]
            same(node['identity'], original['identity'], 'actual hardlink inode/version identity')
            require(node['nlink'] == original['nlink'] == 2, 'actual closed hardlink group')
        elif kind == 'symlink': same(node['target_base64'], item['target_base64'], 'actual raw symlink target')
    return nodes

def expected_request(f, folder, desc, fixture, before, materialize):
    req = desc['request']; path = unb64(req['path_base64'])
    require(req['path_anchor'] in ('fixture','literal'), 'explicit input path origin')
    if req['path_anchor'] == 'fixture': path = os.fsencode(fixture)+path
    content = materialize(req['content']); spec = req['expected']
    if 'literal_hex' in spec: expected = bytes.fromhex(spec['literal_hex'])
    elif 'data' in spec: expected = sha(materialize(spec['data'])).encode()
    else: expected = sha(tree_bytes(f, folder, before[unb64(spec['file_base64'])])).encode()
    raw = bytearray(b'HTXTQ001'+struct.pack('<7Q',1,req['mode'],len(path),len(content),len(expected),0,0)+path+expected+content)
    edit = req['wire_edit']
    if edit:
        if 'truncate' in edit: del raw[edit['truncate']:]
        elif 'append_hex' in edit: raw.extend(bytes.fromhex(edit['append_hex']))
        else:
            value = struct.pack('<Q',edit['u64']) if 'u64' in edit else bytes.fromhex(edit['hex'])
            raw[edit['offset']:edit['offset']+len(value)] = value
    return bytes(raw), {'path_base64':b64(path),'mode':req['mode'],'expected_base64':b64(expected),
                        'content_bytes':len(content),'content_sha256':sha(content)}

def non_directory(rows): return [row for row in rows if row['kind'] != 'directory']
def stable_nodes(rows):
    return [row for row in non_directory(rows) if not unb64(row['path_base64']).split(b'/')[-1].startswith(b'.hepta-text-')]

def complete_actor(f, folder, desc, actor, selected, materialize):
    same(actor['effect_results_injected'], False, 'actual external writer, no substitute completions')
    same(actor['operation'], desc['race']['action'], 'input-owned actor operation')
    require(integer(actor['monotonic_start_ns'],1) and integer(actor['monotonic_end_ns'],actor['monotonic_start_ns']), 'actual actor clocks')
    trigger = desc['race']['trigger']
    matched = [r for r in selected if r['kind'] == trigger['kind'] and r['errno'] == 0
               and r['args'][:len(trigger.get('args_prefix',[]))] == trigger.get('args_prefix',[])
               and all(r['args'][int(k)] == v for k,v in trigger.get('arg_equals',{}).items())]
    require(matched, 'actor has an actual eligible completed effect')
    r = matched[0]
    expected = {k:r[k] for k in ('generation','sequence','kind','phase','args','value','errno','workspace_capacity')}
    expected['raw_return'] = r['raw_linux_return'] & U64
    same(actor['trigger_receipt'], expected, 'actor fires exactly at first admitted real effect')
    before = snapshot_tree(f, folder, actor['before']); after = snapshot_tree(f, folder, actor['after'])
    action = actor['operation']; op = action['op']; target = unb64(desc['expect']['target_base64'])
    if op == 'rename_parent':
        old,new = unb64(action['from_base64']),unb64(action['to_base64'])
        require(old in before and old not in after and new in after, 'actual directory move')
        same(before[old]['identity'][:2], after[new]['identity'][:2], 'renamed held directory identity')
    elif op == 'unlink': require(target in before and target not in after, 'actual unlink mutation')
    else:
        require(target in after, 'actual writer target exists')
        a = after[target]; b = before.get(target)
        if op == 'symlink':
            same(a['kind'],'symlink','actual symlink replacement'); same(a['target_base64'],action['target_base64'],'exact actor symlink bytes')
        elif op == 'chmod_and_mtime':
            same(a['mode'],action['mode'],'actual changed mode')
            same(a['identity'][:3],b['identity'][:3],'chmod retains inode/size')
            same(a['identity'][3]*10**9+a['identity'][4],b['identity'][3]*10**9+b['identity'][4]-2*10**9,'actual requested mtime')
        else:
            require(a['kind']=='file','actual writer ordinary file')
            if op == 'append': wanted = tree_bytes(f,folder,b)+materialize(action['data'])
            elif op == 'truncate': wanted = tree_bytes(f,folder,b)[:action['size']]
            else: wanted = materialize(action['data'])
            same(tree_bytes(f,folder,a),wanted,'complete actual external writer content')
            if op in ('append','truncate','overwrite'): same(a['identity'][:2],b['identity'][:2],'same-inode actor operation')
            if op == 'overwrite': same(a['identity'][2],b['identity'][2],'same-size external overwrite')
            if op == 'replace': require(a['identity'][:2] != b['identity'][:2],'actual replacement inode')
            if op == 'create': require(b is None,'exclusive competing create')
    return actor['trigger_receipt']['sequence']

def corpus_evidence(f, contract, m, generators):
    fixtures, races = generators
    descriptions = fixtures.corpus(); all_cases = 0; total_effects = 0; result_domains = {}
    top = f.obj('corpus','RESULT.json')
    diagnostics = f.obj('corpus','source/authoring/diagnostics.json')
    same(len(diagnostics),26,'complete source diagnostic table')
    elf_path = f.absolute('native','build/'+m['elf']); elf_pin = pin(f.read('native','build/'+m['elf']))
    for domain, (count, effect_count) in contract['domains'].items():
        is_race = domain == 'races'; folder = 'domains/'+domain
        descs = races.race_cases() if is_race else [x for x in descriptions if x['domain']==domain]
        same(len(descs),count,'source-owned complete domain size')
        same(f.obj('corpus',folder+'/corpus.json'),descs,'exact finite source input corpus')
        result = f.obj('corpus',folder+'/RESULT.json'); same(result['status'],'PASS','actual full domain success')
        same(result['schema'],'hepta.runtime.text-publication-native-races.v1' if is_race else 'hepta.runtime.text-publication-native-domain.v1','domain result schema')
        same(result['cases'],count,'all cases completed'); same(result['native_effects'],effect_count,'all effect count')
        same(result['native_elf'],dict(path=elf_path,**elf_pin),'same actual native ELF')
        for flag in ('original_comparison_complete','public_handler_complete','whole_runtime_replaced'):
            same(result[flag],False,'domain scope: '+flag)
        if is_race:
            same(result['actual_external_mutations'],20,'twenty actual external writers')
            same(result['injected_effect_results'],0,'no race completion injection')
            same(result['syscall_fault_qualification_complete'],False,'race and fault scope separate')
        else:
            same(result['original_eligible_cases'],0 if domain=='admission' else count,'original eligible domain')
            same(result['private_descriptor_controls_complete'],False,'no private controls in ordinary domain')
            same(result['race_and_fault_qualification_complete'],False,'ordinary result scope')
        require(number(result['elapsed_seconds']) and result['elapsed_seconds'] <= 180,'finite domain duration')
        names = ['hia_native_text_publication_fixtures.py','qualify_hia_text_publication_native.py']
        if is_race: names.append('qualify_hia_text_publication_races.py')
        same(result['source_pins'],{n:pin(f.read('corpus','source/scripts/'+n)) for n in names},'actual domain source closure')
        same(result['corpus'],pin(f.read('corpus',folder+'/corpus.json')),'full corpus pin')
        child = f.obj('corpus',folder+'/process/process.json'); same(result['process'],child,'actual child process receipt')
        same(child['command'],[elf_path,'--sync' if is_race else '--trace'],'actual child command')
        same(child['cwd'],f.absolute('corpus',folder+'/process'),'actual child cwd')
        clocks(child,180,timed=False)
        same(child['failure'],None,'native capture failure'); same(child['killed_by_harness'],False,'native natural completion')
        same(child['stdout_unframed_bytes'],0,'no unframed native bytes')
        streams = process_streams(f,'corpus',folder+'/process',child)
        receipts = receipt_records(streams['stderr']); same(len(receipts),effect_count,'complete actual effect stream')
        same(f.obj('corpus',folder+'/effects.json'),receipts,'every full effect agrees with index')
        same(result['effects'],pin(f.read('corpus',folder+'/effects.json')),'effects index pin')
        expected_in, expected_out, rows, gen, seq, exchange_index = bytearray(),bytearray(),[],0,0,0
        previous_stderr = 0
        for ordinal, desc in enumerate(descs):
            name = desc['name']; case = folder+'/cases/'+name
            row = f.obj('corpus',case+'/case.json')
            before,after = f.obj('corpus',case+'/before.json'),f.obj('corpus',case+'/after.json')
            before_nodes = setup_binding(f,folder,desc,before,fixtures.materialize)
            after_nodes = snapshot_tree(f,folder,after)
            fixture = f.absolute('corpus',folder+'/fixtures/'+str(ordinal))
            wire, request = expected_request(f,folder,desc,fixture,before_nodes,fixtures.materialize)
            same(f.read('corpus',case+'/input.bin'),wire,'complete actual request bytes')
            record = f.read('corpus',case+'/record.bin'); response = result_record(record)
            private = desc['expect']['kind']=='private'
            require(response['generation'] == gen+(not private) and response['sequence'] >= seq,'retained request lifetime progression')
            if private: require(response['code']==INVALID and response['phase']==0 and response['sequence']==seq and before==after,'private malformed frame no effects')
            selected = receipts[seq:response['sequence']]
            require(all(r['generation']==response['generation'] for r in selected),'request owns all selected effects')
            published = [r for r in selected if r['kind']==17 and r['errno']==0]
            same(len(published),int(desc['race']['published']) if is_race else int(desc['expect']['kind']=='success'),'actual rename commits independently of reply')
            body = response['body']; observation = None; actor_seq = None
            if is_race:
                actor = f.obj('corpus',case+'/actor.json')
                actor_seq = complete_actor(f,folder,desc,actor,selected,fixtures.materialize)
            if not private:
                require(response['code']==len(body) and response['phase']==100,'completed HIA response')
                tag,n,total,new,bg,bs,z = struct.unpack_from('<7Q',body,8)
                if desc['expect']['kind']=='error':
                    error = desc['expect']['error']; message = diagnostics[error] if type(error) is int else error
                    require(tag==1 and body[64:]==message.encode(),'complete original diagnostic bytes')
                    same(stable_nodes(after),stable_nodes(actor['after']),'failed race preserves real external write') if is_race else same(before,after,'ordinary failed publication changes no tree')
                    if is_race: observation={'error':message,'publication_observed_before_error':desc['race']['published']}
                else:
                    require(tag==0,'successful native result')
                    target = unb64(desc['race']['after_target_base64'] if is_race else desc['expect']['target_base64'])
                    node = after_nodes[target]; same(node['kind'],'file','complete published target')
                    wanted = fixtures.expected_output(desc)
                    actual_want = fixtures.materialize(desc['race']['actual_data']) if is_race else wanted
                    actual = tree_bytes(f,folder,node); same(actual,actual_want,'whole published file, no prefix comparison')
                    require(total==len(wanted) and body[120:152]==hashlib.sha256(wanted).digest(),'full native count/SHA')
                    same(list(struct.unpack_from('<7Q',body,64)),node['identity'],'native seven-field actual version')
                    same(new,int(desc['request']['mode']==1),'original create indicator')
                    if is_race:
                        observation={'native_bytes':total,'native_sha256':body[120:152].hex(),'actual_bytes':len(actual),
                                     'actual_sha256':sha(actual),'version':node['identity'],
                                     'same_inode_external_overwrite_preserved':desc['race']['action']['op']=='overwrite'}
                    else:
                        old = before_nodes.get(target); mode = 0o600 if new else old['mode']
                        require(node['mode']==mode and node['nlink']==1 and node.get('xattrs')=={},'plain published file metadata')
                        if old: require(old['identity'][:2]!=node['identity'][:2],'publication replaced old inode')
                        same([r for r in non_directory(before) if unb64(r['path_base64'])!=target],
                             [r for r in non_directory(after) if unb64(r['path_base64'])!=target],'all unrelated nodes unchanged')
                        observation={'bytes':len(wanted),'sha256':sha(wanted),'mode':mode,'version':node['identity']}
                require(all(not p.split(b'/')[-1].startswith(b'.hepta-text-') for p in after_nodes),'no remaining temporary file')
            first = seq+1; gen=response['generation']; seq=response['sequence']
            expected_row={'name':name,'ordinal':ordinal,'status':'PASS','fixture':fixture,'request':request,
                          'generation':gen,'first_sequence':first,'last_sequence':seq,'effects':seq-first+1,
                          'observation':observation,'input':pin(wire),'record':pin(record)}
            if is_race: expected_row.update(actor_sequence=actor_seq,published=desc['race']['published'],actor=pin(f.read('corpus',case+'/actor.json')))
            else: expected_row.update(kind=desc['expect']['kind'],original_eligible=desc['original_eligible'],code=response['code'])
            same(row,expected_row,'complete case index regenerated from actual bytes')
            rows.append(row)
            pairs=[(name,wire,record,selected)]
            if not private:
                drop=b'HTXTQ001'+struct.pack('<7Q',2,0,0,0,0,gen,0)
                drop_record=f.read('corpus',case+'/drop-record.bin'); dr=result_record(drop_record)
                same(dr,{'code':64,'generation':gen,'sequence':seq,'phase':0,
                         'body':b'HTXTR001'+struct.pack('<7Q',2,0,0,0,gen,seq,0)},'complete explicit DROP')
                pairs.append((name+'/drop',drop,drop_record,[]))
            for label,inp,out,events in pairs:
                require(exchange_index<len(child['exchanges']),'all exchange receipts present')
                ex=child['exchanges'][exchange_index]; exchange_index+=1
                before_in,before_out=len(expected_in),len(expected_out)
                expected_in.extend(struct.pack('<Q',len(inp))+inp)
                if is_race:
                    for event in events: expected_in.extend(b'HTXTACK1'+struct.pack('<2Q',event['generation'],event['sequence']))
                expected_out.extend(struct.pack('<Q',len(out))+out)
                same(ex['kind'],label,'exact exchange order'); same(ex['timeout_seconds'],60,'unchanged per-exchange 60s')
                require(number(ex['elapsed_seconds']) and ex['elapsed_seconds']<=60,'actual exchange duration')
                same({k:ex[k] for k in ('request_bytes','request_sha256','record_bytes','record_sha256')},
                     {'request_bytes':len(inp),'request_sha256':sha(inp),'record_bytes':len(out),'record_sha256':sha(out)},'complete exchange byte pins')
                same(ex['started_stream_offsets']['stdin'],before_in,'actual stdin start offset')
                same(ex['ended_stream_offsets']['stdin'],len(expected_in),'actual stdin end offset')
                same(ex['started_stream_offsets']['stdout'],before_out,'actual stdout start offset')
                same(ex['ended_stream_offsets']['stdout'],len(expected_out),'actual stdout end offset')
                begin,end=ex['started_stream_offsets']['stderr'],ex['ended_stream_offsets']['stderr']
                require(integer(begin,previous_stderr) and integer(end,begin) and end<=len(streams['stderr']),'actual stderr read offsets')
                previous_stderr=end
                if is_race:
                    same(ex['effect_receipts'],len(events),'all completed sync effects')
                    same(ex['identity_only_acknowledgements'],len(events),'identity-only ACK count')
                    same(end-begin,len(events)*256,'exact sync receipt bytes')
        same(exchange_index,len(child['exchanges']),'no duplicate or omitted exchanges')
        same(bytes(expected_in),streams['stdin'],'whole actual stdin including all ACKs')
        same(bytes(expected_out),streams['stdout'],'whole actual stdout, no extra results')
        same(result['rows'],rows,'complete result case set')
        wrapper=f.obj('corpus',domain+'.process.json')
        script='qualify_hia_text_publication_races.py' if is_race else 'qualify_hia_text_publication_native.py'
        command=['/usr/bin/python3','-I','-B',f.absolute('corpus','source/scripts/'+script),
                 '--elf',elf_path,'--output',f.absolute('corpus',folder),
                 '--diagnostics',f.absolute('corpus','source/authoring/diagnostics.json')]
        if not is_race: command.extend(['--domain',domain])
        outer=checked_process(f,'corpus',wrapper,command,f.absolute('corpus','source'),domain)
        same(outer['stderr'],b'','successful outer complete stderr')
        messages=[decode(line) for line in outer['stdout'].splitlines()]
        same(len(messages),count+1,'each actual case plus summary stdout')
        for row,message in zip(rows,messages[:-1]):
            expected={'case':row['name'],'status':'PASS','effects':row['effects']}
            expected['published' if is_race else 'code']=row['published' if is_race else 'code']
            same(message,expected,'actual per-case stdout')
        same(messages[-1],{k:v for k,v in result.items() if k not in ('rows','process','source_pins')},'actual full stdout summary')
        result_domains[domain]={'cases':count,'effects':effect_count,'elf_processes':1,
                                'exchanges':exchange_index,'source_sha256':result['source_pins']}
        all_cases+=count; total_effects+=effect_count
    same(all_cases,144,'all native original/private/race cases'); same(total_effects,3675,'all ordinary/race effects')
    # The orchestration record also retains its actual six complete processes.
    require(type(top) is dict,'actual corpus orchestration result')
    same(top['status'],'PASS','complete actual orchestration')
    same(top['cases'],144,'orchestration complete case count'); same(top['normal_cases'],124,'normal/private count')
    same(top['external_writer_cases'],20,'external writer count')
    same(top['native_elf_sha256'],m['elf_sha256'],'orchestration exact native ELF')
    same(top['source_and_native_bytes_unchanged'],True,'actual source unchanged check')
    for flag in ('original_comparison_complete','syscall_fault_qualification_complete','whole_runtime_replaced'):
        same(top[flag],False,'orchestration scope')
    expected_rows=[]
    for domain in ['ordinary','paths','metadata','wide','admission','races']:
        row=f.obj('corpus',domain+'.process.json')
        row.update(result=pin(f.read('corpus','domains/'+domain+'/RESULT.json')),
                   cases=contract['domains'][domain][0],native_effects=contract['domains'][domain][1])
        expected_rows.append(row)
    same(top['domains'],expected_rows,'actual six orchestration process records')
    native_pins=f.obj('corpus','NATIVE-PINS.json')
    require(len(native_pins)==16,'complete corpus-to-build source/image binding')
    for absolute, expected in native_pins.items():
        require(absolute.startswith(f.roots['native']+'/'),'single exact native origin')
        f.read('native',absolute[len(f.roots['native'])+1:],expected)
    return result_domains

def assembly_processes(f, group, folder, commands):
    for index, command in enumerate(commands):
        path=folder+'/boundary-'+str(index); row=f.obj(group,path+'.process.json')
        actual=row['command']; require(type(actual) is list and actual and actual[0].startswith('/usr/bin/'),'actual native assembly executable')
        executable=Path(actual[0]).name
        allowed={command[0],'x86_64-linux-gnu-'+command[0]}
        if command[0]=='ld': allowed.update({'ld.bfd','x86_64-linux-gnu-ld.bfd'})
        require(executable in allowed,'exact resolved native binutils kind')
        same(actual[1:],command[1:],'complete native assembly arguments')
        same(row['controlled_env'],{'LC_ALL':'C'},'actual native assembly environment')
        require(type(row['executable_sha256']) is str and len(row['executable_sha256'])==64,'recorded assembly executable identity')
        streams=checked_process(f,group,row,actual,f.absolute(group,folder),path)
        same(streams['stderr'],b'','actual assembly stderr')
        if command[0]=='readelf': require(b'There are no relocations' in streams['stdout'],'actual relocation-free native object')

def mechanical_processes(f, m):
    root=f.roots['native']; source=root+'/source'; manifest=root+'/build/manifest.json'
    native=f.obj('native','PROCESSES.json')
    same([r['name'] for r in native],['assemble','author-packer','build','native-smoke','callable-controls'],'all actual native build/test processes')
    commands=[['/usr/bin/python3','-I','-B','-c',"import sys;from pathlib import Path;sys.path.insert(0,'"+source+"/scripts');from hia_native_text_publication_build import assemble_boundary;prefix,table=assemble_boundary(Path('"+source+"'),Path('"+root+"/authoring-boundary'));print(table)"],
              ['/usr/bin/python3','-I','-B',source+'/authoring/text_publication/author_packer.py',root+'/authoring-boundary/prefix.bin','768'],
              ['/usr/bin/python3','-I','-B',source+'/scripts/hia_native_text_publication_build.py','--hepta','/home/qq/config-publication-7c/compiler','--output',root+'/build','--source',source]]
    for name,test in [('native-smoke','test_text_publication_elf.py'),('callable-controls','test_text_publication_callable.py')]:
        commands.append(['/usr/bin/python3','-I','-B',source+'/tests/hia_native/'+test,'--manifest',manifest,'--output',root+'/'+name])
    for row, command in zip(native,commands):
        streams=checked_process(f,'native',row,command,source,row['name'])
        same(streams['stderr'],b'','native build/test complete stderr')
    for folder in ('build','authoring-boundary'):
        base=root+'/'+folder
        assembly_processes(f,'native',folder,[['as','--64','-o',base+'/boundary.o',base+'/combined.S'],
            ['readelf','-r',base+'/boundary.o'],['objcopy','-O','binary','-j','.text',base+'/boundary.o',base+'/boundary.bin'],['nm','-n',base+'/boundary.o']])
    boundary=f.obj('boundary','PROCESS.json')
    command=['/usr/bin/python3','-I','-B',f.absolute('boundary','source/tests/hia_native/test_text_publication_boundary.py'),
             '--manifest',manifest,'--output',f.absolute('boundary','controls')]
    same(boundary['command'],command,'actual boundary wrapper command'); same(boundary['cwd'],f.absolute('boundary','source'),'boundary cwd');clocks(boundary,180)
    for stream in ('stdout','stderr'): f.read('boundary',stream,boundary[stream])
    same(boundary['baseline_unchanged'],True,'boundary baseline unchanged'); same(boundary['source_unchanged'],True,'boundary sources unchanged')
    faults=f.obj('faults','PROCESSES.json'); same([r['name'] for r in faults],['pilot','full'],'actual pilot and complete fault suite')
    for row in faults:
        command=['/usr/bin/python3','-I','-B',f.absolute('faults','source/tests/hia_native/test_text_publication_faults.py'),
                 '--manifest',manifest,'--output',f.absolute('faults',row['name'])]
        if row['name']=='pilot': command += ['--only','create']
        streams=checked_process(f,'faults',row,command,f.absolute('faults','source'),row['name'])
        same(streams['stderr'],b'','fault suite complete stderr')
    return native, boundary, faults

def capture_records(f, group, folder, kind):
    index=f.obj(group,folder+'/capture.json'); raw=gzip.decompress(f.read(group,folder+'/calls.bin.gz'))
    same(pin(raw),{'bytes':index['raw_bytes'],'sha256':index['raw_sha256']},'complete private raw capture digest')
    rows=index['rows'] if kind=='callable' else index['records']; offset=0; records=[]
    if kind=='callable': same(index['calls'],13,'complete callable record count')
    for i,row in enumerate(rows,1):
        start=offset
        if kind=='callable':
            require(raw[offset:offset+8]==b'HTXTCAP1','private callable stream magic')
            ident,label,code,*sizes=struct.unpack_from('<8Q',raw,offset+8); offset+=72
            require(label==0,'private callable reserved')
        else:
            require(raw[offset:offset+8]==b'HTXTBND1','private boundary stream magic')
            ident,code,n=struct.unpack_from('<3Q',raw,offset+8); offset+=32
            require(n==5,'five complete private spans');sizes=struct.unpack_from('<5Q',raw,offset); offset+=40
        require(ident==i and sum(sizes)<=len(raw)-offset,'complete sequential private record')
        parts=[]
        for size in sizes: parts.append(raw[offset:offset+size]);offset+=size
        same(row['index'],i,'private record index'); same(row['offset'],start,'private record exact offset')
        same(row['extent'],offset-start,'private record extent'); same(row['spans'],[pin(x) for x in parts],'all complete private buffers')
        same(row['code'] if kind=='callable' else row['return'],code if kind=='callable' else signed(code),'private native return')
        records.append((row,parts))
    same(offset,len(raw),'no trailing or missing private records')
    return records

def callable_controls(f,m):
    folder='callable-controls'; result=f.obj('native',folder+'/RESULT.json')
    same(result['status'],'PASS','actual callable controls passed'); same(result['test_groups'],3,'callable groups')
    same(result['actual_hia_requests'],13,'actual callable HIA count'); same(result['allocation_controls'],5,'real allocation controls')
    same(result['manifest_sha256'],sha(f.read('native','build/manifest.json')),'callable same compiled images')
    for k in ('original_reference_executed','production_mcp_route_replaced'): same(result[k],False,'callable scope')
    same(result['original_cases_added'],0,'no new original semantic cases')
    names=['scripts/text_publication_engine.S','scripts/text_publication_effects.S','scripts/text_publication_children.S','scripts/text_publication_transport.S']
    same(result['source_sha256'],{n:m['sources'][n] for n in names},'same four callable sources')
    same(f.read('native',folder+'/callable/combined.S'),b'\n'.join(f.read('native','source/'+n) for n in names),'same actual callable assembly')
    f.read('native',folder+'/callable/callable.so',result['callable_sha256'])
    base=f.absolute('native',folder+'/callable')
    assembly_processes(f,'native',folder+'/callable',[
        ['as','--64','-o',base+'/callable.o',base+'/combined.S'],['readelf','-r',base+'/callable.o'],
        ['ld','-shared','-z','noexecstack','-o',base+'/callable.so',base+'/callable.o']])
    labels=['dirty-initial-state','workspace-enomem','workspace-retry','wrong-drop-generation','explicit-drop',
            'warm-input-with-invalid-op','post-publication-output-enomem','pending-output-different-input',
            'pending-output-wrong-drop','output-only-retry','second-explicit-drop',
            'terminal-result-discard-enomem','terminal-result-discard-drop']
    codes=[STATE,RESOURCE,160,STATE,64,INVALID,RESOURCE,STATE,STATE,160,64,RESOURCE,64]
    records=capture_records(f,'native',folder,'callable'); same(len(records),13,'complete actual callable input set')
    for (row,parts),label,code in zip(records,labels,codes):
        wire,bo,bw,ao,aw=parts; same(row['label'],label,'exact private input order');same(row['code'],code,'actual callable return')
        for key,work,out in [('engine_before',bw,bo),('engine_after',aw,ao)]:
            state=row[key]
            same(state['workspace_capacity'],len(work),'actual complete workspace extent')
            same(state['output_capacity'],len(out),'actual complete output extent')
            for field,offset in [('phase',0),('grow_need',40),('output_need',48),('sequence',56),('generation',64)]:
                same(state[field],q(work,offset),'private state equals captured work bytes')
            require(all(integer(state[x],1) for x in ('engine','workspace','output','input')),'actual callable mapped pointers')
        state=row['engine_after'];same(state['busy'],0,'callable busy cleared');same(state['fd_mask'],0,'callable no live FD')
        same(state['fd_slots'],[[-1,0]]*4,'complete callable FD slots')
        same(state['last_code'],code,'actual engine last return')
        if code in (STATE,INVALID):
            same((ao,aw),(bo,bw),'all refusal output/workspace bytes unchanged')
            same(state['payload_len'],0,'private refusal no payload')
        elif code==RESOURCE:
            same(state['payload_len'],0,'resource failure no delivered payload')
            if label=='workspace-enomem':
                same(state['workspace'],row['engine_before']['workspace'],'failed workspace allocation keeps old mapping')
                require(state['phase']==0 and state['grow_need']>len(aw),'actual pending workspace growth')
            else: require(state['phase']==100 and state['output_need']==state['pending_output_growth']==160,'terminal output-only retry retained')
        else:
            body=ao[:code]; require(body[:8]==b'HTXTR001','actual callable HIA body')
            same(state['payload_len'],code,'actual delivered extent')
            if code==160: require(body[120:152]==hashlib.sha256(b'body\n').digest() and q(body,8)==0,'complete callable result digest')
            else: require(q(body,8)==2 and state['phase']==0 and state['pending_output_growth']==0,'explicit DROP clears pending delivery')
    same(records[9][0]['engine_after']['sequence'],records[6][0]['engine_after']['sequence'],'output retry repeats no effect')
    same(records[9][1][0],records[6][1][0],'identical complete retry input')
    allocations=f.obj('native',folder+'/allocations.json');same(len(allocations),5,'all five real budgets')
    for row,budget in zip(allocations,(0,4096,8192,12288,16384)):
        same(row['extra_address_space'],budget,'source-owned actual allocation budget');same(row['actual_return'],-12,'actual ENOMEM')
        require(integer(row['vmsize_before'],1),'real process VmSize')
        same(row['vmsize_after'],row['vmsize_before'],'partial-create mappings completely retired')
    return {'hia_requests':13,'real_allocation_failures':5}

def boundary_controls(f,m):
    result=f.obj('boundary','controls/RESULT.json'); same(result['status'],'PASS','actual boundary controls passed')
    same(result['test_groups'],2,'boundary groups');same(result['packer_calls'],18,'all native packer inputs')
    same(result['fd_controls'],{'actual_dispatch_calls':26,'actual_hia_calls':0,'closed_descriptors':3,
                               'opened_descriptors':3,'refusals':22,'two_engine_ownership':True},'mechanical FD controls scope')
    same(result['manifest_sha256'],sha(f.read('native','build/manifest.json')),'boundary exact compiled graph')
    same(result['original_cases_added'],0,'no original cases from mechanical controls');same(result['original_reference_executed'],False,'no boundary reference execution')
    names=['scripts/text_publication_engine.S','scripts/text_publication_effects.S','scripts/text_publication_children.S','scripts/text_publication_transport.S']
    same(result['source_sha256'],{n:m['sources'][n] for n in names},'exact mechanical dispatcher sources')
    wrapper='\n.global text_publication_test_dispatch\ntext_publication_test_dispatch:\n    TXT_ENTER\n    mov r15, rdi\n    call txt_dispatch_effect\n    TXT_LEAVE\n'
    combined=b'\n'.join(f.read('boundary','source/'+n) for n in names)+wrapper.encode()
    same(f.read('boundary','controls/descriptor-boundary/combined.S'),combined,'only mechanical dispatch wrapper appended')
    base=f.absolute('boundary','controls/descriptor-boundary')
    assembly_processes(f,'boundary','controls/descriptor-boundary',[
        ['as','--64','-o',base+'/boundary.o',base+'/combined.S'],['readelf','-r',base+'/boundary.o'],
        ['ld','-shared','-z','noexecstack','-o',base+'/boundary.so',base+'/boundary.o']])
    records=capture_records(f,'boundary','controls','boundary');same(len(records),44,'all packer and dispatch records')
    wire=f.read('native','build/packer.input.bin');elf=f.read('native','build/packer.output.bin')
    cases=[('complete',wire,len(elf),4096,len(elf))]
    def changed(name,offset,value):
        raw=bytearray(wire);struct.pack_into('<Q',raw,offset,value);cases.append((name,bytes(raw),len(elf),4096,INVALID))
    changed('magic',0,0);changed('prefix-size',8,q(wire,8)+1);changed('member-count',16,2);changed('table-offset',24,m['table_offset']+8)
    cases.extend([('short-header',wire[:55],len(elf),4096,INVALID),('short-workspace',wire,len(elf),23,CAPACITY),
                  ('truncated-prefix',wire[:56+q(wire,8)-1],len(elf),4096,CAPACITY)])
    for i in range(3):changed('empty-image-'+str(i),32+8*i,0)
    changed('overflow-image-size',32,U64)
    cases.extend([('trailing-input',wire+b'x',len(elf),4096,INVALID),('truncated-image',wire[:-1],len(elf),4096,INVALID),
                  ('short-output',wire,len(elf)-1,4096,CAPACITY)])
    bad=bytearray(wire);bad[56+q(wire,8)-1]^=1
    cases.extend([('prefix-fingerprint',bytes(bad),len(elf),4096,INVALID),('empty-output',wire,0,4096,CAPACITY),('empty-workspace',wire,len(elf),0,CAPACITY)])
    for (row,parts),(name,request,outcap,workcap,code) in zip(records[:18],cases):
        request_actual,bo,bw,ao,aw=parts
        same(row['label'],'packer:'+name,'source-owned packer control');same(row['return'],code,'actual packer control return')
        same(request_actual,request,'exact mutated packer input');same(bo,bytes([0xa5])*outcap,'complete initial output fill');same(bw,bytes([0x3c])*workcap,'complete initial workspace fill')
        if name=='complete':same(ao,elf,'full successful packer bytes');same(aw,bytes(24)+bw[24:],'exact successful workspace bytes')
        else: same(ao,bo,'whole packer refusal output unchanged')
    fdlabels=['magic','stale-sequence','future-sequence','zero-generation','other-generation','unknown-effect','wrong-slot','wrong-open-flags']
    fdlabels += ['nonzero-'+str(x) for x in (48,56,64,72,80,88,96,104,112,120)]
    fdlabels += ['open-a','open-b','already-owned-slot','stale-close-serial','unowned-close-slot','real-close-a','reopen-a','old-serial-after-reopen']
    success={'open-a','open-b','real-close-a','reopen-a'}; serials={}
    for (row,parts),label in zip(records[18:],fdlabels):
        wire,be,bw,ae,aw=parts
        same(row['label'],'fd:'+label,'source-owned mechanical dispatch input')
        require(len(be)==len(ae)==4096 and be[:8]==ae[:8]==b'HTXTEN02','complete two engine buffers')
        same(wire,bw[512:640],'actual installed private effect frame')
        if label not in success:
            same(row['return'],-22,'private dispatch rejects invalid ownership')
            same((be,bw),(ae,aw),'whole engine and workspace unchanged on FD refusal')
        else:
            same(row['return'],0,'actual mechanical dispatch success')
            if label=='real-close-a': require(struct.unpack_from('<qQ',ae,160)==(-1,0),'actual close clears exact slot')
            else:
                fd,serial=struct.unpack_from('<qQ',ae,160); require(fd>=0 and serial==q(wire,8),'actual open serial')
                serials[label]=(fd,serial)
        require(q(ae,40)==len(aw) and q(be,40)==len(bw),'full private work buffers')
    require(serials['open-a'][0]!=serials['open-b'][0] and serials['open-a'][1]!=serials['reopen-a'][1],'distinct owners and stale serial after reuse')
    return {'packer_calls':18,'mechanical_dispatch_calls':26,'mechanical_refusals':22,'new_hia_business_cases':0}

def pure_function(raw,name):
    tree=ast.parse(raw); nodes=[x for x in tree.body if isinstance(x,ast.FunctionDef) and x.name==name]
    require(len(nodes)==1,'exact source-owned input generator')
    namespace={};exec(compile(ast.Module(body=nodes,type_ignores=[]),'<admitted-input-function>','exec'),namespace)
    return namespace[name]

def fault_snapshot(f,folder,name,wire,*,terminal):
    info=f.obj('faults',folder+'/'+name+'.json')
    raw=gzip.decompress(f.read('faults',folder+'/'+name+'.bin.gz'))
    same(pin(raw),{'bytes':info['raw_bytes'],'sha256':info['raw_sha256']},'complete ptrace private snapshot')
    require(raw[:8]==b'HTXTFSP1' and len(raw)>=48,'complete ptrace snapshot format')
    sizes=struct.unpack_from('<5Q',raw,8);require(sum(sizes)==len(raw)-48,'complete ptrace spans')
    parts=[];at=48
    for size in sizes:parts.append(raw[at:at+size]);at+=size
    same(info['spans'],[pin(x) for x in parts],'all private pointer-owned buffers')
    engine,work,inp,out,header=parts
    require(len(engine)==4096 and engine[:8]==b'HTXTEN02','actual engine snapshot')
    same(len(work),q(engine,40),'full owned workspace');same(len(inp),q(engine,80),'full owned input extent')
    same(inp,wire,'original full borrowed request now owned');same(len(out),q(engine,56),'full output allocation')
    for field,offset in [('phase',0),('error_code',176),('error_errno',184),('owned',192),('published',224),('generation',64),('sequence',56)]:
        same(info[field],q(work,offset),'snapshot HIA field: '+field)
    for field,offset in [('engine_owned',136),('last_code',112),('payload_len',120)]:same(info[field],q(engine,offset),'snapshot engine field: '+field)
    same(info['fd_slots'],list(struct.unpack_from('<8q',engine,160)),'snapshot actual FD slots')
    if terminal:
        require(info['phase']==100 and info['owned']==info['engine_owned']==0 and info['fd_slots']==[-1,0]*4,'terminal FD retirement')
        same(set(info['proc_descriptors']),{'0','1','2'},'actual /proc owned-child descriptor set')
        require(len(header)==72 and header[8:16]==b'HTXTER01','actual queued response header')
    else:
        require(info['sequence']==1 and info['owned']==info['engine_owned']==0 and header==b'','before-first-kernel-effect snapshot')
    return info,parts

def fault_target(rule,nr,args,tags,published):
    kind=tags.get(args['rdi'])
    tests={'read':nr==0 and kind=='source','write':nr==1 and kind=='stage','entropy':nr==318,
           'chmod':nr==91 and kind=='stage','stage-fsync':nr==74 and kind=='stage',
           'parent-fsync':nr==74 and kind=='directory' and published,'rename':nr==316,
           'final-stat':nr==262 and published,'source-stat':nr==5 and kind=='source',
           'stage-stat':nr==5 and kind=='stage','stage-open':nr==257 and args['rdx']==655553,
           'source-close':nr==3 and kind=='source','stage-close':nr==3 and kind=='stage','unlink':nr==263}
    return tests[rule['target']]

def fault_syscalls(events,rules,process,receipts):
    register_names='r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi orig_rax rip cs eflags rsp ss fs_base gs_base ds es fs gs'.split()
    tags={};used=set();injections=[];published=False;opens=closes=0;owned_events=[];last=process['started_monotonic_ns']
    for i,event in enumerate(events,1):
        same(event['index'],i,'complete actual syscall order');nr=event['syscall'];args=event['entry']
        same(set(args),set(register_names),'all entry registers');require(all(unsigned(v) for v in args.values()),'unsigned register values')
        same(args['orig_rax'],nr,'real entered syscall number');same(event['fd_kind'],tags.get(args['rdi']),'actual live FD tag before syscall')
        require(integer(event['entry_monotonic_ns'],last) and event['entry_monotonic_ns']<=process['finished_monotonic_ns'],'actual syscall entry clock')
        last=event['entry_monotonic_ns']
        eligible=[j for j,r in enumerate(rules) if j not in used and fault_target(r,nr,args,tags,published)]
        rule=rules[eligible[0]] if eligible else None
        same(event['rule'],rule,'only source-owned first eligible fault rule')
        submitted=dict(args)
        if rule:
            used.add(eligible[0]);action=rule['action']
            if action=='short':submitted['rsi' if nr==318 else 'rdx']=rule['value']
            elif action=='skip':submitted['orig_rax']=U64
            else:same(action,'after','known mechanical injection action')
            same(event['submitted_entry'],submitted,'complete actually submitted register set')
        else:require('submitted_entry' not in event,'no unreported register mutation')
        if 'terminal_without_return' in event:
            require(i==len(events) and nr in (60,231) and args['rdi']==0 and event['terminal_without_return']==0 and rule is None,'natural final exit syscall')
            continue
        kernel=event['kernel_exit'];delivered=event['delivered_exit']
        same(set(kernel),set(register_names),'all kernel-return registers');same(set(delivered),set(register_names),'all delivered registers')
        require(all(unsigned(v) for v in kernel.values()) and all(unsigned(v) for v in delivered.values()),'complete raw unsigned return registers')
        for key in ('r15','r14','r13','r12','rbp','rbx','rdi','rsi','rdx','r10','r8','r9','orig_rax'):
            same(kernel[key],submitted[key],'actual kernel preserved submitted syscall register '+key)
        same(event['kernel_result'],signed(kernel['rax']),'actual Linux result equals kernel register')
        require(integer(event['exit_monotonic_ns'],last) and event['exit_monotonic_ns']<=process['finished_monotonic_ns'],'actual syscall exit clock');last=event['exit_monotonic_ns']
        expected=dict(kernel)
        if rule and rule['action'] in ('skip','after'):
            if rule['action']=='skip':same(event['kernel_result'],-38,'skipped syscall really returns ENOSYS')
            else:require(nr==3 and event['kernel_result']==0,'close EINTR follows actual kernel consumption')
            expected['rax']=rule['value']&U64
        same(delivered,expected,'no undocumented delivered register changes')
        same(event['delivered_result'],signed(delivered['rax']),'actual delivered return')
        if rule:injections.append(i)
        # Select only the owner's actual Linux operations, excluding the fixture
        # transport and mmap operations; HIA SHA/error calls have no syscall.
        owned=(nr==2 and args['rsi']==720896 or nr==257 and args['rdx'] in (720896,657408,655553)
               or nr in (3,73,262,5,196,0,91,1,74,316,263) and args['rdi'] in tags or nr in (107,318))
        if owned:owned_events.append(event)
        kernel_result=event['kernel_result']
        if kernel_result>=0 and not (rule and rule['action']=='skip'):
            if nr==2 and args['rsi']==720896:require(kernel_result not in tags,'kernel FD not already owned');tags[kernel_result]='directory';opens+=1
            if nr==257:
                require(args['rdx'] in (720896,657408,655553),'only exact owned openat flags')
                require(kernel_result not in tags,'openat FD not already owned');tags[kernel_result]={720896:'directory',657408:'source',655553:'stage'}[args['rdx']];opens+=1
            if nr==3 and args['rdi'] in tags:tags.pop(args['rdi']);closes+=1
            if nr==316:published=True
    require(not tags and opens==closes,'all actual kernel opened descriptors consumed')
    same(len(used),len(rules),'every declared mechanical control actually applied')
    same(process['injection_indices'],injections,'complete physical injection index')
    same(process['opened_descriptors'],opens,'kernel open count');same(process['closed_descriptors'],closes,'kernel close count')
    same(process['syscalls'],len(events),'complete actual syscall capture')
    effects=[r for r in receipts if r['kind'] not in (11,19)]
    same(len(owned_events),len(effects),'each native Linux effect has an actual syscall return')
    numbers={1:2,2:257,3:3,4:73,5:262,6:257,7:5,8:107,9:196,10:0,12:318,13:257,14:91,15:1,16:74,17:316,18:263}
    for effect,event in zip(effects,owned_events):
        same(event['syscall'],numbers[effect['kind']],'source-owned effect matches actual kernel boundary')
        same(effect['raw_linux_return'],event['delivered_result'],'actual delivered syscall bound to exact effect completion')
    return {'syscalls':len(events),'opened':opens,'closed':closes,'injections':len(injections)}

def faults_evidence(f,m):
    source=f.read('faults','source/tests/hia_native/test_text_publication_faults.py')
    descriptions=pure_function(source,'case_list')();same(len(descriptions),26,'all source-owned fault cases')
    elf=f.absolute('native','build/'+m['elf']); diagnostics=f.obj('corpus','source/authoring/diagnostics.json')
    totals={};index=f.obj('handoff','FAULT-INDEX.json');same(set(index),{x['name'] for x in descriptions},'complete fault handoff index')
    for domain in ('pilot','full'):
        cases=descriptions[:1] if domain=='pilot' else descriptions
        same(f.obj('faults',domain+'/cases.json'),cases,'exact actual fault input plan')
        result=f.obj('faults',domain+'/RESULT.json');same(result['status'],'PASS','actual full fault success');same(result['error'],None,'no fault harness failure')
        for flag in ('original_reference_executed',):same(result[flag],False,'fault scope')
        same(result['original_cases_added'],0,'faults add zero original cases')
        same(result['source_sha256'],sha(source),'fault source identity');same(result['elf_sha256'],m['elf_sha256'],'same actual native ELF')
        same(result['manifest_sha256'],sha(f.read('native','build/manifest.json')),'fault exact fresh build')
        rows=[];effects=injections=opens=closes=syscalls=0
        for case in cases:
            folder=domain+'/'+case['name'];process=f.obj('faults',folder+'/process.json')
            streams=checked_process(f,'faults',process,[elf,'--trace'],f.absolute('faults',folder),folder,outer=False,deadline=60)
            same(process['error'],None,'actual owned-child capture succeeded');same(process['executable_sha256'],m['elf_sha256'],'actual traced ELF')
            same(process['original_reference_executed'],False,'no fault original execution')
            old,new=b'old\n'*257,b'new\n'*129
            path=os.fsencode(f.absolute('faults',folder+'/files/file'))
            expected=b'absent' if case['mode']==1 else sha(old).encode()
            wire=b'HTXTQ001'+struct.pack('<7Q',1,case['mode'],len(path),len(new),len(expected),0,0)+path+expected+new
            same(streams['stdin'],struct.pack('<Q',len(wire))+wire,'complete actual fault request')
            same(process['input_bytes_intended'],len(streams['stdin']),'intended full fault input')
            same(process['input_bytes_sent'],len(streams['stdin']),'actual full fault input sent')
            replies=framed(streams['stdout']);same(len(replies),1,'single complete fault response');reply=result_record(replies[0])
            receipts=receipt_records(streams['stderr']);events=f.obj('faults',folder+'/syscalls.json')
            counts=fault_syscalls(events,case['rules'],process,receipts)
            first,_=fault_snapshot(f,folder,'first-effect',wire,terminal=False)
            state,parts=fault_snapshot(f,folder,'before-output',wire,terminal=True)
            same(parts[4]+parts[3][:state['payload_len']],streams['stdout'],'actual queued header and full native output')
            same(state['last_code'],reply['code'],'private state return equals wire');same(state['sequence'],reply['sequence'],'same complete effect count')
            same(state['error_code'],case['error'],'actual HIA error state');same(state['published'],case['published'],'actual HIA publication state')
            same(len([r for r in receipts if r['kind']==17 and r['errno']==0]),case['published'],'actual rename effect')
            body=reply['body'];require(q(body,8)==int(case['error']!=0),'native error/success result')
            if case['error']:
                if case['error']!=255: message=diagnostics[case['error']-1]
                else: message={1:'Operation not permitted',2:'No such file or directory',5:'Input/output error',13:'Permission denied'}[state['error_errno']]+' (os error '+str(state['error_errno'])+')'
                same(body[64:],message.encode(),'complete native fault diagnostic')
            else:
                wanted=old+new if case['mode']==3 else new
                require(q(body,24)==len(wanted) and body[120:152]==hashlib.sha256(wanted).digest(),'complete fault result count/SHA')
            actual=f.read('faults',folder+'/after.bin');before=f.read('faults',folder+'/before.bin')
            same(before,b'' if case['mode']==1 else old,'complete old fixture input')
            wanted=(old+new if case['mode']==3 else new) if case['published'] else old
            same(actual,wanted,'actual full file contents after fault, including committed errors')
            tree=f.obj('faults',folder+'/tree.json'); names=[];target=None
            for node in tree:
                content=f.read('faults',folder+'/'+node['content'],{'bytes':node['content_bytes'],'sha256':node['content_sha256']})
                same(len(content),node['metadata']['st_size'],'actual complete fault tree bytes')
                name=bytes.fromhex(node['name_hex']);names.append(name.decode())
                if name==b'file':target=node;same(content,actual,'target tree equals full after body')
            require(target is not None and len(tree)==(2 if case['name']=='write-and-cleanup-error' else 1),'complete fault tree and expected cleanup residue')
            recorded=result['cases_completed'][len(rows)];same(recorded['after'],target['metadata'],'actual final complete POSIX metadata')
            prior=recorded['before']
            if case['mode']==1:same(prior,None,'create had no original target')
            else:
                same(prior['st_size'],len(old),'old actual stat size')
                if case['published']:require(prior['st_ino']!=target['metadata']['st_ino'],'published inode survives late fault')
                else:
                    for key in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns'):same(prior[key],target['metadata'][key],'failed prepublish retains original inode state')
            row={'name':case['name'],'before':prior,'after':target['metadata'],'error_code':state['error_code'],
                 'published':state['published'],'reply_bytes':len(body),'reply_sha256':sha(body),'effect_count':len(receipts),
                 'injected_calls':counts['injections'],'leftover_names':sorted(x for x in names if x!='file'),
                 'opened_descriptors':counts['opened'],'closed_descriptors':counts['closed']}
            same(recorded,row,'complete fault case summary from raw observations');rows.append(row)
            effects+=len(receipts);injections+=counts['injections'];opens+=counts['opened'];closes+=counts['closed'];syscalls+=counts['syscalls']
            if domain=='full':
                item=index[case['name']];same(item['origin'],f.absolute('faults',folder),'fault original execution path')
                same(item['summary'],row,'fault handoff actual full summary');same(item['injection_indices'],process['injection_indices'],'fault handoff actual injections')
                for name,pinned in item['artifacts'].items():f.read('faults',folder+'/'+name,pinned)
        same(f.obj('faults',domain+'/completed.json'),rows,'complete actual fault sequence')
        for key,want in [('cases',len(cases)),('intended_cases',len(cases)),('actual_elf_processes',len(cases)),('effects',effects),('injected_calls',injections),('unmodified_kernel_cases',1 if domain=='pilot' else 3)]:
            same(result[key],want,'actual fault total '+key)
        totals[domain]={'cases':len(cases),'elf_processes':len(cases),'effects':effects,'injections':injections,'opened':opens,'closed':closes,'syscalls':syscalls}
    require(totals['full']['effects']==822 and totals['full']['injections']==24 and totals['full']['opened']==225,'full fixed fault domain')
    return totals

def smoke_evidence(f,m):
    result=f.obj('native','native-smoke/RESULT.json')
    same(result,{'status':'PASS','actual_elf_processes':8,'actual_hia_requests':10,'effects':233,
                 'full_result_bytes':True,'original_reference_executed':False,'production_mcp_route_replaced':False,
                 'manifest_sha256':sha(f.read('native','build/manifest.json'))},'complete native smoke scope')
    elf=f.absolute('native','build/'+m['elf']);total=0
    def wire(mode,path,text,expected):
        path=os.fsencode(path)
        return b'HTXTQ001'+struct.pack('<7Q',1,mode,len(path),len(text),len(expected),0,0)+path+expected+text
    def drop(generation):return b'HTXTQ001'+struct.pack('<7Q',2,0,0,0,0,generation,0)
    path=f.absolute('native','native-smoke/files/file');first=b'hello\n';second='中🙂'.encode();third=b'\0tail\n'
    inputs={'chain':[wire(1,path,first,b'absent'),drop(1),wire(2,path,second,sha(first).encode()),drop(2),wire(3,path,third,sha(second).encode()),drop(3)],
            'sha-windows':[wire(3,f.absolute('native','native-smoke/files/large'),b'Y'*65536,sha(b'x'*4194304).encode())],
            'invalid':[wire(1,path,b'x',b'absent')[:-1]],
            'errno-child':[wire(1,f.absolute('native','native-smoke/files')+'/'+'a'*256,b'x',b'absent')],
            'race':[wire(1,f.absolute('native','native-smoke/files/race'),b'ours\n',b'absent')]}
    for name in ('chain','sha-windows','invalid','errno-child','race','partial-header','partial-frame','empty'):
        folder='native-smoke/'+name;proc=f.obj('native',folder+'/process.json')
        flags=['--sync'] if name=='race' else ['--trace'] if name in ('chain','sha-windows','errno-child') else []
        code=74 if name in ('partial-header','partial-frame') else 0
        streams=checked_process(f,'native',proc,[elf,*flags],f.absolute('native',folder),folder,
                                outer=False,deadline=60,timed=name!='race',exit_code=code)
        if name=='race':same(proc['timeout_seconds'],60,'actual sync smoke deadline')
        outputs=[result_record(x) for x in framed(streams['stdout'])]
        receipts=receipt_records(streams['stderr']);total+=len(receipts)
        if name=='chain':
            same(len(outputs),6,'all actual chain results')
            for row,want in zip(outputs[::2],(b'hello\n','中🙂'.encode(),'中🙂'.encode()+b'\0tail\n')):
                require(row['code']==160 and row['body'][120:152]==hashlib.sha256(want).digest(),'full chain result digest')
            for i,row in enumerate(outputs[1::2],1):
                require(row['code']==64 and row['generation']==i and q(row['body'],8)==2,'chain explicit DROP')
        elif name=='sha-windows':
            require(len(outputs)==1 and outputs[0]['code']==160 and outputs[0]['body'][120:152]==hashlib.sha256(b'x'*4194304+b'Y'*65536).digest(),'multiwindow SHA complete bytes')
        elif name=='invalid':require(len(outputs)==1 and outputs[0]['code']==INVALID and not receipts,'malformed frame remains private')
        elif name in ('errno-child','race'):
            require(len(outputs)==1 and q(outputs[0]['body'],8)==1,'actual error result')
            if name=='errno-child':require(any(x['kind']==19 for x in receipts),'actual HIA error-render child')
        else:
            require(not outputs and not receipts,'complete framing/EOF cleanup has no effects')
            expected={'partial-header':b'abc','partial-frame':struct.pack('<Q',64)+b'abc','empty':b''}[name]
            same(streams['stdin'],expected,'exact source-owned incomplete EOF input')
        if name=='race':
            raw=streams['stdin'];size=q(raw);at=8+size
            same(raw[8:at],inputs[name][0],'complete actual smoke race input')
            same(raw[at:],b''.join(b'HTXTACK1'+struct.pack('<2Q',r['generation'],r['sequence']) for r in receipts),'all identity-only smoke ACKs')
        elif name not in ('partial-header','partial-frame','empty'):
            same(framed(streams['stdin']),inputs[name],'complete exact source-owned smoke requests')
    same(total,233,'all original smoke effects')
    return {'elf_processes':8,'hia_requests':10,'effects':233}

def handoff_binding(f,m):
    handoff=f.obj('handoff','HANDOFF.json')
    same(handoff['status'],'NATIVE_MECHANICAL_PASS_ORIGINAL_AND_PUBLIC_NOT_CLAIMED','mechanical handoff scope')
    same(handoff['source_whitelist_count'],13,'native source handoff size');same(handoff['artifact_count'],553,'original mechanical artifact count')
    same(handoff['elf_sha256'],m['elf_sha256'],'exact frozen native ELF')
    same(handoff['members'],m['members'],'actual embedded HIA graph')
    same(handoff['files'],f.obj('handoff','FILES.json'),'frozen source handoff rows')
    for flag in ('original_reference_executed','public_mcp_handler_replaced','whole_runtime_replaced'):
        same(handoff[flag],False,'mechanical handoff completion boundary')
    same(handoff['frozen_core_owner_unchanged'],True,'fixed original HIA core')
    manifest=handoff['manifest'];same(manifest['path'],f.absolute('native','build/manifest.json'),'handoff exact execution manifest')
    f.read('native','build/manifest.json',{k:manifest[k] for k in ('bytes','sha256')})
    for key,name in [('dependencies','DEPENDENCIES.json'),('fault_index','FAULT-INDEX.json'),('failures','FAILURES.json')]:
        item=handoff[key];same(item['path'],f.absolute('handoff',name),'handoff artifact original path')
        f.read('handoff',name,{k:item[k] for k in ('bytes','sha256')})
    paths=[('native','PROCESSES.json'),('boundary','PROCESS.json'),('faults','PROCESSES.json')]
    same(len(handoff['actual_processes']),3,'all native actual process sets')
    for item,(group,path) in zip(handoff['actual_processes'],paths):
        same(item['path'],f.absolute(group,path),'handoff actual process path')
        record=f.obj(group,path,{k:item[k] for k in ('bytes','sha256')})
        same(item['processes'],record if type(record) is list else [record],'handoff actual full process receipt')
    return {'original_reference_executed':False,'public_handler_replaced':False}

def native_evidence(*, native, boundary, faults, corpus, handoff, origins=None):
    """Strictly admit immutable native evidence; never run or restore anything.

    All five arguments are original execution roots. ``origins`` is a complete
    explicit mapping from execution roots to physical read roots after moving
    artifacts. Returned artifact keys and data do not depend on read locations.
    """
    f=Files(dict(native=native,boundary=boundary,faults=faults,corpus=corpus,handoff=handoff),origins)
    contract=decode(CONTRACT.read_bytes())
    same(contract['schema'],'hepta.runtime.text-publication-native-read-contract.v1','read contract schema')
    sources=admit_sources(f,contract)
    admit_artifact_inventory(f,contract)
    manifest=native_build(f,contract,sources)
    mechanical_processes(f,manifest)
    smoke=smoke_evidence(f,manifest)
    callable_result=callable_controls(f,manifest)
    boundary_result=boundary_controls(f,manifest)
    faults_result=faults_evidence(f,manifest)
    corpus_result=corpus_evidence(f,contract,manifest,load_generators(f))
    handoff_binding(f,manifest)
    return {'schema':'hepta.runtime.text-publication-native-evidence.v1','status':'PASS',
            'cases':144,'ordinary_original_eligible_cases':99,'private_frame_cases':25,'actual_external_writer_cases':20,
            'corpus_effects':3675,'mechanical_artifacts':553,'smoke':smoke,'callable':callable_result,
            'boundary':boundary_result,'faults':faults_result,'domains':corpus_result,
            'elf_sha256':manifest['elf_sha256'],'sources':dict(sorted(f.sources.items())),
            'artifact_sha256':dict(sorted(f.artifacts.items())),'artifacts':sorted(f.artifacts),
            'reader_sources':{'scripts/'+Path(__file__).name:pin(Path(__file__).read_bytes()),
                              'native/'+CONTRACT.name:pin(CONTRACT.read_bytes())},
            'native_processes_executed_by_reader':0,'rust_processes_executed_by_reader':0,
            'live_fixtures_read':False,'fixtures_restored_by_reader':False,
            'original_reference_executed':False,'original_reference_status':'PENDING_SEPARATE_ORIGINAL_ADMISSION',
            'public_handler_replaced':False,'whole_runtime_replaced':False}

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--config',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args();config=decode(args.config.read_bytes())
    result=native_evidence(**config)
    raw=(json.dumps(result,sort_keys=True,indent=2)+'\n').encode()
    with args.output.open('xb') as stream:stream.write(raw)
    print(json.dumps({'status':'PASS','artifacts':len(result['artifacts']),'sources':len(result['sources']),
                      'cases':144,'native_executed':0,'rust_executed':0,'output':pin(raw)},sort_keys=True),flush=True)

if __name__=='__main__':main()
