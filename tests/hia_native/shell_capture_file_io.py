"""Actual Linux capture-file operations, retained arrays, and a pure reader."""
from __future__ import annotations
import argparse, copy, hashlib, importlib, json, os, selectors, stat, struct
import subprocess, sys, time
from pathlib import Path
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
PENDING, CAPACITY, INVALID = 0xfffffffd, 0xfffffffe, 0xffffffff
MASK = (1 << 64) - 1
SCOPE = dict(production_activated=False, tokio_async_cancellation_qualified=False,
             glibc_thread_cancellation_qualified=False, capture_preparation_qualified=False,
             registry_publication_qualified=False, whole_runtime_replaced=False,
             old_stack_removal_qualified=False)
SOURCES = ('native/shell_capture_file.hepta', 'native/shell_capture_file_abi.md',
           'native/shell_capture_file_reuse.json', 'native/shell_capture_path.hepta',
           'native/shell_capture_file_packer.hepta', 'native/shell_capture_file_layout.json',
           'native/shell_capture_file_fixture.md', 'scripts/shell_capture_file_adapter.S',
           'scripts/hia_native_shell_capture_file_build.py', 'tests/hia_native/shell_capture_file_io.py')
CASE_FILES = ('spec.json', 'requests.json', 'stdin.bin', 'stdout.bin', 'stderr.bin',
              'execution.json', 'observation.json', 'before.json', 'after.json',
              'effects.bin', 'entries.bin', 'retirement.json')

def need(value, message):
    if not value:
        raise ValueError(message)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def pin(raw):
    return {'bytes': len(raw), 'sha256': sha(raw)}

def packed(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True)+'\n').encode()

def decoded(raw):
    def unique(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate JSON key'); result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('JSON constant')))

def ordinary(path):
    path = os.fsdecode(path); before = os.lstat(path)
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'nonordinary evidence')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(fd)
        need((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino), 'evidence open identity')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read()
        after = os.fstat(fd)
        need((opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) ==
             (after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'evidence changed while reading')
        return raw
    finally:
        os.close(fd)

def read_json(path):
    return decoded(ordinary(path))

def write_new(path, raw):
    with Path(path).open('xb') as stream:
        stream.write(raw)

def plain_dir(path):
    need(stat.S_ISDIR(Path(path).lstat().st_mode), 'nonordinary evidence directory')

def case_specs():
    def directory(path, mode=0o755):
        return dict(path_hex=path.hex(), kind='directory', mode=mode)
    def file(path, mode=0o640):
        return dict(path_hex=path.hex(), kind='file', mode=mode, payload_hex=b'old\x00capture\xff\n'.hex())
    def symlink(path, target):
        return dict(path_hex=path.hex(), kind='symlink', mode=0o777, target_hex=target.hex())
    def case(name, operation, path, setup=(), errno=0, target=None, lifecycle=None, umask=0o022, absolute=False):
        local = b'\0' in path
        if lifecycle is None:
            lifecycle = [(1, 3)] if operation == 1 and not errno and not local else []
        return dict(name=name, operation=operation, path_hex=path.hex(), setup=list(setup),
                    expected_errno=errno, expected_local_nul=local,
                    target_hex=None if target is None else target.hex(),
                    lifecycle=[list(x) for x in lifecycle], umask=umask, absolute_under_work=absolute,
                    original_file_operation=operation in (1, 2))
    return (
        case('create_new', 1, b'new', target=b'new'),
        case('truncate_existing', 1, b'file', [file(b'file')], target=b'file'),
        case('create_raw_bytes', 1, b'\xffcapture', target=b'\xffcapture'),
        case('create_empty', 1, b'', errno=2),
        case('create_directory', 1, b'dir', [directory(b'dir')], errno=21),
        case('missing_parent', 1, b'missing/file', errno=2),
        case('repeated_slashes', 1, b'a///new', [directory(b'a')], target=b'a/new'),
        case('dot_components', 1, b'./a/./new', [directory(b'a')], target=b'a/new'),
        case('dotdot', 1, b'a/../new', [directory(b'a')], target=b'new'),
        case('create_trailing_slash', 1, b'new/', errno=21),
        case('symlink_file', 1, b'link', [file(b'target'), symlink(b'link', b'target')], target=b'target'),
        case('dangling_symlink', 1, b'link', [symlink(b'link', b'target')], target=b'target'),
        case('symlink_directory', 1, b'link', [directory(b'target'), symlink(b'link', b'target')], errno=21),
        case('symlink_loop', 1, b'loop', [symlink(b'loop', b'loop')], errno=40),
        case('intermediate_file', 1, b'file/child', [file(b'file')], errno=20),
        case('readonly_file', 1, b'file', [file(b'file', 0o400)], errno=13),
        case('denied_parent', 1, b'denied/child', [directory(b'denied', 0o500)], errno=13),
        case('component_too_long', 1, b'x'*256, errno=36),
        case('path_too_long', 1, b'a/'*2048+b'file', errno=36),
        case('embedded_nul', 1, b'file\0tail', lifecycle=[(1, 3), (1, 4)]),
        case('umask', 1, b'file', target=b'file', umask=0o027),
        case('create_absolute', 1, b'absolute', target=b'absolute', absolute=True),
        case('hold_take', 1, b'file', target=b'file', lifecycle=[(1, 4), (2, 4), (1, 3), (1, 4), (1, 1)]),
        case('replay_and_drop_once', 1, b'file', target=b'file', lifecycle=[(2, 1), (1, 3), (2, 3), (1, 3), (1, 4)]),
        case('fresh_drop_invalid', 3, b''),
        case('fresh_take_invalid', 4, b''),
        case('unlink_file', 2, b'file', [file(b'file')], target=b'file', lifecycle=[(2, 2)]),
        case('unlink_symlink', 2, b'link', [file(b'target'), symlink(b'link', b'target')], target=b'link'),
        case('unlink_directory', 2, b'dir', [directory(b'dir')], errno=21),
        case('unlink_missing', 2, b'missing', errno=2),
        case('unlink_raw_bytes', 2, b'\xffcapture', [file(b'\xffcapture')], target=b'\xffcapture'),
        case('unlink_nul', 2, b'file\0tail', [file(b'file')]),
        case('unlink_intermediate_file', 2, b'file/child', [file(b'file')], errno=20),
        case('unlink_missing_parent', 2, b'missing/file', errno=2),
    )

def path_for(spec, work):
    raw = bytes.fromhex(spec['path_hex'])
    return os.fsencode(work)+b'/'+raw if spec['absolute_under_work'] else raw

def request(op, kind, path):
    return b'HSHCFQ01'+struct.pack('<7Q', op, kind, len(path), 0, 0, 0, 0)+path

def requests_for(spec, work):
    path = path_for(spec, work)
    rows = [(1, spec['operation'])]+[tuple(x) for x in spec['lifecycle']]
    return 513+len(path), [request(op, kind, path if kind in (1, 2) else b'') for op, kind in rows]

def stat_row(s):
    return dict(device=s.st_dev, inode=s.st_ino, mode=s.st_mode, uid=s.st_uid, gid=s.st_gid,
                nlink=s.st_nlink, size=s.st_size, mtime_ns=s.st_mtime_ns, ctime_ns=s.st_ctime_ns)

def identity(row):
    return tuple(row[k] for k in ('device', 'inode', 'mode', 'uid', 'gid'))


def control_identities(corpus, inputs):
    result = {}
    for name in inputs:
        item = (corpus/name).lstat()
        need(stat.S_ISREG(item.st_mode) and item.st_nlink == 1, 'ordinary control input identity')
        result[name] = dict(device=item.st_dev, inode=item.st_ino, mode=item.st_mode)
    return result

def check_control_identities(values, inputs):
    need(type(values) is dict and set(values) == set(inputs), 'complete recorded control identities')
    for value in values.values():
        need(type(value) is dict and set(value) == {'device','inode','mode'} and
             all(type(x) is int and x >= 0 for x in value.values()) and value['inode'] > 0 and
             stat.S_ISREG(value['mode']), 'recorded ordinary control identity')
    need(len({(r['device'],r['inode']) for r in values.values()}) == len(values), 'recorded control identity alias')

def audit_files_snapshot(folder):
    result = {}
    for name in ('effects.bin','entries.bin'):
        path = folder/name
        if not path.exists():
            continue
        before = stat_row(path.lstat()); raw = ordinary(path); after = stat_row(path.lstat())
        need(before == after and before['size'] == len(raw), 'audit changed during producer snapshot')
        result[name] = dict(stat=before, **pin(raw))
    return result

def verify_audit_files(folder, execution):
    rows = execution.get('audit_files')
    need(type(rows) is dict and set(rows) == {'effects.bin','entries.bin'}, 'complete audit file observations')
    for name, row in rows.items():
        need(type(row) is dict and set(row) == {'stat','bytes','sha256'}, 'audit file observation fields')
        item = row['stat']; raw = ordinary(folder/name)
        need(type(item) is dict and set(item) == {'device','inode','mode','uid','gid','nlink','size','mtime_ns','ctime_ns'} and
             all(type(x) is int and x >= 0 for x in item.values()) and item['inode'] > 0 and
             stat.S_ISREG(item['mode']) and stat.S_IMODE(item['mode']) == 0o600 and item['nlink'] == 1 and
             item['uid'] == execution['uid'] and item['gid'] == execution['gid'], 'recorded audit file identity')
        need(item['size'] == len(raw) and {k:row[k] for k in ('bytes','sha256')} == pin(raw), 'audit retained bytes/stat')
    need(identity(rows['effects.bin']['stat']) != identity(rows['entries.bin']['stat']), 'audit files share identity')
    return rows

def relative(raw):
    need(raw and not raw.startswith(b'/') and b'\0' not in raw and
         all(part not in (b'', b'.', b'..') for part in raw.split(b'/')), 'owned relative path')
    return raw

def setup_case(work, spec):
    work.mkdir(mode=0o700)
    for row in spec['setup']:
        path = os.fsencode(work)+b'/'+relative(bytes.fromhex(row['path_hex']))
        if row['kind'] == 'directory':
            os.mkdir(path, row['mode']); os.chmod(path, row['mode'])
        elif row['kind'] == 'file':
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, row['mode'])
            try:
                os.fchmod(fd, row['mode'])
                with os.fdopen(fd, 'wb', closefd=False) as stream:
                    stream.write(bytes.fromhex(row['payload_hex']))
            finally:
                os.close(fd)
        else:
            need(row['kind'] == 'symlink', 'unknown setup kind')
            os.symlink(bytes.fromhex(row['target_hex']), path)

def tree_snapshot(work):
    rows = []
    def visit(path, name):
        s = os.lstat(path); row = dict(path_hex=name.hex(), **stat_row(s))
        if stat.S_ISDIR(s.st_mode):
            row['kind'] = 'directory'; rows.append(row)
            with os.scandir(path) as entries:
                names = sorted(entry.name for entry in entries)
            for child in names:
                visit(path+b'/'+child, name+b'/'+child if name else child)
        elif stat.S_ISREG(s.st_mode):
            row.update(kind='file', payload_hex=ordinary(path).hex()); rows.append(row)
        elif stat.S_ISLNK(s.st_mode):
            row.update(kind='symlink', target_hex=os.readlink(path).hex()); rows.append(row)
        else:
            raise ValueError('unexpected owned fixture type')
    visit(os.fsencode(work), b'')
    return rows

def retirement_order(rows):
    return sorted(rows, key=lambda r: (bytes.fromhex(r['path_hex']).count(b'/'), len(r['path_hex']), r['path_hex']), reverse=True)

def retire(work, final):
    need(tree_snapshot(work) == final, 'fixture changed before retirement')
    removed = []
    for row in retirement_order(final):
        rel = bytes.fromhex(row['path_hex'])
        path = os.fsencode(work)+(b'/'+relative(rel) if rel else b'')
        actual = stat_row(os.lstat(path))
        need(identity(actual) == identity(row), 'fixture retirement identity')
        if row['kind'] == 'directory':
            os.rmdir(path)
        else:
            os.unlink(path)
        need(not os.path.lexists(path), 'fixture not retired')
        removed.append(dict(path_hex=row['path_hex'], before=actual, observed_absent=True))
    return dict(schema='hepta.runtime.shell-capture-file-retirement.v1', recorded_work=str(work),
                final_snapshot=pin(packed(final)), removed=removed, observed_root_absent=True)

def q(raw, at):
    return struct.unpack_from('<Q', raw, at)[0]

def put(raw, at, value):
    struct.pack_into('<Q', raw, at, value & MASK)

def model_call(wire, previous):
    """Independent finite lifecycle, including the complete canonical arena."""
    w = bytearray(previous)
    if len(wire) < 64 or wire[:8] != b'HSHCFQ01':
        return INVALID, b'', bytes(w)
    op, kind, n, *reserved = struct.unpack_from('<7Q', wire, 8)
    if op not in (1, 2) or kind not in (1, 2, 3, 4) or any(reserved) or n != len(wire)-64 or (kind >= 3 and n):
        return INVALID, b'', bytes(w)
    if len(w) < 513+n:
        return CAPACITY, b'', bytes(w)
    live = w[:8] == b'HSHCFW01'
    def result():
        return 48, b'HSHCFR01'+struct.pack('<5Q', 48, q(w, 8), q(w, 64), q(w, 72), q(w, 80)), bytes(w)
    def issue(action, args):
        put(w, 16, 1); put(w, 24, q(w, 24)+1)
        w[128:224] = b'HSHCFFX1'+struct.pack('<11Q', q(w, 24), action, *args, 0, 0, 0, 0, 0)
        return PENDING, b'', bytes(w)
    def finish(phase, result_kind, error, token):
        put(w, 16, phase); put(w, 56, 0); put(w, 64, result_kind)
        put(w, 72, error); put(w, 80, token); w[128:224] = bytes(96)
        return result()
    if op == 1:
        if kind in (1, 2):
            if live:
                return INVALID, b'', bytes(w)
            w[:512] = bytes(512); w[:8] = b'HSHCFW01'
            for at, value in ((8, kind), (32, n), (40, 513+n), (88, kind)):
                put(w, at, value)
            w[512:513+n] = wire[64:]+b'\0'
            if b'\0' in wire[64:]:
                return finish(3, 2, 0, 0)
            return issue(kind, (512, n, 0x80241 if kind == 1 else 0, 438 if kind == 1 else 0))
        if not live or q(w, 8) != 1 or q(w, 16) != 2 or not q(w, 48):
            return INVALID, b'', bytes(w)
        token = q(w, 48); put(w, 8, kind); put(w, 48, 0)
        put(w, 64, 0); put(w, 72, 0); put(w, 80, 0)
        if kind == 4:
            return finish(3, 0, 0, token)
        put(w, 56, token)
        return issue(3, (token, 0, 0, 0))
    if not live or q(w, 8) != kind or (kind <= 2 and wire[64:] != w[512:512+q(w, 32)]):
        return INVALID, b'', bytes(w)
    if q(w, 16) in (2, 3):
        return result()
    need(q(w, 16) == 1, 'model pending phase')
    if not q(w, 184):
        return PENDING, b'', bytes(w)
    error, token = q(w, 200), q(w, 208)
    if kind == 1 and error == 4:
        return issue(1, (512, q(w, 32), 0x80241, 438))
    if kind == 1 and not error:
        put(w, 48, token)
        return finish(2, 0, 0, token)
    if kind == 3:
        return finish(3, 0, 0, 0)
    return finish(3, int(error != 0), error, 0)

def parse_entries(raw):
    at, rows = 0, []
    while raw[at:at+8] == b'HSCFEN01':
        need(len(raw)-at >= 128, 'short entry header')
        h = struct.unpack_from('<16Q', raw, at); start = at; at += 128
        arrays = []
        for size in h[6:9]:
            need(size+32 <= len(raw)-at, 'short complete entry allocation')
            arrays.append(raw[at:at+size+32]); at += size+32
        rows.append(dict(header=h, arrays=arrays, offset=start, end=at))
    need(len(raw)-at == 128 and raw[at:at+8] == b'HSCFAUD1', 'missing entry footer')
    return rows, raw[at:]

def parse_effects(raw):
    at, rows = 0, []
    while raw[at:at+8] == b'HSCFTR01':
        need(len(raw)-at >= 224, 'short effect record')
        h = struct.unpack_from('<16Q', raw, at); slot = raw[at+128:at+224]
        need(h[14] <= len(raw)-at-224, 'short effect path')
        end = at+224+h[14]
        rows.append(dict(header=h, slot=slot, path=raw[at+224:end], offset=at, end=end)); at = end
    need(len(raw)-at == 128 and raw[at:at+8] == b'HSCFAUD1', 'missing effect footer')
    return rows, raw[at:]

def parse_stdout(raw, count):
    need(len(raw) >= 192 and raw[:8] == b'HSCFRDY1', 'fixture ready framing')
    ready = struct.unpack_from('<8Q', raw); at = 64; rows = []
    for _ in range(count):
        need(len(raw)-at >= 16, 'short native result frame')
        ret, extent = struct.unpack_from('<QQ', raw, at); at += 16
        need(ret in (48, INVALID, CAPACITY) and extent == (48 if ret == 48 else 0), 'native result extent')
        need(extent <= len(raw)-at, 'short native result body')
        rows.append((ret, raw[at:at+extent])); at += extent
    need(len(raw)-at == 128 and raw[at:at+8] == b'HSCFAUD1', 'stdout footer framing')
    return ready, rows, raw[at:]

def verify_native(folder, spec, wires, capacity, execution, observation):
    entries, ef = parse_entries(ordinary(folder/'entries.bin'))
    effects, tf = parse_effects(ordinary(folder/'effects.bin'))
    ready, results, sf = parse_stdout(ordinary(folder/'stdout.bin'), len(wires))
    need(ef == tf == sf, 'all native footer bytes')
    footer = struct.unpack('<16Q', ef)
    pid = execution['pid']; need(type(pid) is int and pid > 0, 'actual process pid')
    need(ready[1:3] == (pid, pid) and ready[5:] == (1, 0, 0) and
         ready[3] > 2 and ready[4] > 2 and ready[3] != ready[4], 'ready identity')
    need(len(observation['requests']) == len(wires), 'request observation inventory')
    wi, ei, prior_time = bytes(capacity), 0, execution['monotonic_started_ns']
    counters, live, operations, steps = [0, 0, 0, 0, 0], {}, [], []
    at = 0; effect_end = 0
    for request_index, wire in enumerate(wires, 1):
        expected_i, expected_o = wire, b'\xa7'*64
        timing = observation['requests'][request_index-1]
        need(timing['request'] == request_index and timing['sent_ns'] <= timing['received_ns'] <= timing['observed_ns'], 'request timing')
        first_entry = ei+1
        while True:
            need(at+2 <= len(entries), 'missing complete native entry')
            before, after = entries[at:at+2]; at += 2; ei += 1
            bh, ah = before['header'], after['header']
            for h, phase in ((bh, 0), (ah, 1)):
                need(h[1:9] == (request_index, ei, phase, pid, pid, len(expected_i), 64, capacity), 'entry identity and extents')
                need(tuple(h[11:]) == tuple(counters), 'entry custody counters')
            need(bh[9] == 0 and prior_time <= bh[10] <= ah[10] and
                 timing['sent_ns'] <= bh[10] and ah[10] <= timing['received_ns'], 'entry actual return/time')
            prior_time = ah[10]
            ba, aa = before['arrays'], after['arrays']
            for arrays in (ba, aa):
                for buf, left, right in zip(arrays, (0xc1, 0xa5, 0x5a), (0xc2, 0xa6, 0x5b)):
                    need(buf[:16] == bytes([left])*16 and buf[-16:] == bytes([right])*16, 'native memory guards')
            need(ba[0][16:-16] == expected_i and ba[1][16:-16] == expected_o and ba[2][16:-16] == wi,
                 'exact native before arrays')
            ret, body, expected_w = model_call(expected_i, wi)
            out = body+expected_o[len(body):] if ret == 48 else expected_o
            need(aa[0] == ba[0], 'native input mutation')
            need(ah[9] == ret and aa[1][16:-16] == out, 'actual HIA result and complete output')
            need(aa[2][16:-16] == expected_w, 'complete HIA state transition')
            wi, expected_o = expected_w, out
            if ret != PENDING:
                need(results[request_index-1] == (ret, body), 'published native result')
                steps.append(dict(request=request_index, first_entry=first_entry, last_entry=ei,
                                  return_value=ret, result_hex=body.hex(), held=q(wi, 48),
                                  entry_end=after['end'], effect_end=effect_end,
                                  live_handles={str(k): v for k, v in sorted(live.items())}))
                break
            need(len(effects) >= 2*(counters[0]+1), 'missing actual effect pair')
            a, b = effects[2*counters[0]:2*counters[0]+2]
            h0, h1 = a['header'], b['header']; slot = wi[128:224]
            need(a['slot'] == slot, 'issued slot from actual HIA')
            action, args = q(slot, 16), tuple(q(slot, k) for k in (24, 32, 40, 48))
            need(h0[1:7] == (request_index, ei, q(slot, 8), pid, pid, 0) and
                 h1[1:7] == (request_index, ei, q(slot, 8), pid, pid, 1), 'effect pair identity/order')
            need(h0[7:11] == h1[7:11] and h0[11:14] == (0, 0, 0) and h0[15] == h1[15] == 0,
                 'effect syscall headers')
            if action in (1, 2):
                need(args[0] == 512 and args[1] == q(wi, 32), 'canonical HIA path borrow')
                path = wi[512:512+args[1]]
                syscall_args = (257, MASK-99, 0x80241, 438) if action == 1 else (87, 0, 0, 0)
            else:
                need(action == 3 and args[0] in live and args[1:] == (0, 0, 0), 'close owned capability')
                path = b''; syscall_args = (3, live[args[0]], 0, 0)
            need(h0[7:11] == syscall_args and h0[14] == h1[14] == len(path) and a['path'] == b['path'] == path,
                 'actual syscall arguments/path')
            raw, error, token = h1[11:14]
            need(type(error) is int and 0 <= error <= 4095 and
                 (raw == ((-error)&MASK) if error else raw <= 0x7fffffff), 'raw syscall errno domain')
            if action == 1:
                need(error in (4, spec['expected_errno']) and not spec['expected_local_nul'], 'registered open result')
                if error:
                    need(token == 0, 'failed open minted capability')
                else:
                    need(token == counters[2]+1 and raw not in (0, 1, 2, ready[3], ready[4]) and raw not in live.values(), 'actual minted FD capability')
                    live[token] = raw; counters[2] += 1; counters[4] += 1
            else:
                need(token == 0 and (error or raw == 0), 'non-open result shape')
                if action == 2:
                    need(error == spec['expected_errno'] and not spec['expected_local_nul'], 'registered unlink result')
                else:
                    need(error == 0, 'registered ordinary close result')
                    del live[args[0]]; counters[3] += 1; counters[4] -= 1
            completed_slot = bytearray(slot)
            struct.pack_into('<4Q', completed_slot, 56, 1, raw, error, token)
            need(b['slot'] == bytes(completed_slot), 'complete actual effect result')
            effect_end = b['end']
            operations.append(dict(request=request_index, entry=ei, sequence=q(slot, 8), action=action,
                                   args=list(args), path_hex=path.hex(), syscall=h1[7], actual_fd=h1[8],
                                   raw=raw, errno=error, handle=token))
            counters[0] += 1; counters[1] += 1
            next_w = bytearray(wi); next_w[128:224] = completed_slot; wi = bytes(next_w)
            next_i = bytearray(expected_i); put(next_i, 8, 2); expected_i = bytes(next_i)
    need(at == len(entries) and len(effects) == counters[0]*2, 'complete raw native inventory')
    expected_footer = (int.from_bytes(b'HSCFAUD1', 'little'), pid, len(wires), ei, *counters, 0, 0,
                       results[-1][0], capacity, ready[3], ready[4], 0)
    need(footer == expected_footer, 'reconstructed native footer')
    return dict(ready=ready, results=results, operations=operations, steps=steps,
                counts=dict(requests=len(wires), native_entries=ei, native_arrays=ei*6,
                            syscalls=counters[0], syscall_records=len(effects), minted=counters[2],
                            drop_closed=counters[3], transferred_live_at_exit=counters[4]))

def load_native(manifest):
    manifest = Path(manifest).absolute()
    sys.path.insert(0, str(ROOT/'scripts'))
    builder = importlib.import_module('hia_native_shell_capture_file_build')
    evidence = builder.read_evidence(manifest, source_root=ROOT)
    need(evidence.get('status') == 'PASS', 'strong native build refused')
    metadata = read_json(manifest)
    executable = manifest.parent/metadata['elf']
    need(sha(ordinary(executable)) == metadata['elf_sha256'], 'actual executable identity')
    return manifest, metadata, executable, evidence

def source_pins():
    return {name: pin(ordinary(ROOT/name)) for name in SOURCES}

def process_identity(raw):
    close = raw.rfind(b') ')
    need(close > 0, 'proc stat syntax')
    pid = int(raw.split(b' ', 1)[0]); fields = raw[close+2:].split()
    need(len(fields) >= 20, 'proc stat fields')
    return dict(pid=pid, ppid=int(fields[1]), state=fields[0].decode('ascii'), starttime=int(fields[19]))

def proc_snapshot(pid, expected=None):
    root = Path('/proc')/str(pid); raw = (root/'stat').read_bytes()
    ident = process_identity(raw)
    need(ident['pid'] == pid and ident['ppid'] == os.getpid(), 'actual child identity')
    if expected:
        need(ident['starttime'] == expected['starttime'], 'actual child starttime changed')
    fds = []
    for name in sorted(os.listdir(root/'fd'), key=int):
        path = root/'fd'/name
        fds.append(dict(fd=int(name), link_hex=os.fsencode(os.readlink(path)).hex(),
                        stat=stat_row(os.stat(path)), fdinfo_hex=(root/'fdinfo'/name).read_bytes().hex()))
    return dict(identity=ident, stat_hex=raw.hex(), exe_hex=os.fsencode(os.readlink(root/'exe')).hex(),
                cwd_hex=os.fsencode(os.readlink(root/'cwd')).hex(), fds=fds)

def run_case(folder, spec, manifest, metadata, executable):
    folder.mkdir(); work = folder/'work'; setup_case(work, spec)
    capacity, wires = requests_for(spec, work)
    frames = [struct.pack('<QQ', len(w), capacity)+w for w in wires]
    request_data = dict(workspace_capacity=capacity, wires_hex=[w.hex() for w in wires])
    write_new(folder/'spec.json', packed(spec)); write_new(folder/'requests.json', packed(request_data))
    before = tree_snapshot(work); write_new(folder/'before.json', packed(before))
    env = {'PATH':'/usr/bin:/bin', 'LANG':'C', 'LC_ALL':'C', 'TMPDIR':str(folder.parent.parent/'temporary')}
    argv = [str(executable), '--capture-file-fixture', str(folder)]
    executable_pin = pin(ordinary(executable))
    begin, unix_begin = time.monotonic_ns(), time.time_ns()
    p = subprocess.Popen(argv, cwd=work, env=env, umask=spec['umask'], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, bufsize=0)
    rawout, rawin, observed = bytearray(), bytearray(), {'requests':[]}
    deadline = time.monotonic()+30
    def receive(length):
        value = bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(p.stdout, selectors.EVENT_READ)
            while len(value) < length:
                remaining = deadline-time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise TimeoutError('native file fixture response')
                chunk = os.read(p.stdout.fileno(), length-len(value))
                need(chunk, 'native fixture ended before result')
                value.extend(chunk)
        rawout.extend(value)
        return bytes(value)
    failure = None; stderr = b''; drained = False
    try:
        ready = receive(64)
        need(ready[:8] == b'HSCFRDY1', 'actual fixture ready')
        observed['initial'] = proc_snapshot(p.pid)
        for index, frame in enumerate(frames, 1):
            sent = time.monotonic_ns(); cursor = 0
            while cursor < len(frame):
                amount = os.write(p.stdin.fileno(), frame[cursor:])
                need(amount > 0, 'stdin transport write')
                rawin.extend(frame[cursor:cursor+amount]); cursor += amount
            response = receive(16); ret, extent = struct.unpack('<QQ', response)
            need(extent in (0, 48), 'actual result frame extent')
            body = receive(extent); received = time.monotonic_ns()
            snap = proc_snapshot(p.pid, observed['initial']['identity'])
            tree = tree_snapshot(work)
            observed['requests'].append(dict(request=index, sent_ns=sent, received_ns=received,
                observed_ns=time.monotonic_ns(), process=snap, tree=tree,
                return_value=ret, result_hex=body.hex()))
        p.stdin.close(); p.stdin = None
        rest, stderr = p.communicate(timeout=max(0.001, deadline-time.monotonic())); rawout.extend(rest); drained = True
        need(p.returncode == 0 and not stderr, 'actual native process failed')
        observed['completed'] = dict(exit_code=p.returncode, observed_ns=time.monotonic_ns())
    except BaseException as error:
        failure = error
    finally:
        if not drained:
            if p.poll() is None:
                p.kill()
            rest, tail = p.communicate(); rawout.extend(rest); stderr += tail
        finished = time.monotonic_ns()
        after = tree_snapshot(work)
        for name, raw in [('stdin.bin', bytes(rawin)), ('stdout.bin', bytes(rawout)), ('stderr.bin', stderr),
                          ('observation.json', packed(observed)), ('after.json', packed(after))]:
            write_new(folder/name, raw)
        receipt = dict(schema='hepta.runtime.shell-capture-file-process.v1', argv=argv, cwd=str(work),
                       environment=env, umask=spec['umask'], pid=p.pid, parent_pid=os.getpid(),
                       uid=os.getuid(), gid=os.getgid(), deadline_seconds=30,
                       monotonic_started_ns=begin, monotonic_completed_ns=finished,
                       unix_started_ns=unix_begin, unix_completed_ns=time.time_ns(),
                       exit_code=p.returncode, timed_out=isinstance(failure, (TimeoutError, subprocess.TimeoutExpired)),
                       executable_before=executable_pin, executable_after=pin(ordinary(executable)),
                       native_manifest={'path':str(manifest), **pin(ordinary(manifest))},
                       streams={n:pin(ordinary(folder/n)) for n in ('stdin.bin','stdout.bin','stderr.bin')},
                       audit_files=audit_files_snapshot(folder),
                       failure=None if failure is None else {'type':type(failure).__name__,'message':str(failure)})
        write_new(folder/'execution.json', packed(receipt))
        write_new(folder/'retirement.json', packed(retire(work, after)))
    if failure:
        raise failure
    return verify_case(folder, spec, manifest, metadata, executable)

def check_tree(rows):
    need(type(rows) is list and rows, 'owned tree rows')
    names = []
    for row in rows:
        name = bytes.fromhex(row['path_hex'])
        need(name.hex() == row['path_hex'], 'canonical raw tree path')
        if name:
            relative(name)
        names.append(name)
        need(all(type(row[k]) is int and row[k] >= 0 for k in
                 ('device','inode','mode','uid','gid','nlink','size','mtime_ns','ctime_ns')), 'tree metadata types')
        need(row['inode'] > 0 and row['nlink'] > 0, 'tree inode/link count')
        kind = row['kind']
        type_check = {'directory':stat.S_ISDIR, 'file':stat.S_ISREG, 'symlink':stat.S_ISLNK}
        need(kind in type_check and type_check[kind](row['mode']), 'tree object type')
        base = {'path_hex','device','inode','mode','uid','gid','nlink','size','mtime_ns','ctime_ns','kind'}
        if kind == 'file':
            payload = bytes.fromhex(row['payload_hex'])
            need(len(payload) == row['size'] and row['nlink'] == 1, 'complete regular payload')
            base.add('payload_hex')
        if kind == 'symlink':
            target = bytes.fromhex(row['target_hex'])
            need(len(target) == row['size'] and b'\0' not in target, 'complete symlink target')
            base.add('target_hex')
        need(set(row) == base, 'tree record fields')
    need(names == sorted(set(names)) and names[0] == b'', 'complete unique tree inventory')
    return {row['path_hex']:row for row in rows}

def verify_trees(spec, before, after, snapshots, execution):
    old, new = check_tree(before), check_tree(after)
    expected = {'':dict(kind='directory',mode=0o700)}
    expected.update({row['path_hex']:row for row in spec['setup']})
    need(set(old) == set(expected), 'complete owned setup')
    for key, item in expected.items():
        row = old[key]
        need(row['kind'] == item['kind'] and stat.S_IMODE(row['mode']) == item['mode'] and
             row['uid'] == execution['uid'] and row['gid'] == execution['gid'], 'setup mode/ownership')
        for field in ('payload_hex','target_hex'):
            if field in item:
                need(row[field] == item[field], 'setup complete payload/target')
    success = spec['operation'] in (1, 2) and not spec['expected_errno'] and not spec['expected_local_nul']
    target = spec['target_hex']
    changed_keys = set(old)
    if success and spec['operation'] == 1:
        need(target is not None, 'create target definition'); changed_keys.add(target)
    if success and spec['operation'] == 2:
        need(target in old, 'unlink target definition'); changed_keys.remove(target)
    need(set(new) == changed_keys, 'actual file effect tree membership')
    if not success:
        need(before == after, 'failed or rejected operation changed tree')
    else:
        for key, row in old.items():
            if key == target:
                continue
            actual = new[key]
            if row['kind'] == 'directory':
                need(identity(row) == identity(actual), 'directory identity changed')
            else:
                need(row == actual, 'unrelated file/link changed')
        if spec['operation'] == 1:
            made = new[target]
            need(made['kind'] == 'file' and made['size'] == 0 and made['payload_hex'] == '' and made['nlink'] == 1,
                 'actual create/truncate effect')
            if target in old:
                need(identity(made) == identity(old[target]), 'truncate replaced original inode/mode')
            else:
                need(stat.S_IMODE(made['mode']) == (0o666 & ~spec['umask']) and
                     made['uid'] == execution['uid'] and made['gid'] == execution['gid'], 'kernel creation mode/ownership')
                need((made['device'],made['inode']) not in {(x['device'],x['inode']) for x in old.values()}, 'new file reused live inode')
    need(snapshots and all(row == after for row in snapshots), 'per-request actual tree effects')

def verify_retirement(folder, final):
    receipt = read_json(folder/'retirement.json'); work = folder/'work'
    need(receipt.get('schema') == 'hepta.runtime.shell-capture-file-retirement.v1' and
         receipt.get('recorded_work') == str(work) and receipt.get('final_snapshot') == pin(packed(final)), 'retirement binding')
    expected = retirement_order(final)
    need(len(receipt['removed']) == len(expected), 'retirement inventory')
    for row, item in zip(receipt['removed'], expected):
        need(set(row) == {'path_hex','before','observed_absent'} and row['path_hex'] == item['path_hex'] and
             identity(row['before']) == identity(item) and row['observed_absent'] is True, 'retirement exact identity/order')
    need(receipt.get('observed_root_absent') is True and not os.path.lexists(work), 'owned fixture remains live')

def fdinfo(raw):
    rows = {}
    for line in raw.splitlines():
        key, value = line.split(b':', 1)
        need(key not in rows, 'duplicate fdinfo field'); rows[key] = value.strip()
    need(all(k in rows for k in (b'pos', b'flags', b'ino', b'mnt_id')), 'actual fdinfo fields')
    return dict(position=int(rows[b'pos']), flags=int(rows[b'flags'], 8),
                inode=int(rows[b'ino']), mount_id=int(rows[b'mnt_id']))

def verify_observations(folder, spec, execution, observations, native, final):
    work = folder/'work'; pid = execution['pid']; ready = native['ready']
    snapshots = [observations['initial']]+[r['process'] for r in observations['requests']]
    audit_files = verify_audit_files(folder, execution)
    initial_identity = observations['initial']['identity']; current_tree = check_tree(final)
    for index, snap in enumerate(snapshots):
        ident = process_identity(bytes.fromhex(snap['stat_hex']))
        need(snap['identity'] == ident and ident['pid'] == pid and ident['ppid'] == execution['parent_pid'] and
             ident['starttime'] == initial_identity['starttime'] and ident['state'] not in ('Z','X'), 'retained child custody identity')
        need(snap['exe_hex'] == os.fsencode(execution['argv'][0]).hex() and
             snap['cwd_hex'] == os.fsencode(work).hex(), 'actual executable and cwd observation')
        fds = snap['fds']; names = [r['fd'] for r in fds]
        need(all(type(x) is int and x >= 0 for x in names) and names == sorted(set(names)), 'actual FD inventory')
        mapping = {r['fd']:r for r in fds}
        need(all(fd in mapping for fd in (0, 1, 2, ready[3], ready[4])), 'fixture transport/audit descriptors')
        step = None if index == 0 else native['steps'][index-1]
        for fd, name, extent in ((ready[3], 'effects.bin', 0 if step is None else step['effect_end']),
                                 (ready[4], 'entries.bin', 0 if step is None else step['entry_end'])):
            row = mapping[fd]; info = fdinfo(bytes.fromhex(row['fdinfo_hex']))
            need(identity(row['stat']) == identity(audit_files[name]['stat']) and
                 row['link_hex'] == os.fsencode(folder/name).hex(), 'audit FD file identity')
            need(info['inode'] == row['stat']['inode'] and info['position'] == extent and row['stat']['size'] == extent and
                 info['flags'] & 0x80000 and info['flags'] & 3 == 1, 'audit FD actual position/flags')
        active = {} if step is None else step['live_handles']
        need(set(mapping) == {0,1,2,ready[3],ready[4]} | set(active.values()), 'owned file FD custody inventory')
        for token, fd in active.items():
            row = mapping[fd]; target = current_tree[spec['target_hex']]
            info = fdinfo(bytes.fromhex(row['fdinfo_hex']))
            need(identity(row['stat']) == identity(target) and row['stat']['size'] == 0 and
                 info['inode'] == target['inode'], 'owned capture FD inode')
            need(row['link_hex'] == (os.fsencode(work)+b'/'+bytes.fromhex(spec['target_hex'])).hex(), 'owned capture FD path')
            # Linux x86-64 openat adds kernel O_LARGEFILE; creation/truncation
            # bits are absent from fdinfo, and this fixture never calls fcntl.
            need(info['position'] == 0 and info['flags'] == 0x88001, 'actual capture FD flags/position')
            need(int(token) > 0, 'owned nonzero token')
        if index:
            retained = observations['requests'][index-1]
            need((retained['return_value'], retained['result_hex']) ==
                 (step['return_value'], step['result_hex']), 'observed actual result')
    completed = observations['completed']
    need(type(completed['exit_code']) is int and completed['exit_code'] == 0 and
         observations['requests'][-1]['observed_ns'] <= completed['observed_ns'] <= execution['monotonic_completed_ns'], 'actual fixture exit custody')

def verify_case(folder, spec, manifest, metadata, executable):
    folder = Path(folder).absolute(); plain_dir(folder)
    need(read_json(folder/'spec.json') == spec, 'registered exact case spec')
    work = folder/'work'; capacity, wires = requests_for(spec, work)
    need(read_json(folder/'requests.json') == dict(workspace_capacity=capacity, wires_hex=[w.hex() for w in wires]), 'registered owner requests')
    framed = b''.join(struct.pack('<QQ',len(w),capacity)+w for w in wires)
    need(ordinary(folder/'stdin.bin') == framed, 'complete actual input frames')
    execution = read_json(folder/'execution.json'); observed = read_json(folder/'observation.json')
    need(execution.get('schema') == 'hepta.runtime.shell-capture-file-process.v1' and
         execution.get('argv') == [str(executable),'--capture-file-fixture',str(folder)] and
         execution.get('cwd') == str(work), 'actual process recipe')
    need(execution.get('environment') == {'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','TMPDIR':str(folder.parent.parent/'temporary')} and
         type(execution.get('umask')) is int and execution['umask'] == spec['umask'], 'actual environment and umask')
    need(all(type(execution.get(k)) is int and execution[k] > 0 for k in
             ('pid','parent_pid','uid','gid','monotonic_started_ns','monotonic_completed_ns','unix_started_ns','unix_completed_ns')),
         'actual process identity/time types')
    need(type(execution.get('exit_code')) is int and execution['exit_code'] == 0 and execution.get('timed_out') is False and
         execution.get('failure') is None and type(execution.get('deadline_seconds')) is int and execution['deadline_seconds'] == 30 and
         0 <= execution['monotonic_completed_ns']-execution['monotonic_started_ns'] <= 30_000_000_000, 'actual process deadline/result')
    need(execution.get('executable_before') == execution.get('executable_after') == pin(ordinary(executable)) and
         execution.get('native_manifest') == {'path':str(manifest),**pin(ordinary(manifest))}, 'actual executable/source binding')
    need(execution.get('streams') == {n:pin(ordinary(folder/n)) for n in ('stdin.bin','stdout.bin','stderr.bin')} and
         ordinary(folder/'stderr.bin') == b'', 'complete actual streams')
    native = verify_native(folder, spec, wires, capacity, execution, observed)
    before, after = read_json(folder/'before.json'), read_json(folder/'after.json')
    verify_trees(spec, before, after, [r['tree'] for r in observed['requests']], execution)
    verify_observations(folder, spec, execution, observed, native, after)
    verify_retirement(folder, after)
    need(set(os.listdir(folder)) == set(CASE_FILES), 'case retained members')
    return dict(name=spec['name'], status='PASS', requests=[w.hex() for w in wires],
                results=[dict(return_value=r, body_hex=b.hex()) for r,b in native['results']],
                operations=native['operations'], steps=native['steps'], counts=native['counts'],
                retired=True, original_file_operation=spec['original_file_operation'])

def core_names(names):
    return ['report.json']+['source-snapshots/'+n for n in SOURCES]+[
        'cases/'+name+'/'+file for name in names for file in CASE_FILES]

def ordinary_inventory(folder):
    result = []
    def visit(path, prefix):
        plain_dir(path)
        with os.scandir(path) as stream:
            entries = sorted(stream, key=lambda e:e.name)
        for entry in entries:
            name = prefix+entry.name; s = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(s.st_mode):
                visit(Path(entry.path), name+'/')
            else:
                need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1, 'nonordinary retained member')
                result.append(name)
    visit(Path(folder), '')
    return result

def read_case(folder, native_manifest):
    manifest, metadata, executable, _ = load_native(native_manifest)
    folder = Path(folder).absolute(); specs = {s['name']:s for s in case_specs()}
    need(folder.name in specs, 'unregistered case name'); spec = specs[folder.name]
    validation = verify_case(folder, spec, manifest, metadata, executable)
    _, wires = requests_for(spec, folder/'work')
    return dict(validation=validation, spec=spec, path=path_for(spec, folder/'work'), requests=wires,
                results=[(v['return_value'], bytes.fromhex(v['body_hex'])) for v in validation['results']],
                operations=validation['operations'], before=read_json(folder/'before.json'),
                after=read_json(folder/'after.json'))

def _read_corpus(folder, native_manifest, require_controls=True):
    folder = Path(folder).absolute(); plain_dir(folder)
    manifest, metadata, executable, build = load_native(native_manifest)
    report = read_json(folder/'report.json'); names = [s['name'] for s in case_specs()]
    need(report.get('schema') == 'hepta.runtime.shell-capture-file-os-report.v1' and report.get('status') == 'PASS' and
         report.get('recorded_directory') == str(folder) and report.get('complete_registered_corpus') is True, 'complete OS report identity')
    need(report.get('case_names') == names and sorted(os.listdir(folder/'cases')) == sorted(names), 'complete registered case inventory')
    need(all(report.get(k) is v for k,v in SCOPE.items()), 'qualification scope claims')
    sources = source_pins(); need(report.get('sources') == sources, 'current source binding')
    need(ordinary_inventory(folder/'source-snapshots') == sorted(SOURCES), 'complete source snapshot inventory')
    for name in SOURCES:
        need(ordinary(folder/'source-snapshots'/name) == ordinary(ROOT/name), 'sealed source bytes')
    need(report.get('native_manifest') == {'path':str(manifest),**pin(ordinary(manifest))}, 'strong manifest identity')
    expected_files = [p for p in core_names(names) if p != 'report.json']
    need(report.get('files') == {n:pin(ordinary(folder/n)) for n in expected_files}, 'complete retained file pins')
    need(not os.listdir(folder/'temporary'), 'temporary fixture remains')
    need(set(os.listdir(folder)) <= {'report.json','readback.json','source-snapshots','cases','temporary','controls'}, 'unknown corpus member')
    rows, counts = [], {}
    for spec in case_specs():
        row = verify_case(folder/'cases'/spec['name'], spec, manifest, metadata, executable); rows.append(row)
        for k,v in row['counts'].items():
            counts[k] = counts.get(k,0)+v
    counts.update(cases=len(names), retired_fixtures=len(names), original_file_operations=sum(s['original_file_operation'] for s in case_specs()), kernel_errno_injected=0)
    need(report.get('cases') == rows and report.get('counts') == counts and
         all(type(v) is int for v in report['counts'].values()), 'reconstructed report results/counts')
    controls = verify_controls(folder, manifest) if require_controls else None
    if require_controls:
        need(report.get('physical_controls') == controls, 'physical controls report binding')
    return dict(schema='hepta.runtime.shell-capture-file-os-evidence.v1', status='PASS',
                recorded_directory=str(folder), complete_registered_corpus=True, native_manifest=report['native_manifest'],
                source_files=len(SOURCES), strong_native_build=build, cases=rows, counts=counts,
                retired_fixtures=len(names), physical_controls=controls,
                verification='current source, exact path, actual ELF, complete raw syscall/entry replay', **SCOPE)

def read_evidence(folder, native_manifest, *, require_full=True):
    need(require_full is True, 'partial corpus is not qualified')
    return _read_corpus(folder, native_manifest, True)

def produce_core(output, native_manifest):
    output = Path(output).absolute()
    manifest, metadata, executable, _ = load_native(native_manifest)
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    (output/'cases').mkdir(); (output/'temporary').mkdir(mode=0o700)
    sources = source_pins()
    for name in SOURCES:
        path = output/'source-snapshots'/name; path.parent.mkdir(parents=True, exist_ok=True)
        write_new(path, ordinary(ROOT/name))
    rows, counts = [], {}
    for spec in case_specs():
        row = run_case(output/'cases'/spec['name'], spec, manifest, metadata, executable); rows.append(row)
        for k,v in row['counts'].items():
            counts[k] = counts.get(k,0)+v
        print(json.dumps({'name':spec['name'],'status':'PASS','results':row['results']},sort_keys=True), flush=True)
    names = [s['name'] for s in case_specs()]
    counts.update(cases=len(names), retired_fixtures=len(names), original_file_operations=sum(s['original_file_operation'] for s in case_specs()), kernel_errno_injected=0)
    need(source_pins() == sources, 'producer source changed during native corpus')
    report = dict(schema='hepta.runtime.shell-capture-file-os-report.v1', status='PASS',
                  recorded_directory=str(output), complete_registered_corpus=True,
                  native_manifest={'path':str(manifest),**pin(ordinary(manifest))}, sources=sources,
                  case_names=names, cases=rows, counts=counts, physical_controls=None,
                  files={n:pin(ordinary(output/n)) for n in core_names(names) if n != 'report.json'}, **SCOPE)
    write_new(output/'report.json', packed(report)); _read_corpus(output, manifest, False)
    return report

CONTROL_ERRORS = {
    'missing_case':'complete registered case inventory',
    'duplicate_case':'complete registered case inventory',
    'input_frame':'complete actual input frames',
    'result_transfer':'published native result',
    'effect_pid':'effect pair identity/order',
    'effect_flags':'complete HIA state transition',
    'path_borrow':'complete HIA state transition',
    'completion_extra_write':'exact native before arrays',
    'entry_guard':'native memory guards',
    'fd_inode':'owned capture FD inode',
    'fd_flags':'actual capture FD flags/position',
    'take_lost_fd':'owned file FD custody inventory',
    'retired_payload':'failed or rejected operation changed tree',
    'missing_footer':'missing effect footer',
    'audit_inode':'audit FD file identity',
    'audit_extent':'audit retained bytes/stat',
    'source_snapshot':'sealed source bytes',
}

def mutation(name, baseline):
    """Pure exact byte recipe, used independently again by the final reader."""
    need(name in CONTROL_ERRORS, 'unregistered physical control')
    changed = {}
    def get(path):
        return changed.get(path, baseline[path])
    def js(path, value):
        changed[path] = packed(value)
    def change_q(path, offset, value):
        raw = bytearray(get(path)); put(raw, offset, value); changed[path] = bytes(raw)
    report = decoded(baseline['report.json'])
    folder = Path(report['recorded_directory'])
    if name in ('missing_case','duplicate_case'):
        report['case_names'] = report['case_names'][:-1] if name == 'missing_case' else report['case_names']+[report['case_names'][0]]
    elif name in ('audit_inode','audit_extent'):
        path = 'cases/create_new/'+('observation.json' if name == 'audit_inode' else 'execution.json')
        value = decoded(get(path))
        if name == 'audit_inode':
            target = os.fsencode(folder/'cases/create_new/effects.bin').hex()
            row = next(r for r in value['initial']['fds'] if r['link_hex'] == target)
            row['stat']['inode'] += 1
            raw = bytes.fromhex(row['fdinfo_hex'])
            row['fdinfo_hex'] = b''.join(b'ino:\t'+str(row['stat']['inode']).encode()+b'\n' if line.startswith(b'ino:') else line
                                      for line in raw.splitlines(keepends=True)).hex()
        else:
            value['audit_files']['effects.bin']['stat']['size'] += 1
        js(path,value)
    elif name == 'input_frame':
        path = 'cases/create_new/stdin.bin'; raw = bytearray(get(path)); raw[80] ^= 1; changed[path] = bytes(raw)
    elif name == 'result_transfer':
        change_q('cases/create_new/stdout.bin', 64+16+16, 4)
    elif name in ('effect_pid','effect_flags','path_borrow'):
        path = 'cases/create_new/effects.bin'; raw = bytearray(get(path)); rows,_ = parse_effects(raw)
        for row in rows[:2]:
            if name == 'effect_pid':
                put(raw, row['offset']+32, row['header'][4]+1)
            elif name == 'effect_flags':
                put(raw, row['offset']+72, 0x80041); put(raw, row['offset']+128+40, 0x80041)
            else:
                put(raw, row['offset']+128+24, 256)
        changed[path] = bytes(raw)
        if name != 'effect_pid':
            path = 'cases/create_new/entries.bin'; raw = bytearray(get(path)); rows,_ = parse_entries(raw)
            for row in rows:
                h = row['header']
                if (h[2],h[3]) in ((1,1),(2,0)):
                    start = row['offset']+128+h[6]+32+h[7]+32+16
                    if name == 'effect_flags':
                        put(raw, start+128+40, 0x80041)
                    else:
                        put(raw, start+128+24, 256); raw[start+256:start+260] = b'new\0'
            changed[path] = bytes(raw)
    elif name == 'completion_extra_write':
        path = 'cases/create_new/entries.bin'; raw = bytearray(get(path)); rows,_ = parse_entries(raw)
        row = next(r for r in rows if r['header'][2:4] == (2,0)); h = row['header']
        start = row['offset']+128+h[6]+32+h[7]+32+16
        raw[start+224] ^= 1; changed[path] = bytes(raw)
    elif name == 'entry_guard':
        path = 'cases/create_new/entries.bin'; raw = bytearray(get(path)); raw[128] ^= 1; changed[path] = bytes(raw)
    elif name in ('fd_inode','fd_flags'):
        path = 'cases/create_new/observation.json'; value = decoded(get(path))
        target = os.fsencode(folder/'cases/create_new/work/new').hex()
        row = next(r for r in value['requests'][0]['process']['fds'] if r['link_hex'] == target)
        raw = bytes.fromhex(row['fdinfo_hex'])
        if name == 'fd_inode':
            row['stat']['inode'] += 1
            raw = b''.join(b'ino:\t'+str(row['stat']['inode']).encode()+b'\n' if line.startswith(b'ino:') else line
                           for line in raw.splitlines(keepends=True))
        else:
            flags = fdinfo(raw)['flags'] | 0x4000
            raw = b''.join(b'flags:\t'+format(flags,'o').encode()+b'\n' if line.startswith(b'flags:') else line
                           for line in raw.splitlines(keepends=True))
        row['fdinfo_hex'] = raw.hex()
        js(path, value)
    elif name == 'take_lost_fd':
        path = 'cases/hold_take/observation.json'; value = decoded(get(path))
        target = os.fsencode(folder/'cases/hold_take/work/file').hex()
        fds = value['requests'][1]['process']['fds']
        value['requests'][1]['process']['fds'] = [r for r in fds if r['link_hex'] != target]
        need(len(value['requests'][1]['process']['fds']) == len(fds)-1, 'take mutation target')
        js(path, value)
    elif name == 'retired_payload':
        path = 'cases/readonly_file/after.json'; value = decoded(get(path))
        row = next(r for r in value if r['kind'] == 'file')
        raw = bytearray.fromhex(row['payload_hex']); raw[0] ^= 1; row['payload_hex'] = raw.hex(); js(path,value)
        observation = decoded(get('cases/readonly_file/observation.json'))
        observation['requests'][0]['tree'] = value; js('cases/readonly_file/observation.json', observation)
        retired = decoded(get('cases/readonly_file/retirement.json')); retired['final_snapshot'] = pin(packed(value))
        js('cases/readonly_file/retirement.json', retired)
    elif name == 'missing_footer':
        path = 'cases/create_new/effects.bin'; changed[path] = get(path)[:-128]
    else:
        path = 'source-snapshots/native/shell_capture_file.hepta'; raw = bytearray(get(path)); raw[0] ^= 1; changed[path] = bytes(raw)
    for case in {p.split('/')[1] for p in changed if p.startswith('cases/')}:
        path = 'cases/'+case+'/execution.json'; receipt = decoded(get(path)); touched = False
        for stream in ('stdin.bin','stdout.bin','stderr.bin'):
            target = 'cases/'+case+'/'+stream
            if target in changed:
                receipt['streams'][stream] = pin(changed[target]); touched = True
        for audit in ('effects.bin','entries.bin'):
            target = 'cases/'+case+'/'+audit
            if target in changed:
                receipt['audit_files'][audit].update(pin(changed[target])); touched = True
        if touched:
            js(path, receipt)
    for path, raw in changed.items():
        report['files'][path] = pin(raw)
    changed['report.json'] = packed(report)
    return {k:v for k,v in sorted(changed.items()) if v != baseline[k]}

def replace_ordinary(path, raw):
    before = Path(path).lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'mutation ordinary target')
    fd = os.open(path, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        need(identity(stat_row(os.fstat(fd))) == identity(stat_row(before)), 'mutation opened identity')
        os.ftruncate(fd, 0); at = 0
        while at < len(raw):
            written = os.write(fd, raw[at:]); need(written > 0, 'physical mutation write'); at += written
    finally:
        os.close(fd)
    after = Path(path).lstat()
    need(identity(stat_row(before)) == identity(stat_row(after)) and ordinary(path) == raw, 'physical mutation readback')
    return dict(device=before.st_dev, inode=before.st_ino, mode=before.st_mode)

def reader_process(folder, corpus, manifest, inputs):
    folder.mkdir(); interpreter = Path(sys.executable).resolve()
    argv = [str(interpreter), str(ROOT/'tests/hia_native/shell_capture_file_io.py'),
            '--native-manifest', str(manifest), '--verify-core', str(corpus)]
    env = {'PATH':'/usr/bin:/bin', 'LANG':'C', 'LC_ALL':'C', 'PYTHONDONTWRITEBYTECODE':'1'}
    physical_before = control_identities(corpus, inputs)
    before = {name:pin(ordinary(corpus/name)) for name in inputs}
    need(before == {name:pin(raw) for name,raw in inputs.items()}, 'physical reader inputs before')
    tool = pin(ordinary(interpreter)); source = pin(ordinary(ROOT/'tests/hia_native/shell_capture_file_io.py'))
    start, unix_start = time.monotonic_ns(), time.time_ns()
    p = subprocess.Popen(argv, cwd=ROOT, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    timed_out = False
    try:
        stdout, stderr = p.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        timed_out = True; p.kill(); stdout, stderr = p.communicate()
    finish = time.monotonic_ns()
    write_new(folder/'stdout.bin', stdout); write_new(folder/'stderr.bin', stderr)
    after = {name:pin(ordinary(corpus/name)) for name in inputs}
    receipt = dict(schema='hepta.runtime.shell-capture-file-reader-process.v1', argv=argv, cwd=str(ROOT),
                   environment=env, pid=p.pid, deadline_seconds=30, timed_out=timed_out, exit_code=p.returncode,
                   monotonic_started_ns=start, monotonic_completed_ns=finish,
                   unix_started_ns=unix_start, unix_completed_ns=time.time_ns(),
                   interpreter_before=tool, interpreter_after=pin(ordinary(interpreter)), source=source,
                   physical_inputs_before=physical_before, physical_inputs_after=control_identities(corpus, inputs),
                   inputs_before=before, inputs_after=after, stdout=pin(stdout), stderr=pin(stderr))
    write_new(folder/'execution.json', packed(receipt))
    need(before == after and receipt['physical_inputs_before'] == receipt['physical_inputs_after'] and
         receipt['interpreter_before'] == receipt['interpreter_after'] and not timed_out, 'reader process modified inputs')
    return receipt, decoded(stdout)

def verify_reader_process(folder, corpus, manifest, inputs, physical_identities, expected_error=None):
    receipt = read_json(folder/'execution.json'); interpreter = Path(sys.executable).resolve()
    argv = [str(interpreter), str(ROOT/'tests/hia_native/shell_capture_file_io.py'),
            '--native-manifest', str(manifest), '--verify-core', str(corpus)]
    need(receipt.get('schema') == 'hepta.runtime.shell-capture-file-reader-process.v1' and
         receipt.get('argv') == argv and receipt.get('cwd') == str(ROOT) and receipt.get('environment') ==
         {'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','PYTHONDONTWRITEBYTECODE':'1'}, 'actual reader process recipe')
    need(type(receipt.get('pid')) is int and receipt['pid'] > 0 and type(receipt.get('deadline_seconds')) is int and
         receipt['deadline_seconds'] == 30 and receipt.get('timed_out') is False and
         all(type(receipt.get(k)) is int and receipt[k] > 0 for k in
             ('monotonic_started_ns','monotonic_completed_ns','unix_started_ns','unix_completed_ns')) and
         0 <= receipt['monotonic_completed_ns']-receipt['monotonic_started_ns'] <= 30_000_000_000, 'actual reader process time')
    need(receipt.get('interpreter_before') == receipt.get('interpreter_after') == pin(ordinary(interpreter)) and
         receipt.get('source') == pin(ordinary(ROOT/'tests/hia_native/shell_capture_file_io.py')), 'actual reader executable/source')
    check_control_identities(physical_identities, inputs)
    need(receipt.get('physical_inputs_before') == receipt.get('physical_inputs_after') == physical_identities, 'reader producer physical identities')
    expected = {n:pin(raw) for n,raw in inputs.items()}
    need(receipt.get('inputs_before') == receipt.get('inputs_after') == expected, 'complete reader process input identities')
    stdout, stderr = ordinary(folder/'stdout.bin'), ordinary(folder/'stderr.bin')
    need(receipt.get('stdout') == pin(stdout) and receipt.get('stderr') == pin(stderr) and stderr == b'', 'complete reader process streams')
    need(type(receipt.get('exit_code')) is int and receipt['exit_code'] == (2 if expected_error else 0), 'actual reader process exit')
    value = decoded(stdout)
    if expected_error:
        need(value == {'status':'REJECTED','error_type':'ValueError','error':expected_error}, 'exact named refusal reason')
    else:
        need(value == _read_corpus(corpus, manifest, False), 'restored positive full reader result')

def run_controls(corpus, manifest):
    root = corpus/'controls'; root.mkdir(); names = [s['name'] for s in case_specs()]
    baseline = {name:ordinary(corpus/name) for name in core_names(names)}
    baseline_identities = control_identities(corpus, baseline)
    write_new(root/'baseline-report.json', baseline['report.json']); rows = []
    for name, expected_error in CONTROL_ERRORS.items():
        folder = root/name; changes = mutation(name, baseline); modified = []
        try:
            identities = {}
            for path, raw in changes.items():
                modified.append(path); identities[path] = replace_ordinary(corpus/path, raw)
                need(identities[path] == baseline_identities[path], 'mutation original producer identity')
            inputs = dict(baseline); inputs.update(changes)
            receipt, value = reader_process(folder, corpus, manifest, inputs)
            change_rows = []
            for index, (path, after) in enumerate(changes.items()):
                prefix = f'{index:03d}'
                write_new(folder/(prefix+'.before.bin'), baseline[path]); write_new(folder/(prefix+'.after.bin'), after)
                change_rows.append(dict(path=path, before=pin(baseline[path]), after=pin(after),
                                        physical_identity=identities[path], prefix=prefix))
            write_new(folder/'changes.json', packed(change_rows))
            need(receipt['exit_code'] == 2 and value == {'status':'REJECTED','error_type':'ValueError','error':expected_error}, 'named physical control did not reach expected gate: '+name)
            rows.append(dict(name=name, changes=pin(ordinary(folder/'changes.json')),
                             process={n:pin(ordinary(folder/n)) for n in ('execution.json','stdout.bin','stderr.bin')}))
        finally:
            for path in modified:
                need(replace_ordinary(corpus/path, baseline[path]) == baseline_identities[path], 'restored original producer identity')
    inputs = {name:ordinary(corpus/name) for name in baseline}
    need(inputs == baseline, 'baseline bytes not fully restored')
    reader_process(root/'restored-positive', corpus, manifest, baseline)
    verify_reader_process(root/'restored-positive', corpus, manifest, baseline, baseline_identities)
    report = dict(schema='hepta.runtime.shell-capture-file-physical-controls.v1', status='PASS',
                  recorded_directory=str(root), names=list(CONTROL_ERRORS), controls=rows,
                  baseline_identities=baseline_identities,
                  baseline_inputs={n:pin(raw) for n,raw in baseline.items()},
                  restored_positive={n:pin(ordinary(root/'restored-positive'/n)) for n in ('execution.json','stdout.bin','stderr.bin')})
    write_new(root/'report.json', packed(report))
    return verify_controls(corpus, manifest)

def verify_controls(corpus, manifest):
    root = corpus/'controls'; plain_dir(root)
    report = read_json(root/'report.json')
    need(report.get('schema') == 'hepta.runtime.shell-capture-file-physical-controls.v1' and
         report.get('status') == 'PASS' and report.get('recorded_directory') == str(root) and
         report.get('names') == list(CONTROL_ERRORS), 'complete physical control report')
    need(set(os.listdir(root)) == {'report.json','baseline-report.json','restored-positive'} | set(CONTROL_ERRORS), 'physical control inventory')
    names = [s['name'] for s in case_specs()]
    baseline = {name:ordinary(corpus/name) for name in core_names(names)}
    current = decoded(baseline['report.json']); current['physical_controls'] = None
    baseline['report.json'] = ordinary(root/'baseline-report.json')
    need(decoded(baseline['report.json']) == current, 'exact restored baseline report')
    need(report.get('baseline_inputs') == {n:pin(raw) for n,raw in baseline.items()}, 'complete baseline byte identities')
    baseline_identities = report.get('baseline_identities')
    check_control_identities(baseline_identities, baseline)
    rows = report['controls']
    need([r.get('name') for r in rows] == list(CONTROL_ERRORS), 'named control coverage')
    for row in rows:
        name = row['name']; folder = root/name; plain_dir(folder)
        expected = mutation(name, baseline); changes = read_json(folder/'changes.json')
        need([r.get('path') for r in changes] == list(expected), 'exact named mutation file recipe')
        members = {'changes.json','execution.json','stdout.bin','stderr.bin'}
        for index, change in enumerate(changes):
            path = change['path']; prefix = f'{index:03d}'
            need(set(change) == {'path','before','after','physical_identity','prefix'} and change['prefix'] == prefix, 'mutation record fields')
            before, after = ordinary(folder/(prefix+'.before.bin')), ordinary(folder/(prefix+'.after.bin'))
            need(before == baseline[path] and after == expected[path] and before != after, 'exact named physical mutation bytes')
            need(change['before'] == pin(before) and change['after'] == pin(after), 'physical changed byte pins')
            need(change['physical_identity'] == baseline_identities[path], 'physical mutation preserved original identity')
            members |= {prefix+'.before.bin',prefix+'.after.bin'}
        need(set(os.listdir(folder)) == members, 'complete physical change evidence')
        inputs = dict(baseline); inputs.update(expected)
        verify_reader_process(folder, corpus, manifest, inputs, baseline_identities, CONTROL_ERRORS[name])
        need(row.get('changes') == pin(ordinary(folder/'changes.json')) and row.get('process') ==
             {n:pin(ordinary(folder/n)) for n in ('execution.json','stdout.bin','stderr.bin')}, 'actual control process pins')
    positive = root/'restored-positive'; plain_dir(positive)
    need(set(os.listdir(positive)) == {'execution.json','stdout.bin','stderr.bin'}, 'restored positive members')
    verify_reader_process(positive, corpus, manifest, baseline, baseline_identities)
    need(report.get('restored_positive') == {n:pin(ordinary(positive/n)) for n in ('execution.json','stdout.bin','stderr.bin')}, 'restored positive pins')
    return dict(status='PASS', physical_negative_controls=len(CONTROL_ERRORS), reader_processes=len(CONTROL_ERRORS)+1,
                exact_named_mutations_reconstructed=True, all_baseline_bytes_restored=True,
                report_sha256=sha(ordinary(root/'report.json')))

def run(output, native_manifest):
    output = Path(output).absolute(); manifest = Path(native_manifest).absolute()
    report = produce_core(output, manifest)
    report['physical_controls'] = run_controls(output, manifest)
    replace_ordinary(output/'report.json', packed(report))
    result = read_evidence(output, manifest)
    write_new(output/'readback.json', packed(result))
    return result

def audit_read_only(folder, native_manifest):
    load_native(native_manifest)
    import ctypes
    enabled, probes = True, False
    forbidden, seen = [], [0]
    def hook(event, args):
        if not enabled:
            return
        seen[0] += 1
        bad = event.startswith(('subprocess.','socket.','ctypes.')) or event in {
            'os.system','os.fork','os.forkpty','os.posix_spawn','os.exec','os.kill',
            'os.mkdir','os.remove','os.rmdir','os.rename','os.link','os.symlink',
            'os.chmod','os.chown','os.truncate','os.utime','os.setxattr','os.removexattr'}
        if event == 'open':
            path, mode, flags = args
            bad = bool(type(mode) is str and any(x in mode for x in 'wax+')) or bool(type(flags) is int and flags & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND))
            if isinstance(path, (str,bytes,os.PathLike)):
                bad |= os.fsencode(path).startswith(b'/proc/')
        if bad:
            forbidden.append({'event':event,'probe':probes})
            raise PermissionError('read-only audit blocked '+event)
    sys.addaudithook(hook)
    try:
        result = read_evidence(folder, native_manifest)
        need(not forbidden, 'reader attempted forbidden action'); probes = True
        for action in (lambda:subprocess.run(['/bin/true']), lambda:open(Path(folder)/'forbidden-write','wb'),
                       lambda:open('/proc/self/stat','rb'), lambda:ctypes.CDLL(None)):
            try:
                action()
            except PermissionError:
                pass
            else:
                raise ValueError('audit probe not refused')
        need(len(forbidden) == 4 and all(x['probe'] for x in forbidden), 'audit mechanism probes')
    finally:
        enabled = False
    return dict(schema='hepta.runtime.shell-capture-file-read-audit.v1', status='PASS',
                reader_status=result['status'], observed_events=seen[0], reader_forbidden_actions=0,
                blocked_negative_probes=4, imports_preloaded=True,
                report_sha256=sha(ordinary(Path(folder)/'report.json')), **SCOPE)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-manifest', type=Path, required=True)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--output', type=Path)
    modes.add_argument('--verify', type=Path)
    modes.add_argument('--verify-core', type=Path, help=argparse.SUPPRESS)
    modes.add_argument('--verify-case', type=Path)
    modes.add_argument('--audit-read-only', type=Path)
    args = parser.parse_args()
    try:
        if args.output:
            result = run(args.output, args.native_manifest)
        elif args.verify_core:
            result = _read_corpus(args.verify_core, args.native_manifest, False)
        elif args.verify_case:
            result = read_case(args.verify_case, args.native_manifest)['validation']
        elif args.audit_read_only:
            result = audit_read_only(args.audit_read_only, args.native_manifest)
        else:
            result = read_evidence(args.verify, args.native_manifest)
    except Exception as error:
        print(json.dumps({'status':'REJECTED','error_type':type(error).__name__,'error':str(error)},sort_keys=True), flush=True)
        raise SystemExit(2)
    print(json.dumps(result,sort_keys=True), flush=True)

if __name__ == '__main__':
    main()
