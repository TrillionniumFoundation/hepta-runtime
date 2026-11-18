"""Read actual native syscalls and source-owned continuation receipts.

No process is executed and no live fixture is consulted. Private boundaries
come from full framed stdout writes, never Python stderr-read timing.
"""
from collections import Counter
from pathlib import Path
import errno
import gzip
import os
import re
import stat
import struct

U64 = (1 << 64) - 1
CALL = 0xfffffff0
DELIVERY = 0xffffffcd
SIZES = {b'HRGTR002': 224, b'HFSPCL02': 80, b'HFSPAK02': 192,
         b'HRCNAK02': 128, b'HWDIOAK2': 160, b'HVRDACK1': 128, b'HFLKEYFX': 128}
TARGETS = {18: (19, 1, 0, 10, 2, 13, 11, 20, 21), 3: (None, 10),
    5: (None, 6, 10, 7, 8), 13: (14, 5, 6, 11, 9, 7, 15, 16, 17),
    1: (10, 3), 2: (4, 5, 6, 11, 9, 7, 12), 7: (None, 11, 8),
    21: (22, 27, 5, 6, 11, 9, 7, 23), 23: (29, 11, 9, 7, 26, 24, 30, 31, 32, 25),
    26: (None, 11, 8), 27: (11, 28, 17)}
MAGICS = {18: b'HRMCFA02', 3: b'HRCMCA02', 5: b'HRSCPA02', 13: b'HWDGWA02',
    1: b'HRCADA02', 2: b'HVGWCA02', 7: b'HLPCA002', 21: b'HFSWGA02',
    23: b'HFSCCA02', 26: b'HFDMGA02', 27: b'HFSFEA02'}
NAMES = {'close', 'execve', 'fchmodat', 'flock', 'getcwd', 'mkdirat', 'newfstatat',
         'openat', 'readlink', 'readlinkat', 'renameat2', 'statx', 'write'}
PATH_ARGUMENTS = {'execve': (0,), 'fchmodat': (1,), 'getcwd': (0,), 'mkdirat': (1,),
    'newfstatat': (1,), 'openat': (1,), 'readlink': (0,), 'readlinkat': (1,),
    'renameat2': (1, 3), 'statx': (1,)}
MODE_TYPES = {key: getattr(stat, key) for key in ('S_IFREG', 'S_IFDIR', 'S_IFLNK', 'S_IFIFO', 'S_IFSOCK', 'S_IFCHR', 'S_IFBLK')}


def line(q, raw, number):
    m = re.fullmatch(rb'(\d+)\s+([a-z_0-9]+)\((.*)\)\s+=\s+(-?\d+)(?:\s+([A-Z0-9_]+)\s+\([^\n]*\))?\n', raw)
    q.need(m is not None, 'unparsed complete native trace line '+str(number))
    pid, name, result = int(m[1]), m[2].decode(), int(m[4])
    error = m[5].decode() if m[5] else None
    q.need(pid > 0 and (result == -1) == (error is not None), 'actual syscall PID/return/errno shape')
    error_number = getattr(errno, error, None) if error else 0
    q.need(type(error_number) is int and (not error or error_number > 0), 'actual syscall errno name')
    return {'pid': pid, 'name': name, 'args': q.split_arguments(m[3].decode('ascii')),
            'return': result, 'errno': error, 'errno_number': error_number,
            'normalized_return': -error_number if error else result,
            'line': number, 'bytes': len(raw), 'sha256': q.sha(raw)}


def mode(q, text):
    m = re.search(r'(?:st_mode|stx_mode)=(S_IF[A-Z]+)\|([0-7]+)', text)
    q.need(m is not None and m[1] in MODE_TYPES, 'complete actual file type/mode')
    return MODE_TYPES[m[1]] | int(m[2], 8)


def receipts(q, raw):
    result = []; at = 0
    while at < len(raw):
        magic = raw[at:at+8]; size = SIZES.get(magic)
        q.need(size is not None and size <= len(raw)-at, 'unknown/truncated native effect receipt')
        body = raw[at:at+size]
        result.append({'magic': magic.decode(), 'offset': at, 'bytes': size, 'sha256': q.sha(body),
                       'raw': body, 'words': struct.unpack_from('<'+'Q'*(size//8-1), body, 8)})
        at += size
    return result


def trace_process(q, raw, stdout, stderr, argv, cwd, exchanges, private):
    q.need(raw.endswith(b'\n'), 'unfinished complete native syscall stream')
    records = receipts(q, stderr) if private else []
    if not private: q.need(stderr == b'', 'ordinary public process emitted private receipts')
    ends = [row['response']['offset']+row['response']['bytes'] for row in exchanges] if private else []
    q.need(not private or all(a < b for a, b in zip([0, *ends], ends)), 'nonempty ordered private frame boundaries')
    segments = []; current = {'receipts': [], 'syscalls': [], 'start_line': 1}; ri = fi = offset = 0
    stream_at = {1: 0, 2: 0}; streams = {1: stdout, 2: stderr}
    counts = Counter(); live = {}; opened = closed = peak = 0; pid = None; execs = 0; truncated_paths = clipped_writes = 0
    all_events = []; used_receipts = []
    for number, raw_line in enumerate(raw.splitlines(keepends=True), 1):
        event = line(q, raw_line, number); name, args, result = event['name'], event['args'], event['return']
        q.need(name in NAMES, 'unexpected native syscall '+name)
        if pid is None: pid = event['pid']
        q.need(event['pid'] == pid, 'native executable unexpectedly changed process/thread')
        event['offset'] = offset; offset += len(raw_line); counts[name] += 1
        paths = {}
        for position in PATH_ARGUMENTS.get(name, ()):
            q.need(position < len(args), 'short native syscall argument list')
            if args[position] == 'NULL':
                q.need(name in ('statx', 'newfstatat'), 'unexpected NULL pathname'); paths[position] = (None, False)
            else:
                value, clipped = q.quoted(args[position]); paths[position] = (value, clipped); truncated_paths += int(clipped)
        event['paths'] = paths
        if name == 'execve':
            execs += 1; q.need(number == 1 and execs == 1 and result == 0 and len(args) == 3, 'native initial executable')
            q.need(paths[0] == (os.fsencode(argv[0]), False), 'native trace executable differs')
            q.need(args[1].startswith('[') and args[1].endswith(']'), 'native complete argv rendering')
            q.need([q.quoted(v)[0] for v in q.split_arguments(args[1][1:-1])] == [os.fsencode(a) for a in argv], 'native trace complete argv')
        elif name == 'getcwd':
            q.need(result > 0 and len(args) == 2 and paths[0] == (os.fsencode(cwd), False)
                   and result == len(os.fsencode(cwd))+1 and int(args[1]) >= result, 'native actual cwd initialization')
        elif name == 'openat':
            q.need(len(args) in (3, 4), 'actual openat arguments')
            if args[0] != 'AT_FDCWD': q.need(int(args[0]) in live, 'openat parent not owned')
            if result >= 0:
                q.need(result >= 3 and result not in live, 'native open reuses live descriptor')
                live[result] = {'opened': number, 'path': paths[1], 'flags': args[2]}; opened += 1; peak = max(peak, len(live))
        elif name == 'close':
            q.need(len(args) == 1 and int(args[0]) in live and result == 0, 'native close does not retire owned descriptor')
            del live[int(args[0])]; closed += 1
        elif name == 'flock':
            q.need(len(args) == 2 and int(args[0]) in live and result == 0 and args[1] == 'LOCK_EX|LOCK_NB', 'actual installed owner lock')
        elif name in ('readlink', 'readlinkat'):
            out_index = 1 if name == 'readlink' else 2; cap = int(args[out_index+1])
            if result >= 0:
                value, clipped = q.quoted(args[out_index], 4096)
                q.need(result <= cap and (len(value) == result if not clipped else len(value) == 4096 and result > 4096), 'actual readlink extent')
                event['target_hex'] = value.hex(); event['target_clipped'] = clipped
            else: q.need(re.fullmatch(r'0x[0-9a-f]+', args[out_index]) is not None, 'failed readlink output pointer')
        elif name == 'renameat2':
            q.need(len(args) == 5 and int(args[0]) in live and int(args[2]) in live and args[4] == 'RENAME_NOREPLACE'
                   and result in (0, -1), 'actual atomic noreplace descriptors/flags')
        elif name == 'write':
            q.need(len(args) == 3 and args[0].isdigit() and args[2].isdigit(), 'actual write arguments')
            fd, requested = int(args[0]), int(args[2]); value, clipped = q.quoted(args[1], 4096)
            q.need(fd in streams and requested > 0 and len(value) == (min(requested, 4096) if clipped else requested), 'actual write full buffer/prefix')
            q.need(0 < result <= requested, 'native write failed or made no progress')
            at = stream_at[fd]; full = streams[fd][at:at+result]
            q.need(len(full) == result and full[:min(result, len(value))] == value[:min(result, len(value))], 'actual write differs from retained full stream')
            stream_at[fd] += result; clipped_writes += int(clipped)
            event.update(fd=fd, requested=requested, stream_offset=at, full_bytes=result, full_sha256=q.sha(full), prefix_clipped=clipped)
            if fd == 2:
                while ri < len(records) and records[ri]['offset']+records[ri]['bytes'] <= stream_at[2]:
                    record = records[ri]; record['trace_line'] = number
                    record['last_syscall'] = current['syscalls'][-1] if current['syscalls'] else None
                    current['receipts'].append(record); used_receipts.append(record); ri += 1
            elif private:
                q.need(fi < len(ends) and stream_at[1] <= ends[fi], 'stdout write crosses private request boundary')
                if stream_at[1] == ends[fi]:
                    q.need(ri == len(records) or records[ri]['offset'] >= stream_at[2], 'partial receipt at response boundary')
                    current.update(index=fi, end_line=number, header=exchanges[fi]['header']); segments.append(current)
                    current = {'receipts': [], 'syscalls': [], 'start_line': number+1}; fi += 1
            all_events.append(event); continue
        current['syscalls'].append(event); all_events.append(event)
    q.need(execs == 1 and not live and opened == closed, 'native complete process descriptor cleanup')
    q.need(stream_at == {1: len(stdout), 2: len(stderr)} and ri == len(records), 'all actual stream and receipt bytes accounted for')
    if private: q.need(fi == len(exchanges), 'all framed responses physically written')
    return {'pid': pid, 'segments': segments, 'epilogue': current, 'events': all_events, 'receipts': used_receipts,
        'summary': {'trace_bytes': len(raw), 'trace_sha256': q.sha(raw), 'lines': sum(counts.values()),
            'syscall_counts': dict(sorted(counts.items())), 'opened': opened, 'closed': closed, 'maximum_process_owned_fds': peak,
            'path_display_limit': 4095, 'truncated_paths': truncated_paths, 'write_display_limit': 4096, 'truncated_writes': clipped_writes,
            'full_stdout_bytes': len(stdout), 'full_stderr_bytes': len(stderr), 'full_streams_bound': True,
            'effect_receipts': dict(sorted(Counter(v['magic'] for v in records).items()))}}


def action(q, record):
    raw = record['raw']; words = record['words']; slot = words[1]
    q.need(slot in MAGICS and raw[80:88] == MAGICS[slot], 'controller action magic/slot')
    values = struct.unpack_from('<13Q', raw, 88)
    seq, selector, delivery, ioff, ilen, ooff, ocap, done, code, z0, z1, extent, z2 = values
    q.need(seq > 0 and words[7] == seq and delivery in (0, 1) and z0 == z1 == z2 == 0, 'controller action sequence/flags/reserved')
    q.need(selector < len(TARGETS[slot]) and TARGETS[slot][selector] is not None, 'controller exact child mapping')
    workcap = words[4]
    q.need(4096 <= ioff <= workcap and ilen <= workcap-ioff and 4096 <= ooff <= workcap and 32 <= ocap <= workcap-ooff
           and (ioff+ilen <= ooff or ooff+ocap <= ioff), 'controller borrowed input/output disjoint exact bounds')
    return {'seq': seq, 'selector': selector, 'target': TARGETS[slot][selector], 'delivery': delivery,
        'input_offset': ioff, 'input_bytes': ilen, 'output_offset': ooff, 'output_capacity': ocap,
        'completed_seq': done, 'code': code, 'extent': extent, 'raw': raw[80:192]}


class Continuations:
    def __init__(self, q, root_length):
        self.q = q; self.root_length = root_length
        self.trace_seq = [1, 1]; self.dispatch = {}; self.retained = {}; self.latest = {}

    def segment(self, segment, session, root_slot, initial=False):
        q = self.q; records = segment['receipts']; stats = Counter(); edges = []; stack = []; request = {}; actual_returns = {}
        if initial:
            q.need(len(records) >= 2, 'missing two actual initial Session calls')
            for row in records[:2]:
                q.need(row['magic'] == 'HRGTR002' and row['words'][:9] == (1, 6, 1, 32, 4096, 4096, self.root_length, 0, 0)
                       and row['raw'][80:192] == bytes(112), 'two source-owned startup Session calls')
            records = records[2:]
        for row in records:
            if row['magic'] != 'HRGTR002': continue
            seq, slot, event, code, wc, oc, phase, state_seq, extent = row['words'][:9]
            q.need(seq == self.trace_seq[session]+1 and 0 <= slot < 33 and event in (1, 2, 3, 4), 'actual per-Session trace sequence/slot/event')
            self.trace_seq[session] = seq
            q.need(wc >= 4096 and oc >= 32 and wc % 4096 == oc % 4096 == 0, 'owned descriptor capacities')
            key = session, slot
            if event == 4:
                a = action(q, row); q.need(key in request and key in self.retained, 'completion lacks pending owner action')
                wanted = request[key]; saved = self.retained[key]
                q.need(all(a[k] == wanted[k] for k in ('seq', 'selector', 'delivery', 'input_offset', 'input_bytes', 'output_offset', 'output_capacity')),
                       'child completion changed pending action')
                q.need(a['completed_seq'] == a['seq'] and a['code'] <= 0xffffffff, 'child completion sequence/code')
                if not a['delivery']:
                    q.need(stack and stack[-1]['key'] == key, 'child completion order'); stack.pop()
                    saved['child_code'] = actual_returns.get(a['target']); saved['child_extent'] = a['extent']
                else:
                    q.need('child_extent' in saved and a['extent'] == saved['child_extent'], 'delivery-only changed retained full extent')
                    stats['delivery_only'] += 1
                if a['code'] == DELIVERY:
                    q.need(a['extent'] > a['output_capacity'], 'short-delivery code with sufficient parent capacity'); stats['delivery_short'] += 1
                else:
                    q.need(a['code'] >= 0xffff0000 and a['extent'] == 0 or a['code'] < 0xffff0000 and a['code'] <= a['extent'] <= a['output_capacity'],
                           'completed child code/extent/parent capacity')
                    if saved['child_code'] is not None: q.same(a['code'], saved['child_code'], 'delivered actual child return')
                    del self.retained[key]
                q.need(slot == (stack[-1]['target'] if stack else root_slot), 'completion returned to wrong parent')
                continue
            expected_slot = stack[-1]['target'] if stack else root_slot
            q.need(slot == expected_slot, 'child executed outside its actual retained dispatch')
            if event == 1:
                q.need(code <= 0xffffffff, 'f0 returned wider than u32'); stats['calls'] += 1; actual_returns[slot] = code
                self.latest[key] = row
                if code == CALL and slot in TARGETS:
                    a = action(q, row); q.need(a['completed_seq'] == a['code'] == a['extent'] == 0, 'new HIA action carries stale completion')
                    request[key] = a
                    if a['delivery']:
                        q.need(key in self.retained, 'delivery-only request lacks completed child')
                        saved = self.retained[key]
                        q.need(all(a[k] == saved[k] for k in ('seq', 'selector', 'input_offset', 'input_bytes')), 'delivery-only retry changed child/input')
            elif event == 2:
                q.need(key in self.latest, 'resize lacks preceding actual f0')
                old = self.latest[key]['words']; wgrow, ogrow = wc > old[4], oc > old[5]
                q.need(wgrow != ogrow and (wgrow and oc == old[5] or ogrow and wc == old[4]), 'resize changed wrong/multiple borrows')
                stats['workspace_growth' if wgrow else 'output_growth'] += 1
                q.need(row['raw'][80:192] == self.latest[key]['raw'][80:192], 'resize lost pending continuation')
            else:
                a = action(q, row); q.need(key in request and a['raw'] == request[key]['raw'] and a['delivery'] == 0, 'new child dispatch lacks exact HIA request')
                q.need(key not in self.retained and a['seq'] == self.dispatch.get(key, 0)+1, 'completed child executed again or sequence skipped')
                self.dispatch[key] = a['seq']; self.retained[key] = a
                stack.append({'parent': slot, 'target': a['target'], 'key': key}); stats['dispatches'] += 1
                edges.append({'parent': slot, 'child': a['target'], 'seq': a['seq'], 'phase': phase, 'trace_line': row['trace_line']})
        q.need(not stack and not any(k[0] == session for k in self.retained), 'unfinished child dispatch at actual response')
        counters = segment['header']['counter_deltas']; q.need(len(counters) == 6, 'six actual deltas')
        q.same(counters[1:], [stats['workspace_growth'], stats['output_growth'], stats['dispatches'], stats['delivery_only'], stats['delivery_short']], 'actual counters rederived from receipts')
        q.need(counters[0] >= stats['calls'], 'actual invocation counter underreports receipts')
        extra = counters[0]-stats['calls']; q.need(extra == 0 or any(e['child'] == 28 for e in edges), 'unobserved invocation outside native fence domain')
        stats['fence_calls_without_individual_receipts'] = extra
        return dict(stats), edges


def core(q, events):
    """Normalize complete fd-relative operations, preserving actual ordering."""
    result = []; active = None; owned = {}; serial = 0
    for event in events:
        name, args, ret = event['name'], event['args'], event['return']
        if name == 'write': continue
        begins = name == 'openat' and 'O_PATH' in args[2]
        if active is None:
            if not begins: continue
            q.need(args[0] == 'AT_FDCWD' and q.quoted(args[1]) == (b'/', False), 'fd-relative operation did not start from root')
            active = []; serial = 0
        q.need(name in ('openat', 'mkdirat', 'newfstatat', 'renameat2', 'close'), 'fallback/traversal syscall within fd-relative operation')
        item = {'syscall': name, 'errno': event['errno_number'], 'return': ret}
        if name == 'openat':
            q.need(args[2] == 'O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_PATH|O_DIRECTORY', 'unsafe fd-relative parent flags')
            parent = None if args[0] == 'AT_FDCWD' else owned.get(int(args[0])); q.need(parent is not None or args[0] == 'AT_FDCWD', 'unowned fd-relative open parent')
            value, clipped = q.quoted(args[1]); item.update(parent=parent, path_hex=value.hex(), clipped=clipped, flags=0x2b0000)
            if ret >= 0:
                q.need(ret not in owned, 'fd-relative descriptor collision'); owned[ret] = serial; serial += 1; item['return'] = owned[ret]
            q.need(len(owned) <= 3, 'fd-relative owner exceeded three descriptors')
        elif name == 'close':
            fd = int(args[0]); q.need(fd in owned and ret == 0, 'fd-relative cleanup ownership'); item['fd'] = owned.pop(fd)
        elif name == 'renameat2':
            q.need(int(args[0]) in owned and int(args[2]) in owned and args[4] == 'RENAME_NOREPLACE', 'fd-relative atomic rename ownership/flags')
            aa, ac = q.quoted(args[1]); bb, bc = q.quoted(args[3]); item.update(source_fd=owned[int(args[0])], destination_fd=owned[int(args[2])],
                source_hex=aa.hex(), destination_hex=bb.hex(), source_clipped=ac, destination_clipped=bc, flags=1)
        else:
            q.need(int(args[0]) in owned, 'fd-relative mutation/stat used unowned descriptor')
            value, clipped = q.quoted(args[1]); item.update(parent=owned[int(args[0])], path_hex=value.hex(), clipped=clipped)
            if name == 'mkdirat': q.need(args[2] == '0700', 'mkdir mode'); item['mode'] = 0o700
            else:
                q.need(args[3] == 'AT_SYMLINK_NOFOLLOW', 'source fstat follows leaf'); item['flags'] = 0x100
                item['mode'] = mode(q, args[2]) if ret == 0 else None
        active.append(item)
        if not owned: result.append(active); active = None
    q.need(active is None and not owned, 'fd-relative operation did not retire all descriptors')
    return result


class Effects:
    def __init__(self, q):
        self.q = q; self.last_f0 = {}; self.fs = {}; self.canonical_seq = {}; self.key_seq = {}; self.claimed = set()

    def claim(self, row, name):
        q = self.q; event = row['last_syscall']
        q.need(event is not None and event['name'] == name and event['line'] not in self.claimed
               and event['line'] < row['trace_line'], 'effect receipt lacks unique preceding actual '+name)
        self.claimed.add(event['line']); return event

    def segment(self, segment, session):
        q = self.q; fs_events = []; counts = Counter(); state = self.fs.setdefault(session,
            {'ordinal': 0, 'effect_seq': 0, 'generation': 0, 'physical': [U64]*3, 'pending': None, 'run': None})
        for row in segment['receipts']:
            magic, w = row['magic'], row['words']; counts[magic] += 1
            if magic == 'HRGTR002':
                if w[2] == 1: self.last_f0[session, w[1]] = row
                if w[2] == 3 and action(q, row)['target'] == 30:
                    # The canonical-key bridge owns a fresh invocation and
                    # explicitly clears its sequence while retaining buffers.
                    # A delivery-only retry has no new dispatch and cannot reset it.
                    self.key_seq[session] = 0
                continue
            if magic == 'HFSPCL02':
                ordinal, code, phase, gen, seq, ilen, oc, wc, mask = w
                q.need(ordinal == state['ordinal']+1 and state['pending'] is None, 'FS HIA ordinal or missing prior ACK')
                state['ordinal'] = ordinal
                previous = self.last_f0.get((session, 24))
                q.need(previous is not None and previous['words'][3:6] == (code, wc, oc), 'FS call receipt differs from actual f0/descriptor')
                q.need(mask <= 7 and wc >= 8192 and oc >= 80 and ilen >= 64, 'FS owner input/output/work bounds')
                if code == CALL:
                    q.need(seq == state['effect_seq']+1 and gen in (state['generation'], state['generation']+1) and gen > 0, 'FS generation/effect sequence')
                    state['pending'] = {'ordinal': ordinal, 'phase': phase, 'gen': gen, 'seq': seq, 'mask': mask, 'wc': wc}
                elif code == 80:
                    q.need(mask == 0 and state['physical'] == [U64]*3 and gen in (state['generation'], state['generation']+int(phase == 100)), 'FS terminal descriptor/generation cleanup')
                    state['generation'] = gen
                    out = previous['raw'][192:224]; q.need(out[:8] == b'HFSPO002', 'FS full terminal header identity')
                    status, op, created = struct.unpack_from('<3Q', out, 8)
                    if phase == 100:
                        q.need(status in (0, 1) and op in (1, 2, 3) and created in (0, 1) and state['run'] is None, 'FS final RUN identity or missing DROP')
                        state['run'] = (gen, op, status); counts['FS_RUN'] += 1
                    else:
                        q.need((phase, status, op, created) == (0, 2, 4, 0) and state['run'] is not None and state['run'][0] == gen, 'FS explicit DROP after same-generation RUN')
                        state['run'] = None; counts['FS_DROP'] += 1
                else:
                    q.need(code in (0xffffffef, 0xffffffee) and mask == 0 and state['physical'] == [U64]*3, 'unexpected FS native refusal/effect after incomplete growth')
                continue
            if magic == 'HFSPAK02':
                event = self.filesystem_ack(row, state); fs_events.append(event); continue
            self.other(row, session)
        q.need(state['pending'] is None and state['physical'] == [U64]*3 and state['run'] is None, 'FS child/ACK/DROP not closed before published response')
        return dict(counts), fs_events

    def filesystem_ack(self, row, state):
        q = self.q; w = row['words']
        raw_return, ordinal, phase, fd0, fd1, fd2, mask = w[:7]; e = struct.unpack_from('<16Q', row['raw'], 64)
        p = state['pending']; q.need(p is not None and (ordinal, phase, e[1], e[2], mask) == (p['ordinal'], p['phase'], p['seq'], p['gen'], p['mask']), 'FS ACK identity/late or repeated ACK')
        q.need(row['raw'][64:72] == b'HFSPFX02' and e[13] == 1 and e[15] == 0, 'FS effect magic/completion/reserved')
        kind, a, b, c, d, ee, f = e[3:10]
        q.need(kind in range(1, 7) and e[14] == int(kind == 5), 'FS effect kind/noreplace flag')
        event = self.claim(row, {1:'openat', 2:'openat', 3:'mkdirat', 4:'newfstatat', 5:'renameat2', 6:'close'}[kind])
        args, ret = event['args'], event['return']; q.same(raw_return, event['normalized_return'] & U64, 'FS ACK raw kernel result')
        q.same(e[11], event['errno_number'], 'FS ACK errno')
        q.same(e[10], int(ret >= 0 and kind in (1, 2)), 'FS ACK normalized success')
        q.same(e[12], mode(q, args[2]) if kind == 4 and ret == 0 else 0, 'FS ACK exact stat mode')
        before = state['physical'][:]; after = before[:]
        def descriptor(slot):
            q.need(1 <= slot <= 3 and before[slot-1] != U64, 'FS effect borrows an unowned logical descriptor')
            return before[slot-1]
        def component(index, offset, length):
            q.need(2048 <= offset < p['wc'] and 0 < length < p['wc']-offset, 'FS CString within owned path storage')
            value, clipped = q.quoted(args[index]); q.need(len(value) == min(length, 4095) if clipped else len(value) == length, 'FS complete requested component length')
            q.need(b'/' not in value and b'\0' not in value and value not in (b'.', b'..'), 'FS unsafe component reached syscall')
        if kind == 1:
            q.need(phase == 11 and 1 <= a <= 3 and before[a-1] == U64 and (b, c, d, ee, f) == (0x2b0000, 0, 0, 0, 0), 'FS root open effect')
            q.need(args == ['AT_FDCWD', '"\\x2f"', 'O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_PATH|O_DIRECTORY'], 'FS actual root-open flags/path')
            if ret >= 0: after[a-1] = ret
        elif kind == 2:
            q.need(phase in (13, 16) and 1 <= d <= 3 and before[d-1] == U64 and ee == 0x2b0000 and f == 0, 'FS component open effect')
            q.need(int(args[0]) == descriptor(a) and args[2] == 'O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_PATH|O_DIRECTORY', 'FS actual component parent/flags'); component(1, b, c)
            if ret >= 0: after[d-1] = ret
        elif kind == 3:
            q.need(phase == 15 and d == 0o700 and ee == f == 0 and int(args[0]) == descriptor(a) and args[2] == '0700', 'FS actual mkdir ownership/mode'); component(1, b, c)
        elif kind == 4:
            q.need(phase == 31 and d == 0x100 and ee == f == 0 and int(args[0]) == descriptor(a) and args[3] == 'AT_SYMLINK_NOFOLLOW', 'FS actual source no-follow stat'); component(1, b, c)
        elif kind == 5:
            q.need(phase == 33 and int(args[0]) == descriptor(a) and int(args[2]) == descriptor(d) and args[4] == 'RENAME_NOREPLACE', 'FS actual atomic no-replace parents')
            component(1, b, c); component(3, ee, f)
        else:
            q.need(phase in (14, 91) and b == c == d == ee == f == 0 and int(args[0]) == descriptor(a), 'FS actual reverse cleanup effect')
            after[a-1] = U64
        q.same([fd0, fd1, fd2], after, 'FS actual physical descriptor receipt')
        mask_before = sum((value != U64) << index for index, value in enumerate(before))
        mask_after = sum((value != U64) << index for index, value in enumerate(after))
        q.same(mask, mask_after if kind == 6 else mask_before, 'FS source-owned logical FD mask phase')
        state.update(physical=after, pending=None, effect_seq=e[1], generation=e[2])
        return event

    def other(self, row, session):
        q = self.q; magic, w = row['magic'], row['words']
        if magic == 'HRCNAK02':
            seq, phase, kind, poff, plen, rawret, error, returned, initialoff, currentoff, roff, rcap, wc, observed_mode, repeated = w
            q.need(seq == self.canonical_seq.get(session, 0)+1 and repeated == seq, 'canonical exact effect sequence/ACK')
            self.canonical_seq[session] = seq
            q.need(kind in range(1, 9) and phase == ({4:20, 5:21}.get(kind, kind)) and wc >= 4096, 'canonical effect phase/kind/capacity')
            before = self.last_f0.get((session, 8)); q.need(before is not None and before['words'][3] == CALL, 'canonical effect lacks actual HIA request')
            action_words = struct.unpack_from('<14Q', before['raw'], 80)
            q.need(before['raw'][80:88] == b'HRCANA02' and action_words[1:3] == (seq, kind) and action_words[4:6] == (poff, plen), 'canonical full request/receipt match')
            name = 'readlinkat' if kind == 4 else 'statx' if kind in (1, 2) else 'newfstatat'
            event = self.claim(row, name); args = event['args']; ret = event['return']
            q.same((rawret, error), (event['normalized_return'] & U64, event['errno_number']), 'canonical actual kernel return/errno')
            q.need(poff == plen == 0 if kind in (2, 7) else 4096 <= poff < wc and plen < wc-poff, 'canonical actual source span')
            if kind in (2, 7): q.need(args[0] == '0' and args[1] == 'NULL', 'canonical probe exact NULL path')
            else:
                value, clipped = q.quoted(args[1]); q.need(args[0] == 'AT_FDCWD' and (len(value) == min(plen, 4095) if clipped else len(value) == plen), 'canonical exact pathname extent')
            if kind == 4:
                q.need(4096 <= roff < wc and 0 < rcap <= wc-roff and int(args[3]) == rcap and returned == max(ret, 0), 'canonical readlink actual output bound/return')
            else:
                q.need(returned == 0, 'canonical stat result')
                if kind == 8:
                    q.need(len(args) == 4 and args[3] == 'AT_SYMLINK_NOFOLLOW', 'canonical exact no-follow metadata flags')
                else:
                    q.need(args[-1] != 'AT_SYMLINK_NOFOLLOW', 'canonical stat follow semantics')
                if kind in (3, 5, 6, 8) and ret == 0: q.same(observed_mode & 0xffffffff, mode(q, args[2]), 'canonical ACK stat mode')
            return
        if magic == 'HFLKEYFX':
            seq, kind, a, b, c, d, value, error, stmode, size, extra, done, z0, z1, z2 = w
            q.need(seq == self.key_seq.get(session, 0)+1 and done == 1 and z0 == z1 == z2 == 0, 'canonical cache-key actual ACK sequence')
            self.key_seq[session] = seq
            q.need(kind in (2, 3, 4, 5, 6), 'cache-key effect outside captured source domain')
            name = 'readlink' if kind == 2 else 'statx' if kind in (3, 4, 6) else 'newfstatat'
            event = self.claim(row, name)
            q.same(error, event['errno_number'], 'cache-key ACK actual errno')
            q.same(value, max(event['return'], 0) if kind == 2 else 0, 'cache-key ACK actual return')
            if kind == 2: q.need(int(event['args'][2]) == d and c >= 1024 and stmode == size == extra == 0, 'cache-key readlink owned output contract')
            return
        q.need(False, 'unimplemented receipt in actual SDK domain: '+magic)


def method_order(q, meta, edges, syscalls):
    """Compare actual source-owned child calls with unchanged method markers."""
    kinds = [e['kind'] for e in meta['events']]; entered = meta['handler_entries']
    gateway = [edge for edge in edges if edge['parent'] == 21]
    children = [edge['child'] for edge in gateway]
    if not entered:
        q.need(not any(edge['child'] in (27, 5, 6, 7, 23, 24, 26, 29, 30, 31, 32) for edge in edges), 'typed/meta refusal ran handler/session/effect work')
        q.need(not syscalls, 'typed/meta refusal issued filesystem syscall')
        return
    q.need(children[:2] == [22, 27], 'actual typed admission did not precede fence')
    fence_ok = next(e for e in meta['events'] if e['kind'] == 'effect_fence_exit')['data']['ok']
    if not fence_ok:
        q.same(children, [22, 27], 'fence rejection performed later gateway work')
        q.need(not syscalls, 'early fence rejection issued filesystem syscall'); return
    q.need(children[:5] == [22, 27, 5, 6, 11] and children[-1] == 27, 'fence/session/config/release ordering')
    q.same(children.count(5), 1, 'one actual context application'); q.same(children.count(6), 1, 'one actual current workdir read')
    helper_count = kinds.count('filesystem_helper_enter')
    q.same(children.count(23), helper_count, 'one actual helper dispatch iff original helper entered')
    actual_policies = [edge for edge in edges if edge['child'] == 7]
    q.same(sum(edge['parent'] in (5, 21, 23) for edge in actual_policies), kinds.count('local_policy_enter'),
           'original context/outer/inner local-policy call count case '+str(meta['case_id']))
    q.same(sum(edge['child'] == 26 for edge in edges if edge['parent'] == 23), kinds.count('directory_guard_enter'), 'original directory move guard count')
    if helper_count:
        helper_at = next(i for i, edge in enumerate(edges) if edge['parent'] == 21 and edge['child'] == 23)
        q.need(all(i < helper_at for i, edge in enumerate(edges) if edge['parent'] == 21 and edge['child'] == 7), 'outer policy did not precede actual helper')


def trace_evidence(q, native_capture, corpus, original_capture, original_evidence, observation_module):
    compared = original_capture is not None and original_evidence is not None
    q.need(compared or original_capture is original_evidence is None, 'incomplete original trace comparison arguments')
    native = q.Binder(native_capture); original = q.Binder(original_capture) if compared else None
    original_scenes = {scene['scenario_id']: scene for scene in original_evidence['scenarios']} if compared else {}
    summaries = []; total = Counter(); all_cases = []; observed_core = {}
    for scene in [s for group in corpus['groups'] for s in group['scenarios']]:
        sid = scene['scenario_id']
        expected_core = {}
        if compared:
            original_stdout = original.data('scenario-%03d.stdout'%sid)
            original_rows = q.parse_output(original_stdout); meta_by_case = {r['metadata']['case_id']: r['metadata'] for r in original_rows if r['metadata']['kind'] == 'case'}
            original_lines = original.data('scenario-%03d.strace'%sid).splitlines(keepends=True)
            for case in original_scenes[sid]['trace']['cases']:
                events = [line(q, original_lines[e['line']-1], e['line']) for e in case['events']]
                expected_core[case['case_id']] = core(q, events)
        for layer in ('observed', 'public'):
            if layer == 'public' and len(scene['sessions']) != 1: continue
            private = layer == 'observed'; name = layer+'/scenario-%03d'%sid; folder = name+'/process/'
            process = native.json(folder+'process.json'); exchanges = native.json(folder+'exchanges.json')
            stdout = gzip.decompress(native.data(folder+'stdout.bin.gz')); stderr = gzip.decompress(native.data(folder+'stderr.bin.gz'))
            parsed = trace_process(q, native.data(folder+'native.strace'), stdout, stderr, process['native_argv'], process['cwd'], exchanges, private)
            rows = [q.strict_json(r) for r in native.data(name+'/records.jsonl').split(b'\n') if r]
            for row in rows:
                for field in ('fds', 'fds_before', 'fds_after'):
                    if field in row and row[field]['child_pid'] is not None: q.same(row[field]['child_pid'], parsed['pid'], 'observed descriptor process/actual trace PID')
            requests, indexes = observation_module.plan(scene, private)
            request_cases = {item['action']: item['step'] for item in indexes['cases'] if item['action'] is not None}
            if private:
                continuation = Continuations(q,len(os.fsencode(process['cwd']))); effects = Effects(q); scene_stats = Counter(); scene_core = []
                for segment, request in zip(parsed['segments'], requests, strict=True):
                    identifier = segment['index']; selector = request['session']; slot = request['slot']
                    counters, edges = continuation.segment(segment, selector, 18 if slot == 34 else slot, initial=identifier == 0)
                    receipt_counts, fs_events = effects.segment(segment, selector)
                    scene_stats.update(counters); scene_stats.update(receipt_counts)
                    if identifier > 0:
                        q.need(all(event['line'] in effects.claimed for event in segment['syscalls']), 'unreceipted actual filesystem effect within request')
                    actual_core = core(q, segment['syscalls']); q.same(actual_core, core(q, fs_events), 'every actual fd-relative syscall has its own HIA ACK')
                    scene_core += actual_core
                    if identifier in request_cases:
                        step = request_cases[identifier]; cid = step['case_id']
                        if compared:
                            q.same(actual_core, expected_core[cid], 'whole unchanged fd-relative syscall sequence case '+str(cid))
                            if step['action']['kind'] == 'public': method_order(q, meta_by_case[cid], edges, segment['syscalls'])
                        if step['action']['kind'] != 'public': q.need(not actual_core, 'cache seed performed mutating fd-relative operation')
                        all_cases.append({'case_id': cid, 'core_operations': len(actual_core), 'core_syscalls': sum(map(len, actual_core)),
                            'full_core_sha256': q.sha(q.canonical(actual_core)), 'child_edges': edges, 'counters': counters,
                            'effect_receipts': receipt_counts, 'actual_syscalls': len(segment['syscalls'])})
                    elif identifier > 0: q.need(not segment['syscalls'], 'observer/handshake performed filesystem effects')
                q.need(not parsed['epilogue']['receipts'], 'unclaimed native receipt during process cleanup')
                observed_core[sid] = scene_core; total.update(scene_stats)
            else:
                q.same(core(q, parsed['events']), observed_core[sid], 'ordinary public complete fd-relative effects differ from observed same inputs')
            summaries.append({'layer': layer, 'scenario_id': sid, 'pid': parsed['pid'], **parsed['summary']})
    q.need(len(summaries) == 54 and len(all_cases) == 327, 'complete actual trace process/public/cache scope')
    return {'schema': 'hepta.runtime.filesystem-sdk-native-trace-evidence.v1', 'status': 'PASS',
        'actual_processes': 54, 'actual_observed_public_attempts': 323, 'actual_cache_seed_controls': 4,
        'owned_fixture_actions_separately_admitted': 5, 'counts': dict(sorted(total.items())), 'processes': summaries, 'cases': all_cases,
        'core_io_all_actual_syscalls_compared_to_original': compared, 'absolute_path_substitutions': 0,
        'ordinary_notification_intervals_individually_observed': False, 'native_fence_has_individual_effect_receipts': False,
        'original_scope_only': compared, 'uncovered_new_wide_remote_policy_path': True,
        'artifact_sha256': {prefix+'/'+name: pin['sha256'] for prefix, binder in (('native-capture', native), ('original-capture', original)) if binder is not None for name, pin in sorted(binder.artifacts.items())},
        'new_native_calls': 0, 'new_rust_processes': 0, 'live_fixture_required': False}
