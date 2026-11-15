"""Admit native-first filesystem records and an independently built original.

Admission only reads retained bytes. The Linux ELF owns all runtime semantics;
Python records and verifies the build, wire, kernel trace and file-tree proof.
"""
from pathlib import Path
import argparse
import copy
import errno
import gzip
import hashlib
import importlib.util
import json
import math
import os
import re
import stat
import struct
import sys
sys.dont_write_bytecode = True
U64 = (1 << 64) - 1
EFFECT, WORK_GROW, OUTPUT_GROW = 0xfffffff0, 0xffffffef, 0xffffffee
HELPER_FILES = {'cases.py': {'bytes': 12031, 'sha256': 'f2d3efb4e3da4a800206c018908bd5999a6d14b31dc8a7dd81a502413111dedb'}, 'replay_original.py': {'bytes': 18199, 'sha256': 'f46faf9747aa13c4ea5b1188c3a19fe1d8d1afb5befab3fc4d129da1506b3950'}, 'native_capture.py': {'bytes': 19462, 'sha256': 'ba6492e1a713eb55f090aea518ef155929fe125290757b24260ec14ce01a04b7'}, 'strict_reference.py': {'bytes': 50571, 'sha256': 'b7cfe2fba7ec3290d993ccad754a019d2d5e4b73af208c8a4daa8ddb9135bab5'}, 'capture_native.py': {'bytes': 10369, 'sha256': 'e44d3c600ff44f31eadd8d074d28f6a86bb515bccd60e936fef83acd37eac1d8'}}
NATIVE_FILES = {'native/filesystem_parity.hepta': {'bytes': 372049, 'sha256': '1afb3046366a16a346a21345f3710efefdd312a1f9b35878bd7aec5118ddd454'}, 'native/filesystem_parity_composition.json': {'bytes': 4571, 'sha256': '52c5915dcf50742905ddefe6f3ff132612bea4e4eb85a2923a07835319fad9e7'}, 'native/filesystem_parity_layout.json': {'bytes': 773, 'sha256': 'bc33e25fda7a166e540b0a5998b247e339f338d6a6f91755a43ff832d8bf0bf4'}, 'native/filesystem_parity_packer.hepta': {'bytes': 75861, 'sha256': '59bef09a939dd55fc778c514a376d2ebcc63bf30752dedc0eaf717e6bc0a0c9e'}, 'native/text_budget.hepta': {'bytes': 47464, 'sha256': '89df7b4320fdbd3525450e9446267ae3d54a5b62660d8904fe8f09be36a7fbf9'}, 'native/view_error.hepta': {'bytes': 250530, 'sha256': '22254938e43feaebc8d24147f76c0aefdfc46b8574fad66d247ddafb2c209c5a'}, 'scripts/hia_native_build.py': {'bytes': 16253, 'sha256': '7b01d602d50835f2b73a2b7b39761c0cef08a372493985161d59184d52c0dcb2'}, 'scripts/hia_native_filesystem_parity_build.py': {'bytes': 20874, 'sha256': 'f9c1f646f8983d1f697350cd62cb26c9a94a6d87fbafb5bb3ec0381ef75488de'}, 'scripts/hia_native_loader.py': {'bytes': 12728, 'sha256': '331b1fdc693df44847723f7171a1338918d1558f1cdc48f558cd29b32f2971e2'}}


def need(condition, message):
    if not condition: raise ValueError('filesystem parity native: '+message)


def digest(raw): return hashlib.sha256(raw).hexdigest()


def table(values): return {name: {'bytes': size, 'sha256': sha} for name, (size, sha) in values.items()}


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module

_reference_path = Path(__file__).with_name('strict_reference.py')
need({'bytes': _reference_path.stat().st_size, 'sha256': digest(_reference_path.read_bytes())} == HELPER_FILES['strict_reference.py'], 'original reader identity')
q = load(_reference_path, '_filesystem_native_first_reference')


def same(actual, expected, message):
    need(q.canonical(actual) == q.canonical(expected), message)


def positive_time(value, maximum, message):
    need(type(value) in (int, float) and math.isfinite(value) and 0 < value <= maximum, message)


def elapsed_process(row, command, cwd, timeout, pid=True):
    need(type(row) is dict, 'actual process object')
    same(row.get('command'), command, 'actual command')
    same(row.get('cwd'), cwd, 'actual cwd')
    same(row.get('exit_code'), 0, 'actual process exit')
    same(row.get('timeout_seconds'), timeout, 'actual process deadline')
    need(row.get('timed_out') is False and 'start_error' not in row, 'actual process startup/timeout')
    positive_time(row.get('elapsed_seconds'), timeout, 'actual process elapsed time')
    if pid: need(q.uint(row.get('pid'), 'actual PID') > 0, 'actual PID missing')


def wire(operation, first=b'', second=b'', generation=0):
    body = b'HFSPQ002'+struct.pack('<7Q', operation, len(first), len(second), generation, 0, 0, 0)+first+second
    return struct.pack('<Q', len(body))+body


def input_stream(path, cases):
    records = []; offset = 0
    with Path(path).open('rb') as stream:
        for generation, case in enumerate(cases, 1):
            sha = hashlib.sha256(); count = 0
            for first, second, op, gen in ((case['first'], case['second'], case['operation'], 0),
                    (case['first'], case['second'], case['operation'], 0), (b'', b'', 4, generation)):
                fixed = struct.pack('<Q', 64+len(first)+len(second))+b'HFSPQ002'+struct.pack('<7Q', op, len(first), len(second), gen, 0, 0, 0)
                need(stream.read(len(fixed)) == fixed, 'native complete input header/generation/reserved bytes')
                sha.update(fixed); count += len(fixed)
                for value in (first, second):
                    for at in range(0, len(value), 1 << 20):
                        block = value[at:at+(1 << 20)]; need(stream.read(len(block)) == block, 'native complete raw path span')
                        sha.update(block); count += len(block)
            records.append({'input_offset': offset, 'input_bytes': count, 'input_sha256': sha.hexdigest()}); offset += count
        need(stream.read(1) == b'', 'trailing native input frame')
    return records


def output_stream(raw, cases):
    position = 0; rows = []
    for generation, case in enumerate(cases, 1):
        begin = position; replies = []
        for delivery in range(3):
            start = position; need(position+96 <= len(raw), 'truncated native result')
            returned, size = struct.unpack_from('<2Q', raw, position); position += 16
            need(returned == 80 and size >= 80 and size <= len(raw)-position, 'native output extent')
            body = raw[position:position+size]; position += size
            need(body[:8] == b'HFSPO002', 'native result magic')
            fields = struct.unpack_from('<9Q', body, 8)
            need(size == 80+fields[5]+fields[6], 'native short/chain full bounds')
            replies.append((raw[start:position], fields, body))
        need(replies[0] == replies[1], 'terminal redelivery full bytes changed')
        fields, body = replies[0][1:]; status, op, created, diagnostic, error, sl, cl, gen, seq = fields
        need(status in (0, 1) and op == case['operation'] and created in (0, 1) and 0 <= error <= 4095 and gen == generation, 'native result typed fields')
        need(replies[2][1] == (2, 4, 0, 0, 0, 0, 0, gen, seq), 'actual DROP result')
        try: short, chain = body[80:80+sl].decode('utf-8'), body[80+sl:].decode('utf-8')
        except UnicodeError as e: raise ValueError('filesystem parity native: invalid returned UTF8') from e
        if status == 0: need(diagnostic == error == sl == cl == 0, 'successful native result carries an error')
        else: need(diagnostic > 0 and sl > 0 and cl > 0, 'failed native result lacks full diagnostic')
        rows.append({'case_id': case['case_id'], 'operation': op, 'status': status, 'created_any': created,
            'diagnostic': diagnostic, 'errno': error, 'short': short, 'chain': chain, 'generation': gen, 'sequence': seq,
            'output_offset': begin, 'output_bytes': position-begin, 'output_sha256': digest(raw[begin:position])})
    need(position == len(raw), 'trailing native output bytes')
    return rows


def region_layout(case):
    cap = 1024
    while cap <= max(len(case['first']), len(case['second'])): cap *= 2
    components = {}; last = {}
    for index, name in enumerate(('first', 'second')):
        parts = q.absolute_components(case[name])
        if parts is None: continue
        offset = 2048+(2+index)*cap
        for part in parts:
            components[offset] = part; last[name] = (offset, len(part)); offset += len(part)+1
        need(offset <= 2048+(3+index)*cap, 'component layout overflow')
    return cap, components, last


def page(value): return (value+4095) & ~4095


def receipt_evidence(raw, cases, output_rows):
    """Consume every CALL and its unique actual syscall ACK in strict order."""
    at = index = sequence = call_count = terminal = 0
    workspace, capacity = 8192, 80
    physical, opened_at = [-1]*3, [0]*3
    pending = None; events = []; calls = []; reports = []
    for case in cases:
        reports.append({'case_id': case['case_id'], 'calls': 0, 'effects': 0, 'opens': 0, 'closes': 0,
            'workspace_growth': 0, 'output_growth': 0, 'terminal_redelivery_without_effect': False})
    layouts = [region_layout(case) for case in cases]
    while at < len(raw):
        need(index < len(cases), 'receipt after final DROP')
        case, report, result = cases[index], reports[index], output_rows[index]
        cap, components, last = layouts[index]
        if raw[at:at+8] == b'HFSPCL02':
            need(pending is None, 'native call before pending effect ACK')
            need(at+80 <= len(raw), 'truncated native CALL')
            fields = struct.unpack_from('<9Q', raw, at+8); at += 80; call_count += 1
            number, returned, phase, generation, effect_sequence, input_len, outcap, wcap, mask = fields
            need(number == call_count and returned in (80, EFFECT, WORK_GROW, OUTPUT_GROW), 'native CALL identity/return')
            need(effect_sequence == sequence+(returned == EFFECT), 'native CALL sequence jumped')
            need(input_len == (64 if terminal == 2 else 64+len(case['first'])+len(case['second'])), 'native CALL input length')
            need((outcap, wcap) == (capacity, workspace), 'native CALL actual capacity transition')
            need(mask <= 7, 'native CALL owner mask')
            report['calls'] += 1
            calls.append({'case_id': case['case_id'], 'call': number, 'return': returned, 'phase': phase, 'generation': generation,
                'sequence': effect_sequence, 'input_bytes': input_len, 'output_capacity': outcap, 'workspace_capacity': wcap,
                'owned_mask': mask, 'receipt_offset': at-80, 'receipt_end': at})
            if returned == WORK_GROW:
                need(terminal == 0 and report['effects'] == 0 and phase == 0 and generation == index and mask == 0 and physical == [-1]*3, 'workspace growth moved an active owner')
                required = page(2048+4*cap); need(required > workspace, 'spurious workspace growth')
                workspace = required; report['workspace_growth'] += 1
                need(report['workspace_growth'] == 1, 'repeated workspace growth without progress')
                continue
            need(generation == index+1, 'native generation mismatch')
            if returned == OUTPUT_GROW:
                required = 80+len(result['short'].encode())+len(result['chain'].encode())
                need(terminal == 0 and phase == 100 and mask == 0 and physical == [-1]*3 and required > capacity, 'output growth not final/necessary')
                capacity = page(required); report['output_growth'] += 1
                need(report['output_growth'] == 1, 'repeated output growth without progress')
            elif returned == EFFECT:
                need(terminal == 0 and phase in (11, 13, 14, 15, 16, 31, 33, 91), 'effect after terminal or unexpected phase')
                pending = fields
            else:
                need(mask == 0 and physical == [-1]*3 and sequence == result['sequence'], 'terminal result still owns descriptors or wrong sequence')
                if terminal < 2:
                    need(phase == 100 and capacity >= 80+len(result['short'].encode())+len(result['chain'].encode()), 'terminal phase/output capacity')
                    terminal += 1
                else:
                    need(phase == 0 and report['opens'] == report['closes'], 'DROP did not clear completed owner')
                    report['terminal_redelivery_without_effect'] = True
                    terminal = 0; index += 1
            continue
        need(raw[at:at+8] == b'HFSPAK02' and at+192 <= len(raw), 'invalid or truncated native ACK')
        need(pending is not None, 'ACK has no unique pending CALL')
        ack = struct.unpack_from('<7Q', raw, at+8)
        need(raw[at+64:at+72] == b'HFSPFX02', 'effect magic')
        fx = struct.unpack_from('<15Q', raw, at+72); at += 192
        number, returned, phase, generation, pending_seq, input_len, outcap, wcap, mask = pending
        need(ack[1:3] == (number, phase) and ack[6] == mask, 'ACK does not identify pending CALL')
        sequence += 1; kind = fx[2]; args = list(fx[3:9])
        need(fx[:2] == (sequence, index+1) == (pending_seq, generation), 'late/repeated/cross-generation ACK')
        need(kind in (1, 2, 3, 4, 5, 6) and fx[12:] == (1, int(kind == 5), 0), 'ACK completion/flags/reserved')
        need(phase in {1: (11,), 2: (13, 16), 3: (15,), 4: (31,), 5: (33,), 6: (14, 91)}[kind], 'ACK kind differs from owner phase')
        before = physical[:]; before_mask = sum(1 << i for i, fd in enumerate(before) if fd != -1)
        def live(slot):
            need(1 <= slot <= 3 and physical[slot-1] >= 3, 'effect used an unowned descriptor slot')
            return physical[slot-1]
        def component(offset, length):
            need(offset in components and length == len(components[offset]) and offset+length < workspace, 'effect CString offset/length differs from full input')
            return components[offset]
        if kind == 1:
            slot = args[0]
            need(1 <= slot <= 3 and physical[slot-1] == -1 and slot == physical.index(-1)+1, 'root open did not use the first free private slot')
            need(args[1:] == [0x2b0000, 0, 0, 0, 0], 'root open arguments')
        elif kind == 2:
            live(args[0]); component(args[1], args[2]); slot = args[3]
            need(1 <= slot <= 3 and physical[slot-1] == -1 and slot == physical.index(-1)+1, 'component open private target slot')
            need(args[4:] == [0x2b0000, 0], 'component open flags/reserved')
        elif kind == 3:
            live(args[0]); component(args[1], args[2]); need(args[3:] == [0o700, 0, 0], 'mkdir mode/reserved')
        elif kind == 4:
            live(args[0]); component(args[1], args[2]); need(tuple(args[1:3]) == last.get('first') and args[3:] == [0x100, 0, 0], 'source no-follow stat leaf/flags')
        elif kind == 5:
            live(args[0]); live(args[3]); component(args[1], args[2]); component(args[4], args[5])
            need(tuple(args[1:3]) == last.get('first') and tuple(args[4:]) == last.get('second'), 'rename exact source/destination leaves')
        else:
            live(args[0]); need(args[1:] == [0]*5, 'close arguments')
            if phase == 91: need(opened_at[args[0]-1] == max(opened_at), 'cleanup did not close in reverse acquisition order')
        expected_mask = before_mask & ~(1 << (args[0]-1)) if kind == 6 else before_mask
        need(mask == expected_mask, 'HIA owner mask differs from physical descriptor ownership')
        returned_value = ack[0] if ack[0] < (1 << 63) else ack[0]-(1 << 64)
        error = -returned_value if returned_value < 0 else 0
        need(error <= 4095 and fx[10] == error and fx[9] == int(kind in (1, 2) and not error), 'actual errno/normalized ACK mismatch')
        if kind != 4 or error: need(fx[11] == 0, 'non-stat/error ACK carries stat mode')
        if not error:
            if kind in (1, 2):
                need(returned_value >= 3 and returned_value not in physical, 'actual open FD collision')
                physical[slot-1] = returned_value; opened_at[slot-1] = sequence; report['opens'] += 1
            else: need(returned_value == 0, 'actual non-open success return')
        if kind == 6:
            need(not error, 'actual descriptor close failed'); physical[args[0]-1] = -1; opened_at[args[0]-1] = 0; report['closes'] += 1
        need(list(ack[3:6]) == [fd if fd >= 0 else U64 for fd in physical], 'ACK physical descriptor slots differ')
        events.append({'case_id': case['case_id'], 'call': number, 'phase': phase, 'sequence': sequence, 'generation': index+1,
            'kind': kind, 'args': args, 'raw_result': returned_value, 'errno': error, 'stat_mode': fx[11],
            'owned_mask': mask, 'physical_slots': physical[:], 'physical_slots_before': before,
            'receipt_offset': at-192, 'receipt_end': at})
        report['effects'] += 1; pending = None
    need(at == len(raw) and index == len(cases) and pending is None and physical == [-1]*3 and terminal == 0, 'incomplete CALL/ACK/DROP trace')
    return {'cases': reports, 'events': events, 'calls': calls, 'native_calls': call_count, 'effects': sequence,
        'opens': sum(row['opens'] for row in reports), 'closes': sum(row['closes'] for row in reports)}


def trace_evidence(raw, cases, output_rows, receipts, stream_bytes, elf_path):
    try: text = raw.decode('ascii')
    except UnicodeError as e: raise ValueError('filesystem parity native: non-ASCII actual strace') from e
    need(text.endswith('\n'), 'incomplete native strace file')
    pid = None; previous_stamp = 0; reads = writes = errors = 0; effects = []
    for number, line in enumerate(text.splitlines(), 1):
        match = re.fullmatch(r'(\d+)[ ]+(\d+\.\d+) ([A-Za-z_][A-Za-z0-9_]*)\((.*)\)\s*=\s*(.*)', line)
        need(match is not None, 'incomplete actual syscall line')
        actual_pid, stamp, name, arguments, tail = match.groups(); actual_pid = int(actual_pid); stamp = float(stamp)
        need(math.isfinite(stamp) and stamp >= previous_stamp, 'actual syscall timestamp order'); previous_stamp = stamp
        if pid is None: pid = actual_pid
        need(actual_pid == pid and pid > 0, 'multiple native trace processes')
        returned = re.fullmatch(r'(-?(?:0x[0-9a-f]+|[0-9]+))(?: ([A-Z][A-Z0-9_]+) \([^\n]*\))?', tail)
        need(returned is not None, 'actual syscall return was incomplete')
        value = int(returned[1], 16 if '0x' in returned[1] else 10); error = returned[2]; args = q.split_args(arguments)
        if name in ('openat', 'mkdirat', 'newfstatat', 'renameat2', 'close'):
            need(len(effects) < len(receipts['events']), 'actual syscall lacks HIA ACK')
            ack = receipts['events'][len(effects)]; call = receipts['calls'][ack['call']-1]
            need(errors == call['receipt_end'] == ack['receipt_offset'], 'actual syscall did not occur between its CALL and ACK writes')
            effects.append({'name': name, 'args': args, 'return': value, 'errno': error, 'line': number})
        elif name in ('read', 'write'):
            need(len(args) == 3 and error is None and 0 <= value <= int(args[2], 0), 'actual stdio count/error')
            fd = int(args[0], 0)
            if name == 'read': need(fd == 0, 'unexpected native read fd'); reads += value
            elif fd == 1: writes += value
            else: need(fd == 2, 'unexpected native write fd'); errors += value
        elif name == 'mmap':
            need(len(args) == 6 and args[4] == '-1' and args[3] == 'MAP_PRIVATE|MAP_ANONYMOUS' and error is None and value > 0, 'unexpected native memory/file mapping')
        else:
            need(name == 'execve' and number == 1 and value == 0 and error is None and len(args) == 3, 'unexpected actual syscall '+name)
            need(q.quoted_path(args[0], os.fsencode(elf_path)) == (os.fsencode(elf_path), False), 'actual execve binary path')
            # This actual strace build renders argv as [...] with -s 0.  The
            # complete executable path is observed here; the exact one-argument
            # invocation is bound separately to the actual process receipt and
            # frozen Popen producer.  Do not invent unobserved trace argv bytes.
            need(args[1] == '[...]', 'actual execve argv display convention')
    same([reads, writes, errors], list(stream_bytes), 'full actual syscall stdio byte totals')
    need(len(effects) == len(receipts['events']), 'ACK/actual syscall count mismatch')
    return bind_trace_effects(effects, cases, output_rows, receipts, len(text.splitlines()))


def bind_trace_effects(effects, cases, output_rows, receipts, raw_lines):
    by_case = {case['case_id']: [] for case in cases}
    layouts = {case['case_id']: region_layout(case) for case in cases}
    names = {1: 'openat', 2: 'openat', 3: 'mkdirat', 4: 'newfstatat', 5: 'renameat2', 6: 'close'}
    for event, ack in zip(effects, receipts['events']):
        need(event['name'] == names[ack['kind']], 'ACK kind does not match actual syscall')
        error = getattr(errno, event['errno'], None) if event['errno'] else 0
        need(type(error) is int and error == ack['errno'] and ack['raw_result'] == (-error if error else event['return']), 'ACK differs from actual kernel result')
        kind, aa, bb = ack['kind'], ack['args'], event['args']; physical = ack['physical_slots_before']; components = layouts[ack['case_id']][1]
        def fd(slot): return physical[slot-1]
        def name(raw, offset, length):
            value = components[offset]; need(length == len(value), 'actual component extent'); q.quoted_path(raw, value)
        if kind == 1:
            need(len(bb) == 3 and bb[0] == 'AT_FDCWD', 'root open actual dirfd'); q.quoted_path(bb[1], b'/')
        elif kind == 2:
            need(len(bb) == 3 and int(bb[0]) == fd(aa[0]), 'component open actual dirfd'); name(bb[1], aa[1], aa[2])
        elif kind == 3:
            need(len(bb) == 3 and int(bb[0]) == fd(aa[0]) and bb[2] == '0700', 'mkdir actual dirfd/mode'); name(bb[1], aa[1], aa[2])
        elif kind == 4:
            need(len(bb) == 4 and int(bb[0]) == fd(aa[0]) and bb[3] == 'AT_SYMLINK_NOFOLLOW', 'stat actual dirfd/flags'); name(bb[1], aa[1], aa[2])
            if not error:
                match = re.search(r'\bst_mode=(S_IF[A-Z]+)(?:\|([0-7]+))?', bb[2]); need(match is not None, 'actual source stat mode missing')
                mode = getattr(stat, match[1]) | (int(match[2], 8) if match[2] else 0)
                need(mode == ack['stat_mode'], 'ACK stat mode differs from actual kernel struct')
        elif kind == 5:
            need(len(bb) == 5 and int(bb[0]) == fd(aa[0]) and int(bb[2]) == fd(aa[3]) and bb[4] == 'RENAME_NOREPLACE', 'actual rename dirfds/flags')
            name(bb[1], aa[1], aa[2]); name(bb[3], aa[4], aa[5])
        else: need(len(bb) == 1 and int(bb[0]) == fd(aa[0]), 'actual close FD differs from owned slot')
        by_case[ack['case_id']].append(event)
    outcomes = {row['case_id']: row for row in output_rows}; traces = {}; calls = []
    for case in cases:
        row = outcomes[case['case_id']]
        projection = {'status': row['status'], 'errno_present': int(bool(row['errno'])), 'errno': row['errno'],
            'created_tag': row['created_any']+1 if row['status'] == 0 and row['operation'] == 1 else 0}
        trace = q.operation_trace(by_case[case['case_id']], case, projection)
        need(row['created_any'] == int(any(action['kind'] == 'mkdir' for action in trace['actions'])), 'created_any differs from actual partial mkdir history')
        traces[case['case_id']] = trace
        calls.append({'case_id': case['case_id'], **{key: value for key, value in trace.items() if key != 'actions'}})
    return {'raw_lines': raw_lines, 'actual_semantic_syscalls': len(effects), 'calls': calls}, traces


def compare_states(capture, original, groups, original_groups, rows, original_rows, helper,
                   old_capture, cross_root, original_source, original_capture_relative):
    count = 0
    for name, group in groups.items():
        nn = helper.StateNormalizer(old_capture, cross_root)
        oo = helper.StateNormalizer(original_source['fixture_home'], original_source['cross_root'])
        pairs = [('prepared-state.json', None, None), ('armed-state.json', None, None)]
        for case in group['cases']:
            cid = case['case_id']
            for which in ('before', 'after'):
                pairs.append(('case-'+str(cid)+'-'+which+'.json', rows[cid][which+'_state'], original_rows[cid][which+'_state']))
        pairs.append(('restored-state.json', None, None))
        for filename, actual_pin, original_pin in pairs:
            relative = str(Path(name)/filename)
            if actual_pin is None: actual_pin = {'path': relative, **q.pin(capture.file(relative))}
            if original_pin is None: original_pin = {'path': relative, **q.pin(original.file(original_capture_relative/relative))}
            same(actual_pin['path'], relative, 'native state snapshot name'); same(original_pin['path'], relative, 'original state snapshot name')
            a, _ = q.state_evidence(capture, Path('.'), actual_pin, group['roots'])
            b, _ = q.state_evidence(original, original_capture_relative, original_pin, original_groups[name]['roots'])
            same(nn.normalize(a), oo.normalize(b), 'complete state/identity/content original-native comparison')
            count += 1
    return count


def bind_bundle(sources, bundle, source, manifest_name):
    """Re-derive every module, packer, ELF, bootstrap and source identity."""
    same(source['native_source_files'], NATIVE_FILES, 'native source closure')
    for name, expected in NATIVE_FILES.items():
        sources.file(name, expected)
    sys.path.insert(0, str(sources.root/'scripts'))
    builder = load(sources.file('scripts/hia_native_filesystem_parity_build.py'), '_filesystem_final_bundle')
    evidence = builder.inspect_bundle(bundle.file(manifest_name), source_root=sources.root)
    same(evidence['source_files'], NATIVE_FILES, 'build source closure')
    for kind, module in evidence['modules'].items():
        for name, identity in module['artifacts'].items():
            bundle.file(Path(kind)/name, identity)
    for name, identity in evidence['bootstrap_artifacts'].items():
        bundle.file(Path('bootstrap')/name, identity)
    for name, identity in evidence['pack_files'].items():
        bundle.file(name, identity)
    bundle.file('layout.json', evidence['layout'])
    bundle.file(manifest_name, source['bundle_manifest_pin'])
    bundle.file('filesystem-parity.elf', {key: source['native_elf'][key] for key in ('bytes', 'sha256')})
    need(len(bundle.artifacts) == 33, 'complete standalone build artifact count')
    return evidence


def compressed_stream(binder, relative, expected):
    path = binder.file(relative)
    with gzip.open(path, 'rb') as stream:
        hashed = hashlib.sha256(); count = 0
        while block := stream.read(1 << 20):
            hashed.update(block); count += len(block)
    same({'bytes': count, 'sha256': hashed.hexdigest()}, expected, 'compressed stream full bytes')


def native_evidence(source_root, manifest_path, capture_root, reference_root=None):
    sources, capture = [q.Binder(path) for path in (source_root, capture_root)]
    original = q.Binder(reference_root) if reference_root is not None else None
    manifest_path = Path(manifest_path).absolute()
    bundle = q.Binder(manifest_path.parent)
    summary = capture.json('NATIVE.json')
    source = capture.json('SOURCE.json', summary['source'])
    source_keys = {'schema', 'source_root', 'helper_root', 'helper_files', 'native_source_files',
                   'bundle_manifest', 'bundle_manifest_pin', 'native_elf', 'build_evidence', 'fixture_home',
                   'cross_root', 'fixture_umask', 'elf_umask', 'prior_umask', 'uid', 'euid', 'gid', 'egid',
                   'strace', 'actual_original_processes', 'original_outputs_read', 'public_handler_executed'}
    need(set(source) == source_keys, 'native source exact fields')
    for name in ('source_root', 'helper_root', 'bundle_manifest', 'fixture_home', 'cross_root'):
        need(type(source[name]) is str and Path(source[name]).is_absolute() and '..' not in Path(source[name]).parts,
             'absolute recorded provenance '+name)
    old_capture = Path(source['fixture_home'])
    old_bundle = Path(source['bundle_manifest']).parent
    same(Path(source['bundle_manifest']).name, manifest_path.name, 'bundle manifest basename')
    same(source['native_elf']['path'], str(old_bundle/'filesystem-parity.elf'), 'actual ELF artifact location')
    same(source['helper_root'], str(Path(source['source_root'])/'tests/hia_native/filesystem_parity'), 'helper source location')
    for name, expected in {'schema': 'hepta.runtime.filesystem-parity-native-only-source.v1',
            'fixture_umask': 0o77, 'elf_umask': 0o22, 'prior_umask': 0o77,
            'actual_original_processes': 0, 'original_outputs_read': False, 'public_handler_executed': False}.items():
        same(source[name], expected, 'independent native source '+name)
    need(type(source['uid']) is int and source['uid'] == source['euid'] != 0 and
         type(source['gid']) is int and source['gid'] == source['egid'], 'unprivileged fixture observer')
    same(source['helper_files'], HELPER_FILES, 'native capture helper identities')
    helper_relative = Path('tests/hia_native/filesystem_parity')
    for name, expected in HELPER_FILES.items():
        sources.file(helper_relative/name, expected)
    helper = load(sources.file(helper_relative/'native_capture.py'), '_filesystem_final_native_capture')
    generator = load(sources.file(helper_relative/'cases.py'), '_filesystem_final_input_only')
    evidence = bind_bundle(sources, bundle, source, manifest_path.name)
    same(capture.json('BUILD-EVIDENCE.json', summary['build_evidence']), evidence, 'actual build admission record')
    same(source['build_evidence'], summary['build_evidence'], 'source binds build admission record')
    need(source['strace']['path'] == '/usr/bin/strace' and set(source['strace']) == {'path', 'bytes', 'sha256'}, 'strace descriptor')
    need(q.uint(source['strace']['bytes'], 'strace bytes') > 0 and q.SHA.fullmatch(source['strace']['sha256']), 'strace executable identity')
    bound = {str(Path(source['helper_root'])/name): identity for name, identity in HELPER_FILES.items()}
    bound['/usr/bin/strace'] = {key: source['strace'][key] for key in ('bytes', 'sha256')}
    bound[source['bundle_manifest']] = source['bundle_manifest_pin']
    bound[source['native_elf']['path']] = {key: source['native_elf'][key] for key in ('bytes', 'sha256')}
    same(capture.json('BOUND-SOURCES.json', summary['bound_sources']), bound, 'complete native input freeze')
    admitted = original_source = original_rows = original_calls = original_groups = None
    if original is not None:
        admitted = q.reference_evidence(original.root, original.root/'captures-v1')
        original.artifacts.update({name: {'bytes': admitted['artifact_bytes'][name], 'sha256': sha}
                                   for name, sha in admitted['artifact_sha256'].items()})
        original_source = original.json('captures-v1/SOURCE.json')
        same(source['strace'], original_source['strace'], 'native/original trace executable')
        same(original.json('ORIGINAL-EVIDENCE.json'), admitted, 'independently admitted original record')
        original_rows = [q.strict_json(line) for line in original.data('captures-v1/cases.jsonl').split(b'\n')[:-1]]
        original_calls = {row['case_id']: row['calls'] for row in admitted['normalized_syscalls']}
        original_groups = generator.groups(original_source['fixture_home'], original_source['cross_root'])
    groups = generator.groups(old_capture, Path(source['cross_root']))
    same({name: len(group['cases']) for name, group in groups.items()}, q.GROUP_COUNTS, 'complete native corpus domains')
    inputs = {'groups': {name: [generator.summary(case) for case in group['cases']] for name, group in groups.items()},
              'fixture_definitions': generator.fixture_json({name: {key: value for key, value in group.items() if key != 'cases'}
                                                              for name, group in groups.items()})}
    same(capture.json('INPUTS.json', summary['inputs']), inputs, 'complete input-only native fixture generation')
    raw = capture.data('cases.jsonl', summary['cases_stream'])
    need(raw.endswith(b'\n'), 'incomplete native case stream')
    rows = [q.strict_json(line) for line in raw.split(b'\n')[:-1]]
    same([row.get('case_id') for row in rows], list(range(123)), 'complete native case order')
    processes = capture.json('processes.json', summary['processes'])
    need(type(processes) is list and len(processes) == 8, 'eight native processes')
    return admit_native_streams(sources, bundle, capture, original, source, summary, evidence, admitted,
                                helper, generator, groups, original_groups, original_source, original_rows,
                                original_calls, rows, processes)


def admit_native_streams(sources, bundle, capture, original, source, summary, build_evidence, admitted,
                         helper, generator, groups, original_groups, original_source, original_rows,
                         original_calls, rows, processes):
    old_capture = Path(source['fixture_home'])
    binary = source['native_elf']['path']
    process_index = 0
    actual_rows, traces = {}, {}
    totals = {key: 0 for key in ('native_calls', 'effects', 'opens', 'closes', 'workspace_growth',
                                'output_growth', 'actual_trace_lines', 'actual_trace_syscalls',
                                'input_bytes', 'output_bytes', 'receipt_bytes')}
    all_calls, all_events = [], []
    for name, group in groups.items():
        subsets = [[case] for case in group['cases']] if group.get('regular_file_stdin') else [group['cases']]
        for index, cases in enumerate(subsets):
            process_name = name+('-'+str(index) if len(subsets) > 1 else '')
            process = processes[process_index]; process_index += 1
            folder = Path('processes')/process_name
            same(capture.json(folder/'process.json'), process, 'individual native process receipt')
            command = ['/usr/bin/strace', *q.TRACE_FLAGS, '-o', str(old_capture/folder/'trace.txt'), binary]
            elapsed_process(process, command, str(old_capture), 60)
            for key, expected in {'name': process_name, 'cases': [case['case_id'] for case in cases], 'umask': 0o22,
                    'failure': None, 'input_kind': 'regular-file' if group.get('regular_file_stdin') else 'pipe'}.items():
                same(process.get(key, 'missing'), expected, 'actual native process '+key)
            paths = {}
            for key, filename in (('stdin', 'input.bin'), ('stdout', 'stdout.bin'), ('stderr', 'stderr.bin'), ('trace', 'trace.txt')):
                descriptor = process.get(key)
                need(type(descriptor) is dict and set(descriptor) == {'path', 'bytes', 'sha256'}, 'complete native stream descriptor')
                same(descriptor['path'], str(folder/filename), 'native stream owned path')
                identity = {field: descriptor[field] for field in ('bytes', 'sha256')}
                paths[key] = capture.file(folder/filename, identity)
                compressed_stream(capture, folder/(filename+'.gz'), identity)
            in_rows = input_stream(paths['stdin'], cases)
            out_rows = output_stream(paths['stdout'].read_bytes(), cases)
            receipt = receipt_evidence(paths['stderr'].read_bytes(), cases, out_rows)
            recorded_receipt = {key: copy.deepcopy(value) for key, value in receipt.items() if key != 'calls'}
            for event in recorded_receipt['events']:
                for key in ('physical_slots_before', 'receipt_offset', 'receipt_end'):
                    event.pop(key)
            same(capture.json(folder/'receipts.json'), recorded_receipt, 'complete native receipt report recomputation')
            traced, operations = trace_evidence(paths['trace'].read_bytes(), cases, out_rows, receipt,
                                               (process['stdin']['bytes'], process['stdout']['bytes'], process['stderr']['bytes']), binary)
            same(capture.json(folder/'trace-evidence.json'), traced, 'complete kernel trace report recomputation')
            traces.update(operations)
            for case, input_row, output_row in zip(cases, in_rows, out_rows):
                cid = case['case_id']
                actual_rows[cid] = {**generator.summary(case), **input_row, **output_row, 'group': name, 'process': process_name}
                if original is not None:
                    reference = original_rows[cid]
                    for field in ('status', 'errno', 'short', 'chain'):
                        same(output_row[field], reference[field], 'complete original/native result '+str(cid)+' '+field)
                    if output_row['status'] == 0 and case['operation'] == 1:
                        same(output_row['created_any'], reference['created_tag']-1, 'actual mkdir result bool')
                    elif case['operation'] != 1:
                        same(output_row['created_any'], 0, 'move invented mkdir result')
                    original_case = next(item for item in original_groups[name]['cases'] if item['case_id'] == cid)
                    expected_calls = helper.comparable_calls(original_calls[cid], original_case,
                                                             original_source['fixture_home'], original_source['cross_root'])
                    native_calls = helper.comparable_calls(operations[cid]['calls'], case, old_capture, source['cross_root'])
                    same(native_calls, expected_calls, 'full ordered original/native syscall comparison '+str(cid))
            for key in ('native_calls', 'effects', 'opens', 'closes'):
                totals[key] += receipt[key]
            for key in ('workspace_growth', 'output_growth'):
                totals[key] += sum(row[key] for row in receipt['cases'])
            totals['actual_trace_lines'] += traced['raw_lines']
            totals['actual_trace_syscalls'] += traced['actual_semantic_syscalls']
            for key, stream in (('input_bytes', 'stdin'), ('output_bytes', 'stdout'), ('receipt_bytes', 'stderr')):
                totals[key] += process[stream]['bytes']
            all_calls.extend({'process': process_name, **call} for call in receipt['calls'])
            all_events.extend({'process': process_name, **event} for event in receipt['events'])
    need(process_index == 8, 'complete native process consumption')
    for row in rows:
        same({key: value for key, value in row.items() if key not in ('before_state', 'after_state')},
             actual_rows[row['case_id']], 'case record differs from complete raw streams')
    state_rows = [{**row, 'errno_present': int(bool(row['errno']))} for row in rows]
    headers = {row['case_id']: {key: source[key] for key in ('uid', 'euid', 'gid', 'egid')} for row in rows}
    snapshots = q.admit_states(capture, Path('.'), groups, state_rows, traces, headers)
    need(snapshots == 267, 'complete snapshot/model admission')
    if original is not None:
        compared = compare_states(capture, original, groups, original_groups, rows, original_rows, helper,
                                   old_capture, source['cross_root'], original_source, Path('captures-v1'))
        need(compared == 267, 'complete original snapshot comparison')
    return finish_admission(sources, bundle, capture, original, source, summary, build_evidence,
                            admitted, rows, traces, totals, snapshots, all_calls, all_events)


def finish_admission(sources, bundle, capture, original, source, summary, build_evidence,
                      admitted, rows, traces, totals, snapshots, all_calls, all_events):
    elapsed = summary.get('elapsed_seconds')
    positive_time(elapsed, 180, 'native capture elapsed bound')
    error_bytes = sum(len(row['short'].encode())+len(row['chain'].encode()) for row in rows)
    expected = dict(schema='hepta.runtime.filesystem-parity-native-only-capture.v1', status='PASS',
        cases=123, actual_elf_processes=8, filesystem_snapshots=snapshots,
        **{key: totals[key] for key in ('native_calls', 'effects', 'opens', 'closes', 'workspace_growth',
                                      'output_growth', 'actual_trace_syscalls', 'actual_trace_lines')},
        complete_error_bytes=error_bytes, source=summary['source'], inputs=summary['inputs'],
        processes=summary['processes'], cases_stream=summary['cases_stream'],
        build_evidence=summary['build_evidence'], bound_sources=summary['bound_sources'],
        source_files_unchanged=True, new_rust_processes=0, original_outputs_read=False,
        original_comparison_pending=True, public_filesystem_handlers_complete=False,
        whole_runtime_replaced=False, elapsed_seconds=elapsed)
    same(summary, expected, 'native-only summary recomputation')
    same(totals['effects'], totals['actual_trace_syscalls'], 'every native effect reached the kernel exactly once')
    same(totals['opens'], totals['closes'], 'all actual owned descriptors closed')
    if original is not None:
        same(totals['actual_trace_syscalls'], admitted['actual_semantic_syscalls'], 'native/original effect count')
        same(error_bytes, admitted['body_bytes'], 'complete original/native error bytes')
    def trace_bounds(binder, prefix):
        result = []
        for name in binder.artifacts:
            if name.startswith(prefix) and name.endswith('/trace.txt'):
                lines = binder.data(name).splitlines()
                first = re.match(rb'\d+[ ]+(\d+\.\d+) ', lines[0])
                last = re.match(rb'\d+[ ]+(\d+\.\d+) ', lines[-1])
                need(first is not None and last is not None, 'actual trace time extent')
                result.append((float(first[1]), float(last[1])))
        need(len(result) == 8, 'complete trace ordering extent')
        return min(item[0] for item in result), max(item[1] for item in result)
    native_times = trace_bounds(capture, 'processes/')
    original_times = None
    if original is not None:
        original_times = trace_bounds(original, 'captures-v1/processes/')
        need(native_times[1] < original_times[0], 'original semantic outputs were not independently recorded after native capture')
    qualification = q.Binder(Path(__file__).parent)
    qualification.file('strict_native.py')
    qualification.file('strict_reference.py', HELPER_FILES['strict_reference.py'])
    binders = {'source': sources, 'bundle': bundle, 'native': capture, 'qualification': qualification}
    if original is not None:
        binders['original'] = original
    for binder in binders.values():
        for name, expected_pin in list(binder.artifacts.items()):
            binder.file(name, expected_pin)
    artifacts = {namespace+'/'+name: identity for namespace, binder in binders.items() for name, identity in binder.artifacts.items()}
    if original is None:
        return dict(schema='hepta.runtime.filesystem-parity-native-evidence.v2', status='PASS', cases=123,
            case_counts=q.GROUP_COUNTS, actual_elf_processes=8, actual_native_calls=totals['native_calls'],
            actual_semantic_syscalls=totals['actual_trace_syscalls'], raw_trace_lines=totals['actual_trace_lines'],
            actual_owned_opens=totals['opens'], actual_owned_closes=totals['closes'], state_snapshots=snapshots,
            workspace_growth=totals['workspace_growth'], output_growth=totals['output_growth'],
            complete_native_input_bytes=totals['input_bytes'], complete_native_output_bytes=totals['output_bytes'],
            complete_native_receipt_bytes=totals['receipt_bytes'], complete_native_error_bytes=error_bytes,
            actual_hia_compilations=2, actual_hia_pack_calls=1, build_artifacts=len(bundle.artifacts),
            native_trace_time_extent=native_times,
            maximum_live_descriptors=max(trace['maximum_live_descriptors'] for trace in traces.values()),
            actual_exdev_cases=4, wide_cases=2, terminal_redelivery_no_effect_cases=123, actual_drop_cases=123,
            path_display_truncations=sum(trace['path_display_truncations'] for trace in traces.values()),
            execve_argv_display_elided=True, execve_path_fully_observed=True,
            fresh_cold_qualified=False, public_filesystem_handlers_complete=False, whole_runtime_replaced=False,
            public_sdk_qualified=False, async_wrapper_qualified=False, cache_session_qualified=False,
            private_synthetic_controls_included=False, original_comparison_pending=True,
            original_outputs_read=False, actual_original_processes=0,
            new_rust_processes=0, new_native_calls=0, live_fixture_dependencies=[],
            build_evidence_sha256=digest(q.canonical(build_evidence)),
            normalized_syscalls=[dict(case_id=cid, operation=rows[cid]['operation'], group=rows[cid]['group'],
                                     process=rows[cid]['process'], calls=traces[cid]['calls']) for cid in range(123)],
            native_calls=all_calls, effect_completions=all_events,
            artifact_sha256={name: identity['sha256'] for name, identity in sorted(artifacts.items())},
            artifact_bytes={name: identity['bytes'] for name, identity in sorted(artifacts.items())})
    return dict(schema='hepta.runtime.filesystem-parity-native-first-evidence.v1', status='PASS', cases=123,
        case_counts=q.GROUP_COUNTS, actual_elf_processes=8, actual_native_calls=totals['native_calls'],
        actual_semantic_syscalls=totals['actual_trace_syscalls'], raw_trace_lines=totals['actual_trace_lines'],
        actual_owned_opens=totals['opens'], actual_owned_closes=totals['closes'], state_snapshots=snapshots,
        workspace_growth=totals['workspace_growth'], output_growth=totals['output_growth'],
        complete_native_input_bytes=totals['input_bytes'], complete_native_output_bytes=totals['output_bytes'],
        complete_native_receipt_bytes=totals['receipt_bytes'], complete_original_error_bytes=error_bytes,
        actual_original_processes=admitted['actual_original_processes'],
        actual_original_build_processes=admitted['actual_build_processes'],
        actual_original_replay_processes=admitted['actual_replay_processes'],
        fixed_rust_version=admitted['fixed_rust_version'], fresh_locked_original_builds=admitted['fresh_locked_builds'],
        actual_hia_compilations=2, actual_hia_pack_calls=1, build_artifacts=len(bundle.artifacts),
        native_observed_before_original=True, native_trace_time_extent=native_times, original_trace_time_extent=original_times,
        complete_original_bodies_equal=True, complete_normalized_syscalls_equal=True, complete_normalized_states_equal=True,
        maximum_live_descriptors=max(trace['maximum_live_descriptors'] for trace in traces.values()),
        actual_exdev_cases=4, wide_cases=2, terminal_redelivery_no_effect_cases=123, actual_drop_cases=123,
        path_display_truncations=sum(trace['path_display_truncations'] for trace in traces.values()),
        path_display_note=admitted['path_display_note'], execve_argv_display_elided=True, execve_path_fully_observed=True,
        fresh_cold_qualified=False, public_filesystem_handlers_complete=False, whole_runtime_replaced=False,
        public_sdk_qualified=False, async_wrapper_qualified=False, cache_session_qualified=False,
        private_synthetic_controls_included=False, new_rust_processes=0, new_native_calls=0, live_fixture_dependencies=[],
        build_evidence_sha256=digest(q.canonical(build_evidence)), original_evidence_sha256=digest(q.canonical(admitted)),
        normalized_syscalls=[dict(case_id=cid, operation=rows[cid]['operation'], group=rows[cid]['group'],
                                 process=rows[cid]['process'], calls=traces[cid]['calls']) for cid in range(123)],
        native_calls=all_calls, effect_completions=all_events,
        artifact_sha256={name: identity['sha256'] for name, identity in sorted(artifacts.items())},
        artifact_bytes={name: identity['bytes'] for name, identity in sorted(artifacts.items())})


def main():
    parser = argparse.ArgumentParser()
    for name in ('source-root', 'manifest', 'capture', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--reference', type=Path)
    args = parser.parse_args()
    result = native_evidence(args.source_root, args.manifest, args.capture, args.reference)
    with args.output.open('x') as stream:
        json.dump(result, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write('\n')
    omitted = {'artifact_sha256', 'artifact_bytes', 'normalized_syscalls', 'native_calls', 'effect_completions'}
    print(json.dumps({key: value for key, value in result.items() if key not in omitted}, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
