"""Read complete native captures without importing or executing the application.

The fixed graph emits both HRGTR002 (224 bytes) and canonical ACK records
HRCNAK02 (128 bytes). The memory ledger follows the actual CLONE_VM tree.
It requires every graph allocation to be explicitly unmapped. The one exact
startup MAP_BYTES mapping is process owned and is released by final exit(0).
"""
from pathlib import Path
import argparse, collections, gzip, hashlib, json, re, struct

FIXTURE_SHA = '1e25d052b8279ec1a387a8e66ed31b2dd75783d9f294c81ce9a9ea23c44f46c5'
BINDING_SHA = '280261f2df19a9b0ba988b984ddf8d70e3c77efe68c7a908cb9348db952a1cb7'
PROCESS_MAP_BYTES = 3707834368
PACK = lambda *v: struct.pack('<' + 'Q' * len(v), *v)
word = lambda b, n: struct.unpack_from('<Q', b, n)[0]
pin = lambda b: {'bytes': len(b), 'sha256': hashlib.sha256(b).hexdigest()}


def require(ok, why):
    if not ok:
        raise ValueError(why)


def read_trace(raw, *, expected_counts=(639, 116)):
    cursor = 0
    counts, slots = collections.Counter(), collections.Counter()
    while cursor < len(raw):
        tag = raw[cursor:cursor + 8]
        require(tag in (b'HRGTR002', b'HRCNAK02'), 'unknown complete trace record')
        size = 224 if tag == b'HRGTR002' else 128
        require(cursor + size <= len(raw), 'truncated complete trace record')
        record = raw[cursor:cursor + size]
        counts[tag.decode()] += 1
        if tag == b'HRGTR002':
            slot = word(record, 16)
            require(slot < 71 and word(record, 8) > 0, 'trace slot or sequence')
            slots[slot] += 1
        else:
            require(word(record, 8) == word(record, 120) > 0, 'canonical ACK sequence')
            result, error = word(record, 48), word(record, 56)
            if error:
                require(1 <= error <= 4095 and result == (1 << 64) - error,
                        'canonical ACK syscall error binding')
        cursor += size
    require({64, 65, 66, 69, 70} <= slots.keys(), 'old and new high slots absent')
    if expected_counts is not None:
        require(counts == dict(zip(('HRGTR002', 'HRCNAK02'), expected_counts)), 'complete trace domain count')
    return {'records': dict(counts), 'slots': dict(sorted(slots.items())), 'bytes': cursor}


def read_memory(text, *, expected_counts=(256, 255, 238, 2)):
    live, children, exited, waited, signalled = {}, {}, set(), set(), set()
    root, initial = None, None
    events = collections.Counter()
    guards = set()
    for ordinal, line in enumerate(text.splitlines(), 1):
        match = re.fullmatch(r'(\d+)\s+(.*)', line)
        require(match is not None, 'unframed memory line')
        pid, body = int(match[1]), match[2]
        if root is None:
            root = pid
        require(pid == root or pid in children, 'unbound process in memory trace')
        require(pid not in exited and root not in exited, 'event after process exit')
        if match := re.fullmatch(r'mmap\(NULL, (\d+), PROT_READ\|PROT_WRITE, MAP_PRIVATE\|MAP_ANONYMOUS, -1, 0\)\s+= (0x[0-9a-f]+)', body):
            size, address = int(match[1]), int(match[2], 16)
            require(size > 0 and size % 4096 == 0 and address % 4096 == 0, 'mmap alignment')
            require(all(address + size <= a or a + n <= address for a, n in live.items()),
                    'overlapping live mapping')
            if ordinal == 1:
                require(size == PROCESS_MAP_BYTES, 'exact process-owned initial map')
                initial = address
            else:
                require(size != PROCESS_MAP_BYTES, 'second process-owned initial map')
            live[address] = size
            events['mmap'] += 1
        elif match := re.fullmatch(r'mremap\((0x[0-9a-f]+), (\d+), (\d+), MREMAP_MAYMOVE\)\s+= (0x[0-9a-f]+)', body):
            address, size, new_size, new_address = int(match[1], 16), int(match[2]), int(match[3]), int(match[4], 16)
            require(address != initial and live.get(address) == size, 'mremap ownership')
            require(address not in guards and new_size > size and new_size % 4096 == 0, 'mremap extent')
            del live[address]
            require(all(new_address + new_size <= a or a + n <= new_address for a, n in live.items()),
                    'mremap overlap')
            live[new_address] = new_size
            events['mremap'] += 1
        elif match := re.fullmatch(r'mprotect\((0x[0-9a-f]+), (\d+), PROT_NONE\)\s+= 0', body):
            address, size = int(match[1], 16), int(match[2])
            owners = [a for a, n in live.items() if a + n - 4096 == address]
            require(size == 4096 and len(owners) == 1 and owners[0] != initial, 'exact mapped guard page')
            require(owners[0] not in guards, 'duplicate guard')
            guards.add(owners[0])
            events['mprotect'] += 1
        elif match := re.fullmatch(r'munmap\((0x[0-9a-f]+), (\d+)\)\s+= 0', body):
            address, size = int(match[1], 16), int(match[2])
            require(address != initial and live.get(address) == size, 'munmap exact owned allocation')
            del live[address]
            guards.discard(address)
            events['munmap'] += 1
        elif match := re.fullmatch(r'clone\(child_stack=(0x[0-9a-f]+), flags=CLONE_VM\|CLONE_FILES\|SIGCHLD\)\s+= (\d+)', body):
            child = int(match[2])
            stack = int(match[1], 16)
            require(pid == root and child not in children and child != root, 'exact shared-VM clone tree')
            require(any(a < stack <= a + n for a, n in live.items()), 'clone stack allocation')
            children[child] = root
            events['clone'] += 1
        elif match := re.fullmatch(r'wait4\((\d+), (0x[0-9a-f]+), WNOHANG, NULL\)\s+= 0', body):
            require(pid == root and int(match[1]) in children, 'bound pending wait')
            events['wait_pending'] += 1
        elif match := re.fullmatch(r'wait4\((\d+), \[\{WIFEXITED\(s\) && WEXITSTATUS\(s\) == 0\}\], WNOHANG, NULL\)\s+= (\d+)', body):
            child = int(match[1])
            require(pid == root and child == int(match[2]) and child in children and child in exited and child not in waited,
                    'bound successful wait')
            waited.add(child)
            events['wait_complete'] += 1
        elif match := re.fullmatch(r'--- SIGCHLD \{si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=(\d+), si_uid=(\d+), si_status=0, si_utime=0, si_stime=0\} ---', body):
            child = int(match[1])
            require(pid == root and child in children and child in exited and child not in signalled, 'bound successful SIGCHLD')
            signalled.add(child)
            events['SIGCHLD'] += 1
        elif re.fullmatch(r'exit\(0\)\s+= \?', body):
            if pid == root:
                require(set(children) == waited == signalled == exited, 'all shared-VM children completed and reaped')
                require(live == {initial: PROCESS_MAP_BYTES} and not guards,
                        'every native graph allocation must be explicitly unmapped before process exit')
                live.clear()  # Exact process-owned mapping dies with the final owner.
            exited.add(pid)
            events['exit'] += 1
        else:
            raise ValueError('unknown or failed memory/process syscall: ' + body)
    require(root is not None and exited == {root, *children} and not live, 'complete memory lifecycle')
    require(len(children) == 2, 'both original publication workers completed')
    if expected_counts is not None:
        require(tuple(events[n] for n in ('mmap', 'munmap', 'mprotect', 'mremap')) == expected_counts, 'full resource domain')
    return {'events': dict(events), 'application_pid': root, 'shared_vm_children': sorted(children),
            'explicit_graph_unmaps': events['munmap'], 'remaining_graph_allocations_before_exit': 0,
            'process_owned_mapping_released_by_exit_bytes': PROCESS_MAP_BYTES,
            'remaining_all_allocations_after_exit': 0}


def queries(raw):
    result, cursor = [], 0
    while cursor < len(raw):
        require(raw[cursor:cursor + 8] == b'HFSFXQ02' and cursor + 32 <= len(raw), 'whole fixture input header')
        session, slot, size = (word(raw, cursor + n) for n in (8, 16, 24))
        require(session in (0, 1) and cursor + 32 + size <= len(raw), 'whole fixture input extent')
        result.append((session, slot, raw[cursor + 32:cursor + 32 + size]))
        cursor += 32 + size
    return result


def responses(raw):
    result, cursor = [], 0
    while cursor < len(raw):
        tag = raw[cursor:cursor + 8]
        require(tag in (b'HFSFXR02', b'HFSJPR03'), 'whole response tag')
        header_size = 104 if tag == b'HFSFXR02' else 96
        require(cursor + header_size <= len(raw), 'whole response header')
        header = raw[cursor:cursor + header_size]
        cursor += header_size
        if tag == b'HFSFXR02':
            size = word(header, 32)
            require(size <= word(header, 96) and cursor + size <= len(raw), 'whole response extent')
        elif word(header, 16) in (0, 4):
            size = 0
        else:
            end = raw.find(b'\n', cursor)
            require(end != -1, 'complete public JSON response')
            size = end + 1 - cursor
        result.append((header, raw[cursor:cursor + size]))
        cursor += size
    return result


def read_capture(base, source, inputs):
    freeze = json.loads((inputs / 'SOURCE_FREEZE.json').read_bytes())
    require(freeze['binding']['sha256'] == BINDING_SHA, 'source freeze binding')
    for name, expected in freeze['files'].items():
        require(pin((source / name).read_bytes()) == expected, 'source bytes: ' + name)
    require(pin((inputs / 'fixture.elf').read_bytes())['sha256'] == FIXTURE_SHA, 'exact fixture bytes')
    control = json.loads((inputs / 'CONTROL_INPUT.json').read_bytes())
    require(control['fixture_sha256'] == FIXTURE_SHA, 'control fixture binding')
    folder = base / 'source/capture-v2/installed-controls/installed'
    process = json.loads((folder / 'process.json').read_bytes())
    require(process['exit_code'] == 0 and process['timed_out'] is False and process['failure_cleanup_requested'] is False
            and process['timeout_seconds'] == 60 and 0 < process['elapsed_seconds'] <= 60 and not process['errors'], 'actual process success/budget')
    require(process['command'][:5] == ['/usr/bin/strace', '-f', '-qq', '-e',
            'trace=mmap,mprotect,munmap,mremap,clone,clone3,exit,exit_group,wait4'], 'full process and memory trace selection')
    streams = {n: gzip.decompress((folder / (n + '.bin.gz')).read_bytes()) for n in ('stdin', 'stdout', 'stderr')}
    for name, raw in streams.items():
        require(pin(raw) == process[name], 'full captured stream: ' + name)
    trace, memory = read_trace(streams['stderr']), read_memory((folder / 'memory.strace').read_text())
    require(memory['application_pid'] != process['pid'], 'strace supervisor and actual native process distinguished')
    inputs_wire, output_wire = queries(streams['stdin']), responses(streams['stdout'])
    rows = json.loads((folder / 'responses.json').read_bytes())
    require(len(inputs_wire) == len(output_wire) == len(rows) == 37, 'full installed boundary domain')
    invalid = collections.Counter()
    valid = collections.Counter()
    for index, ((session, slot, wire), (header, body), row) in enumerate(zip(inputs_wire, output_wire, rows), 1):
        require(row['sequence'] == index and row['session'] == session and row['slot'] == slot
                and row['input'] == pin(wire) and row['header_hex'] == header.hex() and row['body'] == pin(body), 'response index binds complete bytes')
        require(word(header, 8) == session, 'response session')
        if slot == 34:
            obj = json.loads(wire)
            if obj.get('id') is not None:
                require(json.loads(body)['id'] == obj['id'], 'public route request identity')
            continue
        require(word(header, 16) == slot and slot in (69, 70), 'response exact private slot')
        if row['label'].startswith('invalid-'):
            require(word(header, 24) == 0xffffffff and body == b'', 'invalid installed ABI rejection')
            invalid[slot] += 1
        else:
            name = 'typed' if slot == 69 else 'plan'
            expected = bytes.fromhex(control[name + '_frame_hex'])
            require(wire == bytes.fromhex(control[name + '_wire_hex']) and body == expected
                    and word(header, 24) == (256 if slot == 69 else len(expected)), 'exact qualified good input and full output')
            valid[slot] += 1
    require(invalid == {69: 6, 70: 13} and valid == {69: 6, 70: 6}, 'installed invalid/valid domains')
    rejected = []
    for slot in (71, 72, (1 << 64) - 1):
        p = base / ('source/capture-v2/installed-controls/slot-' + str(slot))
        proc = json.loads((p / 'process.json').read_bytes())
        require(proc == {'exit_code': 111, 'slot': slot, 'timed_out': False, 'timeout_seconds': 60}, 'exact out-of-range fatal exit')
        require(gzip.decompress((p / 'stdin.bin.gz').read_bytes()) == b'HFSFXQ02' + PACK(0, slot, 0), 'complete invalid slot input')
        require(gzip.decompress((p / 'stdout.bin.gz').read_bytes()) == b'', 'no response for invalid slot')
        diagnostic = gzip.decompress((p / 'stderr.bin.gz').read_bytes())
        require(len(diagnostic) == 448 and diagnostic[:224] == diagnostic[224:], 'both complete initial session receipts')
        receipt = diagnostic[:224]
        require(receipt[:8] == b'HRGTR002' and receipt[8:56] == PACK(1, 6, 1, 32, 4096, 4096)
                and receipt[64:192] == bytes(128) and receipt[192:] == b'HRSWR002' + bytes(24),
                'only initial workdir receipts precede invalid slot exit')
        rejected.append(slot)
    return {'status': 'PASS', 'fixture_sha256': FIXTURE_SHA, 'source_binding_sha256': BINDING_SHA,
            'trace': trace, 'resources': memory, 'actual_installed_queries': 37, 'typed_invalid': 6, 'planner_invalid': 13,
            'rejected_slots': rejected, 'public_binary_write_registered': False, 'whole_runtime_qualified': False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--capture', required=True, type=Path)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--inputs', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    a = parser.parse_args()
    report = read_capture(a.capture, a.source, a.inputs)
    a.output.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
