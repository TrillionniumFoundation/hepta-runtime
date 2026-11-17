"""Inert custody, full-map transitions and balanced strong/weak lifetime checks."""
from collections import Counter
import struct
from common import loads, require


def words(raw):
    require(len(raw) % 8 == 0, 'whole little-endian words')
    return struct.unpack('<' + str(len(raw) // 8) + 'Q', raw)


def map_entries(raw, kind):
    require(len(raw) >= 80 and (len(raw) - 16) % 8 == 0 and raw[-16:] == b'\xa5' * 16,
            'complete map guard')
    head = words(raw[:64])
    require(raw[:8] == b'HARMAP01' and head[1] == 1 and head[2] == kind and head[3] == head[6] == head[7] == 0,
            'canonical map identity')
    capacity = len(raw) - 16
    require(64 <= head[5] <= capacity and head[5] % 8 == 0, 'canonical map used extent')
    entries, at = [], 64
    while at < head[5]:
        require(at + 16 <= head[5], 'complete map entry header')
        size, pointer = words(raw[at:at + 16])
        after = at + ((size + 23) & ~7)
        require(pointer > 0 and after <= head[5], 'complete live weak entry')
        key = raw[at + 16:at + 16 + size]
        require(raw[at + 16 + size:after] == bytes(after - at - 16 - size), 'zero entry padding')
        entries.append((at, key, pointer))
        at = after
    require(len(entries) == head[4] and at == head[5] and raw[at:capacity] == bytes(capacity - at),
            'complete map count and retired bytes')
    if kind == 0:
        require(len({key for _, key, _ in entries}) == len(entries), 'one active weak per exact key')
    return entries


def map_transition(before, after, old_actor, request, kind):
    entries = [(key, pointer) for _, key, pointer in map_entries(before, kind)]
    original_offsets = [at for at, _, _ in map_entries(before, kind)]
    operation, pointer, key_size = (
        int.from_bytes(request[8:16], 'little'), int.from_bytes(request[24:32], 'little'),
        int.from_bytes(request[32:40], 'little'))
    key = request[64:64 + key_size]
    observation = words(request[64 + key_size:])
    phase = old_actor[4]
    if phase == 20:
        found = next((index for index, value in enumerate(entries) if value[0] == key), None)
        if kind == 0 and found is not None:
            entries[found] = (key, pointer)
        else:
            entries.append((key, pointer))
    elif phase == 22 and observation[4] == 0:
        require(old_actor[7] in original_offsets, 'pruned weak entry is owned by the scan')
        entries.pop(original_offsets.index(old_actor[7]))
    elif (phase == 10 and operation == 5) or phase == 27:
        if entries:
            entries.pop(0)
    expected = bytearray(before[:64])
    for key, pointer in entries:
        expected.extend(struct.pack('<2Q', len(key), pointer))
        expected.extend(key)
        expected.extend(bytes((-len(expected)) % 8))
    struct.pack_into('<Q', expected, 32, len(entries))
    struct.pack_into('<Q', expected, 40, len(expected))
    capacity = len(before) - 16
    require(len(expected) <= capacity, 'HIA map publication respects capacity')
    expected.extend(bytes(capacity - len(expected)) + b'\xa5' * 16)
    require(bytes(expected) == after, 'exact complete original-registry map transition')


def actor(raw):
    require(len(raw) == 528 and raw[512:] == b'\xa5' * 16, 'complete actor output tail')
    value = words(raw[:512])
    require(raw[:8] == b'HARGA001' and value[1] in (0, 1, 2, 3) and value[6] <= 1
            and value[11] <= 1 and value[13] == 1 and value[14] <= 1 and value[15] <= 1
            and raw[144:256] == bytes(112) and raw[384:512] == bytes(128), 'canonical HIA actor')
    if value[1] == 0:
        require(raw[256:384] == bytes(128), 'completed actor has no pending effect')
        require((value[4] == 90 and value[2] == 2 and value[6] == 0 and value[11] == 1)
                or (value[4] == 91 and value[2] in (0, 1, 100, 101) and value[11] == 0),
                'completed HIA ownership result')
    elif value[1] == 1:
        require(value[4] in (10, 11, 12, 13, 14), 'sync phase')
        request = [int.from_bytes(b'HASCMD01', 'little'), 1 if value[4] == 10 else 3,
                   value[6], 1, 0, value[15], *([0] * 10)]
        require(words(raw[256:384]) == tuple(request), 'exact HIA synchronization effect')
    elif value[1] == 2:
        phases = {20: 4, 21: 5, 22: 6, 23: 5, 24: 7, 25: 8, 26: 3, 27: 5}
        require(value[4] in phases and value[11] == 1, 'reference effect retains map custody')
        request = words(raw[256:320])
        require(raw[256:264] == b'HARREF01' and request[1] == phases[value[4]]
                and request[2] == value[6] + 1 and request[3] > 0 and not any(request[4:])
                and raw[320:384] == bytes(64), 'exact HIA reference effect')
    else:
        require(value[4] == 28 and value[11] == 1 and value[16] >= 80 and value[16] % 8 == 0
                and raw[256:384] == bytes(128), 'growth keeps actual registry custody')
    return value


def synchronization(request, before, after, returned, tid):
    require(len(request) == 128 and before == b'\xa5' * 144 and len(after) == 144
            and after[128:] == b'\xa5' * 16, 'full native synchronization physical buffers')
    require(returned == 128, 'complete actual synchronization return')
    q, r = words(request), words(after[:128])
    require(request[:8] == b'HASCMD01' and q[1] in (0, 1, 3) and q[2] <= 1
            and q[3] == 1 and q[4] == 0 and q[5] <= 1 and not any(q[6:]),
            'canonical actual synchronization input')
    require(after[:8] == b'HASYNR01' and r[1] == q[1] and r[3] == tid and r[10] == 1
            and r[4] == r[8] == r[9] == r[15] == 0 and r[2] <= 1
            and r[6] <= 1 and r[7] <= 1 and r[13] <= 1 and r[14] <= 1,
            'native synchronization response and actual thread')
    if q[1] == 1:
        require(r[11 + q[2]] == tid and r[13 + q[2]] == 1 and r[2] == r[6 + q[2]],
                'native lock really holds selected map mutex')
    elif q[1] == 3:
        require(r[2] == 0, 'native unlock completed')
    return q, r


def reference(request, before, after, returned, objects):
    require(len(request) == 64 and before == b'\xa5' * 80 and len(after) == 80
            and after[64:] == b'\xa5' * 16 and returned == 64, 'complete native reference physical buffers')
    q, r = words(request), words(after[:64])
    require(request[:8] == b'HARREF01' and q[1] <= 9 and q[2] in (1, 2) and not any(q[4:]),
            'canonical reference request')
    require(after[:8] == b'HARRES01' and r[1] == q[1] and r[6] == q[2]
            and r[2] <= 2 and r[7] <= 1 and r[3] > 0 and r[3] % 4096 == 0
            and r[4] < 1 << 63 and r[5] < 1 << 63, 'actual native reference response')
    operation, pointer = q[1], r[3]
    if operation < 2:
        prior = objects.get(pointer)
        require(prior is None or (prior['strong'] == prior['weak'] == 0 and prior['disposals'] == 1),
                'address reuse follows complete previous lifetime')
        require(q[3] == 0 and q[2] == operation + 1 and r[2] == r[4] == r[5] == 1,
                'actual new reference ownership')
        objects[pointer] = dict(strong=1, weak=0, disposals=0, kind=q[2])
        return 1, 0
    require(pointer == q[3] and pointer in objects and objects[pointer]['kind'] == q[2],
            'reference points to an observed allocation of the right kind')
    item = objects[pointer]
    if operation == 2 or (operation == 7 and r[2] == 1):
        item['strong'] += 1
    elif operation == 3:
        item['strong'] -= 1
    elif operation == 4:
        item['weak'] += 1
    elif operation == 5:
        item['weak'] -= 1
    require(item['strong'] >= 0 and item['weak'] >= 0, 'each drop consumes an observed owning reference')
    if operation in (2, 4, 8, 9):
        require(r[2] == 1, 'successful reference operation result')
    if operation in (3, 5):
        require(r[2] in (0, 2), 'drop result')
    if operation == 6:
        require(r[2] == 0, 'weak strong-count observation')
    if operation == 7:
        require(r[2] in (0, 1) and (r[2] != 0 or r[4] == 0), 'no resurrection after zero strong count')
    if operation == 9:
        require(q[2] == 1 and r[7] == 0, 'Release false marker update')
    if r[2] == 2:
        require(operation in (3, 5) and r[4] == r[5] == 0, 'actual last-reference native unmap')
        item['disposals'] += 1
        require(item['disposals'] == 1, 'one actual disposal per allocation lifetime')
    return 0, int(r[2] == 2)


def check_journal(path, pid, case):
    records = physical = allocations = disposals = 0
    actors, calls, pending, owners, maps, objects = {}, {}, {}, {}, {}, {}
    external_owners = set()
    counts = Counter()
    phases = []
    initial_context = None
    ended = False
    for line in path.open('rb'):
        require(line.endswith(b'\n'), 'complete newline-terminated actual journal')
        row = loads(line)
        require(row['index'] == records, 'every actual journal record exactly once')
        records += 1
        require(row['pid'] == pid and type(row['tid']) is int and row['tid'] > 1,
                'actual native journal process and thread')
        raw = {key: bytes.fromhex(value) for key, value in row.items() if key.endswith('_hex')}
        physical += sum(map(len, raw.values()))
        kind, tid = row['record'], row['tid']
        counts[kind] += 1
        if kind == 'reference-external':
            a, d = reference(raw['input_hex'], raw['output_before_hex'], raw['output_after_hex'],
                             row['returned'], objects)
            allocations += a
            disposals += d
            continue
        if kind == 'boundary-external':
            q, r = synchronization(raw['input_hex'], raw['output_before_hex'], raw['output_after_hex'],
                                   row['returned'], tid)
            key = (tid, q[2])
            if q[1] == 1:
                require(key not in external_owners, 'non-recursive actual probe custody')
                external_owners.add(key)
            elif q[1] == 3:
                require(key in external_owners, 'release an actually held probe mutex')
                external_owners.remove(key)
            continue
        if kind == 'public-start':
            require(not ended and row['call'] not in calls and row['actor'] not in pending,
                    'fresh public call without pending effect')
            request, before = raw['input_hex'], raw['actor_hex']
            require(len(request) >= 208 and request[-16:] == b'\xa5' * 16,
                    'complete external request and guard')
            q = words(request[:64])
            require(request[:8] == b'HARGQ001' and q[1] <= 8 and q[2] == 1
                    and q[4] == len(request) - 208 and q[5] <= 1 and q[6] == q[7] == 0
                    and request[-144:-16] == bytes(128), 'canonical fresh public request')
            require(len(before) == 528 and before[512:] == b'\xa5' * 16, 'complete initial actor')
            previous = actors.get(row['actor'])
            if previous is None:
                require(before[:512] == bytes(512) and q[1] not in (7, 8), 'unpublished fresh actor')
            else:
                require(before == previous and q[1] in (7, 8), 'retained cohort actor across calls')
            actors[row['actor']] = before
            calls[row['call']] = dict(actor=row['actor'], tid=tid, input=request, operation=q[1], effects=0)
            continue
        if kind == 'public-end':
            require(row['call'] in calls, 'every public completion has a unique start')
            call = calls.pop(row['call'])
            identity = row['actor']
            require(call['actor'] == identity and call['tid'] == tid and raw['input_hex'] == call['input'],
                    'same-thread public completion and complete immutable input')
            require(row['returned'] == 512 and row['elapsed_ns'] > 0 and identity not in pending,
                    'complete public result with no pending effect')
            after = raw['actor_hex']
            a = actor(after)
            if call['operation'] == 0:
                expected = [0] * 64
                expected[0], expected[4], expected[13] = int.from_bytes(b'HARGA001', 'little'), 91, 1
                require(words(after[:512]) == tuple(expected) and call['effects'] == 1,
                        'complete prepublication initialization')
                actors[identity] = after
            else:
                require(after == actors[identity] and a[1] == 0 and a[5] == call['operation'],
                        'public result is the last actual HIA actor')
            require((identity in owners) == (a[4] == 90), 'public result retains exactly its actual cohort guard')
            if call['operation'] == 5:
                require(a[2] == 0 and not owners, 'disposal has released both actual mutexes')
                ended = True
            continue
        if kind == 'map-probe':
            require((tid, 0) in external_owners and (tid, 1) in external_owners,
                    'test snapshot owns both actual map mutexes')
            for number, label in ((0, 'active_hex'), (1, 'pins_hex')):
                map_entries(raw[label], number)
                require(raw[label] == maps[number], 'read-only test probe preserves full map chain')
            continue
        if kind == 'quiescent':
            phase = row['phase']
            require(not calls and not pending and not owners and not external_owners, 'actual quiescent ownership')
            context, kernel = raw['context_hex'], raw['kernel_hex']
            require(len(context) == 144 and len(kernel) == 80 and context[-16:] == kernel[-16:] == b'\xa5' * 16,
                    'complete quiescent context and kernel tails')
            c = words(context[:128])
            require(kernel[:8] == b'HASYNC01' and word_at(kernel, 8, 4) == word_at(kernel, 16, 4) == 0
                    and word_at(kernel, 32) == word_at(kernel, 40) == 0 and word_at(kernel, 48) == 1,
                    'quiescent actual native mutex state')
            require(not any(c[12:]) and c[2] > 0 and c[3] == 64 and c[10] > 0 and c[11] > 0,
                    'canonical borrowed kernel and optional observer identity')
            if phase == 'initialized':
                require(not phases and not maps and context[:8] == b'HARCTX01' and c[1] == 1,
                        'one actual initialized native context')
                initial_context = c
                for number, label in ((0, 'active_hex'), (1, 'pins_hex')):
                    require(len(raw[label]) == 80 and map_entries(raw[label], number) == [], 'two empty initialized maps')
                    maps[number] = raw[label]
            elif phase == 'before-disposal':
                require(phases == ['initialized'] and not ended, 'one quiescent pre-disposal snapshot')
                require(raw['active_hex'] == maps[0] and raw['pins_hex'] == maps[1], 'complete pre-disposal map chain')
            elif phase == 'disposed':
                require(phases == ['initialized', 'before-disposal'] and ended,
                        'disposal follows final actual HIA clear')
                require(all(c[i] == 0 for i in (0, 1, 4, 5, 6, 7, 8, 9))
                        and not raw['active_hex'] and not raw['pins_hex'], 'both native table mappings retired')
                require(all(c[i] == initial_context[i] for i in (2, 3, 10, 11)), 'borrowed fields survive native disposal')
                require(all(map_entries(maps[number], number) == [] for number in (0, 1)), 'all weak entries retired before unmap')
            else:
                raise ValueError('unknown quiescent phase')
            phases.append(phase)
            continue
        require(kind == 'effect' and row['call'] in calls, 'every effect belongs to an active public call')
        call = calls[row['call']]
        identity = row['actor']
        require(call['actor'] == identity and call['tid'] == tid and row['elapsed_ns'] > 0,
                'same-thread mechanical effect ownership')
        event, after_event = words(raw['event_before_hex']), words(raw['event_after_hex'])
        require(len(event) == len(after_event) == 16 and event[0] in (1, 2, 3, 4)
                and event[1] == event[2] == 0 and after_event[0] == event[0] and after_event[1] == 1
                and event[15] == after_event[15] == 0, 'complete observer event pair')
        expected_event = list(event)
        expected_event[1:3] = after_event[1:3]
        if event[0] == 4:
            expected_event[6:8] = after_event[6:8]
        require(tuple(expected_event) == after_event, 'unchanged observer metadata outside return and growth')
        request, before, after = raw['input_hex'], raw['output_before_hex'], raw['output_after_hex']
        require(len(request) == event[4], 'whole effect input buffer')
        call['effects'] += 1
        if event[0] == 1:
            require(after_event[2] == 512, 'every actual HIA controller step returns its complete actor')
            require(before == actors[identity], 'complete private actor byte chain')
            old = words(before[:512])
            current = actor(after)
            wire = call['input'][:-16]
            size = word_at(wire, 32)
            require(len(request) == len(wire) and request[:48] == wire[:48]
                    and request[64:64 + size] == wire[64:64 + size], 'immutable original key and public operands')
            previous = pending.pop(identity, None)
            if previous is None:
                require(request == wire, 'fresh HIA step starts with canonical external request')
            else:
                require(previous['reply'] is not None and word_at(request, 48) == previous['serial']
                        and word_at(request, 56) == previous['reply_size']
                        and request[64 + size:] == previous['reply'], 'exact native effect reply enters next HIA step')
            owned, map_kind = event[8], event[9]
            require(owned in (0, 1) and map_kind <= 1, 'map custody observation')
            if owned:
                require(owners.get(identity) == map_kind, 'controller borrows only its actually held map')
                require(len(raw['map_before_hex']) == len(raw['map_after_hex']) == event[7] + 16,
                        'complete controller map buffers')
                require(raw['map_before_hex'] == maps[map_kind], 'complete shared map byte chain')
                map_transition(raw['map_before_hex'], raw['map_after_hex'], old, request, map_kind)
                map_entries(raw['map_after_hex'], map_kind)
                maps[map_kind] = raw['map_after_hex']
            else:
                require(identity not in owners and event[7] == 0
                        and raw['map_before_hex'] == raw['map_after_hex'] == bytes(16),
                        'unowned map view is empty and unchanged')
            actors[identity] = after
            if current[1]:
                pending[identity] = dict(kind=current[1], request=after[256:384] if current[1] == 1 else after[256:320],
                                         serial=current[3], reply=None, map_kind=current[6], required=current[16])
            continue
        if call['operation'] == 0:
            require(event[0] == 2 and call['effects'] == 1, 'initialization executes only native sync initialization')
            q, _ = synchronization(request, before, after, after_event[2], tid)
            require(q[1] == q[2] == 0, 'fresh native kernel initialization')
            continue
        require(identity in pending and pending[identity]['reply'] is None, 'one native effect per HIA issuance')
        issued = pending[identity]
        if event[0] == 2:
            require(issued['kind'] == 1 and request == issued['request'], 'actual sync input is HIA-issued bytes')
            q, _ = synchronization(request, before, after, after_event[2], tid)
            if q[1] == 1:
                require(identity not in owners, 'new actual actor mutex custody')
                owners[identity] = q[2]
            elif q[1] == 3:
                require(owners.pop(identity, None) == q[2], 'release actor actual selected map custody')
            issued.update(reply=after[:128], reply_size=128)
        elif event[0] == 3:
            require(issued['kind'] == 2 and request == issued['request'], 'actual reference input is HIA-issued bytes')
            a, d = reference(request, before, after, after_event[2], objects)
            allocations += a
            disposals += d
            issued.update(reply=after[:64] + bytes(64), reply_size=64)
        else:
            require(issued['kind'] == 3 and not request and after_event[2] == 0
                    and before == after == actors[identity], 'native growth does not invent controller state')
            number, old_capacity, capacity = issued['map_kind'], event[10], event[11]
            require(owners.get(identity) == number and event[8] == 1 and event[9] == number
                    and old_capacity == event[7] and capacity == after_event[7] == issued['required']
                    and capacity > old_capacity, 'actual owned native mapping growth')
            old_map, new_map = raw['map_before_hex'], raw['map_after_hex']
            require(old_map == maps[number], 'complete pre-growth map chain')
            require(new_map == old_map[:-16] + bytes(capacity - old_capacity) + b'\xa5' * 16,
                    'complete preserved growth prefix, zero extension and guard')
            map_entries(new_map, number)
            maps[number] = new_map
            issued.update(reply=bytes(128), reply_size=0)
    require(phases == ['initialized', 'before-disposal', 'disposed'] and ended and not calls
            and not pending and not owners and not external_owners, 'closed context, call and custody lifetimes')
    require(allocations > 0 or case in ('already_unwinding_guard', 'active_poison_first'), 'actual owning reference domain')
    require(allocations == disposals and all(value['strong'] == value['weak'] == 0 and value['disposals'] == 1
                                           for value in objects.values()), 'all strong and weak references actually disposed')
    return dict(records=records, physical_bytes=physical, calls=counts['public-end'],
                allocations=allocations, disposals=disposals, record_counts=dict(counts),
                semantic_reexecutions=0)


def word_at(raw, at, size=8):
    return int.from_bytes(raw[at:at + size], 'little')
