"""Inert full-byte reader for the frozen composed controller evidence."""
from collections import Counter, defaultdict
from pathlib import Path
import re
import struct
from common import (ROOT, COMPILER, HEPTA_COMMIT, HEPTA_TREE, envelope, files, loads,
                    pin, read, require, sha, source)
from recipes import recipes
import read_callable

SYNC_SOURCE = 'e780e46fcdb3278b6b4e87b56da79397dc6f8abbb741e7260e7e71ac4bab07a5'
IMAGES = {
    'audit-store-controller': '1c2d4e44f4d2185ef06dc1de0566f21a33f92bee61b05fa7ebed6ee9841de90a',
    'audit-native-sync': '3f680858821d674511aba0a59df606bc03bc9384216e6e4fa88b1a01c7bbeae5',
    'audit-controller-callable': '1c7a1322303ac23f5a69535a804e40c56650ab152d8ed30f58ca29ce31a3322f',
}
EFFECTS = {
    10: (6, 0), 11: (1, 0), 12: (6, 0), 13: (6, 0), 14: (6, 0), 15: (4, 0),
    16: (5, 0), 17: (3, 0), 18: (6, 0), 19: (2, 1), 20: (6, 0), 21: (3, 1),
    22: (1, 0), 23: (5, 0), 24: (3, 0), 25: (5, 0), 26: (3, 0),
    40: (7, 0), 41: (1, 0), 42: (7, 0), 43: (6, 0), 44: (5, 0), 45: (3, 0), 46: (3, 0),
    50: (7, 0), 51: (3, 1), 52: (1, 0), 53: (5, 0), 54: (3, 0),
}


def words(raw):
    require(len(raw) % 8 == 0, 'whole physical little-endian words')
    return struct.unpack('<' + str(len(raw) // 8) + 'Q', raw)


def write_word(raw, index, value):
    raw[index * 8:index * 8 + 8] = value.to_bytes(8, 'little')


def check_actor(raw, generation):
    require(len(raw) == 528 and raw[512:] == b'\xa5' * 16, 'complete controller output tail')
    value = words(raw[:512])
    require(raw[:8] == b'HAUCOR01' and value[1] in (0, 1, 2) and value[16] == generation
            and all(value[index] in (0, 1) for index in (5, 6, 11, 12, 13, 15, 25))
            and value[23] == 0 and raw[208:256] == b'\0' * 48 and raw[384:512] == b'\0' * 128,
            'complete canonical private actor')
    require(value[6] != 0 or value[7] == value[8] == 0, 'canonical actor deadline')
    if value[1] == 0:
        require(raw[256:384] == b'\0' * 128 and value[24] == 0 and value[11] == value[25] == 0,
                'completed actor has no outstanding queue effect')
        require((value[4] == 30 and value[2] == 3 and value[13] == 1 and value[12] == 1 - value[5])
                or (value[4] == 90 and value[2] in (0, 5, 6) and value[12] == value[13] == 0),
                'completed actor actual custody')
    elif value[1] == 2:
        require(value[2] == 0 and value[4] == 60 and value[11] == 1
                and value[12] == value[13] == value[25] == 0 and value[24] >= 144 and value[24] % 16 == 0
                and raw[256:384] == b'\0' * 128, 'growth retains exclusive queue custody')
    else:
        require(value[2] == 0 and value[4] in EFFECTS and value[24] == 0, 'actual controller phase')
        request = list(words(raw[256:384]))
        operation, kind = EFFECTS[value[4]]
        expected = [int.from_bytes(b'HASCMD01', 'little'), operation, kind, generation, 0, 0, 0, 0, 0, *([0] * 7)]
        if operation in (1, 2, 3):
            expected[5] = value[15]
        if operation == 4:
            expected[4] = value[22]
            if value[6]:
                remaining = max(0, ((value[8] << 64) | value[7]) - ((value[19] << 64) | value[18]))
                seconds, nanos = divmod(min(remaining, ((1 << 63) - 1) * 1_000_000_000 + 999_999_999), 1_000_000_000)
                expected[6:9] = [1, seconds, nanos]
        require(request == expected, 'exact HIA-emitted mechanical effect')
    return value


def check_queue(raw, capacity, generation):
    require(len(raw) == capacity + 16 and capacity >= 128 and capacity % 16 == 0
            and raw[capacity:] == b'\xa5' * 16, 'complete shared queue tail')
    value = words(raw[:capacity])
    require(raw[:8] == b'HAUQS001' and value[7] == generation and value[2] in (0, 1)
            and value[4] in (0, 1) and not (value[2] and value[3]) and value[6] == 128 + value[5] * 16
            and value[6] <= capacity and not any(value[8:16]), 'canonical shared queue header')
    waiting = list(zip(value[16:16 + value[5] * 2:2], value[17:17 + value[5] * 2:2]))
    require(all(ticket < value[1] and access in (0, 1) for ticket, access in waiting)
            and all(a[0] < b[0] for a, b in zip(waiting, waiting[1:]))
            and raw[value[6]:capacity] == b'\0' * (capacity - value[6]), 'complete FIFO records and retired bytes')
    return value, waiting


def queue_transition(before, after, old_actor, actor, command, generation):
    expected = bytearray(before)
    if command == 0:
        require(before[:-16] == b'\0' * (len(before) - 16), 'prepublication zero queue')
        expected[:8] = b'HAUQS001'
        write_word(expected, 6, 128)
        write_word(expected, 7, generation)
    elif command == 3:
        old, waiting = check_queue(before, len(before) - 16, generation)
        phase, access, ticket = old_actor[4], actor[5], actor[9]
        if phase in (12, 60) and actor[4] == 13:
            require(ticket == old[1] and actor[25] == 1, 'fresh monotonically assigned FIFO ticket')
            expected[old[6]:old[6] + 16] = struct.pack('<2Q', ticket, access)
            write_word(expected, 1, old[1] + 1)
            write_word(expected, 5, old[5] + 1)
            write_word(expected, 6, old[6] + 16)
        elif phase in (13, 15) and actor[4] in (16, 17, 25):
            require(waiting.count((ticket, access)) == 1, 'retiring the owned FIFO ticket')
            at = waiting.index((ticket, access))
            if actor[4] in (16, 17):
                require(at == 0 and old[2] == 0 and (access == 1 or old[3] == 0),
                        'actual FIFO admission without passing a writer')
                require(actor[13] == 1 and actor[25] == 0 and actor[4] == (16 if access else 17),
                        'admission creates exactly one active guard')
                write_word(expected, 3 if access else 2, old[3] + 1 if access else 1)
            else:
                require(actor[13] == 0 and actor[25] == 0 and actor[14] in (5, 6), 'cancellation has no active guard')
            offset = 128 + at * 16
            expected[offset:old[6] - 16] = before[offset + 16:old[6]]
            expected[old[6] - 16:old[6]] = b'\0' * 16
            write_word(expected, 5, old[5] - 1)
            write_word(expected, 6, old[6] - 16)
        elif phase in (22, 52):
            require(old_actor[13] == 1 and old_actor[12] == 0 and actor[13] == 0,
                    'real inner guard released before FIFO reservation')
            if access:
                require(old[3] > 0, 'released shared owner existed')
                write_word(expected, 3, old[3] - 1)
                if actor[15]:
                    write_word(expected, 4, 1)
            else:
                require(old[2] == 1, 'released exclusive owner existed')
                write_word(expected, 2, 0)
        elif phase in (41, 42, 43) and actor[4] == 44:
            require(access == 1 and old_actor[13] == 1 and actor[13] == 0 and old[3] > 0,
                    'shared finish consumes its actual guard')
            write_word(expected, 3, old[3] - 1)
    require(bytes(expected) == after, 'complete actual queue transition')


def check_boundary(row):
    request = bytes.fromhex(row['input_hex'])
    before = bytes.fromhex(row['output_before_hex'])
    after = bytes.fromhex(row['output_after_hex'])
    require(len(request) == 128 and len(before) == len(after) == 144
            and before == b'\xa5' * 144 and after[128:] == b'\xa5' * 16, 'full native boundary output tail')
    require(row['returned'] == 128, 'every actual boundary call returned its full frame')
    frame, result = words(request), words(after[:128])
    require(request[:8] == b'HASCMD01' and frame[1] <= 7 and frame[2] <= 1
            and frame[3] == row['generation'] and frame[5] <= 1 and not any(frame[9:]),
            'canonical actual boundary request')
    require(after[:8] == b'HASYNR01' and result[1] == frame[1] and result[3] == row['tid']
            and result[10] == row['generation'] and result[15] == 0,
            'native response and independently observed actual TID')
    require(result[2] in (0, 1, 2) and result[5] < 1 << 32 and result[6] <= 1 and result[7] <= 1
            and result[13] <= 1 and result[14] <= 1
            and result[4] in ((0, 4, 11, 110) if frame[1] == 4 else (0,)), 'actual kernel result ranges')
    if frame[1] != 6:
        require(result[8] == result[9] == 0, 'clock fields only on actual clock operation')
    if frame[1] in (1, 2) and result[2] != 2:
        require(result[11 + frame[2]] == row['tid'] and result[13 + frame[2]] == 1
                and result[2] == result[6 + frame[2]], 'actual mutex acquisition and poison')
    if frame[1] == 4:
        require(result[11] == row['tid'] and result[13] == 1 and result[2] in (0, 1),
                'actual wait reacquires the queue mutex')
    require(result[2] != 2 or frame[1] == 2, 'WouldBlock requires an actual try-lock')
    return request, after[:128], len(request) + len(before) + len(after)


def instant(row):
    matched = re.fullmatch(r'Instant \{ tv_sec: (-?[0-9]+), tv_nsec: ([0-9]+) \}', row['debug'])
    require(matched is not None, 'pinned actual Instant diagnostic representation')
    seconds, nanos = map(int, matched.groups())
    require(0 <= nanos < 1_000_000_000 and -(1 << 63) <= seconds < (1 << 63), 'actual Instant component ranges')
    value = 0 if seconds < 0 else seconds * 1_000_000_000 + nanos
    require(row['value'] == value, 'exact absolute monotonic deadline mapping')
    return value


def check_journal(root, pid, domain):
    raw = read(root / 'threads/journal.jsonl')
    require(raw.endswith(b'\n'), 'complete actual controller journal')
    rows = [loads(line) for line in raw.splitlines()]
    require(sorted(row['index'] for row in rows) == list(range(len(rows))), 'every actual journal record exactly once')
    rows.sort(key=lambda row: row['index'])
    actors, pending, queues, contexts, closed, deadlines = {}, {}, {}, {}, set(), {}
    actor_ids, starts, results, kinds = set(), Counter(), Counter(), Counter()
    by_case_context, next_tickets, poisons = defaultdict(set), defaultdict(list), defaultdict(list)
    acquisition_threads = defaultdict(Counter)
    boundaries, extras = {}, []
    physical, mappings = 0, 0
    for row in rows:
        require(row['pid'] == pid and type(row['tid']) is int and row['tid'] > 1
                and row['case'] in domain['native_cases'], 'actual controller process, thread and case')
        kind, generation, tid = row['record'], row['generation'], row['tid']
        kinds[kind] += 1
        if kind in ('exclusive-workers', 'shared-workers', 'exclusive-unwind', 'existing-unwind'):
            require(generation == 0, 'case observation is outside a live native context')
            extras.append(dict(case=row['case'], kind=kind,
                               **{key: value for key, value in row.items()
                                  if key not in ('case', 'record', 'generation', 'index', 'pid', 'tid')}))
            continue
        if kind == 'clock-mapping':
            value = instant(row)
            require(generation == 0 and row['case'] == 'deadline_mapping_is_exact_on_the_pinned_linux_toolchain'
                    and 0 <= row['before'] <= value <= row['after'], 'actual epoch bounded by independent kernel clocks')
            mappings += 1
            continue
        require(type(generation) is int and generation > 0 and generation not in closed, 'live actual context')
        if generation not in contexts:
            require(kind == 'boundary' and words(bytes.fromhex(row['input_hex']))[1] == 0,
                    'context begins with actual native synchronization initialization')
            contexts[generation] = row['case']
            by_case_context[row['case']].add(generation)
        require(contexts[generation] == row['case'], 'source-owned context case')
        if kind == 'deadline':
            key = (generation, tid)
            require(key not in deadlines, 'one retained actual deadline for the following API start')
            deadlines[key] = instant(row)
            continue
        if kind == 'boundary':
            request, response, count = check_boundary(row)
            physical += count
            boundaries[generation, tid] = (words(request), words(response))
            if row['actor']:
                actor_id = row['actor']
                require(actor_id in actors and actors[actor_id]['tid'] == tid
                        and actors[actor_id]['generation'] == generation, 'boundary belongs to its actual actor')
                old = actors[actor_id]['raw']
                state = words(old[:512])
                require(state[1] == 1 and row['serial'] == state[3] and request == old[256:384]
                        and actor_id not in pending, 'actual boundary executes the exact emitted actor effect once')
                pending[actor_id] = ('boundary', response)
            else:
                require(row['serial'] == 0, 'mechanical probe has no controller serial')
            continue
        if kind == 'growth':
            actor_id = row['actor']
            require(actor_id in actors and actors[actor_id]['tid'] == tid
                    and actors[actor_id]['generation'] == generation and actor_id not in pending,
                    'growth belongs to its actual actor')
            state = words(actors[actor_id]['raw'][:512])
            before, after = bytes.fromhex(row['before_hex']), bytes.fromhex(row['after_hex'])
            old_capacity, required = row['old_capacity'], row['required']
            require(state[1] == 2 and state[11] == 1 and state[3] == row['serial'] and state[24] == required
                    and before == queues[generation] and len(before) == old_capacity + 16 and required > old_capacity,
                    'actual retained-custody growth request')
            require(after == before[:old_capacity] + b'\0' * (required - old_capacity) + b'\xa5' * 16,
                    'growth preserves every old logical byte')
            check_queue(after, required, generation)
            queues[generation] = after
            pending[actor_id] = ('growth', b'\0' * 128)
            physical += len(before) + len(after)
            continue
        if kind == 'controller':
            actor_id = row['actor']
            request = bytes.fromhex(row['input_hex'])
            before, after = bytes.fromhex(row['output_before_hex']), bytes.fromhex(row['output_after_hex'])
            queue_before, queue_after = bytes.fromhex(row['queue_before_hex']), bytes.fromhex(row['queue_after_hex'])
            require(len(request) == 256 and len(before) == 528 and row['returned'] == 512,
                    'every actual controller step returned its full frame')
            frame, old = words(request), words(before[:512])
            require(request[:8] == b'HAUCTL01' and frame[1] in range(6) and not any(frame[9:16]),
                    'canonical actual controller command')
            command = frame[1]
            actor = check_actor(after, generation)
            if actor_id not in actors:
                require(command in (0, 1, 2) and before == b'\0' * 512 + b'\xa5' * 16,
                        'new actor begins with its complete zero private state')
                actor_ids.add(actor_id)
                actors[actor_id] = dict(raw=before, generation=generation, tid=tid)
            require(actors[actor_id] == dict(raw=before, generation=generation, tid=tid),
                    'complete private actor byte chain and actual owner')
            if command == 3:
                require(actor_id in pending and frame[2] == old[3] and not any(frame[4:16]),
                        'one matching completed effect per resumed serial')
                effect_kind, observation = pending.pop(actor_id)
                require(request[128:] == observation and frame[3] == (128 if effect_kind == 'boundary' else 0),
                        'resume consumes the full actual effect response')
                if effect_kind == 'boundary':
                    response = words(observation)
                    require(row['queue_owned'] is (response[11] == tid and response[13] == 1),
                            'shared queue passed only with actual native custody')
                    require(actor[10] == tid and tuple(actor[18:20]) == tuple(response[8:10]) and actor[22] == response[5],
                            'private actor retains actual thread, clock and sequence')
                else:
                    require(row['queue_owned'] is True, 'growth continuation retains actual custody')
            else:
                require(actor_id not in pending and frame[2] == frame[3] == 0 and frame[4] == generation
                        and frame[5] in (0, 1) and frame[8] in (0, 1) and not any(frame[16:]),
                        'canonical new API command')
                require(actor[15] == frame[8] and actor[17] == command, 'actual API command and unwind flag')
                starts[str(command)] += 1
                if frame[5]:
                    require(command in (1, 2) and deadlines.pop((generation, tid), None)
                            == ((frame[7] << 64) | frame[6]), 'API uses the retained exact deadline')
                else:
                    require(frame[6] == frame[7] == 0 and command != 2, 'canonical absent API deadline')
                if command in (1, 2):
                    acquisition_threads[row['case']][tid] += 1
                    require(actor[4] == 10 and actor[5] == command - 1 and actor[6:9] == frame[5:8],
                            'new acquisition retains its exact access and deadline')
                if command in (4, 5):
                    require(old[1] == 0 and old[4] == 30 and old[13] == 1
                            and actor[4] == (40 if command == 4 else 50), 'finish or Drop consumes an actual held guard')
            require(actor[3] == (old[3] + 1 if actor[1] in (1, 2) else old[3]), 'monotonic actor continuation serial')
            require(row['initial'] is (command == 0), 'queue initialization is explicitly before publication')
            if row['queue_owned']:
                if command != 0:
                    require(queue_before == queues.get(generation), 'complete shared queue byte chain')
                    check_queue(queue_before, row['queue_capacity'], generation)
                else:
                    require(generation not in queues and row['queue_capacity'] == 128, 'one fresh queue initialization')
                check_queue(queue_after, row['queue_capacity'], generation)
                queue_transition(queue_before, queue_after, old, actor, command, generation)
                queues[generation] = queue_after
            else:
                require(command != 0 and row['queue_capacity'] == 0
                        and queue_before == queue_after == b'\xa5' * 16,
                        'unlocked phases never access shared queue bytes')
            if actor[1] == 0:
                results[str(actor[2])] += 1
            actors[actor_id]['raw'] = after
            physical += len(request) + len(before) + len(after) + len(queue_before) + len(queue_after)
            continue
        if kind == 'queue-probe':
            queue = bytes.fromhex(row['queue_hex'])
            frame, response = boundaries[generation, tid]
            require(frame[1:3] == (1, 0) and response[11] == tid and response[13] == 1
                    and queue == queues[generation], 'independent queue inspection has actual mutex custody')
            check_queue(queue, len(queue) - 16, generation)
            physical += len(queue)
            continue
        if kind == 'quiescent':
            kernel, queue = bytes.fromhex(row['kernel_hex']), bytes.fromhex(row['queue_hex'])
            require(len(kernel) == 80 and kernel[64:] == b'\xa5' * 16, 'complete quiescent kernel tail')
            require(kernel[:8] == b'HASYNC01' and int.from_bytes(kernel[48:56], 'little') == generation
                    and not any(kernel[8:12] + kernel[16:20] + kernel[28:48] + kernel[56:64]),
                    'all actual native custody released at quiescence')
            q, waiting = check_queue(queue, len(queue) - 16, generation)
            require(queue == queues[generation] and q[2] == q[3] == q[5] == 0 and q[6] == 128 and not waiting,
                    'every active guard and FIFO reservation released')
            qpoison, ipoison = struct.unpack('<I', kernel[12:16])[0], struct.unpack('<I', kernel[20:24])[0]
            require(qpoison in (0, 1) and ipoison in (0, 1), 'quiescent standard poison bits')
            poisons[row['case']].append((qpoison, ipoison, q[4]))
            next_tickets[row['case']].append(q[1])
            closed.add(generation)
            physical += len(kernel) + len(queue)
            continue
        raise ValueError('unfrozen actual journal record kind')
    require(not pending and not deadlines and closed == set(contexts), 'every actual continuation and context closed')
    require({name: len(value) for name, value in by_case_context.items()} == domain['contexts']
            and sorted(contexts) == list(range(1, domain['context_count'] + 1)), 'all source-owned actual contexts')
    require(len(actors) == domain['actor_count'] and sorted(actor_ids) == list(range(1, domain['actor_count'] + 1))
            and all(words(row['raw'][:512])[4] == 90 for row in actors.values()), 'all actual actors reach final release')
    require(starts == domain['api_starts'] and results == domain['results']
            and sum(results.values()) == domain['api_completions'], 'complete actual API and outcome domain')
    require({name: sorted(values) for name, values in next_tickets.items()} == domain['next_tickets'],
            'every expected FIFO ticket was admitted or cancelled')
    expected_poison = {name: [(0, 0, 0)] * count for name, count in domain['contexts'].items()}
    expected_poison.update(
        exclusive_owner_panic_preserves_inner_poison_and_releases_fifo=[(0, 1, 0)],
        existing_unwind_preserves_distinct_reader_and_mutex_poison_rules=[(0, 0, 0), (0, 0, 1)],
        shared_admission_and_finish_preserve_writer_and_queue_poison=[(0, 1, 0), (1, 0, 0)],
        shared_panic_refuses_active_peers_without_revoking_finished_reads=[(0, 0, 1)])
    require({name: sorted(value) for name, value in poisons.items()} == expected_poison,
            'actual reader and standard mutex poison outcomes')
    for name, workers, per_worker in (
        ('exclusive_threads_serialize_256_actual_critical_sections', 16, 16),
        ('sixty_five_actual_shared_owners_keep_custody_until_finish', 65, 1),
    ):
        require(len(acquisition_threads[name]) == workers and set(acquisition_threads[name].values()) == {per_worker},
                'every actual independent worker completed its exact acquisition domain')
    require(mappings == domain['clock_mapping_observations'], 'all independent actual clock mappings')
    original_raw = read(root / 'threads/original-observations.jsonl')
    require(original_raw.endswith(b'\n'), 'complete independent original observations')
    original = [loads(line) for line in original_raw.splitlines()]
    expected_extras = [
        dict(case='exclusive_threads_serialize_256_actual_critical_sections', kind='exclusive-workers',
             threads=16, critical_sections=256, counter=256),
        dict(case='sixty_five_actual_shared_owners_keep_custody_until_finish', kind='shared-workers',
             threads=65, concurrent_guards=65, finished=65),
        dict(case='exclusive_owner_panic_preserves_inner_poison_and_releases_fifo', kind='exclusive-unwind',
             inner_poisoned=True, queue_poisoned=False, fifo_released=True),
        dict(case='existing_unwind_preserves_distinct_reader_and_mutex_poison_rules', kind='existing-unwind',
             contexts=2, mutex_poisoned=False, shared_drop_reader_poisoned=True),
    ]
    ordering = lambda value: value['case']
    require(sorted(original, key=ordering) == sorted(extras, key=ordering) == sorted(expected_extras, key=ordering),
            'complete original/native independent worker and unwind observations agree')
    return dict(records=len(rows), record_kinds=dict(kinds), contexts=len(contexts), actors=len(actors),
                api_starts=dict(starts), outcomes=dict(results), completed_operations=sum(results.values()),
                original_observations=pin(original_raw), journal=pin(raw), physical_bytes=physical,
                clock_mappings=mappings, actual_original_native_observations=len(extras))


def semantic(root):
    root = Path(root).resolve(strict=True)
    identity = source()
    capture = envelope(root)
    domain = loads(read(ROOT / 'DOMAIN.json'))
    require(capture['schema'] == 'hepta.audit-store-controller.capture.v1' and capture['status'] == 'PASS'
            and capture['source_manifest_sha256'] == identity and capture['domain'] == pin(read(ROOT / 'DOMAIN.json')),
            'same-source complete semantic capture')
    require(capture['scope'] == domain['scope'] and capture['public_handler_qualified'] is False
            and capture['whole_runtime_replaced'] is False, 'exact qualified controller scope')
    original = check_original()
    build = check_build(root, identity)
    emission = check_emission(root, identity)
    callable_emission = read_callable.emission(root, identity)
    pids = check_processes(root, capture, domain)
    observer_free = read_callable.observer_free(root, identity, pids['observer-free-native'])
    journal = check_journal(root, pids['native-threads'], domain)
    return dict(schema='hepta.audit-store-controller.read.v1', status='COMPLETE_HIA_NATIVE_AUDIT_CALLABLE_PASS',
                source_manifest_sha256=identity, original=original, build=build, emission=emission,
                callable_emission=callable_emission, observer_free=observer_free,
                journal=journal, original_tests=len(domain['original_cases']), native_tests=len(domain['native_cases']),
                scope=domain['scope'], public_handler_qualified=False, whole_runtime_replaced=False, semantic_reexecutions=0)


def verify(output, require_controls=False):
    output = Path(output).resolve(strict=True)
    result = semantic(output / 'semantic')
    if require_controls:
        import reader_controls
        result['controls'] = reader_controls.verify(output, result)
    return result


def check_build(root, identity):
    build = root / 'build'
    report = loads(read(build / 'COMPOSED_BUILD.json'))
    require(report['schema'] == 'hepta.audit-store-controller.composed-build.v1'
            and report['source_manifest_sha256'] == identity and report['compiler_sha256'] == COMPILER
            and report['compiler_bootstrap'] == 'fresh pinned B1=B2=B3'
            and report['sync_source_manifest_sha256'] == SYNC_SOURCE
            and set(report['modules']) == set(IMAGES), 'fresh composed B3 build binding')
    sync = build / 'sync-source'
    sync_manifest = read(sync / 'SOURCE_MANIFEST.json')
    require(sha(sync_manifest) == SYNC_SOURCE, 'qualified synchronization source identity')
    sync_files = files(sync, ('SOURCE_MANIFEST.json',))
    require({name: {key: row[key] for key in ('bytes', 'sha256')} for name, row in sync_files.items()}
            == loads(sync_manifest)['files'] and all(row['mode'] == 0o644 for row in sync_files.values()),
            'complete qualified synchronization source bytes and modes')
    dependency = loads(read(sync / 'COMPILER_FILES.json'))
    require(dependency['commit'] == HEPTA_COMMIT and dependency['tree'] == HEPTA_TREE
            and len(dependency['files']) == report['compiler_files'] == 1080, 'complete pinned compiler closure')
    retained = files(build / 'compiler-source')
    require(set(retained) == set(dependency['files']), 'complete retained compiler source set')
    for name, row in retained.items():
        require(row['sha256'] == dependency['files'][name], 'retained compiler source: ' + name)
    bootstrap = loads(read(build / 'bootstrap/bootstrap.json'))
    require(bootstrap['dependency'] == dependency and bootstrap['generation_sha256'] == COMPILER,
            'bootstrap compiler/source identity')
    compiler_source = read(build / 'compiler-source/examples/hia_bootstrap/selfhost.hepta')
    require(bootstrap['compiler_source_sha256'] == sha(compiler_source), 'bootstrap source bytes')
    for stage in ('B1', 'B2', 'B3'):
        folder = build / 'bootstrap'
        image = read(folder / (stage + '.image.bin'))
        complete = read(folder / (stage + '.output.bin'))
        receipt = loads(read(folder / (stage + '.receipt.json')))
        require(pin(image) == dict(bytes=673413, sha256=COMPILER), 'fixed-point compiler generation')
        require(read(folder / (stage + '.input.bin')) == compiler_source, 'full compiler input')
        require(len(complete) == 1048576 and complete[:len(image)] == image
                and complete[len(image):] == b'\xa5' * (len(complete) - len(image)), 'full compiler output tail')
        require(receipt['status'] == 'returned' and receipt['source_unchanged'] is True
                and receipt['produced_sha256'] == COMPILER and receipt['output_sha256'] == sha(complete)
                and receipt['result_u64'] == receipt['core_u32'] == len(image)
                and receipt['forbidden_compiler_modules_loaded'] == [], 'actual bootstrap receipt')
    modules = {}
    for name, image_sha in IMAGES.items():
        folder = build / 'modules' / name
        manifest = loads(read(folder / 'manifest.json'))
        source_path = {'audit-store-controller': ROOT / 'native/audit_store_controller.hepta',
                       'audit-native-sync': sync / 'native/audit_sync_boundary.hepta',
                       'audit-controller-callable': ROOT / 'native/audit_controller_callable.hepta'}[name]
        raw_source = read(source_path)
        image = read(folder / 'module.image.bin')
        output = read(folder / 'module.output.bin')
        receipt = loads(read(folder / 'module.receipt.json'))
        expected = report['modules'][name]
        require(expected == dict(manifest='modules/' + name + '/manifest.json',
                                 manifest_pin=pin(read(folder / 'manifest.json')), image=pin(image)),
                'complete composed module binding')
        require(manifest['schema'] == 'hepta.runtime.native-module.v1' and manifest['name'] == name
                and manifest['target'] == 'linux-x86_64'
                and manifest['abi'] == 'hepta.runtime.borrowed-bytes.linux-x86_64.v1'
                and manifest['compiler_commit'] == HEPTA_COMMIT and manifest['compiler_sha256'] == COMPILER
                and manifest['source'] == name + '.hepta' and manifest['image'] == 'module.image.bin'
                and manifest['source_sha256'] == sha(raw_source) and manifest['image_sha256'] == sha(image) == image_sha
                and manifest['standalone'] is None and manifest['buffer_profile'] == 'history.v1',
                'native module identity')
        require(read(folder / (name + '.hepta')) == read(folder / 'module.input.bin') == raw_source,
                'exact compiler module source')
        require(0 < len(image) < 1048576 and len(output) == 1048576 and output[:len(image)] == image
                and output[len(image):] == b'\xa5' * (len(output) - len(image)), 'complete module output and tail')
        require(receipt['status'] == 'returned' and receipt['source_unchanged'] is True
                and receipt['artifact_sha256'] == receipt['image_sha256'] == COMPILER
                and receipt['input_sha256'] == receipt['source_sha256'] == sha(raw_source)
                and receipt['output_sha256'] == sha(output) and receipt['produced_sha256'] == sha(image)
                and receipt['result_u64'] == receipt['core_u32'] == receipt['produced_bytes'] == len(image)
                and receipt['forbidden_compiler_modules_loaded'] == [], 'actual B3 compilation')
        build_receipt = loads(read(folder / 'build.json'))
        require(build_receipt['compile_receipt'] == receipt and build_receipt['compiler_dependency'] == dependency,
                'complete module build receipt')
        modules[name] = pin(image)
    return dict(modules=modules, compiler_files=len(retained), sync_source_manifest_sha256=SYNC_SOURCE)


def check_original():
    reference = ROOT / 'reference'
    owner = read(reference / 'target/src/mcp/runtime/request_audit.rs')
    tests = read(reference / 'target/src/mcp/runtime/request_audit_tests.rs')
    excerpt = read(reference / 'audit_store_lock.rs.txt')
    cases = read(reference / 'audit_store_tests.rs.txt')
    require(pin(owner) == dict(bytes=68414, sha256='b5189f2923153ffa83d0b45a7cdf89873b0f17ebbe6ec1b174c05bab291d73da')
            and pin(tests) == dict(bytes=47327, sha256='a066822705a713929dd2791f1e889f9cf6b7c16567d0d6e71a4c4946b20e14a7'),
            'byte-exact target original files')
    require(pin(excerpt) == dict(bytes=7395, sha256='6b80246ce3c2ff97edb71f6f70d21b692b801648c355427672780d01b5f14b25')
            and owner.count(excerpt) == 1, 'unchanged complete original lock owner')
    require(pin(cases) == dict(bytes=8045, sha256='88aa6e9b82591cab9d3198a820e54d0cc871191d65e99322ca0f660700524d2a')
            and tests.count(cases) == 1, 'unchanged five original actual-thread tests')
    return dict(owner=pin(owner), tests=pin(tests), owner_excerpt=pin(excerpt), test_excerpt=pin(cases))


def check_processes(root, capture, domain):
    rows = loads(read(root / 'processes/processes.json'))
    expected = recipes(capture['source_root'], capture['producer_root'], capture['python'],
                       capture['rust_bin'], capture['compiler_root'], capture['sync_source_root'], domain)
    require(len(rows) == len(expected), 'complete semantic process set')
    pids, named = set(), {}
    for row, (name, argv) in zip(rows, expected, strict=True):
        require(row['name'] == name and row['argv'] == argv and row['cwd'] == capture['source_root']
                and row['timeout_seconds'] == domain['process_budgets'][name], 'actual process command and original budget')
        require(row['exit_code'] == 0 and row['timed_out'] is False and row['completed'] is True
                and 0 < row['elapsed_seconds'] < row['timeout_seconds'], 'successful bounded process completion')
        require(type(row['pid']) is int and row['pid'] > 1 and row['pgid'] == row['pid']
                and row['pid'] != row['parent_pid'] and row['pid'] not in pids, 'actual isolated process identity')
        pids.add(row['pid'])
        named[name] = row['pid']
        require(row['stdin'] is None, 'no hidden semantic stdin')
        for stream in ('stdout', 'stderr'):
            item = row[stream]
            require(item['file'] == name + '.' + stream, 'complete process stream path')
            require(pin(read(root / 'processes' / item['file'])) == {k: item[k] for k in ('bytes', 'sha256')},
                    'full process stream bytes')
    version = read(root / 'processes/compiler-version.stdout').decode()
    require('\nrelease: 1.95.0\n' in version and '\nhost: x86_64-unknown-linux-gnu\n' in version,
            'exact Rust release and host')
    for kind in ('original', 'native'):
        require(read(root / ('threads/' + kind + '-tests')).startswith(b'\x7fELF'), 'retained actual Rust test executable')
        stdout = read(root / ('processes/' + kind + '-threads.stdout')).decode()
        observed = re.findall(r'^test ([a-z0-9_]+) \.\.\. ok$', stdout, re.M)
        count = len(domain[kind + '_cases'])
        require(observed == domain[kind + '_cases'] and
                f'test result: ok. {count} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;' in stdout,
                'all actual original or native thread tests')
        require(read(root / ('processes/' + kind + '-threads.stderr')).count(b'panicked at')
                == domain[kind + '_unwind_observations'], 'all source-owned actual unwind observations')
    return named


def check_emission(root, identity):
    folder = root / 'emission'
    report = loads(read(folder / 'EMISSION.json'))
    composition = loads(read(root / 'build/sync-source/native/audit_sync_boundary.composition.json'))
    expected_image = composition['emitted_instructions']
    count = expected_image['bytes']
    image = read(folder / 'boundary.bin')
    require(pin(image) == expected_image and report['boundary'] == expected_image, 'exact emitted instruction bytes')
    require(report['schema'] == 'hepta.audit-native-sync.emission.v1'
            and report['source_manifest_sha256'] == SYNC_SOURCE and report['native_calls'] == 7
            and report['refusals'] == 6 and report['whole_runtime_replaced'] is False, 'emission binding')
    require(report['module_manifest'] == pin(read(root / 'build/modules/audit-native-sync/manifest.json')),
            'actual emitter module binding')
    good = b'HASYPK01' + (1).to_bytes(8, 'little')
    expected = [('valid', good, count + 64, count), ('empty', b'', count + 64, 0xffffffff),
                ('short', good[:-1], count + 64, 0xffffffff), ('long', good + b'\0', count + 64, 0xffffffff),
                ('magic', b'X' + good[1:], count + 64, 0xffffffff),
                ('version', good[:8] + (2).to_bytes(8, 'little'), count + 64, 0xffffffff),
                ('capacity', good, count - 1, 0xfffffffe)]
    require(len(report['calls']) == 7, 'all emitter calls retained')
    physical = 0
    for row, (name, wire, capacity, result) in zip(report['calls'], expected, strict=True):
        require(row['name'] == name and row['returned'] == result and row['output_capacity'] == capacity
                and row['workspace_capacity'] == 64, 'emitter case domain')
        require(set(row['buffers']) == {'input', 'output-before', 'output-after', 'workspace-before', 'workspace-after'},
                'complete physical emitter buffer set')
        raw = {}
        for label, member in row['buffers'].items():
            require(member['file'] == name + '.' + label + '.bin', 'emitter buffer path')
            raw[label] = read(folder / member['file'])
            require(pin(raw[label]) == {k: member[k] for k in ('bytes', 'sha256')}, 'emitter physical buffer identity')
            physical += len(raw[label])
        require(raw['input'] == wire and raw['output-before'] == b'\xa5' * (capacity + 16)
                and raw['workspace-before'] == raw['workspace-after'] == b'\xa5' * 64 + b'\x5a' * 16,
                'emitter input, guards and untouched workspace')
        require(raw['output-after'] == (image + b'\xa5' * (capacity + 16 - count) if name == 'valid'
                                        else raw['output-before']), 'full emitted output or refusal')
    return dict(image=expected_image, calls=7, refusals=6, physical_bytes=physical)

