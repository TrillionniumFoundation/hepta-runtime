"""Frozen logical lock traces; Python supplies expectations, never runtime policy."""
from pathlib import Path
import gzip
import hashlib
import json
import struct

MAX = (1 << 64) - 1
INVALID, CAPACITY, STATE_ERROR = 0xffffffff, 0xfffffffe, 0xfffffff9


def frame(op, ticket=0, *, access=0, deadline=None, now=0, after=0, observation=0, thread=0):
    values = [op, ticket, access, int(deadline is not None),
              0 if deadline is None else deadline & MAX, 0 if deadline is None else deadline >> 64,
              now & MAX, now >> 64, after & MAX, after >> 64, observation, thread, 0, 0, 0]
    return struct.pack('<8s15Q', b'HAUDLK01', *values)


class Model:
    """Logical original queue/guard outcomes, with separate Python integer clocks."""
    def __init__(self):
        self.next = 0
        self.entries = []
        self.writer = None
        self.readers = 0
        self.reader_poison = self.queue_poison = self.inner_poison = False
        self.closed = False

    def state(self):
        if self.closed:
            return bytes(128)
        head = struct.pack('<8s15Q', b'HAUDLS01', self.next, int(self.writer is not None), self.readers,
                           int(self.reader_poison), int(self.queue_poison), int(self.inner_poison),
                           len(self.entries), 128 + 80 * len(self.entries),
                           MAX if self.writer is None else self.writer, 0, 0, 0, 0, 0, 0)
        return head + b''.join(struct.pack('<10Q', row['ticket'], row['access'], row['phase'],
            int(row['deadline'] is not None), 0 if row['deadline'] is None else row['deadline'] & MAX,
            0 if row['deadline'] is None else row['deadline'] >> 64, row['thread'], 0, 0, 0)
            for row in self.entries)

    @staticmethod
    def expired(deadline, now):
        return deadline is not None and now >= deadline

    def release(self, row, panicking=False):
        effect = 0
        if row['access']:
            self.reader_poison |= panicking
            self.readers -= 1
        else:
            effect = int(row['phase'] == 4)
            self.inner_poison |= panicking and bool(effect)
            self.writer = None
        self.entries.remove(row)
        return effect

    def apply(self, op, ticket=0, *, access=0, deadline=None, now=0, after=0, observation=0, thread=0):
        result = phase = notify = effect = 0
        if op == 1:
            if self.expired(deadline, now):
                result = 5
            elif self.queue_poison:
                result = 6
            elif self.expired(deadline, after):
                result = 5
            elif self.reader_poison or (access and self.inner_poison) or self.next == MAX:
                result = 6
            else:
                ticket = self.next
                self.next += 1
                self.entries.append(dict(ticket=ticket, access=access, phase=1, deadline=deadline, thread=thread))
                result = phase = 1
        elif 2 <= op <= 6:
            row = next(row for row in self.entries if row['ticket'] == ticket)
            assert row['thread'] == thread
            if op == 2:
                assert row['phase'] == 1
                if observation or self.queue_poison:
                    self.queue_poison = True
                    result = 6
                elif self.expired(row['deadline'], now):
                    result = 5
                elif self.reader_poison or (row['access'] and self.inner_poison):
                    result = 6
                if result:
                    self.entries.remove(row)
                    notify = 1
                else:
                    first = next(item for item in self.entries if item['phase'] == 1)
                    if self.writer is not None or first is not row or (not row['access'] and self.readers):
                        result = phase = 1
                    else:
                        row['phase'] = 2
                        phase = result = 2
                        if row['access']:
                            self.readers += 1
                            notify = 1
                        else:
                            self.writer = ticket
            elif op == 3:
                assert row['phase'] == 2
                if self.expired(row['deadline'], now):
                    self.release(row)
                    result, notify = 5, 1
                elif row['access']:
                    row['phase'], phase, result = 4, 4, 3
                else:
                    row['phase'], phase, result = 3, 3, 4
            elif op == 4:
                assert row['phase'] == 3 and row['access'] == 0
                if observation:
                    self.inner_poison |= observation == 1
                    self.release(row)
                    result, notify, effect = 6, 1, int(observation == 1)
                else:
                    assert not self.inner_poison
                    row['phase'] = 4
                    if self.expired(row['deadline'], now):
                        effect = self.release(row)
                        result, notify = 5, 1
                    else:
                        result, phase = 3, 4
            elif op == 5:
                assert row['phase'] == 4 and row['access'] == 1
                result = 6 if self.queue_poison or self.reader_poison or self.inner_poison else (
                    5 if self.expired(row['deadline'], now) else 0)
                self.release(row)
                notify = 1
            else:
                assert row['phase'] >= 2
                effect = self.release(row, bool(observation))
                notify = 1
        elif op == 7:
            if observation == 1:
                self.queue_poison = True
            else:
                self.inner_poison = True
        elif op == 9:
            assert not self.entries
        else:
            assert op in (0, 8)
        response = struct.pack('<8s15Q', b'HAUDLR01', op, result, ticket, phase, notify, self.next,
                               int(self.writer is not None), self.readers, int(self.reader_poison),
                               int(self.queue_poison), int(self.inner_poison),
                               sum(row['phase'] == 1 for row in self.entries), len(self.entries),
                               128 + 80 * len(self.entries), effect)
        if op == 9:
            self.closed = True
        return response


class Scenario:
    def __init__(self, name, workspace=0):
        self.name, self.workspace = name, workspace
        self.model = Model()
        self.rows = []
        self.call(0)

    def call(self, op, ticket=0, **kwargs):
        request = frame(op, ticket, **kwargs)
        response = self.model.apply(op, ticket, **kwargs)
        self.rows.append(dict(request_hex=request.hex(), result=128, output_hex=response.hex(),
                              state_hex=self.model.state().hex()))
        return struct.unpack_from('<Q', response, 24)[0]

    def begin(self, access=0, deadline=None, thread=None, now=1):
        return self.call(1, access=access, deadline=deadline, thread=thread or self.model.next + 1,
                         now=now, after=now)

    def held(self, access=0, deadline=None, now=1):
        ticket = self.begin(access, deadline, now=now)
        self.advance(ticket, now)
        return ticket

    def advance(self, ticket, now=1, inner=0):
        row = next(row for row in self.model.entries if row['ticket'] == ticket)
        thread = row['thread']
        self.call(2, ticket, thread=thread, now=now)
        self.call(3, ticket, thread=thread, now=now)
        if not row['access']:
            self.call(4, ticket, thread=thread, now=now if not inner else 0, observation=inner)

    def step(self, op, ticket, **kwargs):
        row = next(row for row in self.model.entries if row['ticket'] == ticket)
        self.call(op, ticket, thread=row['thread'], **kwargs)

    def end(self):
        self.call(8)
        self.call(9)
        return dict(name=self.name, initial_workspace=self.workspace, rows=self.rows)


def scenarios():
    result = []
    for count in (1, 2, 3, 32, 65, 257):
        case = Scenario('adjacent-readers-' + str(count), workspace=0 if count & 1 else 128)
        readers = [case.held(1, 1000) for _ in range(count)]
        for ticket in readers[::2] + readers[1::2]:
            case.step(5, ticket, now=2)
        result.append(case.end())
    case = Scenario('writer-reader-writer-reader-fifo')
    writer = case.held()
    reader = case.begin(1, 100)
    writer2 = case.begin()
    reader2 = case.begin(1, 100)
    for ticket in (reader, writer2, reader2):
        case.step(2, ticket, now=2)
    case.step(6, writer)
    case.advance(reader, 2)
    for ticket in (writer2, reader2):
        case.step(2, ticket, now=2)
    case.step(5, reader, now=3)
    case.advance(writer2, 3)
    case.step(2, reader2, now=3)
    case.step(6, writer2)
    case.advance(reader2, 4)
    case.step(5, reader2, now=4)
    result.append(case.end())
    for position in range(3):
        case = Scenario('cancelled-waiter-position-' + str(position))
        held = case.held()
        waiting = [case.begin(1, 10) if i == position else case.begin() for i in range(3)]
        for ticket in waiting:
            case.step(2, ticket, now=2)
        case.step(2, waiting[position], now=10)
        case.step(6, held)
        for i, ticket in enumerate(waiting):
            if i != position:
                case.advance(ticket, 11)
                case.step(6, ticket)
        result.append(case.end())
    for boundary in (2, (1 << 64) - 1, 1 << 64, (1 << 80) + 7, (1 << 127) + 13):
        for access in (0, 1):
            for phase in ('prequeue', 'postqueue', 'loop', 'post-admission', 'held'):
                case = Scenario('deadline-%s-%d-%d' % (phase, access, boundary))
                if phase in ('prequeue', 'postqueue'):
                    case.call(1, access=access, deadline=boundary, now=boundary if phase == 'prequeue' else boundary-1,
                              after=boundary, thread=1)
                else:
                    ticket = case.begin(access, boundary, now=boundary-1)
                    case.step(2, ticket, now=boundary if phase == 'loop' else boundary-1)
                    if phase != 'loop':
                        case.step(3, ticket, now=boundary if phase == 'post-admission' else boundary-1)
                    if phase == 'held':
                        if access:
                            case.call(8)
                            case.step(5, ticket, now=boundary)
                        else:
                            case.step(4, ticket, now=boundary)
                result.append(case.end())
    for poison in (1, 2):
        case = Scenario('mutex-poison-%d-finish-and-admission' % poison)
        reader = case.held(1, 10)
        case.call(7, observation=poison)
        case.step(5, reader, now=10)
        case.call(1, access=1, deadline=20, now=1, after=1, thread=8)
        if poison == 1:
            case.call(1, now=1, after=1, thread=9)
        else:
            writer = case.begin()
            case.advance(writer, inner=1)
        case.call(1, access=1, deadline=1, now=1, after=1, thread=10)
        result.append(case.end())
    case = Scenario('shared-panic-retains-finished-boundary')
    completed = case.held(1, 100)
    case.step(5, completed, now=2)
    peer = case.held(1, 100)
    panic = case.held(1, 100)
    writer = case.begin()
    case.step(2, writer, now=2)
    case.step(6, panic, observation=1)
    case.step(5, peer, now=2)
    case.step(2, writer, now=2)
    case.call(1, access=1, deadline=100, now=2, after=2, thread=9)
    case.call(1, now=2, after=2, thread=10)
    result.append(case.end())
    for inner in (1, 2):
        case = Scenario('actual-inner-outcome-' + str(inner))
        ticket = case.begin()
        case.advance(ticket, inner=inner)
        result.append(case.end())
    for kind in ('poisoned-wake', 'deadline-before-reader-poison', 'writer-panic'):
        case = Scenario(kind)
        writer = case.held()
        reader = case.begin(1, 10)
        case.step(2, reader, now=2)
        if kind == 'poisoned-wake':
            case.step(2, reader, now=10, observation=1)
            case.step(6, writer)
        elif kind == 'writer-panic':
            case.step(6, writer, observation=1)
            case.step(2, reader, now=2)
        else:
            case.step(6, writer)
            case.advance(reader, 2)
            second = case.held(1, 10)
            waiting = case.begin(1, 10)
            case.step(6, reader, observation=1)
            case.step(2, waiting, now=10)
            case.step(5, second, now=10)
        result.append(case.end())
    for exhausted in (MAX-1, MAX):
        case = Scenario('checked-ticket-' + str(exhausted))
        case.model.next = exhausted
        case.rows.append(dict(workspace_patch=dict(offset=8, data_hex=struct.pack('<Q', exhausted).hex()),
                              source='original-private-queue-next-ticket-fault-boundary'))
        case.call(1, now=1, after=1, thread=1)
        if exhausted == MAX-1:
            case.advance(exhausted)
            case.step(6, exhausted)
        case.call(1, now=1, after=1, thread=2)
        result.append(case.end())
    return result


def domain():
    rows = scenarios()
    return dict(schema='hepta.runtime.audit-store-queue.domain.v1', scenarios=rows,
                scenario_count=len(rows), semantic_calls=sum('request_hex' in r for s in rows for r in s['rows']),
                exact_target='d3d75c30719db966b004756f610007a7c723729e',
                private_model_only=True, original_reference_comparison_pending=True,
                native_mutex_and_condvar_execution_pending=True, whole_runtime_replaced=False)


def controls():
    model = Model()
    model.apply(0)
    empty = model.state()
    model.apply(1, access=1, deadline=100, now=1, after=1, thread=1)
    queued = model.state()
    model.apply(2, thread=1, now=1)
    model.apply(3, thread=1, now=1)
    shared = model.state()
    rows = []
    def add(name, wire, state=empty, expected=INVALID, capacity=128):
        rows.append(dict(name=name, request_hex=wire.hex(), state_hex=state.hex(),
                         output_capacity=capacity, expected_result=expected,
                         entire_output_and_workspace_unchanged=True))
    ordinary = frame(8)
    for size in (0, 1, 7, 8, 63, 127):
        add('short-frame-' + str(size), ordinary[:size])
    add('extra-frame-byte', ordinary + b'\0')
    add('wrong-magic', b'X' + ordinary[1:])
    add('unknown-operation', frame(10))
    for offset in (16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120):
        changed = bytearray(ordinary)
        struct.pack_into('<Q', changed, offset, 1)
        add('unused-snapshot-word-' + str(offset), bytes(changed))
    add('missing-thread', frame(1, now=1, after=1))
    add('shared-without-deadline', frame(1, access=1, now=1, after=1, thread=1))
    add('retrograde-clock', frame(1, now=2, after=1, thread=1))
    add('invalid-access', frame(1, access=2, now=1, after=1, thread=1))
    add('invalid-inner-outcome', frame(4, observation=3, thread=1))
    add('invalid-drop-panic', frame(6, observation=2, thread=1))
    add('failure-inner-with-clock', frame(4, observation=1, now=1, thread=1))
    add('invalid-poison', frame(7, observation=3))
    for cap in (0, 1, 31, 63, 127):
        add('short-output-' + str(cap), ordinary, expected=CAPACITY, capacity=cap)
    add('invalid-frame-before-output-capacity', ordinary[:-1], expected=INVALID, capacity=0)
    for length in (0, 1, 7, 127):
        add('short-state-' + str(length), ordinary, state=bytes(length), expected=STATE_ERROR)
    add('uninitialized-state', ordinary, state=bytes(128), expected=STATE_ERROR)
    for offset, value in ((0,0),(16,2),(32,2),(40,2),(48,2),(56,MAX),(64,127),(72,0),(80,1),(120,1)):
        changed = bytearray(empty)
        struct.pack_into('<Q', changed, offset, value)
        add('malformed-state-word-' + str(offset), ordinary, bytes(changed), STATE_ERROR)
    for offset, value in ((128,MAX),(136,2),(144,5),(152,0),(176,0),(184,1),(192,1),(200,1)):
        changed = bytearray(shared)
        struct.pack_into('<Q', changed, offset, value)
        add('malformed-live-entry-' + str(offset), ordinary, bytes(changed), STATE_ERROR)
    add('wrong-thread', frame(5, thread=2, now=1), shared, STATE_ERROR)
    add('unissued-ticket', frame(5, ticket=1, thread=1, now=1), shared, STATE_ERROR)
    add('double-poll-held', frame(2, thread=1, now=1), shared, STATE_ERROR)
    add('inner-for-shared', frame(4, thread=1, now=1), shared, STATE_ERROR)
    add('drop-queued', frame(6, thread=1), queued, STATE_ERROR)
    add('finish-queued', frame(5, thread=1, now=1), queued, STATE_ERROR)
    add('shutdown-live-custody', frame(9), shared, STATE_ERROR)
    add('second-initialize', frame(0), empty, STATE_ERROR)
    return rows


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def index():
    value = domain()
    raw = encoded(value)
    private = controls()
    return dict(schema='hepta.runtime.audit-store-queue.frozen-domain.v1',
                complete_domain=dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()),
                scenario_count=value['scenario_count'], semantic_calls=value['semantic_calls'],
                scenarios=[dict(name=s['name'], rows=len(s['rows']),
                                bytes=len(encoded(s)), sha256=hashlib.sha256(encoded(s)).hexdigest())
                           for s in value['scenarios']],
                private_controls=dict(cases=len(private), bytes=len(encoded(private)),
                                      sha256=hashlib.sha256(encoded(private)).hexdigest()),
                original_reference_comparison_pending=True, concurrent_native_lock_qualified=False,
                source_generator='cases.py', whole_runtime_replaced=False)


if __name__ == '__main__':
    value = domain()
    raw = encoded(value)
    output = Path(__file__).resolve().parent.parent / 'authoring-domain.json.gz'
    packed = gzip.compress(raw, compresslevel=9, mtime=0)
    output.write_bytes(packed)
    assert gzip.decompress(output.read_bytes()) == raw
    path = Path(__file__).with_name('DOMAIN.json')
    path.write_bytes(encoded(index()))
    print(json.dumps(dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                         scenarios=value['scenario_count'], semantic_calls=value['semantic_calls'])))
