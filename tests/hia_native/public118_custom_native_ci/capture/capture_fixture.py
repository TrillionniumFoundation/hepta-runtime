"""Capture the private two-session carrier without implementing a tool.

The carrier selects an already allocated native Session and calls the same HIA
frontend/publisher as the public transport. Its binary headers are observations;
in particular mode=4 is not an OS BrokenPipe. Public stdio is captured separately
by RecordedPublicProcess. Every accepted byte and every complete output byte is
retained, including on a framing or deadline failure.
"""
from pathlib import Path
import importlib.util
import os
import selectors
import struct
import time

_spec = importlib.util.spec_from_file_location('_filesystem_fixture_common', Path(__file__).absolute().with_name('capture_common.py'))
common = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(common)

REQUEST_MAGIC = b'HFSFXQ02'
RESPONSE_MAGIC = b'HFSFXR02'
PUBLIC_MAGIC = b'HFSJPR03'
PUBLIC_SLOT = 34
OBSERVER_SLOT = 33
SEED_SLOT = 23


def request_frame(session, slot, payload):
    common.need(type(session) is int and session in (0, 1), 'private session selector')
    common.need(type(slot) is int and 0 <= slot < (1 << 64), 'private child selector')
    common.need(type(payload) is bytes and len(payload) < (1 << 64), 'complete private input span')
    return REQUEST_MAGIC + struct.pack('<3Q', session, slot, len(payload)) + payload


def response_header(raw, session, slot):
    """Decode only the mechanical carrier. Business status is left untouched."""
    if slot == PUBLIC_SLOT:
        common.need(len(raw) >= 96 and raw[:8] == PUBLIC_MAGIC, 'private frontend response header')
        values = struct.unpack_from('<11Q', raw, 8)
        common.need(values[0] == session and values[1] in (0, 1, 2, 3, 4) and values[2] in (0, 1), 'private frontend response identity/mode')
        common.need(values[-2:] == (0, 0), 'private frontend reserved header')
        if values[1] == 4:
            common.need(values[2] == 1 and values[3:9] == (0,) * 6, 'closed carrier response has native work')
        return {'header_bytes': 96, 'session': session, 'slot': slot, 'mode': values[1],
                'closed': values[2], 'counter_deltas': list(values[3:9])}
    common.need(len(raw) >= 104 and raw[:8] == RESPONSE_MAGIC, 'private child response header')
    values = struct.unpack_from('<12Q', raw, 8)
    common.need(values[:2] == (session, slot), 'private child response identity')
    return {'header_bytes': 104, 'session': session, 'slot': slot, 'native_return': values[2],
            'body_bytes': values[3], 'counter_deltas': list(values[4:10]),
            'workspace_capacity': values[10], 'output_capacity': values[11]}


def decode_response(raw, session, slot):
    head = response_header(raw, session, slot)
    body = raw[head['header_bytes']:]
    if slot == PUBLIC_SLOT:
        if head['mode'] in (1, 2, 3):
            common.need(bool(body) and body.endswith(b'\n') and b'\n' not in body[:-1], 'complete actual public JSON line')
        else:
            common.need(not body, 'silent/closed carrier wrote a public body')
    else:
        common.need(len(body) == head['body_bytes'], 'complete native child output extent')
    return head, body


def cache_seed(entries):
    common.need(type(entries) is list, 'complete cache seed list')
    spans = []
    for entry in entries:
        common.need(set(entry) == {'path_hex', 'content'} and type(entry['content']) is str, 'declared cache seed input')
        path = common.bytes_path(entry['path_hex']); content = entry['content'].encode('utf-8')
        spans.append(struct.pack('<2Q', len(path), len(content)) + path + content)
    payload = struct.pack('<Q', len(spans)) + b''.join(spans)
    return b'HFSSE002' + struct.pack('<5Q', 4, len(payload), 0, 0, 0) + payload


def observer_spans(body):
    """Retain and partition the exact valid extents; do not invent state fields."""
    common.need(len(body) >= 640 and body[:8] == b'HFSOBS02', 'complete native observer header')
    sizes = struct.unpack_from('<7Q', body, 8)
    common.need(sizes[2:] == (64, 256, 256, 0, 0), 'native observer section sizes')
    common.need(len(body) == 640 + sizes[0] + sizes[1], 'native observer complete extent')
    sections = {}; at = 64
    for name, size in zip(('session', 'cache', 'context', 'scope', 'lease'), sizes[:5]):
        sections[name] = body[at:at + size]; at += size
    common.need(at == len(body), 'native observer unclaimed bytes')
    state, cache = sections['session'], sections['cache']
    common.need(len(state) >= 64 and state[:8] == b'HRSWST02', 'native Session state magic')
    common.need(len(state) == 64 + sum(struct.unpack_from('<2Q', state, 8)), 'native Session complete valid extent')
    common.need(len(cache) >= 64 and cache[:8] == b'HVCSTA01', 'native cache state magic')
    common.need(struct.unpack_from('<Q', cache, 8)[0] == 1 and struct.unpack_from('<Q', cache, 16)[0] == len(cache), 'native cache state version/extent')
    count = struct.unpack_from('<Q', cache, 24)[0]
    # Every actual record needs at least two u64 lengths. This checks corrupted
    # observations without imposing a quota on a valid cache or response.
    common.need(count <= (len(cache) - 64) // 16, 'native cache count cannot fit complete records')
    entries = []; keys = set(); at = 64
    for _ in range(count):
        common.need(len(cache) - at >= 16, 'native cache record header')
        n, m = struct.unpack_from('<2Q', cache, at); at += 16
        common.need(n <= len(cache) - at and m <= len(cache) - at - n, 'native cache record spans')
        key, value = cache[at:at + n], cache[at + n:at + n + m]; at += n + m
        common.need(key not in keys, 'native cache repeated canonical key'); keys.add(key)
        key.decode('utf-8'); value.decode('utf-8')
        entries.append((key, value))
    common.need(at == len(cache), 'native cache trailing unclaimed bytes')
    return sections, entries


def state_projection(body):
    """Project documented raw state fields, retaining the full body elsewhere."""
    sections, pairs = observer_spans(body)
    state = sections['session']; root_len, current_len, present, poisoned, applied, initialized, reserved = struct.unpack_from('<7Q', state, 8)
    common.need(present in (0, 1) and poisoned in (0, 1) and applied in (0, 1), 'native Session Boolean fields')
    common.need(initialized == 1 and reserved == 0 and (present or current_len == 0), 'native Session initialized/present state')
    root = state[64:64 + root_len]; current = state[64 + root_len:]
    common.need(len(current) == current_len, 'native Session current path extent')
    return {'root_hex': root.hex(), 'current_hex': current.hex() if present else None,
            'effective_hex': (root if poisoned or not present else current).hex(),
            'poisoned': bool(poisoned), 'session_applied': bool(applied),
            'cache_entries': {key.decode('utf-8'): value.decode('utf-8') for key, value in pairs},
            'section_pins': {name: {'bytes': len(raw), 'sha256': common.sha(raw)} for name, raw in sections.items()}}


class RecordedFixtureProcess(common.RecordedPublicProcess):
    """One synchronous private call at a time, with concurrent pipe draining."""
    def _completed(self):
        minimum = 96 if self.expected_slot == PUBLIC_SLOT else 104
        if len(self.pending) < minimum:
            return None
        head = response_header(self.pending, self.expected_session, self.expected_slot)
        if self.expected_slot == PUBLIC_SLOT:
            if head['mode'] in (1, 2, 3):
                end = self.pending.find(b'\n', max(minimum, self.scan_from))
                if end < 0:
                    self.scan_from = len(self.pending)
                    return None
                extent = end + 1
            else:
                extent = minimum
        else:
            extent = minimum + head['body_bytes']
            if len(self.pending) < extent:
                return None
        raw = bytes(self.pending[:extent]); del self.pending[:extent]; self.scan_from = 0
        decode_response(raw, self.expected_session, self.expected_slot)
        return raw

    def _read(self, ready, key, replies):
        try:
            raw = os.read(key.fd, 65536)
        except BlockingIOError:
            return
        if not raw:
            self.eof[key.data] = True; ready.unregister(key.fileobj); return
        self.streams[key.data].write(raw)
        if key.data == 'stdout':
            self.pending.extend(raw)
            complete = self._completed()
            if complete is not None:
                replies.append(complete)
                common.need(len(replies) == 1 and not self.pending, 'private carrier unsolicited response bytes')

    def call(self, session, slot, payload):
        common.need(not self.closed and not self.pending, 'private call after close/unclaimed response')
        request = request_frame(session, slot, payload)
        self.expected_session, self.expected_slot = session, slot
        self.scan_from = 0
        begin = time.monotonic(); attempted_at = self.streams['attempted-stdin'].size
        stdin_at = self.streams['stdin'].size; stdout_at = self.streams['stdout'].size; stderr_at = self.streams['stderr'].size
        self.streams['attempted-stdin'].write(request)
        written = 0; replies = []; error = None; timed_out = False; transport = None
        try:
            with selectors.DefaultSelector() as ready:
                ready.register(self.process.stdin, selectors.EVENT_WRITE, 'stdin')
                for name in ('stdout', 'stderr'):
                    if not self.eof[name]: ready.register(getattr(self.process, name), selectors.EVENT_READ, name)
                while written < len(request) or not replies:
                    remaining = 60 - (time.monotonic() - begin)
                    if remaining <= 0:
                        timed_out = True; raise TimeoutError('actual private exchange exceeded 60 seconds')
                    events = ready.select(remaining)
                    if not events:
                        timed_out = True; raise TimeoutError('actual private exchange exceeded 60 seconds')
                    events.sort(key=lambda item: item[0].data == 'stdin')
                    for key, _ in events:
                        if key.data != 'stdin':
                            self._read(ready, key, replies); continue
                        try:
                            count = os.write(key.fd, memoryview(request)[written:written + 65536])
                        except BlockingIOError:
                            continue
                        common.need(count > 0, 'private stdin made no progress')
                        self.streams['stdin'].write(memoryview(request)[written:written + count]); written += count
                        if written == len(request): ready.unregister(self.process.stdin)
                    if self.eof['stdout'] and not replies:
                        raise EOFError('actual private carrier ended before its full response')
                common.need(len(replies) == 1 and written == len(request), 'incomplete actual private exchange')
                transport = 'private-frame'
        except BaseException as failure:
            error = {'type': type(failure).__name__, 'message': str(failure), 'errno': getattr(failure, 'errno', None)}
            transport = 'execution-failure'; raise
        finally:
            response = replies[0] if len(replies) == 1 else b''
            head, body = decode_response(response, session, slot) if response else (None, b'')
            record = {'index': len(self.exchanges), 'session': session, 'slot': slot, 'deadline_seconds': 60,
                'elapsed_seconds': time.monotonic() - begin, 'timed_out': timed_out, 'transport': transport, 'error': error,
                'attempted_input': {'offset': attempted_at, 'bytes': len(request), 'sha256': common.sha(request)},
                'accepted_input': {'offset': stdin_at, 'bytes': written, 'sha256': common.sha(request[:written])},
                'stdout_range': {'offset': stdout_at, 'bytes': self.streams['stdout'].size - stdout_at},
                'stderr_range': {'offset': stderr_at, 'bytes': self.streams['stderr'].size - stderr_at},
                'response': None if not response else {'offset': stdout_at, 'bytes': len(response), 'sha256': common.sha(response)},
                'body': None if head is None else {'offset': stdout_at + head['header_bytes'], 'bytes': len(body), 'sha256': common.sha(body)},
                'header': head, 'stdout_eof': self.eof['stdout'], 'stderr_eof': self.eof['stderr']}
            self._record_exchange(record)
        return record, body

    def public(self, session, full_wire):
        common.need(type(full_wire) is bytes and full_wire.endswith(b'\n'), 'original complete public input wire')
        # The fixture provides framing. Preserve every original JSON byte and
        # remove only its final transport LF, including duplicate object keys.
        return self.call(session, PUBLIC_SLOT, full_wire[:-1])

    def observe(self, session):
        record, body = self.call(session, OBSERVER_SLOT, b'')
        common.need(record['header']['native_return'] == 0, 'actual observer return')
        sections, entries = observer_spans(body)
        return record, body, sections, entries

    def seed(self, session, entries):
        record, body = self.call(session, SEED_SLOT, cache_seed(entries))
        common.need(record['header']['native_return'] == 32 and body == b'HRCFGM01' + bytes(24), 'actual scope/cache seed completion')
        return record, body
