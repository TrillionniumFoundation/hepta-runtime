"""Qualification transport: native state/pure owners and labelled synthetic I/O."""
from __future__ import annotations
import ctypes
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

CALL, WAIT, GROW, GROW_OUTPUT = 0xffffffe0, 0xffffffe1, 0xffffffef, 0xffffffee
INVALID, CAPACITY, STATE, CANCELED = 0xffffffff, 0xfffffffe, 0xfffffff9, 0xfffffff7
Q = lambda *values: struct.pack('<' + 'Q' * len(values), *values)
sha = lambda value: hashlib.sha256(value).hexdigest()


def frame(magic, words, body=b''):
    return magic + Q(*words) + body


class Buffer:
    def __init__(self, size, fill=0, guard=0x5a):
        self.size, self.guard = size, guard
        self.raw = ctypes.create_string_buffer(size + 16)
        self.address = ctypes.addressof(self.raw)
        ctypes.memset(self.address, fill, size)
        ctypes.memset(self.address + size, guard, 16)

    def read(self, at, count):
        assert 0 <= at <= self.size and 0 <= count <= self.size - at
        return ctypes.string_at(self.address + at, count)

    def write(self, at, value):
        assert 0 <= at <= self.size and len(value) <= self.size - at
        ctypes.memmove(self.address + at, value, len(value))

    def word(self, at):
        return struct.unpack('<Q', self.read(at, 8))[0]

    def put(self, at, value):
        self.write(at, Q(value))

    def check(self):
        assert ctypes.string_at(self.address + self.size, 16) == bytes([self.guard]) * 16

    def grow(self, size):
        assert size > self.size
        replacement = Buffer(size, guard=self.guard)
        ctypes.memmove(replacement.address, self.address, self.size)
        return replacement


def module_at(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class NativeWorld:
    """Keeps actual native locks/history/cache across calls; I/O is a fixture."""

    def __init__(self, registry, reference, source_root, record=None, controller_source=None, profiles_dir=None, render_source=None):
        self.reference, self.source_root = Path(reference), Path(source_root)
        sys.path.insert(0, str(self.reference / 'scripts'))
        sys.path.insert(0, str(self.reference / 'tests/hia_native'))
        if profiles_dir is not None:
            sys.path.insert(0, str(Path(profiles_dir).resolve(strict=True)))
        from hia_native_loader import NativeModule
        if profiles_dir is not None:
            NativeModule = module_at(Path(profiles_dir) / 'hia_native_loader.py',
                                     '_batch_write_private_loader').NativeModule
        from batch_plan_harness import NativePlan
        from batch_apply_harness import NativeApply
        registry_path = Path(registry).resolve(strict=True)
        registry_doc = json.loads(registry_path.read_bytes())
        names = {0:'batch_write',1:'file_lock_service',3:'history',5:'view_cache',7:'file_lock_state',8:'editable_content',9:'batch_plan',10:'line_endpoint',11:'line_verify',12:'batch_apply',13:'batch_render'}
        self.registry = {target: registry_path.parent / registry_doc[name]['manifest'] for target,name in names.items()}
        self.modules, self.loaded = {}, []
        self.counts = {'native_root_calls': 0, 'native_leaf_calls': 0, 'requests': 0,
                       'synthetic_filesystem_completions': 0, 'synthetic_canonical_completions': 0,
                       'buffer_growths': 0, 'actual_filesystem_effects': 0}
        paths = {0: Path(controller_source) if controller_source else source_root / 'native/batch_write.hepta',
                 13: Path(render_source) if render_source else source_root / 'native/batch_render.hepta'}
        paths.update({target: self.reference / 'native' / (name + '.hepta') for target, name in
                      [(1, 'file_lock_service'), (3, 'history'), (5, 'view_cache'),
                       (7, 'file_lock_state'), (8, 'editable_content'), (9, 'batch_plan'),
                       (10, 'line_endpoint'), (11, 'line_verify'), (12, 'batch_apply')]})
        for target, path in self.registry.items():
            raw = path.read_bytes()
            manifest = json.loads(raw)
            assert manifest['source_sha256'] == sha(paths[target].read_bytes())
            assert manifest['compiler_commit'] == 'd3e2c90173cf733e42b299d0c4274df4b593a12f'
            assert manifest['compiler_sha256'] == 'bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'
            expected_profile = 'batch-write.v1' if target in (0, 13) else 'batch-plan.v1'
            assert manifest['buffer_profile'] == expected_profile
            if target not in (9, 10, 11, 12):
                self.modules[target] = NativeModule(path, manifest_sha256=sha(raw))
            self.loaded.append({'id': target, 'manifest_sha256': sha(raw),
                                'source_sha256': manifest['source_sha256'],
                                'image_sha256': manifest['image_sha256']})
        self.plan = NativePlan({1: self.registry[9], 2: self.registry[10], 3: self.registry[11]},
                               source_root=self.reference, reference_root=self.reference)
        self.apply = NativeApply(self.registry[12], self.registry[8], source_root=self.reference,
                                  reference_root=self.reference)
        self.record = record
        self.state, self.history, self.cache = Buffer(65536), Buffer(65536), Buffer(65536)
        self.invoke(7, frame(b'HRFLOCK1', [0] * 7), self.state)
        self.invoke(3, frame(b'HHISTQ01', [0] * 7), self.history)
        self.invoke(5, frame(b'HVCACH01', [0] * 5), self.cache)
        self.events, self.keys, self.io = [], [], {}
        self.key = b'local:/fixture'
        self.pending_action = None
        self.fault = None
        self.written = None

    def close(self):
        self.plan.close()
        self.apply.close()
        for module in self.modules.values():
            module.close()

    def observe(self, target, wire, code, output, before, work):
        if self.record:
            self.record({'target': target, 'input_hex': wire.hex(), 'code': code,
                         'output_capacity': output.size,
                         'output_hex': output.read(0, code).hex() if code < 0xffff0000 else '',
                         'output_sha256': sha(output.read(0, output.size)),
                         'workspace_bytes': work.size,
                         'workspace_before_sha256': sha(before),
                         'workspace_after_sha256': sha(work.read(0, work.size)),
                         'workspace_prefix_hex': work.read(0, min(work.size, 1024)).hex()})

    def invoke(self, target, wire, work=None, capacity=None):
        source = Buffer(len(wire), guard=0x7c)
        source.write(0, wire)
        amount = max(65536, 4 * len(wire) + 4096)
        work = work if work is not None else Buffer(amount)
        capacity = capacity if capacity is not None else max(4096, 3 * len(wire) + 4096)
        for _ in range(20):
            output = Buffer(capacity, fill=0xa5, guard=0xa5)
            before = work.read(0, work.size)
            code = self.modules[target]._entry(source.raw, len(wire), output.raw, output.size,
                                               work.raw, work.size)
            self.counts['native_leaf_calls'] += 1
            self.observe(target, wire, code, output, before, work)
            source.check(); output.check(); work.check()
            assert source.read(0, len(wire)) == wire
            if code == CAPACITY:
                assert output.read(0, capacity) == b'\xa5' * capacity
                assert work.read(0, work.size) == before, (target, 'stateful capacity mutation')
                capacity *= 2
                work = work.grow(work.size * 2)
                self.counts['buffer_growths'] += 1
                if target == 7: self.state = work
                if target == 3: self.history = work
                if target == 5: self.cache = work
                continue
            if code >= 0xffff0000:
                assert output.read(0, capacity) == b'\xa5' * capacity
                return code, b''
            assert code <= output.size
            assert output.read(code, output.size - code) == b'\xa5' * (output.size - code)
            return code, output.read(0, code)
        raise AssertionError('native state/leaf growth did not converge')

    def key_result(self):
        key = self.keys.pop(0) if self.keys else self.key
        self.events.append(('canonical', key.hex()))
        self.counts['synthetic_canonical_completions'] += 1
        return frame(b'HRLKY001', [1, len(key), 0], key)

    def lock(self, wire):
        work, output, source = Buffer(max(131072, len(wire) + 512)), Buffer(64, fill=0xa5, guard=0xa5), Buffer(len(wire), guard=0x7c)
        source.write(0, wire)
        for _ in range(5):
            before = work.read(0, work.size)
            code = self.modules[1]._entry(source.raw, len(wire), output.raw, 64, work.raw, work.size)
            self.counts['native_leaf_calls'] += 1
            self.observe(1, wire, code, output, before, work)
            source.check(); output.check(); work.check()
            assert source.read(0, len(wire)) == wire
            if code != 0xfffffff0:
                assert code == 64, code
                return output.read(0, code)
            child, at, count, reply = (work.word(n) for n in (80, 88, 96, 104))
            if child == 1:
                data = self.key_result()
            else:
                assert child == 2
                code, data = self.invoke(7, work.read(at, count), self.state)
                assert code == 64
            work.write(reply, data)
            work.put(120, len(data)); work.put(128, len(data)); work.put(136, 1)
        raise AssertionError('native lock service continuation exceeded contract')

    def pure(self, target, wire):
        capacity = max(4096, 3 * len(wire) + 4096)
        for _ in range(20):
            owner = self.plan if target == 9 else self.apply
            before = dict(owner.counts)
            result = owner.invoke(wire, capacity)
            total = sum(owner.counts[k] - before[k] for k in before if k != 'requests')
            self.counts['native_leaf_calls'] += total
            if self.record:
                self.record({'target': target, 'input_hex': wire.hex(),
                             'nested_actual_calls': total,
                             'result': {k: v for k, v in result.items() if k not in ('output', 'prefix')},
                             'output_hex': result['output'].hex()})
            if result['code'] == CAPACITY:
                capacity *= 2
                self.counts['buffer_growths'] += 1
                continue
            return result['code'] if result['code'] >= 0xffff0000 else result['output']
        raise AssertionError('native pure-owner capacity did not converge')

    def child(self, target, wire):
        operation = struct.unpack_from('<Q', wire, 8)[0]
        self.events.append(('child', target, operation))
        if target == 1: return self.lock(wire)
        if target == 2: return self.key_result()
        if target == 3: return self.invoke(3, wire, self.history)[1]
        if target == 5: return self.invoke(5, wire, self.cache)[1]
        if target in (8, 13):
            code, data = self.invoke(target, wire)
            return code if code >= 0xffff0000 else data
        if target in (9, 12): return self.pure(target, wire)
        self.counts['synthetic_filesystem_completions'] += 1
        if target == 6:
            if operation == 1:
                sequence = self.io.get('exists_sequence')
                value = sequence.pop(0) if sequence else self.io.get('exists', 1)
                return frame(b'HFLRO001', [1, 0, 8], Q(value))
            assert operation == 2
            sequence = self.io.get('read_sequence')
            value = sequence.pop(0) if sequence else self.io.get('read_error', self.io.get('content', b'before'))
            if isinstance(value, int): return value
            status = int('read_error' in self.io)
            if isinstance(value, tuple): status, value = value
            return frame(b'HFLRO001', [2, status, len(value)], value)
        assert target == 4 and operation == 1 and wire[:8] == b'HRAWI001'
        plen, amount = struct.unpack_from('<QQ', wire, 16)
        assert amount == len(wire) - 64 - plen
        value = wire[64 + plen:]
        self.written = value
        if 'expected_write' in self.io: assert value == self.io['expected_write']
        if self.io.get('write_cancel'): return CANCELED
        if 'write_error' in self.io:
            value = self.io['write_error']
            return frame(b'HRAWR001', [1, 4, len(value)], value)
        return frame(b'HRAWR001', [0, 0, 0])

    def root(self, wire, *, cancel=0, capacity=32, workspace=8192, fault=None):
        source = Buffer(len(wire), guard=0x7c); source.write(0, wire)
        output, work = Buffer(capacity, fill=0xa5, guard=0xa5), Buffer(workspace)
        if workspace >= 120: work.put(112, cancel)
        start = len(self.events)
        for step in range(260):
            before = work.read(0, work.size)
            code = self.modules[0]._entry(source.raw, len(wire), output.raw, output.size, work.raw, work.size)
            self.counts['native_root_calls'] += 1
            self.observe(0, wire, code, output, before, work)
            source.check(); output.check(); work.check()
            assert source.read(0, len(wire)) == wire
            if code in (GROW, GROW_OUTPUT):
                size = work.word(120)
                if code == GROW:
                    assert size > work.size
                    work = work.grow(size)
                else:
                    assert size > output.size
                    output = Buffer(size, fill=0xa5, guard=0xa5)
                self.counts['buffer_growths'] += 1
                continue
            if code == WAIT:
                assert self.pending_action is not None
                action, self.pending_action = self.pending_action, None
                action(work)
                work.put(328, 1)
                continue
            if code == CALL:
                effect = struct.unpack('<16Q', work.read(256, 128))
                assert effect[0] == int.from_bytes(b'HFBTCALL', 'little') and effect[7:] == (0,) * 9
                target, at, count, reply, limit = effect[2:7]
                data = self.child(target, work.read(at, count))
                if isinstance(data, int):
                    work.put(312, data); work.put(320, 0)
                else:
                    assert len(data) <= limit
                    if reply + len(data) > work.size:
                        work = work.grow(reply + len(data))
                        self.counts['buffer_growths'] += 1
                    work.write(reply, data)
                    work.put(312, len(data)); work.put(320, len(data))
                work.put(328, 1)
                if fault: fault(work, target, data)
                continue
            self.counts['requests'] += 1
            if code >= 0xffff0000:
                assert output.read(0, output.size) == b'\xa5' * output.size
                return code, b'', self.events[start:], work
            assert code <= output.size
            data = output.read(0, code)
            assert output.read(code, output.size - code) == b'\xa5' * (output.size - code)
            assert data[:8] == b'HFBWR001' and struct.unpack_from('<Q', data, 16)[0] == len(data) - 32
            assert work.word(0) == 201 and work.read(8, work.size - 8) == bytes(work.size - 8)
            return code, data, self.events[start:], work
        raise AssertionError('native batch body continuation exceeded envelope')
