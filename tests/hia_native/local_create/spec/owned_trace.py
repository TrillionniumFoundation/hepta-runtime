"""Add Local spec path observations to the frozen owned-child tracer.

The underlying fork/ptrace admission, signal control, stdout visibility, write
payload custody and reap mechanism are reused byte-for-byte. This extension
observes only its already owned child and those reported descendants.
"""
from pathlib import Path
import hashlib
import importlib.util
import os
import struct

LEAF_TRACER_SHA = 'd40af1d2b8dee7990b19669e8dd32db72b6cf146277c2f937e91830a62562b42'


def descriptor(word):
    value = word & 0xffffffff
    return value - (1 << 32) if value & (1 << 31) else value


def load_leaf(path):
    path = Path(path).resolve(strict=True)
    assert hashlib.sha256(path.read_bytes()).hexdigest() == LEAF_TRACER_SHA
    spec = importlib.util.spec_from_file_location('frozen_owned_create_trace', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def trace_type(leaf):
    class SpecTrace(leaf.Trace):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.spec_active = self.mode == 'native'
            self.spec_calls = {'metadata': 0, 'mkdir': 0, 'readlink': 0}
            self.native_child_sequence = 0
            self.native_child = None

        def observe_marker(self, pid, raw):
            event = super().observe_marker(pid, raw)
            if event is not None and event.get('owner') == 'rust':
                if event['event'] == 1:
                    self.spec_active = True
                elif event['event'] == 13:
                    self.spec_active = False
            return event

        def c_string(self, pid, pointer):
            raw = bytearray()
            for index in range(16384):
                byte = self.read(pid, pointer + index, 1)
                if byte == b'\0':
                    return bytes(raw)
                raw.extend(byte)
            raise AssertionError('fixture path exceeds the declared observation resource')

        def entry(self, pid, nr, args):
            observed = super().entry(pid, nr, args)
            if not self.spec_active:
                return observed
            if self.mode == 'native' and nr == 1 and args[0] == 2 and args[2] == 64:
                raw = self.read(pid, args[1], 64)
                if raw[:8] == b'HLCSPFX1':
                    extent, child, sequence, generation, flags, size, zero = struct.unpack_from('<7Q', raw, 8)
                    assert extent == 64 + size and zero == 0 and 1 <= child <= 7
                    assert flags == (3 if child == 3 else 5 if child == 4 else 1)
                    assert sequence == self.native_child_sequence + 1 and generation == 1 and pid == self.root_pid
                    self.native_child_sequence = sequence; self.native_child = child
                    event = self.record('spec_child_entry', tid=pid, child=child, sequence=sequence,
                                        generation=generation, flags=flags, request_bytes=size, raw_hex=raw.hex())
                    self.pending[pid]['event'] = event
                    return event
            metadata = None
            if nr in (4, 6):
                metadata = dict(operation='metadata', path_pointer=args[0], result_pointer=args[1],
                                result_extent=144, flags=0x100 if nr == 6 else 0, dirfd=None)
            elif nr == 262:
                metadata = dict(operation='metadata', path_pointer=args[1], result_pointer=args[2],
                                result_extent=144, flags=args[3], dirfd=descriptor(args[0]))
            elif nr == 332:
                metadata = dict(operation='metadata', path_pointer=args[1], result_pointer=args[4],
                                result_extent=256, flags=args[2], dirfd=descriptor(args[0]), mask=args[3])
            elif nr in (83, 258):
                metadata = dict(operation='mkdir', path_pointer=args[0] if nr == 83 else args[1],
                                mode=args[1] if nr == 83 else args[2], dirfd=None if nr == 83 else descriptor(args[0]))
            elif nr in (89, 267):
                metadata = dict(operation='readlink', path_pointer=args[0] if nr == 89 else args[1],
                                result_pointer=args[1] if nr == 89 else args[2],
                                result_capacity=args[2] if nr == 89 else args[3],
                                dirfd=None if nr == 89 else descriptor(args[0]))
            if metadata is None:
                return observed
            # Rust 1.95 try_statx checks availability after its first failure by
            # making exactly this null-buffer call and testing EFAULT. It has
            # no pathname; record the actual probe instead of reading address 0.
            if nr == 332 and tuple(args[:5]) == (0, 0, 0, 4095, 0):
                assert self.mode in ('rust', 'native')
                event = self.record('runtime_statx_probe_entry', tid=pid, nr=nr, arguments=list(args))
                self.pending[pid].update(operation='spec_probe', event=event)
                return event
            operation = metadata['operation']
            self.spec_calls[operation] += 1
            try:
                path = self.c_string(pid, metadata['path_pointer'])
            except BaseException as error:
                self.record('spec_path_observation_refusal', tid=pid, nr=nr, arguments=list(args),
                            observation=metadata, error=repr(error))
                raise
            event = self.record('spec_syscall_entry', tid=pid, operation=operation,
                call=self.spec_calls[operation], nr=nr, path_hex=path.hex(),
                arguments=list(args), **{k: v for k, v in metadata.items() if k not in ('operation', 'path_pointer')})
            pending = self.pending[pid]
            assert pending['operation'] is None
            pending.update(operation='spec_path', spec_operation=operation, call=self.spec_calls[operation],
                           event=event, observation=metadata)
            return event

        def returned(self, pid, result):
            pending = self.pending.get(pid)
            if pending is not None and pending['operation'] == 'spec_probe':
                self.pending.pop(pid)
                event = self.record('runtime_statx_probe_exit', tid=pid, nr=pending['nr'], kernel_return=result)
                assert result == -14, 'the declared Linux host must return the actual availability-probe EFAULT'
                return event
            if pending is None or pending['operation'] != 'spec_path':
                return super().returned(pid, result)
            pending = self.pending.pop(pid)
            metadata = pending['observation']
            operation = pending['spec_operation']
            output = b''
            if operation == 'metadata' and result == 0:
                output = self.read(pid, metadata['result_pointer'], metadata['result_extent'])
            elif operation == 'readlink' and result >= 0:
                assert result <= metadata['result_capacity']
                output = self.read(pid, metadata['result_pointer'], result)
            return self.record('spec_syscall_exit', tid=pid, operation=operation, call=pending['call'],
                nr=pending['nr'], kernel_return=result, completion=result, path_hex=pending['event']['path_hex'],
                returned_bytes=leaf.pin(output), returned_hex=output.hex(), target_syscall_executed=True)

    return SpecTrace
