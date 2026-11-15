# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Read complete activity captures without running an image or a reference."""
from pathlib import Path
import gzip
import importlib.util
import json
import struct
import sys

from audit_activity_registry import HARNESS, regular, require, sha
from hia_native_result_storage_qualification import object_at, pin

COUNTS = {'active': (36, 3137, 3113, 24), 'active_publication': (68, 4688, 4656, 32)}


def harness(root, name):
    directory = Path(root) / HARNESS;path = directory / (name + '.py')
    sys.path.insert(0, str(directory))
    spec = importlib.util.spec_from_file_location('_activity_' + name + '_' + sha(regular(path)), path)
    module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def unpacked(folder, record):
    path = Path(folder) / record['path']
    require(path.parent == Path(folder) and not path.is_symlink(), 'unconfined activity corpus')
    raw = regular(path)
    require((len(raw), sha(raw)) == (record['compressed_bytes'], record['compressed_sha256']),
        'compressed activity corpus differs')
    value = gzip.decompress(raw)
    require((len(value), sha(value)) == (record['bytes'], record['sha256']),
        'complete uncompressed activity corpus differs')
    return value


class Playback:
    """Replay the frozen scenario driver against retained frames, without I/O."""

    def __init__(self, original_class, folder, publication):
        self.original_class = original_class;self.folder = Path(folder)
        self.input = regular(self.folder / 'stdin.bin');self.output = regular(self.folder / 'stdout.bin')
        self.stderr = regular(self.folder / 'stderr.bin');self.record = object_at(self.folder / 'result.json')
        require(len(self.input) % 384 == len(self.output) % 96 == 0 and not self.stderr,
            'activity process has partial frames or stderr')
        self.input_at = 0;self.output_at = 0;self.sent = {};self.received = {}
        self.stdout = bytearray();self.buffer = bytearray();self.order = []
        self.phases = [];self.commuting_tags = set();self.deferred_tags = [];self.deferred_kind = 'pins'
        self.publication = publication

    def send(self, actor, op, token=0, id='', flag=0):
        tag = len(self.sent) + 1;name = id.encode()
        wire = b'HRAAQ001' + struct.pack('<7Q', op, token, len(name), flag, 0, 0, 0) + name
        require(len(wire) <= 320 and actor in range(4), 'activity scenario sent an invalid frame')
        frame = b'HRAAC001' + struct.pack('<7Q', tag, actor, len(wire), 0, 0, 0, 0) + wire + bytes(320 - len(wire))
        require(self.input[self.input_at:self.input_at + 384] == frame,
            'complete activity input differs from its frozen scenario')
        self.input_at += 384
        self.sent[tag] = dict(actor=actor, op=op, token=token, id=id, flag=flag)
        return tag

    def receive(self, tag):
        require(tag in self.sent, 'response requested before its submitted activity command')
        while tag not in self.received:
            require(self.output_at < len(self.output), 'activity output ended before a required response')
            raw = self.output[self.output_at:self.output_at + 96];self.output_at += 96
            self.original_class.feed(self, raw)
        return self.received[tag][0]

    def finish(self):
        while self.output_at < len(self.output):
            raw = self.output[self.output_at:self.output_at + 96];self.output_at += 96
            self.original_class.feed(self, raw)
        require(self.input_at == len(self.input) and not self.buffer
            and set(self.sent) == set(self.received), 'activity capture omits or adds submitted commands')
        if self.deferred_tags:
            rows = [self.received[tag][0] for tag in self.deferred_tags]
            require(sorted(row[1] for row in rows) == [1, 2, 3, 4]
                and sorted(row[-1] for row in rows) == [1, 2, 3, 4]
                and all(row[0] == 0 and row[1] == row[2] for row in rows), 'EOF deferred activity domain differs')
            if self.deferred_kind == 'pins':
                require(all(row[4] == 1 for row in rows), 'EOF pin ownership differs')
            else:
                require(self.publication and all(row[3:6] == (0, 0, 0) for row in rows),
                    'EOF detached marker ownership differs')
            self.phases.append(dict(name='eof-drained-' + self.deferred_kind,
                native_result_multiset=sorted(self.received[tag][1] for tag in self.deferred_tags)))
        expected = dict(exit_code=0, reaped=True, requests=len(self.sent),
            observed_task_count=5, worker_threads=4, stdin_bytes=len(self.input), stdin_sha256=sha(self.input),
            stdout_bytes=len(self.output), stdout_sha256=sha(self.output), stderr_bytes=0, stderr_sha256=sha(b''),
            all_submitted_requests_completed=True, thread_join_and_lease_cleanup_on_eof=True,
            response_arrival_order=self.order,
            exact_frames={str(tag): self.received[tag][2] for tag in self.received if tag not in self.commuting_tags},
            commuting_tags=sorted(self.commuting_tags), commuting_phases=self.phases)
        row = self.record
        require(set(row) == set(expected) | {'pid', 'elapsed_seconds', 'observed_linux_tasks'}
            and all(row.get(key) == value for key, value in expected.items()),
            'complete activity process result differs from its actual frames')
        tasks = row['observed_linux_tasks']
        require(type(row['pid']) is int and row['pid'] > 0 and row['pid'] in tasks
            and len(tasks) == len(set(tasks)) == 5 and tasks == sorted(tasks)
            and all(type(tid) is int and tid > 0 for tid in tasks)
            and type(row['elapsed_seconds']) in (int, float) and 0 <= row['elapsed_seconds'] <= 180,
            'actual activity process observation is incomplete')
        require({path.name for path in self.folder.iterdir()} == {'stdin.bin', 'stdout.bin', 'stderr.bin', 'result.json'},
            'unexpected or partial activity process evidence')
        return row


def activity_capture(root, folder, domain, executable_pins):
    folder = Path(folder);report = object_at(folder / 'result.json')
    cases = harness(root, 'audit_' + domain + '_cases');test = harness(root, 'test_audit_' + domain)
    rows = list(cases.definitions());count, requests, exact, commuting = COUNTS[domain]
    require(len(rows) == len({row[0] for row in rows}) == count, 'activity case domain changed')
    labels = set(executable_pins);require(labels in ({'native'}, {'native', 'original'}), 'activity implementation set differs')
    done = []
    for name, kind, data in rows:
        pair = {}
        for label in sorted(labels):
            playback = Playback(test.Session, folder / name / label, domain == 'active_publication')
            cases.exercise(playback, kind, data);pair[label] = playback.finish()
        if 'original' in pair:
            left, right = pair['native'], pair['original']
            require(left['requests'] == right['requests'] and left['exact_frames'] == right['exact_frames']
                and left['commuting_tags'] == right['commuting_tags']
                and left['commuting_phases'] == right['commuting_phases'],
                'complete original activity results or commuting phase multisets differ')
            if not left['commuting_tags']:
                require(left['stdin_sha256'] == right['stdin_sha256'], 'original activity input differs')
        done.append(dict(name=name, kind=kind, requests=pair['native']['requests'],
            commuting_operations=len(pair['native']['commuting_tags']),
            exact_tagged_frames=len(pair['native']['exact_frames']),
            processes={key: {field: value for field, value in record.items()
                if field not in ('exact_frames', 'response_arrival_order', 'commuting_phases')}
                for key, record in pair.items()}))
    reference = 'original' in labels
    expected = dict(status='PASS', cases=count, requests_per_implementation=requests,
        exact_tagged_frames_per_implementation=exact, commuting_operations_per_implementation=commuting,
        actual_native_processes=count, actual_original_processes=count if reference else 0,
        real_four_worker_threads_observed=True, all_submitted_commands_completed=True,
        exact_noncommuting_frames_equal=reference, commuting_phase_multisets_equal=reference,
        original_arc_weak_atomic_and_mutex_executed=reference, shared_private_transport_gate=True,
        native_language_unwind_qualified=False, unserialized_original_interleavings_qualified=False,
        public_request_dispatch_qualified=False, audit_storage_closed=False,
        whole_runtime_replaced=False, production_activated=False, source_executables=executable_pins, results=done)
    require(all(report.get(key) == value for key, value in expected.items())
        and sum(row['requests'] for row in done) == requests
        and sum(row['exact_tagged_frames'] for row in done) == exact
        and sum(row['commuting_operations'] for row in done) == commuting,
        'complete activity comparison summary differs')
    return report


def hot_cache_capture(root, folder, manifest_sha256, original_sha256=None):
    folder = Path(folder);report = object_at(folder / 'result.json')
    cases = harness(root, 'audit_hot_cache_cases');rows = list(cases.cases())
    encode = lambda value: (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\n').encode()
    require(unpacked(folder, report['inputs']) == b''.join(encode(row) for row in rows),
        'complete scripted hot-cache input differs')
    expected_wire = b''.join(struct.pack('<Q', len(cases.request(step))) + cases.request(step)
        for row in rows for step in row['steps'])
    require(unpacked(folder, report['native_requests']) == expected_wire, 'complete native hot-cache requests differ')
    native = [json.loads(line) for line in unpacked(folder, report['native_results']).splitlines()]
    old_raw = unpacked(folder, report['original_results'])
    original = [json.loads(line) for line in old_raw.splitlines()]
    reference = original_sha256 is not None
    require(len(rows) == len(native) == 194 and len(original) == (194 if reference else 0),
        'complete hot-cache process domain differs')
    done = []
    for index, (case, actual) in enumerate(zip(rows, native, strict=True)):
        require(set(actual) == {'name', 'results'} and actual['name'] == case['name']
            and len(actual['results']) == len(case['steps']), 'hot-cache result domain differs')
        for step, result in zip(case['steps'], actual['results'], strict=True):
            require(result['name'] == step.get('name', '') and result['trace'] == step['effects'],
                'hot-cache scripted effects or order differ')
            raw = bytes.fromhex(result['result_hex'])
            require(raw[:8] == b'HRACR001' and len(raw) >= 64
                and result['native_calls'] == len(result['trace']) + 1, 'hot-cache native result framing differs')
        if reference:
            prior = original[index]
            require(prior['name'] == case['name'] and prior['original_functions_executed'] is True
                and prior['original_cache_state_uses_std_once_lock_and_mutex'] is True
                and prior['real_archive_executed'] is False and prior['real_hot_filesystem_executed'] is False
                and len(prior['results']) == len(actual['results']), 'original hot-cache scope differs')
            for before, after in zip(prior['results'], actual['results'], strict=True):
                require(all(before[key] == after[key] for key in ('name', 'result_hex', 'trace')),
                    'complete original hot-cache results or ordered effects differ')
        done.append(dict(name=case['name'], commands=len(actual['results']),
            native_calls=sum(row['native_calls'] for row in actual['results']),
            child_effects=sum(len(row['trace']) for row in actual['results'])))
    expected = dict(status='PASS', cases=194, commands_per_implementation=855,
        actual_original_processes=194 if reference else 0, native_machine_invocations=6855,
        scripted_child_calls_per_implementation=6000, original_executable_sha256=original_sha256,
        manifest_sha256=manifest_sha256, all_original_results_and_effect_transcripts_equal=reference,
        original_mutex_and_once_lock_executed=reference, borrowed_canaries_verified=True,
        case_results=done, child_contracts_scripted=True, shared_private_owner_gate=True,
        real_archive_executed=False, real_hot_filesystem_executed=False,
        native_language_unwind_qualified=False, concurrent_cache_interleavings_qualified=False,
        standalone_native_process_qualified=False, whole_runtime_replaced=False,
        production_activated=False, audit_storage_closed=False)
    require(all(report.get(key) == value for key, value in expected.items())
        and sum(row['commands'] for row in done) == 855
        and sum(row['native_calls'] for row in done) == 6855
        and sum(row['child_effects'] for row in done) == 6000, 'hot-cache complete summary differs')
    processes = report['original_processes'];require(len(processes) == (194 if reference else 0), 'hot-cache process receipts differ')
    if reference:
        lines = old_raw.splitlines(keepends=True)
        for case, output, process in zip(rows, lines, processes, strict=True):
            incoming = encode(case)
            require(process['name'] == case['name'] and process['reaped'] is True
                and process['exit_code'] == 0 and process['timed_out'] is False
                and type(process['pid']) is int and process['pid'] > 0
                and (process['stdin_bytes'], process['stdin_sha256']) == (len(incoming), sha(incoming))
                and (process['stdout_bytes'], process['stdout_sha256']) == (len(output), sha(output))
                and process['stderr_bytes'] == 0 and process['stderr_sha256'] == sha(b''),
                'complete original hot-cache process is missing or changed')
    return report
