"""Actual held synchronous turns and whole-worker mkdir cancellation.

The original functions and runtime remain unchanged. Only the already owned
fixture is stopped, and all external fixture mutations are explicit records.
"""
from pathlib import Path
import argparse
import gzip
import hashlib
import json
import os
import signal
import struct
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cases as ordinary
import owned_trace as trace_module
import observations as native_observations


def definition(name, scenario, *, context=1, poison=False, content=b'new\r\ntext',
               path=b'created.bin', setup='none', outcome='cancelled', error_class=None):
    spec = ordinary.case(name, context=context, poison=poison, content=content, path=path,
                         setup=setup, outcome='error' if error_class else 'success', error_class=error_class)
    return dict(name=name, scenario=scenario, fixture=spec, expected_outcome=outcome)


CASES = [
    definition('exists_existing_sync_cancel', 'exists_sync', setup='existing_file', outcome='result', error_class='exists'),
    definition('exists_missing_sync_cancel', 'exists_sync'),
    definition('parent_exists_sync_cancel', 'parent_sync'),
    definition('parent_missing_sync_cancel', 'parent_sync', path=b'one/two/created.bin'),
    definition('canonical_sync_cancel', 'canonical_sync', outcome='result'),
    definition('canonical_empty_sync_cancel', 'canonical_sync', content=b'', outcome='result'),
    definition('canonical_no_context_sync_cancel', 'canonical_sync', context=2, outcome='result'),
    definition('canonical_poisoned_sync_cancel', 'canonical_sync', poison=True, outcome='result'),
    definition('mkdir_inflight_cancel', 'mkdir_inflight', path=b'one/two/created.bin'),
    definition('mkdir_ready_cancel', 'mkdir_ready', path=b'one/two/created.bin'),
    definition('mkdir_ready_poll_cancel', 'mkdir_ready_poll', path=b'one/two/created.bin'),
    definition('mkdir_error_ready_poll_cancel', 'mkdir_ready_poll', path=b'protected/absent/created.bin',
               setup='readonly_parent', outcome='result', error_class='mkdir'),
    definition('mkdir_repeat_pending_cancel', 'mkdir_repeat', path=b'one/two/created.bin'),
    definition('mkdir_completion_before_pending', 'mkdir_before_wait', path=b'one/two/created.bin', outcome='result'),
    definition('canonical_removed_file_sync_cancel', 'canonical_unlink', outcome='result'),
]


def u64(raw, offset):
    return struct.unpack_from('<Q', raw, offset)[0]


def visible(raw, index):
    at = 0
    for ordinal in range(index + 1):
        if len(raw) - at < 8:
            return None
        extent = u64(raw, at)
        at += 8
        if extent >= 0xffff0000:
            assert ordinal == index and extent == 0xfffffff7
            return dict(outcome='cancelled', consumed=at)
        if len(raw) - at < extent:
            return None
        body = bytes(raw[at:at + extent])
        at += extent
        if ordinal == index:
            assert body[:8] == b'HLCSPR01' and len(body) >= 32 and u64(body, 8) == 1
            assert u64(body, 16) in (0, 1) and u64(body, 24) == len(body) - 32
            return dict(outcome='result', kind=u64(body, 16), message_hex=body[32:].hex(), consumed=at)
    raise AssertionError('unreachable fixture result parse')


def cache_frames(raw):
    at, snapshots, markers = 0, [], []
    while at < len(raw):
        assert len(raw) - at >= 16
        extent = u64(raw, at + 8)
        assert 16 <= extent <= len(raw) - at
        body = raw[at:at + extent]
        if body[:8] == b'HLCSCS01':
            assert extent >= 48 and u64(body, 40) == extent - 48
            phase, poison, count = struct.unpack_from('<3Q', body, 16)
            assert phase in (0, 1) and poison in (0, 1)
            entries, cursor = {}, 48
            for _ in range(count):
                kn, vn = struct.unpack_from('<2Q', body, cursor)
                cursor += 16
                assert kn <= len(body) - cursor and vn <= len(body) - cursor - kn
                key = bytes(body[cursor:cursor + kn]); value = bytes(body[cursor + kn:cursor + kn + vn])
                key.decode('utf-8'); value.decode('utf-8')
                assert key not in entries and len(value) <= 1 << 20
                entries[key] = value; cursor += kn + vn
            assert cursor == extent and list(entries) == sorted(entries)
            snapshots.append(dict(phase=phase, poisoned=bool(poison), entries=entries))
        else:
            assert body[:8] == b'HLCARP01' and extent == 128 and body[72:] == bytes(56)
            markers.append(dict(event=u64(body, 16), serial=u64(body, 24), poll=u64(body, 32), tid=u64(body, 48)))
        at += extent
    assert [row['phase'] for row in snapshots] == [0, 1]
    assert sorted(row['serial'] for row in markers) == list(range(1, len(markers) + 1))
    return snapshots, markers


class Policy:
    def __init__(self, case, request):
        self.case, self.request, self.scenario = case, request, case['scenario']
        self.matched = set(); self.witnesses = []; self.abort_returned = False
        self.ready_forwarded = False; self.mkdir_ready_published = False
        self.repeat_count = 0; self.last_repeat_poll = None
        self.initial_repeat_poll = None; self.actual = None; self.removed_file = False

    def observe(self, trace, event):
        scenario = self.scenario
        if trace.mode == 'native' and event['kind'] == 'mechanism_syscall_entry' and event['nr'] == 15 and event['tid'] == trace.root_pid and trace.cancel_sent:
            self.abort_returned = True  # actual native rt_sigreturn, not a Rust event
        if event['kind'] == 'marker_entry' and event.get('owner') == 'native':
            action, life, phase = event['action'], event['life'], (event['flags'] >> 16) & 255
            deferred = scenario in ('exists_sync', 'parent_sync', 'mkdir_ready_poll') and trace.cancel_sent
            if event['tid'] == trace.root_pid and action == 6 and life == 4 and deferred and 'cancel_publication_gate' not in self.matched:
                self.matched.add('cancel_publication_gate'); return 'cancel_publication_gate'
            if event['tid'] == trace.root_pid and action == 3 and life == 3 and 'pending_gate' not in self.matched:
                needs_started = scenario in ('exists_sync', 'parent_sync', 'mkdir_ready_poll') and trace.cancel_sent
                if scenario == 'mkdir_before_wait' or needs_started:
                    self.matched.add('pending_gate'); return 'pending_gate'
            if action == 9 and life == 3 and phase == 6 and scenario == 'mkdir_ready' and 'ready' not in self.matched:
                assert event['tid'] != trace.root_pid
                self.matched.add('ready'); return 'ready'
            if action == 11 and life == 2 and phase == 6 and scenario == 'mkdir_ready_poll' and 'poll' not in self.matched:
                assert event['tid'] == trace.root_pid and trace.calls['open'] == 0
                self.matched.add('poll'); return 'poll'
        if event['kind'] == 'marker_entry' and event.get('owner') == 'rust':
            marker = event['event']
            if marker == 9:
                self.abort_returned = True
            if marker == 5:
                self.ready_forwarded = True
            if marker == 4 and trace.spec_calls['mkdir'] and trace.calls['open'] == 0:
                self.mkdir_ready_published = True
            if marker == 2 and 'pending_gate' not in self.matched:
                needs_started = scenario in ('exists_sync', 'parent_sync', 'mkdir_ready_poll') and trace.cancel_sent
                if scenario == 'mkdir_before_wait' or needs_started:
                    self.matched.add('pending_gate')
                    return 'pending_gate'
            if marker == 4 and scenario == 'mkdir_ready' and trace.spec_calls['mkdir'] and 'ready' not in self.matched:
                self.matched.add('ready')
                return 'ready'
            if marker == 1 and scenario == 'mkdir_ready_poll' and self.mkdir_ready_published and trace.calls['open'] == 0 and 'poll' not in self.matched:
                self.matched.add('poll')
                return 'poll'
        if event['kind'] == 'spec_syscall_entry':
            operation = event['operation']; path = bytes.fromhex(event['path_hex'])
            if operation == 'metadata' and 'sync' not in self.matched and event['tid'] == trace.root_pid:
                if scenario == 'exists_sync' and path == trace.target:
                    self.matched.add('sync'); return 'sync'
                if scenario == 'parent_sync' and path == os.path.dirname(trace.target):
                    self.matched.add('sync'); return 'sync'
            if scenario in ('canonical_sync', 'canonical_unlink') and trace.calls['close'] == 1 and 'sync' not in self.matched:
                assert event['tid'] == trace.root_pid
                self.matched.add('sync')
                if scenario == 'canonical_unlink':
                    path = Path(os.fsdecode(trace.target)); raw = path.read_bytes()
                    assert raw == self.request['content']
                    path.unlink(); self.removed_file = True
                    trace.record('owned_fixture_mutation', operation='unlink-after-successful-close',
                                 path_hex=trace.target.hex(), removed_content=ordinary.pin(raw))
                return 'sync'
            if operation == 'mkdir' and 'mkdir_effect' not in self.matched:
                self.matched.add('mkdir_effect')
                if scenario in ('mkdir_ready', 'mkdir_ready_poll', 'mkdir_before_wait'):
                    return 'bootstrap_mkdir'
                if scenario in ('mkdir_inflight', 'mkdir_repeat') or trace.cancel_sent:
                    return 'mkdir_effect'
        if event['kind'] == 'syscall_entry' and event['operation'] == 'open' and trace.cancel_sent and 'open_effect' not in self.matched:
            self.matched.add('open_effect')
            return 'open_effect'
        return None

    def advance(self, trace):
        holds = list(trace.holds.items())
        if not trace.cancel_sent:
            trigger = next((hold for _, hold in holds if hold['reason'] in ('sync', 'ready', 'poll')), None)
            if trigger is None and trace.parent_pending and self.scenario == 'mkdir_inflight':
                trigger = next((hold for _, hold in holds if hold['reason'] == 'mkdir_effect'), None)
            if trigger is not None:
                self.witnesses.append(dict(kind='cancel_at', event=trigger['event']['index'], reason=trigger['reason']))
                trace.cancel(trigger['reason'])
        if self.scenario == 'mkdir_repeat' and trace.parent_pending and not trace.cancel_sent:
            effect = next((hold for _, hold in holds if hold['reason'] == 'mkdir_effect'), None)
            if effect is not None:
                if self.initial_repeat_poll is None:
                    self.initial_repeat_poll = trace.polls
                if self.repeat_count < 3 and self.last_repeat_poll != trace.polls:
                    self.repeat_count += 1; self.last_repeat_poll = trace.polls
                    self.witnesses.append(dict(kind='actual_repeat_wake', ordinal=self.repeat_count, poll=trace.polls))
                    trace.force_wake('same started mkdir ticket remains held')
                elif self.repeat_count == 3 and trace.polls > self.last_repeat_poll:
                    trace.cancel('three actual repeated Pending turns retained one mkdir worker')
        for pid, hold in list(trace.holds.items()):
            reason = hold['reason']
            if reason in ('sync', 'poll') and trace.cancel_sent and (trace.mode == 'native' or self.abort_returned):
                trace.release(pid, 'resume the running native turn with actual SIGUSR1 pending' if trace.mode == 'native' else 'actual AbortHandle.abort returned during the same running poll')
            elif reason == 'bootstrap_mkdir' and trace.parent_pending:
                trace.release(pid, 'actual original parent returned Pending before whole mkdir continued')
            elif reason in ('pending_gate', 'cancel_publication_gate'):
                if self.scenario == 'mkdir_before_wait':
                    if self.ready_forwarded or (trace.mode == 'native' and any(pid != trace.root_pid for pid in trace.exit_codes)):
                        self.witnesses.append(dict(kind='mkdir_completed_before_pending_turn_released', event=hold['event']['index']))
                        trace.release(pid, 'actual worker result forwarded its wake before wait boundary')
                elif any(row['reason'] in ('mkdir_effect', 'open_effect') for row in trace.holds.values()):
                    self.witnesses.append(dict(kind='admitted_async_effect_started_before_cancel_publication' if reason == 'cancel_publication_gate' else 'next_async_effect_started_in_same_poll', event=hold['event']['index']))
                    trace.release(pid, 'the admitted whole worker started before cancellation publication' if reason == 'cancel_publication_gate' else 'the next whole worker started before runtime applied deferred cancellation')
        current = visible(trace.stdout, self.request['create_index'])
        if current is not None:
            for pid, hold in list(trace.holds.items()):
                if hold['reason'] in ('ready', 'mkdir_effect', 'open_effect'):
                    assert current['outcome'] == 'cancelled'
                    self.witnesses.append(dict(kind='cancel_frame_readable_before_worker_release', event=hold['event']['index']))
                    trace.release(pid, 'complete cancellation result was actually read from stdout')

    def finish(self, trace):
        result = visible(trace.stdout, self.request['create_index'])
        assert result is not None and result['outcome'] == self.case['expected_outcome']
        if self.scenario != 'mkdir_before_wait':
            assert trace.cancel_sent and self.abort_returned
        else:
            assert not trace.cancel_sent and any(row['kind'] == 'mkdir_completed_before_pending_turn_released' for row in self.witnesses)
        if trace.mode == 'native':
            snapshots, native_records = native_observations.observations(trace.stderr)
            markers = []
            if trace.cancel_sent:
                delivery = [row for row in trace.events if row['kind'] == 'signal_delivery'
                            and row['tid'] == trace.root_pid and row['signal'] == signal.SIGUSR1]
                assert len(delivery) == 1
                assert any(row['kind'] == 'mechanism_syscall_entry' and row['nr'] == 15 and row['tid'] == trace.root_pid
                           and row['index'] > delivery[0]['index'] for row in trace.events)
        else:
            snapshots, markers = cache_frames(trace.stderr)
        fixture = self.case['fixture']
        assert snapshots[0] == dict(phase=0, poisoned=fixture['poison'], entries=self.request['seeds'])
        expected_cache = dict(self.request['seeds'])
        if result['outcome'] == 'result':
            expected_kind = 1 if fixture['error_class'] else 0
            assert result['kind'] == expected_kind
            message = bytes.fromhex(result['message_hex'])
            if expected_kind == 0:
                assert message == f"File created successfully with {len(self.request['content'])} bytes".encode()
                if fixture['context'] == 1 and not fixture['poison']:
                    value = self.request['content'].replace(b'\r\n', b'\n')
                    if len(value) <= 1 << 20:
                        expected_cache[self.request['canonical_key']] = value
                    else:
                        expected_cache.pop(self.request['canonical_key'], None)
            elif fixture['error_class'] == 'exists':
                assert message.startswith(b'File already exists: ')
                assert trace.calls == dict(open=0, write=0, close=0)
                assert not trace.spec_calls['mkdir']
            else:
                assert fixture['error_class'] == 'mkdir'
                assert message.startswith(b'Permission denied. Cannot create directories: ')
                assert trace.calls == dict(open=0, write=0, close=0)
        assert snapshots[1] == dict(phase=1, poisoned=fixture['poison'], entries=expected_cache)
        events = [row['event'] for row in markers]
        if trace.mode == 'rust':
            assert events.count(6) == events.count(7) == events.count(13) == 1
        if result['outcome'] == 'cancelled':
            if trace.mode == 'rust':
                assert events.count(11) == 1 and not any(event in (3, 12) for event in events)
            assert not trace.calls['write']
            path = Path(os.fsdecode(trace.target))
            if self.scenario in ('exists_sync', 'parent_sync', 'mkdir_ready_poll') and trace.calls['open']:
                assert trace.calls == dict(open=1, write=0, close=1) and path.read_bytes() == b''
            else:
                assert trace.calls == dict(open=0, write=0, close=0) and not path.exists()
            if b'/one/two/' in trace.target:
                assert path.parent.is_dir()
        else:
            if trace.mode == 'rust':
                assert events.count(3) == events.count(12) == 1 and 11 not in events
            if not fixture['error_class']:
                path = Path(os.fsdecode(trace.target))
                if self.removed_file:
                    assert not path.exists()
                else:
                    assert path.read_bytes() == self.request['content']
                assert trace.calls['open'] == trace.calls['close'] == 1
        if self.scenario == 'mkdir_repeat':
            assert self.repeat_count == 3 and trace.polls >= self.initial_repeat_poll + 3
        mkdir_events = [row for row in trace.events if row['kind'] == 'spec_syscall_entry' and row['operation'] == 'mkdir']
        if mkdir_events:
            assert all(row['tid'] != trace.root_pid for row in mkdir_events)
            assert len({row['tid'] for row in mkdir_events}) == 1
        assert not trace.holds
        self.actual = result

    def result(self):
        return dict(scenario=self.scenario, matched=sorted(self.matched), witnesses=self.witnesses,
            semantic_result=self.actual, repeat_wakes=self.repeat_count, explicit_removed_file=self.removed_file)


def run(binary, output, fixtures, leaf_source, mode):
    assert mode in ('native','rust')
    os.umask(0o022)
    binary = Path(binary).resolve(strict=True); output = Path(output).resolve(); output.mkdir(exist_ok=False)
    fixtures = Path(fixtures).resolve(); fixtures.mkdir(exist_ok=True); assert not any(fixtures.iterdir())
    leaf = trace_module.load_leaf(leaf_source); Trace = trace_module.trace_type(leaf)
    source_paths = [Path(__file__).resolve(), Path(ordinary.__file__).resolve(),
                    Path(trace_module.__file__).resolve(), Path(leaf_source).resolve(), Path(native_observations.__file__).resolve()]
    before = {str(path): ordinary.pin(path.read_bytes()) for path in source_paths}
    report = dict(schema='hepta.runtime.local-create-spec-held.v1', status='RUNNING', mode=mode,
        cases=CASES, checks=[], execution=dict(source=str(Path(__file__).resolve().parent), output=str(output), binary=str(binary), fixtures=str(fixtures), leaf_source=str(Path(leaf_source).resolve())), source_before=before, binary_before=ordinary.pin(binary.read_bytes()),
        process_deadline_seconds=60, qualifier_deadline_seconds=180, actual_root_processes=0,
        actual_owned_processes=0, public_handler_qualified=False, full_create_file_spec_qualified=False,
        whole_runtime_replaced=False, old_stack_removal_qualified=False)
    started = time.monotonic()
    try:
        for case in CASES:
            assert time.monotonic() - started < 180
            folder = output / case['name']; folder.mkdir()
            work = fixtures / case['name']; work.mkdir()
            request = ordinary.request(case['fixture'], work)
            policy = Policy(case, request)
            trace = Trace(binary, work, request['wire'], request['path'], folder / 'trace', mode, policy)
            setup = case['fixture']['setup']
            if setup == 'existing_file':
                (work / 'created.bin').write_bytes(b'original file must remain\n')
            elif setup == 'readonly_parent':
                (work / 'protected').mkdir(mode=0o500)
            else:
                assert setup == 'none'
            initial, initial_contents = ordinary.snapshot(work)
            trace.record('owned_fixture_setup_before_spawn', entries=initial,
                         contents={key: ordinary.pin(raw) for key, raw in initial_contents.items()})
            for key, raw in initial_contents.items():
                with gzip.open(folder / ('initial-file-' + hashlib.sha256(bytes.fromhex(key)).hexdigest() + '.bin.gz'), 'xb') as stream:
                    stream.write(raw)
            result = trace.run()
            final, final_contents = ordinary.snapshot(work)
            for key, raw in final_contents.items():
                with gzip.open(folder / ('final-file-' + hashlib.sha256(bytes.fromhex(key)).hexdigest() + '.bin.gz'), 'xb') as stream:
                    stream.write(raw)
            record = dict(name=case['name'], status='PASS', leaf_trace=ordinary.pin((folder / 'trace/result.json').read_bytes()),
                actual_root_pid=result['root_pid'], actual_owned_pids=result['owned_pids'],
                filesystem_before_spawn=initial, filesystem_after_drain=final,
                spec_syscall_counts=trace.spec_calls, leaf_syscall_counts=trace.calls,
                full_result=policy.result(), elapsed_seconds=result['elapsed_seconds'])
            ordinary.retire(work); assert not work.exists()
            record['fixture_retired'] = True
            (folder / 'result.json').write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')
            report['checks'].append(record)
            report['actual_root_processes'] += 1
            report['actual_owned_processes'] += len(result['owned_pids'])
            (output / 'summary.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
            print(json.dumps(dict(case=len(report['checks']), name=case['name'], mode=mode, status='PASS')), flush=True)
        report['source_after'] = {str(path): ordinary.pin(path.read_bytes()) for path in source_paths}
        report['binary_after'] = ordinary.pin(binary.read_bytes())
        assert report['source_after'] == before and report['binary_after'] == report['binary_before']
        assert not any(fixtures.iterdir()) and len(report['checks']) == len(CASES)
        report['status'] = 'SPEC_HELD_CAPTURE_PASS'
    except BaseException as error:
        report.update(status='FAIL', error=repr(error)); raise
    finally:
        report['elapsed_seconds'] = time.monotonic() - started
        (output / 'summary.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({key: report[key] for key in ('status', 'actual_root_processes',
        'actual_owned_processes', 'elapsed_seconds')}, sort_keys=True), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True); parser.add_argument('--output', required=True)
    parser.add_argument('--fixtures', required=True); parser.add_argument('--leaf-source', required=True)
    parser.add_argument('--mode', choices=('native', 'rust'), required=True)
    arguments = parser.parse_args()
    run(arguments.binary, arguments.output, arguments.fixtures, arguments.leaf_source, arguments.mode)
