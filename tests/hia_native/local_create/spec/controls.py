"""Readonly controls over copied real full Local captures, without new calls."""
import builtins
import contextlib
import copy
import gzip
import io
import os
from pathlib import Path
import struct
import subprocess
import tempfile
from unittest import mock

ARTIFACT_CHANGES = (
    'case-missing', 'case-order', 'case-duplicate', 'ordinary-exit', 'ordinary-timeout',
    'ordinary-command', 'ordinary-count', 'input', 'file', 'ordinary-stdout',
    'native-cache-tail', 'native-cache-value', 'held-exit', 'held-timeout', 'owned-tree',
    'unreaped', 'wait4', 'target-descriptor', 'payload', 'mkdir-effect', 'mkdir-prefix',
    'cancel-before-held', 'release-before-visible', 'repeat-pending', 'canonical-close-order',
    'source-after', 'scope', 'extra-artifact', 'missing-artifact', 'journal-task-order')


@contextlib.contextmanager
def no_execution():
    attempted = []
    def refuse(*args, **kwargs):
        attempted.append(True)
        raise AssertionError('a readonly full Local reader attempted execution')
    with contextlib.ExitStack() as stack:
        stack.enter_context(mock.patch.object(subprocess, 'Popen', refuse))
        for name in ('fork', 'execve', 'system', 'posix_spawn', 'posix_spawnp'):
            if hasattr(os, name): stack.enter_context(mock.patch.object(os, name, refuse))
        yield
    if attempted: raise AssertionError('readonly evidence control executed an implementation')


@contextlib.contextmanager
def forbid_producer_reads(producer):
    """Relocated evidence must not silently fall back to its old output path."""
    prefix = os.path.abspath(os.fspath(producer)); attempted = []
    def wrap(original):
        def guarded(path, *args, **kwargs):
            if isinstance(path, (str, bytes, os.PathLike)):
                normalized = os.path.abspath(os.fsdecode(path))
                if normalized == prefix or normalized.startswith(prefix + os.sep):
                    attempted.append(normalized)
                    raise AssertionError('relocated reader opened or inspected producer evidence')
            return original(path, *args, **kwargs)
        return guarded
    with contextlib.ExitStack() as stack:
        for owner, name in ((builtins, 'open'), (io, 'open'), (os, 'open'), (os, 'stat'), (os, 'lstat')):
            stack.enter_context(mock.patch.object(owner, name, wrap(getattr(owner, name))))
        yield
    if attempted: raise AssertionError('relocated reader touched its producer evidence')


def replace(path, raw):
    path.unlink(); path.write_bytes(raw)


def replace_json(path, value, q): replace(path, q.compact(value) + b'\n')


@contextlib.contextmanager
def snapshot(output, artifacts, root, source_files=None):
    from evidence_snapshot import copy_evidence_files, unrelated_fixture_guard
    with tempfile.TemporaryDirectory(prefix='local-spec-evidence-', dir=Path(output).parent) as name:
        destination = Path(name); copied = destination / 'capture'
        with unrelated_fixture_guard(output): copy_evidence_files(output, copied, artifacts)
        source = Path(root)
        if source_files is not None:
            source = destination / 'source'
            copy_evidence_files(root, source, {key: value['sha256'] for key, value in source_files.items()})
        yield source, copied


def mutate_artifact(output, change, q):
    """Rehash affected wrappers so the semantic reader sees the forged record."""
    assert change in ARTIFACT_CHANGES
    base = Path(output) / q.FOLDER / 'native'
    ordinary = change in ARTIFACT_CHANGES[:12] or change in ('mkdir-prefix', 'source-after', 'scope', 'extra-artifact', 'missing-artifact')
    domain = base / ('ordinary' if ordinary else 'held')
    summary = q.decode((domain / 'summary.json').read_bytes())
    if ordinary:
        name = 'dangling_parent_symlink' if change == 'mkdir-prefix' else 'ascii'
        folder = domain / name; row = q.decode((folder / 'result.json').read_bytes())
        if change == 'case-missing': summary['rows'].pop()
        elif change == 'case-order': summary['rows'][0], summary['rows'][1] = summary['rows'][1], summary['rows'][0]
        elif change == 'case-duplicate': summary['rows'][1] = copy.deepcopy(summary['rows'][0])
        elif change == 'ordinary-exit': row['exit_code'] = 1
        elif change == 'ordinary-timeout': row['timed_out'] = True
        elif change == 'ordinary-command': row['command'].append('--not-the-original-process')
        elif change == 'ordinary-count': summary['actual_root_processes'] = True
        elif change in ('input', 'ordinary-stdout', 'native-cache-tail', 'native-cache-value', 'mkdir-prefix'):
            stream = 'stdin' if change == 'input' else 'stdout' if change in ('ordinary-stdout', 'mkdir-prefix') else 'stderr'
            path = folder / (stream + '.bin.gz'); raw = bytearray(gzip.decompress(path.read_bytes()))
            if change in ('input', 'ordinary-stdout'): raw[-1] ^= 1
            elif change == 'native-cache-tail':
                assert raw[:8] == b'HLCSNA01'; extent = q.reader().U(raw, 8)
                used = q.reader().U(raw, 32); capacity = q.reader().U(raw, 24)
                assert capacity > used and raw[extent - 1] == 0; raw[extent - 1] = 1
            elif change == 'native-cache-value':
                assert raw[:8] == b'HLCSNA01'
                key_size, value_size = struct.unpack_from('<QQ', raw, 48 + 64)
                assert value_size > 0; raw[48 + 64 + 16 + key_size] ^= 1
            else:
                needle = b'Failed to create dirs for'; at = raw.find(needle); assert at >= 0
                raw[at] = ord('X')
            replace(path, gzip.compress(bytes(raw), mtime=0)); row[stream] = q.pin(raw)
        elif change == 'file':
            file_row = next(item for item in row['final_filesystem'] if item['kind'] == 'file')
            path = folder / ('final-file-' + q.sha(bytes.fromhex(file_row['path_hex'])) + '.bin.gz')
            raw = bytearray(gzip.decompress(path.read_bytes())); assert raw; raw[-1] ^= 1
            replace(path, gzip.compress(bytes(raw), mtime=0)); file_row['content'] = q.pin(raw)
        elif change == 'source-after': next(iter(summary['source_after'].values()))['sha256'] = '0' * 64
        elif change == 'scope': summary['whole_runtime_replaced'] = True
        elif change == 'extra-artifact': (domain / 'unconsumed.bin').write_bytes(b'not an admitted artifact')
        elif change == 'missing-artifact': (folder / 'stdout.bin.gz').unlink()
        else: raise AssertionError('missing ordinary mutation implementation')
        if change not in ('case-missing', 'case-order', 'case-duplicate'):
            replace_json(folder / 'result.json', row, q)
            summary['rows'][next(index for index, item in enumerate(summary['rows']) if item['name'] == name)] = row
        replace_json(domain / 'summary.json', summary, q)
        return

    name = ('mkdir_inflight_cancel' if change in ('mkdir-effect', 'cancel-before-held', 'release-before-visible') else
            'mkdir_repeat_pending_cancel' if change == 'repeat-pending' else 'canonical_sync_cancel')
    folder = domain / name; trace = folder / 'trace'
    row = q.decode((folder / 'result.json').read_bytes()); result = q.decode((trace / 'result.json').read_bytes())
    events = [q.decode(line) for line in (trace / 'events.jsonl').read_bytes().splitlines()]
    changed_events = False
    if change == 'held-exit': result['exit_codes'][str(result['root_pid'])] = 1
    elif change == 'held-timeout': result['timed_out'] = True
    elif change == 'owned-tree':
        child = next(pid for pid in result['owned_pids'] if pid != result['root_pid'])
        result['owned_pids'].remove(child); result['exit_codes'].pop(str(child))
    elif change == 'unreaped': result['unreaped_owned_pids'] = [result['root_pid']]
    elif change == 'wait4':
        event = next(event for event in events if event['kind'] == 'mechanism_syscall_exit' and event.get('nr') == 61 and event['kernel_return'] > 0)
        events.remove(event); changed_events = True
    elif change == 'target-descriptor':
        event = next(event for event in events if event['kind'] == 'syscall_exit' and event.get('operation') == 'open')
        event['completion'] += 1; changed_events = True
    elif change == 'payload':
        path = trace / 'write-payloads.bin.gz'; raw = bytearray(gzip.decompress(path.read_bytes())); assert len(raw) > 8
        raw[8] ^= 1; replace(path, gzip.compress(raw, mtime=0))
        event = next(event for event in events if event['kind'] == 'syscall_entry' and event.get('operation') == 'write')
        event['payload'] = q.pin(raw[8:]); changed_events = True
    elif change == 'mkdir-effect':
        path = trace / 'stderr.bin'; raw = bytearray(path.read_bytes()); at = raw.find(b'HSHMKFX1'); assert at >= 0
        raw[at + 56] ^= 1; replace(path, raw); result['stderr'] = q.pin(raw)
    elif change == 'cancel-before-held':
        event = next(event for event in events if event['kind'] == 'cancel_signal_sent')
        hold = next(event for event in events if event['kind'] == 'hold' and event['reason'] == 'mkdir_effect')
        events.remove(event); events.insert(events.index(hold), event); changed_events = True
    elif change == 'release-before-visible':
        cancel = next(event for event in events if event['kind'] == 'cancel_signal_sent')
        release = next(event for event in events if event['kind'] == 'release' and event['held_reason'] == 'mkdir_effect')
        visible = next(event for event in events if event['kind'] == 'stdout_read' and event['index'] > cancel['index'])
        events.remove(release); events.insert(events.index(visible), release); changed_events = True
    elif change == 'repeat-pending':
        wake = next(event for event in events if event['kind'] == 'forced_wake_signal')
        pending = next(event for event in events if event['kind'] == 'marker_entry' and event['index'] > wake['index']
                       and event.get('action') == 3 and event.get('life') == 3)
        events.remove(pending); changed_events = True
        path = trace / 'stderr.bin'; raw = path.read_bytes(); frame = bytes.fromhex(pending['raw_hex']); assert frame in raw
        raw = raw.replace(frame, b'', 1); replace(path, raw); result['stderr'] = q.pin(raw)
    elif change == 'canonical-close-order':
        close = next(event for event in events if event['kind'] == 'syscall_exit' and event.get('operation') == 'close')
        hold = next(event for event in events if event['kind'] == 'hold' and event['reason'] == 'sync')
        events.remove(close); events.insert(events.index(hold) + 1, close); changed_events = True
    elif change == 'journal-task-order':
        selected = [event for event in events if event['kind'] == 'marker_entry' and event['tid'] == result['root_pid']][:2]
        assert len(selected) == 2 and selected[0]['raw_hex'] != selected[1]['raw_hex']
        path = trace / 'stderr.bin'; frames = q.reader().journal_frames(path.read_bytes(), 'native')
        indices = [frames.index(bytes.fromhex(event['raw_hex'])) for event in selected]
        frames[indices[0]], frames[indices[1]] = frames[indices[1]], frames[indices[0]]
        raw = b''.join(frames); replace(path, raw); result['stderr'] = q.pin(raw)
    else: raise AssertionError('missing held mutation implementation')
    if changed_events:
        mapping = {event['index']: index for index, event in enumerate(events)}
        for index, event in enumerate(events):
            event['index'] = index; event['elapsed_seconds'] = result['elapsed_seconds'] * index / (len(events) + 1)
            for field in ('event_index', 'held_event'):
                if field in event: event[field] = mapping[event[field]]
        replace(trace / 'events.jsonl', b''.join(q.compact(event) + b'\n' for event in events)); result['events'] = len(events)
    replace_json(trace / 'result.json', result, q)
    row['leaf_trace'] = q.pin((trace / 'result.json').read_bytes())
    row['actual_root_pid'] = result['root_pid']; row['actual_owned_pids'] = result['owned_pids']
    row['full_result'] = result['policy']; row['elapsed_seconds'] = result['elapsed_seconds']
    replace_json(folder / 'result.json', row, q)
    summary['checks'][next(index for index, item in enumerate(summary['checks']) if item['name'] == name)] = row
    replace_json(domain / 'summary.json', summary, q)
