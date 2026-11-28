"""Read the complete retained ordinary body comparison without starting processes."""
from __future__ import annotations
from pathlib import Path
import argparse
import hashlib
import importlib
import json
import os
import stat
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
sha = lambda raw: hashlib.sha256(raw).hexdigest()
pin = lambda raw: dict(bytes=len(raw), sha256=sha(raw))


def require(value, reason):
    if not value:
        raise ValueError(reason)


def regular(root, relative):
    require(type(relative) is str and relative and not Path(relative).is_absolute()
        and all(part not in ('', '.', '..') for part in relative.split('/')), 'artifact path is not relative')
    value = root
    for part in relative.split('/'):
        value = value / part
        require(not value.is_symlink(), 'artifact path traverses a symlink')
    require(stat.S_ISREG(value.lstat().st_mode), 'artifact is not a regular file')
    return value


def framed(raw):
    frames = []; at = 0
    while at < len(raw):
        require(len(raw) - at >= 8, 'truncated transport length')
        count, = struct.unpack_from('<Q', raw, at); at += 8
        require(8 <= count <= 134217728 and count <= len(raw) - at, 'transport extent differs')
        frames.append(raw[at:at + count]); at += count
    return frames


def compact(value, vault):
    if isinstance(value, bytes):
        name = sha(value) + '.bin'
        require(regular(vault, name).read_bytes() == value, 'complete state blob differs')
        return dict(path=name, **pin(value))
    if isinstance(value, list): return [compact(item, vault) for item in value]
    if isinstance(value, dict):
        return {(key.hex() if isinstance(key, bytes) else key): compact(item, vault) for key, item in value.items()}
    return value


def snapshot(root, vault):
    nodes = []; groups = {}
    def walk(folder, prefix):
        for entry in sorted(os.scandir(folder), key=lambda item: item.name):
            name = prefix + entry.name; info = entry.stat(follow_symlinks=False)
            row = dict(path_hex=name.hex(), mode=stat.S_IMODE(info.st_mode), uid=info.st_uid,
                gid=info.st_gid, links=info.st_nlink)
            if stat.S_ISREG(info.st_mode):
                raw = Path(os.fsdecode(entry.path)).read_bytes()
                require(len(raw) == info.st_size, 'completed retained file changed while reading')
                row.update(kind='file', content=compact(raw, vault))
                groups.setdefault((info.st_dev, info.st_ino), []).append(name.hex())
            elif stat.S_ISDIR(info.st_mode): row['kind'] = 'directory'
            elif stat.S_ISLNK(info.st_mode): row.update(kind='symlink', target_hex=os.readlink(entry.path).hex())
            else: raise ValueError('retained fixture contains a special filesystem object')
            nodes.append(row)
            if row['kind'] == 'directory': walk(entry.path, name + b'/')
    walk(os.fsencode(root), b'')
    return dict(nodes=sorted(nodes, key=lambda row: bytes.fromhex(row['path_hex'])),
        hardlink_groups=sorted(sorted(group) for group in groups.values() if len(group) > 1))


def verify(root, source):
    root = root.resolve(strict=True); source = source.resolve(strict=True)
    sys.path.insert(0, str(source))
    paired = importlib.import_module('run_paired'); ordinary = importlib.import_module('run_ordinary')
    original = importlib.import_module('observations'); native = importlib.import_module('native_observations')
    require(all(Path(module.__file__).resolve().parent == source for module in (paired, ordinary, original, native)),
        'reader imported a different captured implementation')
    def no_process(*_args, **_kwargs): raise RuntimeError('read-only body evidence admission cannot launch a process')
    subprocess.Popen = no_process; subprocess.run = no_process
    report_raw = regular(root, 'result.json').read_bytes(); report = json.loads(report_raw)
    require(report['schema'] == 'hepta.runtime.local-text-body-paired-development.v1'
        and report['status'] == 'LOCAL_TEXT_BODY_ORDINARY_PAIRED_PASS'
        and report['source_files'] == paired.files(source) and report['source_unchanged'] is True
        and report['expected_root_pairs'] == report['actual_root_pairs'] == 68 and report['actual_root_processes'] == 136
        and report['expected_operations_per_side'] == report['actual_operations_per_side'] == 129
        and report['process_deadline_seconds'] == 60 and report['capture_deadline_seconds'] == 180
        and 0 <= report['elapsed_seconds'] <= 180 and report['same_absolute_workdir'] is True
        and all(report[key] is False for key in ('fresh_reference_build_performed', 'fresh_native_build_performed',
            'full_body_async_qualified', 'public_handler_qualified', 'whole_runtime_replaced', 'old_stack_removal_qualified')),
        'body comparison source, count, deadline or qualification scope differs')
    require(all(report['source_files'][name] == value for name, value in paired.FROZEN.items()), 'original ordinary domain source differs')
    old_binary, old_build = paired.original_build(Path(report['reference_build_path']))
    new_binary, new_build = paired.native_build(Path(report['native_build_path']))
    require(old_build == report['reference_build'] and new_build == report['native_build'], 'actual source/build/member/packer custody differs')
    definitions = paired.cases.cases()
    require(report['expected_case_names'] == [row['name'] for row in definitions]
        and len(report['cases']) == len(definitions), 'body capture omitted or renamed a source case')
    vault = root / 'blobs'; pids = set(); count = 0; old_bytes = 0; new_bytes = 0; artifacts = {}; observed_root = None
    for index, (spec, summary) in enumerate(zip(definitions, report['cases'], strict=True)):
        name = f'case-{index:02d}-{spec["name"]}'; require(summary['folder'] == name, 'ordinary case order differs')
        folder = root / name; pair_raw = regular(folder, 'result.json').read_bytes(); pair = json.loads(pair_raw)
        require(pin(pair_raw) == summary['receipt'] and summary == dict(folder=name, receipt=pin(pair_raw), **pair)
            and pair['name'] == spec['name'] and pair['status'] == 'PAIRED_COMPLETE_STATE_PASS'
            and pair['operations'] == len(spec['operations']) and pair['same_absolute_workdir'] is True
            and pair['completed_capture_relocated'] is True and pair['process_deadline_seconds'] == 60
            and pair['file_snapshots_identical'] is True and pair['complete_states_identical'] is True
            and pair['compared_owner_boundaries'] == len(spec['operations']) * 6
            and pair['compared_hint_boundaries'] == len(spec['operations']), 'paired case receipt differs')
        cwd = Path(pair['actual_working_directory'])
        require(cwd.is_absolute() and cwd.parts[-3:] == (name, 'lane', 'work'), 'actual shared cwd differs')
        if observed_root is None: observed_root = cwd.parents[2]
        require(observed_root == cwd.parents[2] and not (folder / 'lane').exists(), 'completed lane was not retired')
        # Frozen seed keys are simple local names; this constructs the original
        # fixture input and does not simulate any filesystem/body operation.
        def fixture_key(work, path):
            require(path and b'/' not in path and b'\0' not in path and path not in (b'.', b'..'), 'seed key domain differs')
            return os.fsencode(work) + b'/' + path
        old_key = ordinary.canonical; ordinary.canonical = fixture_key
        try: requests, setup_count = ordinary.requests(spec, cwd)
        finally: ordinary.canonical = old_key
        wire = b''.join(ordinary.q(len(frame)) + frame for frame in requests)
        rows = {}; streams = {}; states = {}
        for lane, binary, decode in (('original', old_binary, original.decode), ('native', new_binary, native.decode)):
            capture = folder / lane; raw = regular(capture, 'result.json').read_bytes(); row = json.loads(raw)
            require(pair['captures'][lane] == dict(folder=lane, receipt=pin(raw)), 'process receipt identity differs')
            require(row['schema'] == 'hepta.runtime.local-text-body-ordinary-case.v1'
                and row['name'] == spec['name'] and row['status'] == 'PASS' and row['command'] == [str(binary)]
                and row['cwd'] == str(cwd) and row['environment'] == ordinary.ENVIRONMENT
                and row['process_deadline_seconds'] == 60 and row['timed_out'] is False
                and row['process_reaped'] is True and row['exit_code'] == 0 and 0 <= row['elapsed_seconds'] <= 60
                and row['setup_frames'] == setup_count and row['input_frames'] == len(requests)
                and type(row['pid']) is int and row['pid'] > 0 and row['pid'] not in pids, 'actual completed process custody differs')
            pids.add(row['pid'])
            current = {key: regular(capture, key + '.bin').read_bytes() for key in ('stdin', 'stdout', 'stderr')}
            require(row['streams'] == {key: pin(value) for key, value in current.items()}
                and current['stdin'] == wire, 'complete original source input or retained stream differs')
            responses = framed(current['stdout']); require(len(responses) == len(requests), 'source request/result count differs')
            parsed = [ordinary.response(request, response, spec['operations'][i - setup_count] if i >= setup_count else None)
                for i, (request, response) in enumerate(zip(requests, responses, strict=True))]
            require(row['responses'] == parsed, 'actual complete response receipt differs')
            state = decode(current['stderr'], spec['operations'])
            require(row['observations'] == [dict(frame, state=compact(frame['state'], vault)) for frame in state], 'actual complete observer receipt differs')
            require(len(row['files_after_body']) == len(spec['operations'])
                and [item['generation'] for item in row['files_after_body']] == list(range(1, len(spec['operations']) + 1))
                and snapshot(capture / 'work', vault) == row['files_after_body'][-1]['snapshot'], 'retained final complete filesystem differs')
            for item in [row['filesystem_before'], *[item['snapshot'] for item in row['files_after_body']]]:
                for node in item['nodes']:
                    if node['kind'] == 'file':
                        data = regular(vault, node['content']['path']).read_bytes()
                        require(node['content'] == compact(data, vault), 'complete file observation blob differs')
            for file_name in ('result.json', 'stdin.bin', 'stdout.bin', 'stderr.bin'):
                artifacts[name + '/' + lane + '/' + file_name] = pin(regular(capture, file_name).read_bytes())
            rows[lane], streams[lane], states[lane] = row, current, state
        require(streams['original']['stdin'] == streams['native']['stdin']
            and streams['original']['stdout'] == streams['native']['stdout'], 'complete transport parity differs')
        for field in ('operations', 'setup_frames', 'input_frames', 'cwd', 'environment', 'filesystem_before', 'responses', 'files_after_body'):
            require(rows['original'][field] == rows['native'][field], 'complete paired receipt differs: ' + field)
        native.compare(states['original'], states['native'])
        compared = len(wire) + len(streams['original']['stdout'])
        require(pair['byte_identical_input_and_response_bytes'] == compared
            and pair['complete_original_observer_bytes'] == len(streams['original']['stderr'])
            and pair['complete_native_arena_observer_bytes'] == len(streams['native']['stderr']), 'comparison byte accounting differs')
        count += compared; old_bytes += len(streams['original']['stderr']); new_bytes += len(streams['native']['stderr'])
        artifacts[name + '/result.json'] = pin(pair_raw)
    require(count == report['complete_input_and_response_bytes'] and old_bytes == report['complete_original_observer_bytes']
        and new_bytes == report['complete_native_arena_observer_bytes'] and len(pids) == 136, 'complete domain aggregate differs')
    artifacts['result.json'] = pin(report_raw)
    return dict(status='LOCAL_TEXT_BODY_PAIRED_READONLY_PASS', root_pairs=68, actual_root_processes=136,
        operations_per_side=129, complete_input_and_response_bytes=count, complete_original_observer_bytes=old_bytes,
        complete_native_arena_observer_bytes=new_bytes, artifact_sha256=artifacts, source_files=report['source_files'],
        process_launches=0, full_body_async_qualified=False, public_handler_qualified=False,
        whole_runtime_replaced=False, old_stack_removal_qualified=False)


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True); parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(); result = verify(args.capture, args.source)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({key: result[key] for key in ('status', 'root_pairs', 'actual_root_processes', 'operations_per_side',
        'complete_input_and_response_bytes', 'complete_original_observer_bytes', 'complete_native_arena_observer_bytes', 'process_launches')}, sort_keys=True))


if __name__ == '__main__': main()
