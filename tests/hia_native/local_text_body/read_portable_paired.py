"""Read complete captures, including retired fixture trees, without processes."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import portable_support as support
import read_paired as frozen
from portable_support import require, PIN, decode, regular


def archive_snapshot(path, vault):
    path = Path(path)
    require(not path.exists() and not path.is_symlink(), 'retired fixture still exists')
    archived = decode(regular(path.parent, 'final-filesystem.json'))
    require(archived['schema'] == 'hepta.runtime.local-text-body-filesystem-archive.v1',
            'body filesystem archive schema differs')
    snapshot = archived['snapshot']
    names = []
    nodes = {}
    for node in snapshot['nodes']:
        raw_name = bytes.fromhex(node['path_hex'])
        require(raw_name and not raw_name.startswith(b'/') and b'\0' not in raw_name
                and all(part not in (b'', b'.', b'..') for part in raw_name.split(b'/')),
                'body archived raw path differs')
        require(node['path_hex'] not in nodes, 'body duplicate archived path')
        nodes[node['path_hex']] = node
        names.append(raw_name)
        for key in ('mode', 'uid', 'gid', 'links'):
            require(type(node[key]) is int and node[key] >= 0, 'body archived metadata type differs')
        require(node['mode'] <= 0o7777 and node['links'] >= 1, 'body archived metadata range differs')
        base = {'path_hex', 'mode', 'uid', 'gid', 'links', 'kind'}
        if node['kind'] == 'file':
            require(set(node) == base | {'content'}, 'body archived file fields differ')
            blob = node['content']
            raw = regular(vault, blob['path'])
            require(blob == dict(path=hashlib.sha256(raw).hexdigest() + '.bin', **PIN(raw)),
                    'body archived complete file bytes differ')
        elif node['kind'] == 'symlink':
            require(set(node) == base | {'target_hex'}, 'body archived symlink fields differ')
            require(b'\0' not in bytes.fromhex(node['target_hex']), 'body archived symlink target differs')
        else:
            require(node['kind'] == 'directory' and set(node) == base, 'body archived file kind differs')
    require(names == sorted(names), 'body archived raw path order differs')
    for raw in names:
        if b'/' in raw:
            parent = nodes.get(raw.rsplit(b'/', 1)[0].hex())
            require(parent is not None and parent['kind'] == 'directory', 'body archived parent differs')
    groups = snapshot['hardlink_groups']
    require(groups == sorted(groups), 'body archived hardlink group order differs')
    seen = set()
    for group in groups:
        require(len(group) >= 2 and group == sorted(group) and len(set(group)) == len(group),
                'body archived hardlink group differs')
        require(all(name not in seen and name in nodes and nodes[name]['kind'] == 'file' for name in group),
                'body archived hardlink node differs')
        seen.update(group)
        reference = {k: v for k, v in nodes[group[0]].items() if k != 'path_hex'}
        require(reference['links'] == len(group)
                and all({k: v for k, v in nodes[name].items() if k != 'path_hex'} == reference for name in group),
                'body archived hardlink state differs')
    require(all(node['links'] == 1 or name in seen for name, node in nodes.items() if node['kind'] == 'file'),
            'body archived multiply linked file has no complete group')
    return snapshot


def verify(capture, *, relocation=None):
    capture = Path(capture).resolve(strict=True)
    source = support.source_evidence()
    support.configure(relocation=relocation)
    launches = (subprocess.Popen, subprocess.run)
    previous_regular, previous_snapshot = frozen.regular, frozen.snapshot
    accessed = {}
    def tracked(root, name):
        result = previous_regular(root, name)
        accessed[str(result.relative_to(capture))] = hashlib.sha256(result.read_bytes()).hexdigest()
        return result
    def selected_snapshot(path, vault):
        if path.exists() or path.is_symlink():
            return previous_snapshot(path, vault)
        value = archive_snapshot(path, vault)
        name = str((path.parent / 'final-filesystem.json').relative_to(capture))
        accessed[name] = hashlib.sha256(regular(capture, name)).hexdigest()
        for node in value['nodes']:
            if node['kind'] == 'file':
                blob_name = 'blobs/' + node['content']['path']
                accessed[blob_name] = hashlib.sha256(regular(capture, blob_name)).hexdigest()
        return value
    frozen.regular, frozen.snapshot = tracked, selected_snapshot
    try:
        result = frozen.verify(capture, support.HERE)
    finally:
        frozen.regular, frozen.snapshot = previous_regular, previous_snapshot
        subprocess.Popen, subprocess.run = launches
    require(support.source_evidence() == source, 'body readonly source changed')
    result['artifact_sha256'] = accessed
    result['source_inputs'] = source
    return result


def retire(capture):
    capture = Path(capture).resolve(strict=True)
    before = verify(capture)
    report = decode(regular(capture, 'result.json'))
    records = []
    for pair in report['cases']:
        for lane in ('original', 'native'):
            folder = capture / pair['folder'] / lane
            work = folder / 'work'
            require(work.is_dir() and work.resolve() == work.absolute(), 'body retirement ownership differs')
            row = decode(regular(folder, 'result.json'))
            snapshot = frozen.snapshot(work, capture / 'blobs')
            require(snapshot == row['files_after_body'][-1]['snapshot'], 'body retirement state changed')
            archive = dict(schema='hepta.runtime.local-text-body-filesystem-archive.v1', snapshot=snapshot)
            raw = (json.dumps(archive, indent=2, sort_keys=True) + '\n').encode()
            destination = folder / 'final-filesystem.json'
            with destination.open('xb') as handle:
                handle.write(raw)
            # Only completed fixtures created by this exact 68-pair capture are
            # retired. Their full bytes, modes, raw names and link groups above
            # were independently compared before granting removal.
            for current, directories, _files in os.walk(work, topdown=True, followlinks=False):
                os.chmod(current, 0o700)
                directories[:] = [name for name in directories if not (Path(current) / name).is_symlink()]
            shutil.rmtree(work)
            records.append(dict(path=str(destination.relative_to(capture)), **PIN(raw)))
    after = verify(capture)
    require(before['root_pairs'] == after['root_pairs'] == 68, 'body retirement lost a source case')
    result = dict(status='BODY_FIXTURES_RETIRED_AFTER_COMPLETE_READBACK', archives=records,
                  actual_processes_started=0, root_pairs=68, roots_retired=136)
    (capture / 'retirement.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--retire', action='store_true')
    parser.add_argument('--producer-output', type=Path)
    parser.add_argument('--current-output', type=Path)
    args = parser.parse_args()
    require(bool(args.producer_output) == bool(args.current_output), 'body relocation requires both roots')
    relocation = ((args.producer_output.absolute(), args.current_output.resolve(strict=True))
                  if args.producer_output else None)
    if args.retire:
        require(relocation is None, 'body retirement only owns the actual producer capture')
        retire(args.capture)
    result = verify(args.capture, relocation=relocation)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({key: result[key] for key in ('status', 'root_pairs', 'actual_root_processes',
        'operations_per_side', 'complete_input_and_response_bytes', 'process_launches')}, sort_keys=True))
