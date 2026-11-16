"""Inputs and filesystem setup for the public wide-interface qualification.

No expected result or expected state is computed here. Workdir inputs come
from the unchanged independently materialized original-method corpus.
"""
from pathlib import Path
import os

LARGE_SIZE = 67_108_865


def large_view_case():
    return {'metadata': dict(case_id=1001, name='public-string-endpoint-over-64MiB', session=2001,
        path_hex=b'file'.hex(), params={'start': 'x' * LARGE_SIZE}, reset_cache=True,
        context=True, raw_path=False, cancel_after_render=False,
        setup=[dict(kind='write', path_hex=b'file'.hex(), blob=0)], hooks=[],
        cache_probes=[b'file'.hex()]), 'blobs': [b'a\n']}


def workdir_selected(scenario):
    if len(scenario['sessions']) != 1 or scenario['policy_id'] == 'remote-policy':
        return False
    if 'capability-resolution' in scenario['name']:
        return False
    if any(step['action']['kind'] not in ('public', 'helper') for step in scenario['steps']):
        return False
    public = [step for step in scenario['steps'] if step['action']['kind'] == 'public']
    return bool(public) and all(type(step['action']['message']['params'].get('arguments', {}))
                                in (dict, type(None)) for step in public)


def setup_workdir(scenario, fixture_root):
    root = Path(fixture_root).absolute()
    for action in scenario['setup']:
        path = Path(os.fsdecode(bytes.fromhex(action['path_hex'])))
        if not path.is_absolute() or '..' in path.parts or not path.is_relative_to(root):
            raise ValueError('workdir fixture path escaped its owner')
        path.parent.mkdir(parents=True, exist_ok=True)
        kind = action['kind']
        if kind == 'mkdir':
            path.mkdir(parents=True, exist_ok=True)
        elif kind == 'write':
            path.write_bytes(bytes.fromhex(action['data_hex']))
        elif kind == 'symlink':
            path.symlink_to(os.fsdecode(bytes.fromhex(action['target_hex'])))
        elif kind == 'hardlink':
            target = Path(os.fsdecode(bytes.fromhex(action['target_hex'])))
            if not target.is_relative_to(root):
                raise ValueError('workdir hardlink escaped its fixture')
            os.link(target, path)
        elif kind == 'fifo':
            os.mkfifo(path, 0o600)
        else:
            raise ValueError('unsupported workdir input setup: ' + kind)
