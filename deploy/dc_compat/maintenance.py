# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Read-only maintenance gate: unknown child ownership is never safe to stop."""
import json
import pathlib


def assert_no_live_workers(state):
    state = pathlib.Path(state)
    for path in (state / 'processes').glob('*/metadata.json'):
        if json.loads(path.read_bytes()).get('state') not in ('completed', 'spawn_failed'):
            raise RuntimeError('Owned process is active or its termination is unknown; leave its owner running')
    for path in (state / 'searches').glob('*/metadata.json'):
        if json.loads(path.read_bytes()).get('isComplete') is not True:
            raise RuntimeError('Owned search must finish before maintenance')
