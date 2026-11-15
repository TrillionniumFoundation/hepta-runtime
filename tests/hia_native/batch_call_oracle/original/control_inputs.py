"""Explicit fixture continuation inputs; no expected outputs or I/O results.

These actions follow the two cancellation inputs in the unchanged 215-case
corpus. They are subordinate real calls, not additional original main cases.
"""


def cancel_followup(metadata):
    assert metadata['execution'] == 'async'
    stage = metadata['cancel']['stage']
    assert stage in ('first_read', 'atomic_write')
    assert metadata['params']['path'] == 'file'
    fifo = 'file' if stage == 'first_read' else '.octofs_tmp_file.tmp'
    return {
        'metadata': {
            'kind': 'post_cancel_followup', 'parent_case_id': metadata['case_id'],
            'session': metadata['session'], 'reset_history': False, 'reset_cache': False,
            'initial': [
                {'kind': 'remove', 'path': fifo},
                {'kind': 'write', 'path': 'file', 'blob': 0, 'mode': 0o640},
            ],
            'params': {'path': 'file', 'operations': [
                {'operation': 'insert', 'start': 0, 'content': 'followup'},
            ]},
        },
        'blobs': [b'after-cancel\n'],
    }
