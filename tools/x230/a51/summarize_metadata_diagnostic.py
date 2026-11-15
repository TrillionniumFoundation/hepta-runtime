#!/usr/bin/env python3
"""Summarize immutable A51 diagnostic evidence; never launch a controller."""
import gzip
import hashlib
import json
import os
from pathlib import Path

ROOT = Path('/home/qian/hepta-runtime-optimization-20261023/a41-phase-timing-20261025-r01/a51-metadata-diagnostic-r01')
PINS = {
    'report.json': (245954, '6f806dd3fac57f13d1cb9041c2905ee12e536d758e7ded35912552f61da1413d'),
    'metadata-trace.json': (2148360, '0cfec2026463cbd7669ac63e5d60641f609e574d31266025f6e613e910faee28'),
}

def create(name, raw):
    fd = os.open(ROOT / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return {'path': str(ROOT / name), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}

def main():
    documents, originals = {}, {}
    for name, (size, sha) in PINS.items():
        raw = (ROOT / name).read_bytes()
        assert len(raw) == size and hashlib.sha256(raw).hexdigest() == sha
        originals[name] = raw
        documents[name] = json.loads(raw)
    report, trace = documents['report.json'], documents['metadata-trace.json']
    assert report['complete'] and trace['complete_capture']
    rows = []
    for call, events in sorted(trace['calls'].items(), key=lambda item: int(item[0])):
        if int(call) == 0:
            continue
        phases = {}
        for event in events:
            phases.setdefault(event['phase'], []).append(event)
        stages = {}
        for name, selected in phases.items():
            if len(selected) == 2 and selected[0]['kind'] == 'begin' and selected[1]['kind'] == 'end':
                stages[name] = selected[1]['at_us'] - selected[0]['at_us']
        marks = {name: [{'kind': event['kind'], 'call_us': event['call_us'],
                         'remaining_us': event['remaining_us'], 'cohort': event['cohort'],
                         'value': event['value']} for event in selected]
                 for name, selected in phases.items()
                 if name in ('api_enter', 'permit_wait', 'permit_acquired', 'blocking_submitted',
                             'blocking_entered', 'blocking_result', 'caller_result_ready',
                             'caller_scope_end', 'cohort_leader', 'cohort_follower', 'cohort_frozen',
                             'cohort_complete', 'group_ready', 'original_readers_joined')}
        rows.append({'call': int(call), 'tool': events[0]['tool'], 'limit': events[0]['limit'],
                     'cursor': events[0]['cursor'], 'stage_us': stages, 'marks': marks})
    current = report['controllers'][0]
    result = {'schema': 'hepta-a51-diagnostic-analysis/v1', 'diagnostic_complete': report['complete'],
              'product_passed': report['product_passed'], 'performance_adopted': False,
              'attempted': report['attempted'], 'successful': report['successful'],
              'failed': report['failed'], 'unexecuted': report['unexecuted'],
              'setup': current['setup'], 'trace_capture': report['trace'],
              'cohort_sizes': [event['value'] for event in trace['events'] if event['phase'] == 'cohort_frozen'],
              'calls': rows, 'cpu': {key: value for key, value in current.items() if 'cpu' in key},
              'source_trace_pins': PINS,
              'scope': 'Opt-in diagnostic with 20 fixed measured calls; no performance comparison or failure-rate estimate.'}
    receipt = create('diagnostic-analysis.json', (json.dumps(result, sort_keys=True, indent=2) + '\n').encode())
    compressed = create('metadata-trace.original.json.gz', gzip.compress(originals['metadata-trace.json'], mtime=0))
    descriptor = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    print(json.dumps({'analysis': receipt, 'compressed_trace': compressed,
                      'measured_successful': result['successful'], 'cohort_sizes': result['cohort_sizes']}))

if __name__ == '__main__':
    main()
