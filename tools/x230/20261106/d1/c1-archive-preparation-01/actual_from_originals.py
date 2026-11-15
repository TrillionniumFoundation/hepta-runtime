def actual_from_originals(originals, snapshots, expected_job_id):
    need(type(expected_job_id) is str and len(expected_job_id.split('-')) == 3
         and all(part and set(part) <= set('0123456789abcdef') for part in expected_job_id.split('-')),
         'the actual original holder job ID is required')
    data = {}
    for name in CORE_PATHS:
        path = originals / name
        if os.path.lexists(path):
            data[name] = read_original(path, snapshots)
    pages = load_pages(originals, 'c1-holder-native-read-01-', snapshots, data, True)
    need(sum(map(len, data.values())) <= MAX_TOTAL, 'captured core receipts exceed bound')
    native = original_object(data, 'c1-holder-native-01.json')
    need(native is not None and native.get('job_id') == expected_job_id
         and native.get('state') in {'succeeded', 'failed', 'cancelled', 'timed_out'}
         and (native.get('exit_code') is None or type(native.get('exit_code')) is int),
         'actual original holder terminal is required')
    native_stream_pages([json.loads(data[name]) for name in pages], native)
    parent = original_object(data, 'c1-campaign-01/report.json')
    audit = original_object(data, 'c1-observation-01/independent-summary.json')
    adapter = original_object(data, 'c1-adapter-evidence-01/adapter-report.json')
    holder = original_object(data, 'c1-holder-report-01.json')
    native_success = native.get('state') == 'succeeded' and native.get('exit_code') == 0
    if native_success:
        # Do not mislabel a successful original as failed merely because a local
        # mirror has not yet received its required original bodies.
        need(all(name in data for name in CORE_PATHS if name != 'c1-holder-start-01.json'),
             'successful holder is awaiting its full actual core receipt mirror')
    passed = bool(native_success and parent is not None and parent.get('passed') is True
        and parent.get('diagnostic_evidence_passed') is True and parent.get('measurement_attribution_valid') is True
        and audit is not None and audit.get('verified') is True
        and adapter is not None and adapter.get('analysis_complete') is True
        and holder is not None and holder.get('passed') is True and holder.get('owned_agent_reaped') is True)
    counts = None if audit is None else {key: audit.get(key) for key in COUNTS}
    if passed:
        native_terminal(native, expected_job_id, 'succeeded', 0)
        need(parent.get('schema') == 'hepta-d1-c1-campaign-control/v1'
             and parent.get('candidate_adopted') is False and parent.get('performance_acceptance_claim') is False
             and audit.get('schema') == 'hepta-native-observation-independent-analysis/v3'
             and adapter.get('schema') == 'hepta-d1-c1-phase-cost-adapter/v1'
             and holder.get('schema') == 'hepta-x230-r21-held-agent-campaign/v1',
             'original diagnostic success scope differs')
        need(type(counts) is dict and all(type(value) is int and value >= 0 for value in counts.values()),
             'actual original diagnostic count shape differs')
        need(counts == dict(zip(COUNTS, (768, 96, 72, 936, 0))),
             'original successful diagnostic did not complete the fixed protocol')
    return {'schema': 'hepta-d1-c1-archive-actual-pins/v1', 'sealed': True,
        'holder_original_job_id': expected_job_id,
        'outcome': 'diagnostic_passed' if passed else 'not_passed',
        'native_read_paths': pages, 'counts': counts,
        'files': {name: None if name not in data else {'bytes': len(data[name]), 'sha256': sha(data[name])}
                  for name in [*CORE_PATHS, *pages]}}
