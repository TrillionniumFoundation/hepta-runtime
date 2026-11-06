function buildR35ObservationRecovery(reference, pins) {
  const checks=[];
  function need(x,m){if(!x)throw Error(m);}
  function replace(s,a,b,label){need(s.split(a).length===2,"replacement count: "+label);checks.push(label);return s.replace(a,b);}
  function block(s,a,b,replacement,label){const i=s.indexOf(a),j=s.indexOf(b,i+a.length);need(i>=0&&j>i&&s.indexOf(a,i+1)<0,"block anchors: "+label);checks.push(label);return s.slice(0,i)+replacement+s.slice(j);}
  let s=reference.replaceAll("r34","r35").replaceAll("R34","R35");
  s=block(s,"ACTUAL = ","HOLDER_JOB =", "ACTUAL = None\n", "actual-unsealed");
  s=replace(s,"REFERENCE_SHA = 'd9aedf45f00d9e7a525de89d348aca7081be4df480b747b4464d4fdc0fb313ce'","REFERENCE_SHA = 'bcd3bc3f0e9606d94be8bbbe45f719dbe4798a540e95f9ca596362f8d4d89f32'","reference");
  s=replace(s,"QUALIFICATION_ARCHIVE_SHA = '488f38422ffca19dc28ecc986fda5218cff090fe8a906053a217eee8e741cb1b'","QUALIFICATION_ARCHIVE_SHA = 'a40f7d42c4c17bad59e81f07736ba6999f66d35973ce8c62c9655b9d88476b3a'","Q-archive");
  s=replace(s,"CI_ARCHIVE_SHA = '9431da8651cfa3e43fe83a1ec3de3f2f85165e20316f2fd8142bacba004abd73'","CI_ARCHIVE_SHA = 'f5f569ccd51d3f2f8cdb11aee115967f0df367a04cf0fd9f50c21a8b5d86d42f'","CI-archive");
  const sorted=Object.fromEntries(Object.keys(pins).sort().map(k=>[k,pins[k]]));
  s=block(s,"STATIC_PINS = ","DYNAMIC_REQUIRED =", "STATIC_PINS = "+JSON.stringify(sorted,null,1)+"\n", "real-R35-static-pins");
  s=block(s,"RECOVERY = ","PINNED =", "", "drop-R34-archive-recovery-chain");
  s=replace(s,"PINNED = {**STATIC_PINS, **(ACTUAL['sha256'] if ACTUAL is not None else {}), **RECOVERY_PINS}","PINNED = {**STATIC_PINS, **(ACTUAL['sha256'] if ACTUAL is not None else {})}","no-old-recovery-pins");
  s=replace(s,"REQUIRED = tuple(sorted(set(STATIC_PINS) | set(DYNAMIC_REQUIRED) | set(RECOVERY_PINS)))","REQUIRED = tuple(sorted(set(STATIC_PINS) | set(DYNAMIC_REQUIRED)))","required-current-only");
  const guard=String.raw`def require_sealed():
    need(type(ACTUAL) is dict and ACTUAL.get('schema') == 'hepta-r35-original-observation-archive-bindings/v1',
         'unsealed R35 collector: actual original receipts are missing')
    need(type(ACTUAL.get('holder_job_id')) is str and ACTUAL['holder_job_id'] and HOLDER_JOB == ACTUAL['holder_job_id'],
         'actual original holder job is missing')
    for key in ('sha256', 'bytes'):
        need(type(ACTUAL.get(key)) is dict and set(ACTUAL[key]) == set(DYNAMIC_REQUIRED),
             'actual receipt identity membership differs')
    need(all(type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value)
             for value in ACTUAL['sha256'].values())
         and all(type(value) is int and 0 <= value <= MAX_FILE for value in ACTUAL['bytes'].values()),
         'malformed actual original identities')
    need(all(type(ACTUAL.get(key)) is bool for key in
         ('workflow_reported_passed', 'observation_gate_passed', 'performance_gates_passed', 'controller_rss_passed'))
         and type(ACTUAL.get('rejection_reasons')) is list, 'actual workflow/gate outcome shape differs')
    counts = ACTUAL.get('native_audit_counts')
    need(type(counts) is dict and set(counts) == {'verified', 'measured_calls', 'warmup_calls',
         'preflight_restart_calls', 'total_calls', 'failed_calls'}
         and type(counts['verified']) is bool
         and all(type(value) is int and value >= 0 for key, value in counts.items() if key != 'verified'),
         'actual native audit counts missing')
    need(type(ACTUAL.get('compiler_monitor_sample_count')) is int and ACTUAL['compiler_monitor_sample_count'] > 0,
         'actual compiler monitor sample count missing')
    need(ACTUAL.get('candidate_adopted') is False and ACTUAL.get('normal_lifecycle_started') is False
         and ACTUAL.get('lifecycle_materialization_started') is False
         and ACTUAL.get('lifecycle_materializer_job_id') is None and ACTUAL.get('normal_lifecycle_job_id') is None
         and ACTUAL.get('normal_lifecycle_state') == 'not_started_at_capture'
         and ACTUAL.get('normal_lifecycle_final_outcome') is None,
         'this collector requires the actual first OBS snapshot before lifecycle launch')


`;
  s=replace(s,"def collect():\n","def collect():\n    require_sealed()\n","collect-entry-guard");
  s=replace(s,"def summary(kind, data, namespace):\n","def summary(kind, data, namespace):\n    require_sealed()\n","summary-entry-guard");
  s=replace(s,"def create_archive():\n","def create_archive():\n    require_sealed()\n","create-entry-guard");
  s=replace(s,"def verify_archive(path, expected_sha):\n","def verify_archive(path, expected_sha):\n    require_sealed()\n","verify-entry-guard");
  s=replace(s,"def collect():\n",guard+"def collect():\n","insert-guard-definition");
  s=replace(s,"base = ROOT / 'observation-evidence-02'","base = ROOT / 'observation-evidence-01'","new-output-namespace");
  s=replace(s,"    need(all(sha(data[name]) == expected for name, expected in PINNED.items()), 'frozen original input differs')",
    "    need(all(sha(data[name]) == expected for name, expected in PINNED.items()), 'frozen original input differs')\n    need(all(len(data[name]) == expected for name, expected in ACTUAL['bytes'].items()),\n         'actual original input byte lengths differ')","actual-size-guard");
  s=replace(s,"'hepta-r35-rejected-observation-owner-postflight/v1'","'hepta-r35-observation-postflight/v1'","neutral-postflight-schema");
  s=replace(s,"and postflight.get('candidate_adopted') is False, 'original postflight must retain unrun lifecycle state')",
    "and postflight.get('candidate_adopted') is False\n         and postflight.get('normal_lifecycle_state') == 'not_started_at_capture'\n         and postflight.get('original_lifecycle_materializer_job_id') is None\n         and postflight.get('original_normal_lifecycle_job_id') is None\n         and postflight.get('normal_lifecycle_final_outcome') is None,\n         'original postflight must retain the actual pre-lifecycle snapshot')","postflight-at-capture");
  s=block(s,"    archive_failure_native = ","    if monitor.get", "", "drop-R34-failure-summary");
  s=block(s,"        'capacity_component':", "        'normal_lifecycle':", "", "drop-R34-capacity-and-recovery-summary");
  const extra=String.raw`    expected_counts = {key: native_audit.get(key) for key in
        ('verified', 'measured_calls', 'warmup_calls', 'preflight_restart_calls', 'total_calls', 'failed_calls')}
    if expected_counts != ACTUAL['native_audit_counts'] or expected_counts != postflight.get('native_audit_counts'):
        errors.append('actual/postflight/native audit counts differ')
    if (parent['passed'] != ACTUAL['workflow_reported_passed']
            or gates['observation_gate_passed'] != ACTUAL['observation_gate_passed']
            or gates.get('performance_gates_passed') != ACTUAL['performance_gates_passed']
            or gates.get('rejection_reasons') != ACTUAL['rejection_reasons']
            or gates['controller_rss'].get('passed') != ACTUAL['controller_rss_passed']
            or postflight.get('performance_gates_passed') != ACTUAL['performance_gates_passed']
            or postflight.get('rejection_reasons') != ACTUAL['rejection_reasons']
            or postflight.get('controller_rss_passed') != ACTUAL['controller_rss_passed']):
        errors.append('actual/postflight/original performance outcome differs')
    if (monitor.get('sample_count') != ACTUAL['compiler_monitor_sample_count']
            or postflight.get('compiler_monitor_sample_count') != ACTUAL['compiler_monitor_sample_count']
            or monitor_audit.get('validation', {}).get('validated_sample_count') != ACTUAL['compiler_monitor_sample_count']):
        errors.append('actual/postflight/compiler monitor sample count differs')
    binding(monitor_audit.get('ledger', {}), 'monitor audit ledger')
    if monitor_audit.get('ledger') != parent['compiler_monitor'].get('ledger'):
        errors.append('parent and monitor audit ledger identities differ')
    if postflight.get('normal_lifecycle_path_presence') != namespace:
        errors.append('postflight and captured lifecycle namespaces differ')
    if not postflight.get('lifecycle_nonlaunch_source'):
        errors.append('original coordinator lifecycle nonlaunch source missing')
`;
  s=replace(s,"    cpu_passed = all",extra+"    cpu_passed = all","actual-outcome-reconciliation");
  s=replace(s,"'state': 'not_run_after_original_observation_rejection',",
    "'state': 'not_started_at_capture',\n            'disposition': postflight.get('normal_lifecycle_disposition'),\n            'nonlaunch_source': postflight.get('lifecycle_nonlaunch_source'),\n            'final_outcome': None,","neutral-lifecycle-summary");
  s=replace(s,"'performance_ABBA_established': False, 'saturation_established': False",
    "'performance_ABBA_established': None, 'saturation_established': None","no-future-lifecycle-outcomes");
  s=replace(s,"'causal_attribution': 'No causal diagnosis follows from this single original rejected campaign.'",
    "'causal_attribution': 'This original OBS snapshot does not establish causality or final adoption.'","neutral-scope");
  s=replace(s,'"""Archive the original R35 observation and rejection evidence without rerunning it.',
    '"""Archive the original R35 ordinary OBS snapshot without rerunning it.',"neutral-title");
  need(!/\bRECOVERY(?:_PINS)?\b/.test(s)&&!s.includes("r34-cancel")&&!s.includes("rejected-observation-owner"),"old scope remains");
  return {source:s,transformations:checks};
}
