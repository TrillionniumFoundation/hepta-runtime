# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
def main():
    os.umask(0o077)
    need(ROOT.resolve(strict=True)==ROOT and ROOT.stat().st_uid==os.geteuid() and os.geteuid()!=0,
         'fixed operator root')
    need(Path(__file__).resolve()==ROOT/'postflight_r35_lifecycle_owner_01.py', 'fixed postflight script path')
    out=ROOT/'lifecycle-owner-postflight-01.json'
    need(not os.path.lexists(out), 'create-only owner postflight already exists')
    script_identity=ident(read(Path(__file__).resolve()))
    documents={name:read(ROOT/name,pin) for name,pin in PINS.items()}
    values={name:json.loads(raw) for name,raw in documents.items() if name.endswith('.json')}

    def bound(value,name):
        need(isinstance(value,dict) and value.get('path')==str(ROOT/name), 'original path differs '+name)
        need(type(value.get('bytes')) is int and type(value.get('sha256')) is str, 'original identity missing '+name)
        if name in documents:
            need(ident(documents[name])=={k:value[k] for k in ('bytes','sha256')}, 'reported original identity differs '+name)
        else:
            documents[name]=read(ROOT/name,value)
        return documents[name]

    def closed(rows,names,codes,directory,process_key='owned_process_absent'):
        need([r['name'] for r in rows]==names and len(rows)==len(codes), 'original stage order differs '+directory)
        for row,code in zip(rows,codes):
            need(row['returncode']==code and row['waited_and_reaped'] is True
                 and row[process_key] is True and row['owned_process_group_absent'] is True
                 and row.get('timed_out',False) is False and row.get('cleanup_error') is None,
                 'original owned stage not closed '+row['name'])
            if 'passed' in row: need(row['passed'] is (code==0), 'original stage outcome differs')
            for stream in ('stdout','stderr'):
                bound(row[stream],directory+'/'+row['name']+'.'+stream)

    def holder(prefix,job,parent_sha,passed,code):
        term=values[prefix+'-native-01.json']; page=values[prefix+'-read-01.json']
        native(term,page,job,'succeeded' if code==0 else 'failed',code)
        rows=[json.loads(line) for line in page['stdout']['text'].splitlines() if line]
        owned=values[prefix+'-report-01.json']
        need(len(rows)==2 and rows[0]['phase']=='owned_agent_ready' and rows[0]['identity_count']==5
             and rows[0]['remote_script_sha256']==parent_sha, 'original held-agent readiness differs')
        need(rows[-1]['passed'] is passed and rows[-1]['remote_returncode']==code
             and rows[-1]['owned_agent_reaped'] is True and page['stderr']['text']=='', 'original holder stream differs')
        need(owned['schema']=='hepta-x230-r21-held-agent-campaign/v1' and owned['passed'] is passed
             and owned['remote_returncode']==code and owned['holder_script_sha256']==HOLDER_SHA
             and owned['remote_script_sha256']==parent_sha and owned['finished_utc'], 'original holder report differs')
        need(owned['automatic_ssh_retries']==0 and owned['services_modified'] is False
             and owned['owned_agent_reaped'] is True and owned['owned_agent_directory_absent_after_context'] is True
             and owned['owned_agent_socket_absent_after_context'] is True, 'original held-agent custody not closed')
        return {'job_id':job,'state':term['state'],'exit_code':code,'log_bytes':term['log_bytes'],
                'complete_native_bytes_verified':True,'owned_agent_reaped':True,
                'owned_agent_directory_absent':True,'owned_agent_socket_absent':True}

    def monitor(parent,directory,count):
        row=parent['compiler_monitor']; audit=values[directory+'/compiler-monitor.audit.json']
        need(row['passed'] is True and audit['monitor_sources_unchanged'] is True
             and audit['source_recheck_errors']==[] and audit['validation']['passed'] is True
             and audit['validation']['errors']==[], 'original compiler monitor closure differs')
        bound(row['independent_audit'],directory+'/compiler-monitor.audit.json')
        need(row['ledger']==audit['ledger'], 'original monitor ledger references differ')
        raw=bound(row['ledger'],directory+'/compiler-monitor.json'); ledger=json.loads(raw)
        need(ledger['sample_count']==len(ledger['samples'])==audit['validation']['validated_sample_count']==count,
             'original monitor sample inventory differs')
        for source in row['sources'].values():
            path=Path(source['path']); need(path.is_relative_to(ROOT/'tools-01'), 'monitor source outside fixed tools')
            bound(source,path.relative_to(ROOT).as_posix())
        return count

    def shutdown(row,label):
        need(row['exit_code']==0 and row['shutdown_method']=='stdin_eof'
             and row['observed_descendant_survivors']==[] and row['reader_error'] is None
             and row['unmatched_responses']==0 and row['transport_capture']['reader_eof'] is True
             and row.get('resources',{}).get('sampler_error') is None, 'original normal shutdown not closed '+label)
        return {'label':label,'exit_code':0,'stdin_eof':True,'reader_eof':True,
                'observed_descendant_survivors':[],'original_body_retained':True}

    qualified=values['qualification-01/report.json']; source_map=values['qualification-01/source-map.json']
    preparation=values['preparation.json']; qsummary=values['qualification-01/isolated-tests/summary.json']
    native(values['qualification-terminal-status-01.json'],values['qualification-native-read-01.json'],
           JOBS['qualification'],'succeeded',0)
    need(qualified['schema']=='hepta-x230-composed-qualification/v1' and qualified['qualified'] is True
         and qualified['finished_utc'] and not qualified.get('error') and qualified['jobs']==2
         and qualified['automatic_test_retries']==0 and qualified['service_changes'] is False
         and qualified['source']==str(ROOT/'source'), 'original qualification did not succeed')
    need([r['name'] for r in qualified['stages']]==Q_STAGES
         and all(r['returncode']==0 for r in qualified['stages']), 'original eight qualification stages differ')
    need(qualified['source_after']==qualified['source_tested']==source_map and len(source_map)==220,
         'original qualified source map differs')
    harness=qualified['harness_before']
    need(harness==qualified['harness_after'] and len(harness)==19, 'original nineteen harness inputs differ')
    need(preparation['schema']=='hepta-x230-r35-preparation/v1' and preparation['passed'] is True
         and preparation['qualification_started'] is True and preparation['qualification_returncode']==0
         and preparation['qualification_report_sha256']==PINS['qualification-01/report.json']['sha256']
         and preparation['source_after_qualification']==source_map and preparation['automatic_retries']==0,
         'original preparation/qualification binding differs')
    need(qsummary['schema']=='hepta-isolated-libtest/v1' and qsummary['success'] is True
         and qsummary['enumeration_errors']==[] and {k:qsummary[k] for k in COUNTS}==COUNTS,
         'original qualification counts differ')
    ci=values['rust-ci-01/report.json']; ciaudit=values['rust-ci-01/nextest-output-audit.json']
    native(values['rust-ci-native-01.json'],values['rust-ci-native-read-01.json'],JOBS['exact_ci'],'succeeded',0)
    need(ci['schema']=='hepta-r35-external-rust-ci/v1' and ci['passed'] is True and ci['finished_utc']
         and not ci.get('error') and ci['owned_children_closed'] is True and ci['source_inputs_unchanged'] is True
         and ci['automatic_retries']==0 and ci['original_qualification_job_id']==JOBS['qualification'],
         'original exact-CI closure differs')
    closed(ci['stages'],['cargo-version','rustc-version','nextest-version','cargo-check','nextest-list','nextest-run'],
           [0]*6,'rust-ci-01')
    need(ci['nextest_output_audit']==ciaudit and ciaudit['verified'] is True
         and {k:ciaudit[k] for k in COUNTS}==COUNTS, 'original exact-CI audit/counts differ')

    obs=values['campaign-01/report.json']; obs_gates=values['campaign-01/summary.json']
    obs_holder=holder('observation-holder',JOBS['observation'],OBS_PARENT_SHA,True,0)
    need(obs['schema']=='hepta-r25-observation-campaign-control/v1' and obs['passed'] is True
         and obs['finished_utc'] and not obs.get('error') and obs['launcher_sha256']==OBS_PARENT_SHA,
         'original observation parent differs')
    need(all(obs[k] is True for k in ('inputs_unchanged','source_inputs_unchanged','baseline_source_inputs_unchanged',
         'measurement_attribution_valid','correctness_stages_completed','observation_gate_passed')),
         'original observation/source closure differs')
    need(obs_gates['schema']=='hepta-r25-observation-gates/v1'
         and all(obs_gates[k] is True for k in ('correctness_verified','evidence_verified',
                 'observation_gate_passed','performance_gates_passed'))
         and obs['rejection_reasons']==obs_gates['rejection_reasons']==[], 'original observation gates differ')
    closed(obs['stages'],OBS_STAGES,[0]*7,'campaign-01')
    obs_audit=values['campaign-01/native-observation/independent-summary.json']
    need(obs_audit['verified'] is True and obs_audit['original_sha256']==PINS['campaign-01/native-observation/report.json']['sha256']
         and obs_audit['original_bytes']==PINS['campaign-01/native-observation/report.json']['bytes']
         and {k:obs_audit[k] for k in OBS_COUNTS}==OBS_COUNTS, 'original observation raw/audit differs')
    observation_monitor_count=monitor(obs,'campaign-01',301)

    lc=values['lifecycle-campaign-01/report.json']; normal=values['lifecycle-abba-01/report.json']
    index=values['lifecycle-abba-01/round-index.json']; gates=values['lifecycle-abba-01/gates.json']
    descriptive=values['lifecycle-abba-01/summary.json']; tool_tests=values['lifecycle-tool-tests-01/report.json']
    lc_holder=holder('lifecycle-holder',JOBS['normal_lifecycle'],LC_PARENT_SHA,False,1)
    native(values['lifecycle-materialization-native-01.json'],values['lifecycle-materialization-read-01.json'],
           JOBS['lifecycle_materialization'],'succeeded',0)
    need(lc['schema']=='hepta-r35-normal-lifecycle-campaign-control/v1' and lc['passed'] is False
         and lc['adoption_passed'] is False and lc['finished_utc'] and lc['launcher_sha256']==LC_PARENT_SHA,
         'original rejected lifecycle parent differs')
    need(all(lc[k] is True for k in ('inputs_unchanged','source_inputs_unchanged','baseline_source_inputs_unchanged',
         'measurement_attribution_valid')) and lc['automatic_retries']==0 and lc['production_services_modified'] is False
         and not lc.get('finalization_error') and lc['open_blockers']==[], 'original lifecycle finalization did not close')
    closed(lc['stages'],['lifecycle-tool-tests','normal-lifecycle-abba'],[0,1],'lifecycle-campaign-01')
    need(lc['binaries']==obs['binaries'] and lc['binaries']['B']==BINARIES, 'original LC/OBS retained programs differ')
    for name,pin in BINARIES.items():
        need(qualified['binaries'][name]['path']==pin['path'] and qualified['binaries'][name]['sha256']==pin['sha256'],
             'retained LC program differs from original qualification')
    lc_input=values['lifecycle-inputs-01.json']
    bound(lc['input_receipt'],'lifecycle-inputs-01.json')
    need(lc_input['schema']=='hepta-r25-lifecycle-inputs/v1' and lc_input['attempt']=='01'
         and lc_input['launcher_sha256']==LC_PARENT_SHA
         and lc['source_inputs_sha256']==lc_input['source_inputs_sha256']==obs['source_inputs_sha256']
         and lc['baseline_source_inputs_sha256']==obs['baseline_source_inputs_sha256'], 'original LC/OBS input source binding differs')
    need(normal['schema']=='hepta-r25-lifecycle-abba-control/v1' and normal['passed'] is False
         and normal['order']=='ABBA' and normal['automatic_retries']==0 and normal['inputs_unchanged'] is True
         and normal['finished_realtime_ns'], 'original normal ABBA outcome differs')
    closed(normal['stages'],NORMAL_STAGES,[0]*9+[1],'lifecycle-abba-01','proc_absent')
    need(index['schema']=='hepta-r25-lifecycle-round-index/v1' and index['closed'] is True
         and index['order']=='ABBA' and index['round_count']==len(index['rounds'])==4 and index['automatic_retries']==0
         and all(index[k]==normal[k] for k in ('rounds','baseline','candidate','tools_manifest','plan')),
         'original closed ABBA index differs')
    need(normal['baseline']==lc['binaries']['A']['hepta-runtime'] and normal['candidate']==BINARIES['hepta-runtime'],
         'original ABBA runtime arms differ')
    need(descriptive['verified'] is True and descriptive['round_index_sha256']==PINS['lifecycle-abba-01/round-index.json']['sha256']
         and gates['schema']=='hepta-r25-lifecycle-gates/v1' and gates['verified'] is True and gates['passed'] is False
         and gates['normal_lifecycle_descriptive_verified'] is True and gates['automatic_retries']==0,
         'original verified-but-rejected LC gate differs')
    bound(gates['round_index'],'lifecycle-abba-01/round-index.json')
    bound(gates['gate_policy'],'lifecycle-tools-01/lifecycle-gate-policy.json')
    need(tool_tests['passed'] is True and tool_tests['tests_run']==14
         and tool_tests['skipped']==tool_tests['errors']==tool_tests['failures']==0, 'original 14 tool tests differ')
    shutdowns=[]; round_counts=[]
    for number,arm in enumerate('ABBA'):
        entry=index['rounds'][number]; directory='lifecycle-abba-01/round-%d-%s'%(number,arm)
        need(entry['index']==number and entry['arm']==arm and entry['directory']==directory.split('/')[-1],
             'original round path/order differs')
        raw=bound(entry['report'],directory+'/report.json'); report=json.loads(raw)
        audit_raw=bound(entry['independent_analysis'],directory+'/independent-summary.json'); audit=json.loads(audit_raw)
        need(report['passed'] is True and report['automatic_rpc_retries']==0
             and report['candidate_sha256']==lc['binaries'][arm]['hepta-runtime']['sha256']
             and audit['schema']=='hepta-six-host-cancel-recovery-independent-verification/v2' and audit['verified'] is True
             and audit['source_sha256']==ident(raw)['sha256'] and audit['source_bytes']==len(raw)
             and audit['candidate_sha256']==report['candidate_sha256'], 'original round/audit closure differs')
        need(len(entry['phase_files'])==11 and {Path(p['path']).name for p in entry['phase_files']}==set(PHASE_FILES),
             'original eleven-phase inventory differs')
        for phase in entry['phase_files']: bound(phase,directory+'/'+Path(phase['path']).name)
        row={k:audit[k] for k in LC_COUNT_KEYS}; need(all(type(v) is int and v>=0 for v in row.values())
             and row['automatic_rpc_retries']==0, 'original lifecycle audit counts malformed')
        round_counts.append({'round':number,'arm':arm,'counts':row})
        for phase in ('shutdown','after_cancel_shutdown'): shutdowns.append(shutdown(report[phase],directory+'/'+phase))
    counts={k:sum(row['counts'][k] for row in round_counts) for k in LC_COUNT_KEYS}
    need(counts==LC_COUNTS and len(shutdowns)==8, 'original full lifecycle counts/cleanup differ')
    lifecycle_monitor_count=monitor(lc,'lifecycle-campaign-01',149)
    false_flags=[{'comparison':name,'gate':gate,'adoption_required':row['adoption_required']}
                 for name,row in gates['comparisons'].items() for gate,passed in row['gates'].items() if passed is False]
    required_failures=[row for row in false_flags if row['adoption_required'] is True]
    need(required_failures==[{'comparison':'concurrent_cancel','gate':'throughput','adoption_required':True}],
         'original required LC rejection differs')
    compact=values['lifecycle-evidence-01.compact.json']; manifest=values['lifecycle-evidence-01.manifest.json']
    need(manifest['summary']==compact and compact['archived_receipt_binding_errors']==[]
         and compact['original_lifecycle_holder_job_id']==JOBS['normal_lifecycle']
         and compact['workflow_reported_passed'] is False and compact['normal_lifecycle_gate_passed'] is False
         and compact['counts']['original_audit_count_sums']==counts
         and compact['all_four_rounds_and_eight_standard_shutdowns_observed'] is True
         and compact['all_observed_standard_shutdowns_clean'] is True, 'original LC archive compact differs')

    def snapshot():
        names={'Cargo.toml','Cargo.lock','rustfmt.toml'}|{p.relative_to(ROOT/'source').as_posix()
              for sub in ('src','examples') for p in (ROOT/'source'/sub).rglob('*') if p.is_file()}
        need(names==set(source_map) and sum(n.endswith('.py') for n in names)==17, 'current compiler input membership differs')
        current={}
        for name,digest in source_map.items():
            p=Path(name); need(not p.is_absolute() and '..' not in p.parts, 'unsafe compiler input path')
            current[name]=ident(read(ROOT/'source'/p)); need(current[name]['sha256']==digest, 'current source differs '+name)
        source_snapshot=values['lifecycle-campaign-01/source-inputs.json']
        need(source_snapshot['file_count']==220 and source_snapshot['files']==current
             and source_snapshot['sha256']==lc['source_inputs_sha256'], 'current source differs from original LC snapshot')
        directory=ROOT/'source/tools/x230/20261028'
        names={p.name for p in directory.glob('*.py')}
        need(names==set(harness), 'current original harness membership differs')
        current_harness={name:ident(read(directory/name))['sha256'] for name in sorted(names)}
        need(current_harness==harness, 'current original qualification harness changed')
        retained={}
        for name,pin in BINARIES.items():
            path=ROOT/'qualification-01'/name; need(pin['path']==str(path), 'unexpected retained program path')
            retained[name]={'path':str(path),**ident(read(path,pin,16*1024*1024))}
        return {'source_files':current,'harness_sha256':current_harness,'retained_release_programs':retained}

    cache=ROOT/'target-build'
    need(cache.resolve(strict=True)==cache and cache.is_dir() and cache.stat().st_uid==os.geteuid(),
         'original cache location differs')
    cache_before=cache.stat(); before=snapshot()
    for name,raw in list(documents.items()): read(ROOT/name,ident(raw))
    after=snapshot(); cache_after=cache.stat()
    need(before==after and (cache_before.st_dev,cache_before.st_ino)==(cache_after.st_dev,cache_after.st_ino),
         'source/harness/retained programs or cache identity changed during postflight')
    read(Path(__file__).resolve(),script_identity)
    originals={name:{'path':str(ROOT/name),**ident(raw)} for name,raw in sorted(documents.items())}
    report={
        'schema':'hepta-r35-rejected-lifecycle-owner-postflight/v1',
        'captured_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'snapshot_scope':'After the original completed rejected normal LC; prior OBS snapshot remains unchanged',
        'postflight_script':{'path':str(Path(__file__).resolve()),**script_identity},
        'postflight_job_id_from_supervisor':os.environ.get('HEPTA_RUNTIME_JOB_ID'),
        'cache_owner':str(ROOT),'cache_path':str(cache),'cache_moved':False,'cache_deleted':False,
        'cache_directory_identity':{'device':cache_before.st_dev,'inode':cache_before.st_ino,
            'mtime_ns_decimal':str(cache_before.st_mtime_ns),'ctime_ns_decimal':str(cache_before.st_ctime_ns)},
        'current_machine_idle_claimed':False,'future_preparer_must_check_cache_referencing_processes':True,
        'current_source_matches_qualified_map':True,'compiler_input_count':220,'embedded_python_input_count':17,
        'qualification_harness_count':19,'qualification_harness_matches_original':True,
        'qualification_harness_sha256':before['harness_sha256'],
        'retained_release_program_count':3,'retained_release_programs':before['retained_release_programs'],
        'source_harness_and_retained_programs_rechecked_before_output':True,
        'original_qualification_job_id':JOBS['qualification'],'qualification_completed':True,'qualification_counts':COUNTS,
        'original_exact_ci_job_id':JOBS['exact_ci'],'exact_ci_closed':True,'exact_ci_counts':COUNTS,
        'original_observation_job_id':JOBS['observation'],'observation_workflow_closed':True,
        'observation_gate_passed':True,'observation_performance_passed':True,'observation_rejection_reasons':[],
        'observation_holder':obs_holder,'observation_native_audit_counts':OBS_COUNTS,
        'observation_compiler_monitor_sample_count':observation_monitor_count,
        'lifecycle_materialization_started':True,'original_lifecycle_materializer_job_id':JOBS['lifecycle_materialization'],
        'normal_lifecycle_started':True,'original_normal_lifecycle_job_id':JOBS['normal_lifecycle'],
        'normal_lifecycle_workflow_closed':True,'normal_lifecycle_controllers_closed':True,
        'normal_lifecycle_reported_workflow_passed':False,'normal_lifecycle_reported_adoption_passed':False,
        'normal_lifecycle_gate_verified':True,'normal_lifecycle_gate_passed':False,
        'normal_lifecycle_disposition':'Rejected by the unchanged original required normal-lifecycle gate',
        'normal_lifecycle_required_failed_flags':required_failures,'normal_lifecycle_all_reported_false_flags':false_flags,
        'lifecycle_holder':lc_holder,'normal_lifecycle_rounds':4,'normal_lifecycle_counts':counts,
        'normal_lifecycle_original_audit_counts_by_round':round_counts,
        'normal_lifecycle_standard_shutdown_count':8,'normal_lifecycle_shutdowns':shutdowns,
        'normal_lifecycle_tool_tests_passed':14,'normal_lifecycle_compiler_monitor_sample_count':lifecycle_monitor_count,
        'lifecycle_archive_whole_file_identity_rechecked':True,'archive_member_verifier_reexecuted':False,
        'lifecycle_archive_identity':originals['lifecycle-evidence-01.tar.gz'],
        'candidate_adopted':False,'accepted_baseline_commit':'baab4def80be7af015b2e7a594cb302f66c4130e',
        'originals':originals,'tests_benchmarks_or_auditors_reexecuted':False,
        'original_observation_postflight_modified':False,'new_workloads_started':0,
    }
    body=(json.dumps(report,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
    identity=create(out,body)
    print(json.dumps({'receipt':identity,**report},sort_keys=True),flush=True)


if __name__=='__main__':
    main()
