#!/usr/bin/env python3
"""Bind closed R21 qualification, campaign and Mac evidence, preserving rejection."""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
inputs = {}

def read(name, relative, expected=None):
    p = ROOT / relative
    b = p.read_bytes()
    h = hashlib.sha256(b).hexdigest()
    if expected:
        assert h == expected, (name, h)
    inputs[name] = {'source': str(p), 'size': len(b), 'sha256': h,
                    'git_blob_sha1': hashlib.sha1(('blob ' + str(len(b)) + '\0').encode() + b).hexdigest()}
    return json.loads(b) if p.suffix == '.json' else b

qc = read('qualification_control', 'r21/actual-qualification-01/control-report.json', 'e664d6c75572d590df4537fc47cfddc1b66b7f1aeba100a5b7e542bcdf43e1b1')
qa = read('qualification_acceptance', 'r21/actual-qualification-01/independent-acceptance-01.json', '950a3e0d905e12937fa94ed4f9c4ad138e4797e5e4276abc19bc6c208a2a59a1')
ql = read('qualification_local_closure', 'r20/audit-python/r21-qualification-download-01/closure-01.json', '01a3d29fc897b4af034ed90a936a225fcc4ed41c82f4e566a358dd9f50c1c34d')
qs = read('qualified_candidate_source_binding', 'r20/audit-python/audit-tools/r21-qualified-source-binding-01.json', 'be700abc4b1ed1f69e166a5a2bd5af8c5288da6afaba8574a8ff2274ba2b840d')
cc = read('campaign_control', 'r21/campaign-download-01/preexport/report.json', 'd4f7fbe92f16aaa6a16c9ed4dc11d522dcb7ebadc29234db7c6096b63819bb4c')
cx = read('campaign_control_archived_copy', 'r21/campaign-download-01/extracted/r21/campaign-control-01/report.json', inputs['campaign_control']['sha256'])
cr = read('campaign_offline_replay', 'r21/campaign-replay-01/report.json', '9e149837a638bddf40d77c6d4e370f8d2c3f5946a91e373ce92b18d7da119666')
br = read('boundary_offline_summary', 'r21/campaign-replay-01/boundary.json', '70838a999468acc180429f0323b92052dfede44210575eb32b022f63dddea32c')
lc = read('lifecycle_control', 'r21/campaign-download-01/extracted/r21/lifecycle-abba-01/report.json', 'f971a8739c1bea46cbf17b5a30df6487066e6469fcbccc294cd379a8c0b5fa90')
metrics = read('closed_metrics_projection', 'r21/campaign-metrics-02/metrics-01.json', '113299b455ac6fc8f3d49132bd1713c11d5c58f417ad3fd7b79ca64821d8707a')
ma = read('mac_holder_offline_audit', 'r21/audit-harness/mac-holder-download-01/independent-verification-01.json', 'f38356e2a9e16e97cefd8ea4a507e62095b3c88eebc4b867aa570f87a39dfc44')
mr = read('mac_holder_report', 'r21/audit-harness/mac-holder-download-01/extracted/campaign-01/report.json', '085d95d9f8aad6c23fb70a69f0860d0f16798f0f05c260776f44a91f7f967c6e')
bootstrap = read('mac_actual_bootstrap', 'r21/audit-harness/mac-holder-download-01/extracted/campaign-01/remote-script.py', 'de42d946174b996d14c5e04892c0eeea9436d578d7ded6e2f8c0298b8bf5d0b1')
forwarded = read('mac_foreground_stdout', 'r21/audit-harness/mac-holder-download-01/extracted/campaign-01/forwarded.stdout', '075c84581d13ee9d174c27abb2cf18c143518b91803c274e016bf018523892e9')
footer = json.loads(forwarded.decode().splitlines()[-1])
chain = read('actual_component_chain', 'r21/component-chain-01.json', '29542f436269549936ecc24cd5d65b7f994200ede963f4b4cf9c4556483644b8')
campaign_handoff = read('campaign_closed_handoff', 'r21/evidence-operations/handoff-01.json', 'be00e4dab044b67e926f12ed7d42a917610d344cf299d1dc820d424664aa2268')
mac_handoff = read('mac_closed_handoff', 'r21/audit-harness/mac-holder-download-01/handoff-01.json', '40b6f2e573ef7498c1644130593d6086c401086a71426caa4612beee5042fdcb')
for key, relative, expected in [
    ('qualification_archive', 'r20/audit-python/r21-qualification-download-01/qualification.tar.gz', '2cacd53aa32fa1a81620284ca0f0c60a282b1e7bd3ba47b7401a65b8101bd667'),
    ('campaign_archive', 'r21/campaign-download-01/campaign-evidence-01.tar.gz', 'f899f7a4140154db2bf74641c9e64d768852b9b072ca67c5a8d3ab50648c1b26'),
    ('mac_archive', 'r21/audit-harness/mac-holder-download-01/holder-01.tar.gz', 'bbab5b09ddd974f042a20e1265b85f6bded98715f74eb656cb571f28b2aec436')]:
    if key == 'mac_archive' and not (ROOT / relative).exists():
        matches = [p for p in (ROOT / 'r21/audit-harness/mac-holder-download-01').glob('*.tar.gz') if hashlib.sha256(p.read_bytes()).hexdigest() == expected]
        assert len(matches) == 1
        relative = str(matches[0].relative_to(ROOT))
    read(key, relative, expected)

def stage_closed(stage, path_field, group_field):
    return (stage['returncode'] == 0 and stage['waited_and_reaped'] is True
            and stage[path_field] is True and stage[group_field] is True)

runtime = '7709579269d5c7ec1eba8512dd7cc028ecc602c08156f8172a15203080e39878'
checks = {
    'qualification_actual_control_acceptance_source_bound': qc['passed'] is True and qa['accepted'] is True and qs['passed'] is True and len(qa['checks']) == 31 and all(qa['checks'].values()) and len(qs['checks']) == 12 and all(qs['checks'].values()),
    'qualification_counts_and_no_retries_preserved': qc['test_counts'] == {'passed':1637,'failed':0,'ignored':33,'selected':1670} and qc['automatic_retries'] == 0,
    'qualification_owned_stages_reaped': len(qc['stages']) == 2 and all(stage_closed(s, 'proc_absent', 'process_group_absent') for s in qc['stages']),
    'qualification_all_raw_offline_checks_passed': ql['passed'] is True and ql['checks'] == {'export': {'all_true':True,'count':9}, 'raw_replay':{'all_true':True,'count':6}, 'source_binding':{'all_true':True,'count':12}} and ql['raw_commands'] == 1647 and ql['raw_streams'] == 3294 and ql['all_four_owned_local_stage_children_waited_and_reaped'] is True,
    'campaign_start_bound_to_actual_qualification_and_bootstrap': cc['expected_startup_hashes'] == {'expected_acceptance_sha256': inputs['qualification_acceptance']['sha256'], 'expected_control_report_sha256':inputs['qualification_control']['sha256'], 'expected_qualification_report_sha256':qa['qualified_report_sha256'], 'expected_candidate_sha256':runtime} and cc['mac_stdin_source_sha256'] == inputs['mac_actual_bootstrap']['sha256'] == mr['remote_script_sha256'],
    'campaign_complete_correctness_and_input_identity': cc == cx and cc['passed'] is True and cc['all_input_hashes_preserved'] is True and cc['all_correctness_stages_passed'] is True,
    'campaign_five_owned_stages_reaped_without_retry': len(cc['stages']) == 5 and all(stage_closed(s, 'proc_path_absent','process_group_absent') and s['automatic_retry'] is False and s['pre_gate_passed'] is True and s['post_gate_passed'] is True for s in cc['stages']),
    'lifecycle_nine_owned_stages_reaped_without_retry': len(lc['stages']) == 9 and all(stage_closed(s, 'proc_absent','owned_process_group_absent') and s['automatic_retry'] is False for s in lc['stages']),
    'offline_campaign_all_seven_original_results_exact': cr['passed'] is True and len(cr['audits']) == 7 and all(a['passed'] is True and a['equals_original_analysis'] is True and a['returncode'] == 0 and a['waited_and_reaped'] is True and a['automatic_retry'] is False for a in cr['audits']) and cr['all_original_payloads_unchanged'] is True,
    'no_offline_workloads_or_retries': cr['workloads_run'] is False and cr['builds_run'] is False and cr['network_requests'] == 0 and cr['automatic_retries'] == 0 and cc['automatic_campaign_retries'] == cc['automatic_stage_retries'] == cc['automatic_rpc_retries'] == 0,
    'native_counts_and_original_rejection_preserved': cr['native_counts']['matches'] is True and cr['native_counts']['actual'] == {'failed_calls':0,'measured_calls':2304,'preflight_restart_calls':72,'total_calls':2664,'warmup_calls':288} and cc['native_regression_screen_passed'] is False and cr['native_regression_screen_passed'] is False and metrics['native_regression_screen_passed'] is False and cc['native_regression_screen'] == cr['native_regression_screen'] == metrics['native_regression_screen'],
    'boundary_exact_success_refusal_and_recovery': br['evidence_verified'] is True and br['diagnostic_passed'] is True and br['drain_and_recovery_passed'] is True and br['counts'] == {'success':32,'capacity_rejection':32,'other_error':0} and br['automatic_rpc_retries'] == 0 and br['topology']['physical_machine_groups'] == 6,
    'lifecycle_actual_counts_verified': cr['lifecycle']['verified'] is True and cr['lifecycle']['round_count'] == 4 and cr['lifecycle']['total_new_starts'] == 24 and cr['lifecycle']['total_same_key_lookups'] == cr['lifecycle']['total_cancellations'] == 48,
    'mac_exact_package_and_24_independent_checks': ma['passed'] is True and len(ma['checks']) == 24 and all(ma['checks'].values()) and ma['holder_report_sha256'] == inputs['mac_holder_report']['sha256'] and ma['archive_sha256'] == inputs['mac_archive']['sha256'],
    'mac_holder_remote_success_and_cleanup_observed': mr['passed'] is True and mr['remote_returncode'] == 0 and mr['owned_agent_reaped'] is True and mr['owned_agent_directory_absent_after_context'] is True and mr['owned_agent_socket_absent_after_context'] is True and ma['export_cleanup_metadata_absent'] is True,
    'mac_footer_cross_bound_without_invented_remote_hash': footer == ma['forwarded_final_line'] and footer['passed'] is cc['passed'] and footer['native_regression_screen_passed'] is cc['native_regression_screen_passed'] and footer['report'] == '/home/qian/hepta-runtime-optimization-20261105-r21/campaign-control-01/report.json' and ma['x230_report_sha256'] is None and ma['x230_report_bytes_read'] is False,
    'no_machine_or_production_service_changes': cc['production_service_changes'] is False and cc['machine_settings_changed'] is False and type(cc['builds_started']) is int and cc['builds_started'] == 0 and mr['services_modified'] is False,
    'final_own_compiler_snapshot_idle': cc['final_compiler_check']['idle'] is True and all(v['original_identity_absent'] is True for v in cc['final_compiler_check']['recorded_processes']) and cc['final_compiler_check']['signals_sent'] == 0,
    'candidate_and_retained_source_are_distinct': qs['candidate_trees_recomputed']['src'] == '5f814d4faa80b87cfb3a34ca38275664444c0883' and qs['baseline_src_tree'] == '3aa8c9aadbf42b6a0ebdac3954bd1e64b4055e20' and qs['final_was_directly_coldprocess_tested'] is False,
    'metric_projection_closed_without_new_measurements': metrics['passed_projection'] is True and metrics['all_projection_inputs_unchanged'] is True and metrics['workloads_or_auditors_run_here'] is False,
    'campaign_transport_closed_and_writer_stopped': campaign_handoff['completed'] is True and campaign_handoff['this_agent_local_running_writers'] == 0 and campaign_handoff['this_agent_remote_inflight'] == 0 and campaign_handoff['archive_download_chunks'] == 80 and campaign_handoff['archive_download_errors'] == campaign_handoff['archive_download_retries'] == 0,
    'qualification_transport_closed': ql['download']['all_remote_calls_awaited_and_finished'] is True and ql['download']['remaining_remote_calls'] == ql['download']['errors'] == ql['download']['automatic_retries'] == 0,
}
assert all(v is True for v in checks.values()), {k:v for k,v in checks.items() if v is not True}
out = {
    'schema':'hepta-r21-final-evidence-orchestration/v1',
    'closed_utc': datetime.now(timezone.utc).isoformat(),
    'evidence_closed':True, 'candidate_adopted':False, 'native_regression_screen_passed':False,
    'decision':'Reject R21 composite and both previously rejected hash-buffer candidates; retain accepted R19 compiled source.',
    'evidence_checks':checks, 'inputs':inputs,
    'qualification':{'passed':True,'actual_counts':qc['test_counts'],'automatic_retries':0,'actual_binaries':qc['binaries'],'control':inputs['qualification_control'],'acceptance':inputs['qualification_acceptance'],'source_binding':inputs['qualified_candidate_source_binding'],'offline_closure':inputs['qualification_local_closure'],'archive':inputs['qualification_archive'],'archive_members':3365,'payload_files':3364,'omitted_elf_witnesses':8},
    'campaign':{'correctness_passed':True,'native_regression_screen_passed':False,'control':inputs['campaign_control'],'offline_replay':inputs['campaign_offline_replay'],'metrics':inputs['closed_metrics_projection'],'archive':inputs['campaign_archive'],'archive_members':5380,'payload_files':5379,'omitted_elf_witnesses':9,'native_counts':cr['native_counts']['actual'],'native_regression_screen':cr['native_regression_screen'],'boundary_counts':br['counts'],'boundary_drain_recovery_passed':True,'lifecycle_counts':metrics['lifecycle_counts'],'original_analysis_entries':7,'automatic_campaign_retries':0,'automatic_rpc_retries':0,'quiescence_seconds':cc['quiescence']['elapsed_seconds'],'stages':[{'name':s['name'],'seconds':s['seconds'],'returncode':s['returncode'],'waited_and_reaped':s['waited_and_reaped'],'proc_path_absent':s['proc_path_absent'],'process_group_absent':s['process_group_absent']} for s in cc['stages']]},
    'mac_holder':{'passed':True,'audit_checks':24,'archive':inputs['mac_archive'],'report':inputs['mac_holder_report'],'audit':inputs['mac_holder_offline_audit'],'bootstrap':inputs['mac_actual_bootstrap'],'holder_script_sha256':mr['holder_script_sha256'],'forwarded_stdout':inputs['mac_foreground_stdout'],'footer':footer,'remote_returncode':0,'owned_agent_returncode':mr['owned_agent_returncode'],'owned_agent_reaped':True,'owned_socket_and_directory_absent':True,'foreground_reap_scope':ma['foreground_reap_scope'],'mac_exporter_read_x230_report':False,'cross_package_binding_scope':'Root hashes the independently received X230 report; the Mac footer binds path, result and original bootstrap, not a remote report digest. Host clocks are not used to infer cross-machine ordering.'},
    'source_decision':{'retained_commit':'acdd07363cbff335e50c2944e02143d44ab03d6b','retained_src_tree':'3aa8c9aadbf42b6a0ebdac3954bd1e64b4055e20','qualified_rejected_src_tree':qs['candidate_trees_recomputed']['src'],'compiled_source_changes_planned':False,'production_deployment_performed':False,'actual_publication_tree_verified_here':False,'publication_commit':None,'verification_scope':'Publication tree/commit/ref checked separately after creating the docs/tools-only tree; this pre-publication record does not invent its future commit.'},
    'publication_catalog_scope':'The final catalog binds this report and the local-review archive after freezing. This report intentionally contains neither its own identity nor a hash of the archive that contains it.',
    'limitations':['Finite ABBA screening is not a statistical confidence interval or global optimum proof.','The unchanged READ maximum is retained; no cause of that latency was established.','ELF bodies were not downloaded or rehashed locally; exact full remote hashes and accepted paths/sizes are bound.','Source provenance inherits 218 unchanged leaf SHA-to-Git associations from published R19 proof.','Controller CPU excludes SSH/remote CPU; sampled tree RSS is incomplete and may double-count shared pages.','No maximum sustained start rate, admission identity peak, or stable memory reduction is claimed.']
}
target = ROOT / 'r21/publication/reviews/orchestration-final-01.json'
with target.open('x') as stream:
    json.dump(out, stream, sort_keys=True, ensure_ascii=False, indent=2);stream.write('\n')
print(json.dumps({'passed':True,'checks':len(checks),'path':str(target),'bytes':target.stat().st_size,'sha256':hashlib.sha256(target.read_bytes()).hexdigest()}))
