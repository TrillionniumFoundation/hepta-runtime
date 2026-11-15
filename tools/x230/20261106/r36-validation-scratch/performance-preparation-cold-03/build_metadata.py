#!/usr/bin/env python3
"""AST and byte-only source package assembly; never import generated tools."""
import ast
import hashlib
import json
import os
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = '/home/qian/hepta-runtime-validation-scratch-20261106-r36-cold-02'
OLD = '/home/qian/hepta-runtime-optimization-20261106-r35'
PROFILE = '/home/qian/hepta-runtime-phase-cost-20261106-d1/c1-observation-01/profile/profile.json'
PROFILE_SHA = 'ed680dc1613e4aea4de99336d21009c73e71554694edbe23f9dc3a433b586e89'
TOPOLOGY_SHA = 'c131f12bd145d53bd2c26d0917411a41e6e85d19a6273fc19d0ef3744d23658e'
MAC = '/Users/qianqi/work/hepta-runtime-r36-validation-scratch-cold-02-parent-01'
STAGES = ['format', 'fmt-check', 'harness-tests', 'clippy', 'test-build',
          'isolated-tests', 'audit-isolated-tests', 'release']
CHANGED = {'src/mcp/runtime/ssh_observation_profile.rs',
           'src/mcp/runtime/ssh_observation_reference_tests.rs'}


def need(value, reason):
    if not value:
        raise ValueError(reason)


def ident(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def create(path, raw):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def funcs(text):
    return {node.name: ast.get_source_segment(text, node)
            for node in ast.parse(text).body if isinstance(node, ast.FunctionDef)}


def normalize(text):
    return text.replace(ROOT, OLD).replace('r36', 'r35').replace('R36', 'R35')


def rewritten(value):
    if isinstance(value, str):
        return value.replace(OLD, ROOT).replace('r35', 'r36').replace('R35', 'R36')
    if isinstance(value, list):
        return [rewritten(item) for item in value]
    if isinstance(value, dict):
        return {key: rewritten(item) for key, item in value.items()}
    return value


def main():
    original = (HERE / 'reference/r35_campaign.py').read_text()
    parent = (HERE / 'generated/r36_campaign.py').read_text()
    lifecycle = (HERE / 'generated/r36_lifecycle_campaign.py').read_text()
    old_lifecycle = (HERE / 'reference/r35_lifecycle_campaign.py').read_text()
    old_marker = original.index('"""R35-specific receipt checks, inserted into the unchanged campaign parent.')
    new_marker = parent.index('R36_PREPARATION_SEAL = None')
    restored_prefix = normalize(parent[:new_marker])
    restored_prefix = restored_prefix.replace(PROFILE,
        '/home/qian/hepta-runtime-optimization-20261023/r11-native-observation-abba-20261103-02/profile/profile.json')
    restored_prefix = restored_prefix.replace(PROFILE_SHA, 'fe1e9551b5b8812ad6ed3da018c282b7261f7caeb2f49e4dcfefba7ff784ab08')
    restored_prefix = restored_prefix.replace(TOPOLOGY_SHA, '8c0767d3318131a7d470d9cde8e327a59ce18adf022c8bc1b1d5a0fa9a865287')
    restored_prefix = restored_prefix.replace('TOPOLOGY = ROOT / "measurement-fixtures-01/topology.json"',
                                             'TOPOLOGY = R16 / "benchmark-topology.json"')
    restored_prefix = restored_prefix.replace('FROZEN_JOBS = ROOT / "measurement-fixtures-01/jobs"',
        'FROZEN_JOBS = Path("/home/qian/hepta-runtime-optimization-20261023/a31-frozen-originals-r01")')
    need(restored_prefix == original[:old_marker], 'nonbinder prefix differs beyond declared fixture/root changes')
    old_suffix = original[original.index('def commands('):]
    new_suffix = parent[parent.index('def commands('):]
    restored_suffix = normalize(new_suffix.replace('    require_r36_preparation_seal()\n', '', 1)
        .replace('"s36-cancel-recovery-"', '"r35-cancel-recovery-"').replace('"hs36"', '"h35"'))
    need(restored_suffix == old_suffix, 'original seven-stage control/measurement suffix differs')
    restored_lifecycle = normalize(lifecycle.replace('    parent.require_r36_preparation_seal()\n', '', 1)
                                   .replace('/home/qian/s36lc1', '/home/qian/r35lc1'))
    need(restored_lifecycle == old_lifecycle, 'normal lifecycle changed beyond namespace and unsealed guard')
    for name in ('prepare_campaign_inputs.py', 'prepare_lifecycle_inputs.py'):
        need(normalize((HERE / 'generated' / name).read_text()) == (HERE / 'reference' / name).read_text(),
             'original materializer changed: ' + name)
    first, second = funcs(original[:old_marker]), funcs(restored_prefix)
    need(set(first) == set(second) and all(first[name] == second[name] for name in first),
         'general parent helper changed')
    old_installer = funcs((HERE / 'reference/install_measurement_tools.py').read_text())
    new_installer = funcs((HERE / 'generated/install_measurement_tools.py').read_text())
    need(old_installer['bootstrap'] == new_installer['bootstrap']
         and old_installer['need'] == new_installer['need'], 'installer safety reader changed')
    holder = (HERE / 'reference/held_agent_campaign_02.py').read_bytes()
    need(ident(holder) == {'bytes': 11374,
        'sha256': '715e996217c7d33a7483354f16f2d39c9a033f51f3a20a52484495a00262dd65'}, 'original holder differs')
    names = ['install_measurement_tools.py', 'prepare_campaign_inputs.py', 'prepare_lifecycle_inputs.py',
             'r36_campaign.py', 'r36_lifecycle_campaign.py']
    files = {name: ident((HERE / 'generated' / name).read_bytes()) for name in names}
    for name in names:
        ast.parse((HERE / 'generated' / name).read_bytes())
    fixtures = {str(path.relative_to(HERE / 'frozen-fixture-inputs')): ident(path.read_bytes())
                for path in sorted((HERE / 'frozen-fixture-inputs').rglob('*')) if path.is_file()}
    need(len(fixtures) == 7 and fixtures['topology.json'] == {'bytes': 796, 'sha256': TOPOLOGY_SHA},
         'recovered seven-file fixture package differs')
    frozen_jobs = sorted(Path(name).name for name in fixtures if name.startswith('jobs/'))
    source_preparer = ident((HERE / 'reference/prepare_r36_qualify_cold02.py').read_bytes())
    actual_input = ident((HERE / 'reference/actual-cold-input.json').read_bytes())
    actual_closure = ident((HERE / 'reference/actual-cold-closure.json').read_bytes())
    need(source_preparer == {'bytes': 40160, 'sha256': 'd0816b3c9522f74981141d03dc6745ac2c3923404d8af4e629fe2d37ae28eb79'},
         'reviewed cold-only source differs')
    need(actual_input == {'bytes': 4250, 'sha256': 'a4c41f869095f5aeb32c7e26020bd36cf849048198b7f9cbf39ffc3bba24d305'}
         and actual_closure == {'bytes': 8522, 'sha256': '9f4ad0dc2da45e10fad64da62beb92b5fbdc68b776d7ea15990f7690a18c6ddd'},
         'reviewed cold-only input identities differ')
    qualification_inputs = {
        'prepare_qualify.py': dict(source_preparer, path=ROOT + '/prepare_qualify.py'),
        'qualification-input.json': dict(actual_input, path=ROOT + '/qualification-input.json'),
        'candidate/candidate.patch': {'path': ROOT + '/candidate/candidate.patch', 'bytes': 6384,
             'sha256': 'fc0d76fda9d8fb921443f6031a80a1bff3dd765284fc54bd08055c613abb04d0'},
    }
    prep_reference = {'qualification_launcher': qualification_inputs['prepare_qualify.py'],
                      'qualification_input': qualification_inputs['qualification-input.json'],
                      'owner_closure_input': dict(actual_closure, path=ROOT + '/cache-owner-closure-inputs.json'),
                      'cargo_home': '/home/qian/.cargo'}
    old_bundle = json.loads((HERE / 'reference/runner-bundle-manifest.json').read_bytes())
    bundle = rewritten(old_bundle)
    bundle.update(files=files, runtime_root=ROOT, preparation_reference=prep_reference,
        qualification_inputs=qualification_inputs, preparation_launcher_sha256=source_preparer['sha256'],
        fixture_inputs=fixtures, frozen_job_names=frozen_jobs,
        candidate_input_reference=ident((HERE / 'candidate-input.reference.json').read_bytes()),
        reference_parent_bundle_sha256=ident((HERE / 'reference/runner-bundle-manifest.json').read_bytes())['sha256'],
        reference_parent_sources=old_bundle['files'], reference_parent_tree=None,
        reference_parent_commit='e2e693ecf5d4309286238ed0bd101a31d1f24435',
        scope='R36 validation-scratch PR108: accepted R24 plus two scratch-path files; cold-only qualification',
        status='UNSEALED_TEMPLATE_ACTUAL_COLD_QUALIFICATION_NOT_BOUND', sealed=False,
        profile_seed={'path': PROFILE, 'bytes': 792, 'sha256': PROFILE_SHA, 'private_body_included': False},
        build_mode='cold-only', prior_preparation_root='/home/qian/hepta-runtime-validation-scratch-20261106-r36',
        private_namespaces={'observation': ['/home/qian/hs36n01', '/home/qian/hs36b01', '/home/qian/hs36c01'],
            'normal_lifecycle_prefix': '/home/qian/s36lc1',
            'recovery': '/home/qian/hepta-runtime-optimization-20261104-r16/s36-cancel-recovery-01'})
    need(bundle['future_qualification']['test_counts'] is None
         and all(row == {'bytes': None, 'sha256': None} for row in bundle['future_qualification']['binaries'].values()),
         'future qualification result was filled')
    outputs = {'generated/runner-bundle-manifest.json': canonical(bundle),
               'mac-launchers-01/held_agent_campaign_02.py': holder}
    for name in ('r36_campaign.py', 'r36_lifecycle_campaign.py'):
        outputs['mac-launchers-01/' + name] = (HERE / 'generated' / name).read_bytes()
    for name in ('campaign-inputs-01.example.json', 'lifecycle-inputs-01.example.json'):
        value = rewritten(json.loads((HERE / 'reference' / name).read_bytes()))
        value.update(qualification_launcher=qualification_inputs['prepare_qualify.py'],
                     qualification_input=qualification_inputs['qualification-input.json'],
                     candidate_patch=qualification_inputs['candidate/candidate.patch'])
        launcher = 'r36_campaign.py' if name.startswith('campaign-') else 'r36_lifecycle_campaign.py'
        value['launcher_sha256'] = files[launcher]['sha256']
        if name.startswith('lifecycle-'):
            value['campaign_helpers'] = dict(files['r36_campaign.py'], path=ROOT + '/tools-01/r36_campaign.py')
        outputs[name] = canonical(value)
    helper_names = ['need', 'checked', 'canonical', 'create', 'private_directory']
    sealer_header = ('#!/usr/bin/env python3\n'
        '"""Seal only parent input identities from actual local qualification originals.\n'
        'No generated parent, binder, installer, auditor, compiler, or workload is executed.\n"""\n'
        'import argparse\nimport ast\nimport hashlib\nimport json\nimport os\nfrom pathlib import Path\n'
        'import pprint\nimport re\nimport stat\n\n'
        'HERE = Path(__file__).resolve().parent\nROOT = Path(' + repr(ROOT) + ')\n'
        'HEX = re.compile(r"[0-9a-f]{64}\\Z")\n'
        'STAGES = ' + repr(STAGES) + '\nCHANGED = ' + repr(CHANGED) + '\n\n')
    parent_functions = funcs(parent)
    copied_helpers = '\n\n\n'.join(parent_functions[name] for name in helper_names +
                        ['verify_r36_terminal', 'r36_owner_native_streams'])
    sealer = sealer_header + copied_helpers + '\n\n\n' + (HERE / 'seal_bundle_body.py').read_text()
    ast.parse(sealer)
    outputs['seal_parent_bundle.py'] = sealer.encode()
    request_names = ['qualification_launcher', 'qualification_input', 'owner_closure_input', 'preparation',
                     'qualification_report', 'source_map', 'isolated_summary', 'isolated_audit', 'native_terminal', 'native_read']
    request = {'schema': 'hepta-r36-scratch-parent-sealing-request/v1', 'runtime_root': ROOT,
        'artifacts': {name: {'local_path': None, 'bytes': None, 'sha256': None} for name in request_names},
        'note': 'Fill only actual original local files after successful cold qualification; no success is assumed.'}
    outputs['seal-request.unsealed.json'] = canonical(request)
    plan = {'schema': 'hepta-r36-scratch-full-acceptance-operator-plan/v1', 'sealed': False,
        'runtime_root': ROOT, 'mac_parent_directory': MAC,
        'actual_qualification': None, 'actual_exact_ci': None, 'actual_observation': None, 'actual_normal_lifecycle': None,
        'source_baseline_commit': 'baab4def80be7af015b2e7a594cb302f66c4130e',
        'source_changed_paths': sorted(CHANGED),
        'private_namespaces': bundle['private_namespaces'],
        'sequence': ['actual original eight-stage qualification', 'seal reviewed parent static inputs from original local receipts',
             'create-only deploy sealed tools and seven recovered fixture inputs; run original tool installer once',
             'original exact Rust CI using the sealed parent binder; preserve original native terminal/read/report/plan/audit/logs',
             'original observation materializer after completed qualification and exact CI',
             'original Mac held-agent observation parent',
             'only if the original observation gate passes: original lifecycle materializer and original Mac lifecycle parent',
             'archive original outputs and decide only from original required gates; no selective rerun'],
        'planned_observation': {'order': 'ABBA', 'hosts': 6, 'concurrency': [1, 8, 16],
            'calls_per_concurrency_per_round': 192, 'warmups_per_concurrency_per_round': 24,
            'workers': 2, 'arena_max': 1, 'quiet_seconds': 90, 'planned_measured_calls': 2304,
            'planned_warmup_calls': 288, 'planned_preflight_and_restart_calls': 72,
            'planned_total_calls': 2664, 'boundary_bursts': 2, 'boundary_concurrency': 32, 'recovery_hosts': 6},
        'normal_lifecycle_required_comparisons': ['all_operations', 'launch', 'concurrent_cancel'],
        'normal_lifecycle_original_tool_tests': 14,
        'thresholds': {'throughput_b_over_a_min': 0.95, 'p95_b_over_a_max': 1.10,
            'controller_cpu_b_over_a_max': 1.10, 'controller_rss_extra_kib_max': 512,
            'controller_rss_b_over_a_max': 1.05, 'primary_concurrency': 8},
        'lifecycle_threshold_source': 'Unchanged 27-file lifecycle tools, original analyze_lifecycle_gates.py including its CPU tick tolerance.',
        'argv_templates': {
            'install_measurement_tools': ['/usr/bin/python3', '-B', ROOT + '/tools-01/install_measurement_tools.py', '--bundle-sha256', None],
            'materialize_observation': ['/usr/bin/python3', '-B', ROOT + '/tools-01/prepare_campaign_inputs.py',
                '--example-sha256', None, '--preparer-sha256', files['prepare_campaign_inputs.py']['sha256'],
                '--preparation-sha256', None, '--qualification-terminal-sha256', None, '--qualification-job-id', None],
            'materialize_lifecycle_after_observation_gate': ['/usr/bin/python3', '-B', ROOT + '/tools-01/prepare_lifecycle_inputs.py',
                '--example-sha256', None, '--preparer-sha256', files['prepare_lifecycle_inputs.py']['sha256']],
            'observation_holder': ['/usr/bin/python3', '-B', '-u', MAC + '/held_agent_campaign_02.py',
                '--remote-script', MAC + '/r36_campaign.py', '--out',
                '/Users/qianqi/work/hepta-runtime-r36-validation-scratch-cold-02-observation-holder-01', '--timeout-seconds', '3600'],
            'lifecycle_holder_after_observation_gate': ['/usr/bin/python3', '-B', '-u', MAC + '/held_agent_campaign_02.py',
                '--remote-script', MAC + '/r36_lifecycle_campaign.py', '--out',
                '/Users/qianqi/work/hepta-runtime-r36-validation-scratch-cold-02-lifecycle-holder-01', '--timeout-seconds', '3600']},
        'deployment': {'x230/tools-01': ROOT + '/tools-01', 'mac': MAC,
            'example_jsons': 'Review examples only. The original installer creates actual templates with derived lifecycle hashes.',
            'private_profile_body': 'Never included; existing D1 seed is hash-bound and read under the unchanged original helper guards.'},
        'execution_policy': 'Root owns every host call and formal lock. No operation has been launched by this package.',
        'measurement_results': None}
    outputs['operator-plan.unsealed.json'] = canonical(plan)
    proof = {'schema': 'hepta-r36-scratch-parent-local-static-checks/v1', 'passed': True,
        'method': 'Full-text inverse normalization and AST parsing only; no generated entrypoint/helper imported or called.',
        'parent_general_helpers_equal_after_namespace_normalization': sorted(first),
        'parent_general_helpers_byte_identical': sorted(name for name in first
              if first[name] == funcs(parent[:new_marker])[name]),
        'nonbinder_prefix_matches_original_after_fixed_fixture_and_root_edits': True,
        'entire_seven_stage_suffix_matches_original_after_namespace_and_early_guard_removal': True,
        'lifecycle_matches_original_after_namespace_and_early_guard_removal': True,
        'both_materializers_namespace_only': True,
        'installer_bootstrap_and_need_byte_identical': True,
        'sealer_copies_original_helpers_exactly': helper_names + ['verify_r36_terminal', 'r36_owner_native_streams'],
        'original_holder_byte_identical': True, 'all_generated_sources_ast_parse': True,
        'fixture_files': fixtures, 'input_examples_future_results_null': True,
        'preparation_source_identity': source_preparer, 'prepared_source_files': files,
        'host_calls': 0, 'target_functions_executed': 0, 'actual_qualification_result': None}
    outputs['LOCAL_STATIC_CHECKS.json'] = canonical(proof)
    for name, raw in outputs.items():
        create(HERE / name, raw)
    print(json.dumps({'created': len(outputs), 'bundle': ident(outputs['generated/runner-bundle-manifest.json']),
                      'sealer': ident(outputs['seal_parent_bundle.py']),
                      'static': ident(outputs['LOCAL_STATIC_CHECKS.json']), 'target_functions_executed': 0}, sort_keys=True))


if __name__ == '__main__':
    os.umask(0o077)
    main()
