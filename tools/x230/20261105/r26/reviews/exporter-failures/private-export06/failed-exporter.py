#!/usr/bin/env python3
"""Outcome-preserving private diagnostic export06; no process or workload execution."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import traceback
import types

ROOT = Path('/home/qian/hepta-runtime-optimization-20261105-r25')
PRIVATE05 = ROOT / 'mechanism-diagnostic-05'
OUT = ROOT / 'mechanism-evidence-export-06'
EXPORTER = ROOT / 'tools/export_private_diagnostic_06.py'
HELPER = ROOT / 'tools/diagnostic_stable_archive_06.py'
INPUT = ROOT / 'tools/private-diagnostic-export-input-06.json'
HELPER_SHA = '34ce88cc28da10e1167dabaf6e3480aa42f5e6e76a29472d93959334aa9ec2ed'
BUILD05_SHA = '6364c71ca6567b40fbfe8c211f0479f7a89e1c4dab568e1e7756be36e528f705'
H = None


def need(value, reason):
    if not value:
        raise RuntimeError(reason)


def load_stable_helper():
    need(HELPER.resolve(strict=True) == HELPER, 'indirect archive helper')
    fd = os.open(HELPER, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
             and before.st_nlink == 1 and 0 < before.st_size <= 131072, 'unsafe helper descriptor')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(131073)
        fields = ('st_dev', 'st_ino', 'st_uid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        need(len(raw) == before.st_size and hashlib.sha256(raw).hexdigest() == HELPER_SHA
             and all(getattr(before, key) == getattr(os.fstat(fd), key) == getattr(HELPER.lstat(), key)
                     for key in fields), 'archive helper bytes or descriptor changed')
    finally:
        os.close(fd)
    module = types.ModuleType('_hepta_diagnostic_stable_archive06')
    module.__file__ = str(HELPER)
    exec(compile(raw, str(HELPER), 'exec'), module.__dict__)
    return module


def read(path, retain=False):
    return H.read(Path(path), retain=retain)


def listing(path):
    value = H.listing(path)
    return [Path(name) for name in value['files']], value['directories']


def stamp(value):
    return H.stamp(value)


def byte_pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def parse_original(raw):
    """Retain any bytes elsewhere; an absent/partial/non-object JSON is never completed."""
    if raw is None:
        return {'status': 'absent', 'value': None}
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError) as error:
        return {'status': 'malformed_or_partial_json', 'value': None,
                'error': {'type': type(error).__name__, 'reason': str(error)[:512]}}
    return {'status': 'object' if isinstance(value, dict) else 'non_object_json', 'value': value}


def project_original(document):
    value = document.get('value')
    result = {'status': document['status']}
    if 'error' in document:
        result['parse_error'] = document['error']
    if isinstance(value, dict):
        result.update({key: value[key] for key in ('schema', 'passed', 'attribution_allowed', 'finished_utc',
            'started_utc', 'error', 'parent_returncode', 'wrapper_returncode', 'parent_invocations',
            'wrapper_invocations', 'monitor_passed', 'socket_parent_cleanup') if key in value})
    return result


def validate_operation(value):
    need(isinstance(value, dict) and set(value) == {'executed', 'job_id', 'terminal_raw', 'terminal_pin', 'reason'}
         and type(value['executed']) is bool, 'explicit actual operation declaration required')
    if not value['executed']:
        need(value['job_id'] is None and value['terminal_raw'] is None and value['terminal_pin'] is None
             and isinstance(value['reason'], str) and value['reason'].strip(), 'unrun operation cannot invent a terminal')
        return {'executed': False, 'reason': value['reason'], 'strong_terminal_proved': False}
    need(isinstance(value['job_id'], str) and re.fullmatch('[0-9a-f]+-[0-9a-f]+-[0-9a-f]+', value['job_id'])
         and isinstance(value['terminal_raw'], str) and value['reason'] is None, 'actual original job/terminal required')
    raw = value['terminal_raw'].encode('utf-8')
    need(len(raw) <= 65536 and byte_pin(raw) == value['terminal_pin'], 'original terminal raw byte binding differs')
    terminal = json.loads(raw)
    need(isinstance(terminal, dict) and terminal.get('job_id') == value['job_id']
         and terminal.get('state') in ('succeeded', 'failed', 'cancelled', 'timed_out')
         and terminal.get('terminal_publication_confirmed') is True
         and type(terminal.get('terminal_publication_protocol')) is int
         and terminal['terminal_publication_protocol'] == 1 and terminal.get('automatic_retry') is False,
         'same authoritative original terminal required; running/unknown is not a final export input')
    need(type(terminal.get('output_complete')) is bool and type(terminal.get('output_durable')) is bool,
         'original completeness flags absent')
    if terminal['state'] == 'succeeded':
        need(terminal.get('exit_code') == 0 and terminal.get('cancelled') is False
             and terminal.get('timed_out') is False, 'native success contradicts original terminal flags')
    logs_complete = terminal['output_complete'] and terminal['output_durable']
    for stream in ('stdout', 'stderr'):
        counts = terminal['log_bytes'][stream]
        need(type(counts.get('seen')) is int and type(counts.get('stored')) is int
             and 0 <= counts['stored'] <= counts['seen'], 'original log byte counts invalid')
        need(type(terminal['log_synced'][stream]) is bool and type(terminal['log_truncated'][stream]) is bool,
             'original log flags absent')
        logs_complete = (logs_complete and terminal['log_synced'][stream] and not terminal['log_truncated'][stream]
                         and terminal['log_errors'][stream] is None and counts['stored'] == counts['seen'])
    return {'executed': True, 'job_id': value['job_id'], 'state': terminal['state'],
            'exit_code': terminal.get('exit_code'), 'terminal_original': terminal,
            'terminal_raw_identity': value['terminal_pin'], 'strong_terminal_proved': True,
            'native_logs_lossless_complete': bool(logs_complete),
            'output_complete': terminal['output_complete'], 'output_durable': terminal['output_durable']}


def classify_phase(operation, documents, monitor_proof):
    """Original outer completion cannot manufacture a finished inner checkpoint."""
    result = {'original_operation': operation, 'original_reports': {
        label: project_original(document) for label, document in documents.items()},
        'capacity_admission_made_here': False, 'production_adoption_made_here': False,
        'original_positive_chain_reproduced': False}
    if not operation['executed']:
        result['disposition'] = 'not_executed'
        return result
    parent = documents.get('parent_report', {}).get('value')
    wrapper = documents.get('wrapper_report', {}).get('value')
    bootstrap = documents.get('bootstrap_final', {}).get('value')
    if not isinstance(parent, dict) or not parent.get('finished_utc'):
        result['disposition'] = 'partial_or_missing_parent_final_report'
    elif not isinstance(wrapper, dict) or not wrapper.get('finished_utc') or not isinstance(bootstrap, dict):
        result['disposition'] = 'partial_or_missing_outer_report'
    elif (parent.get('schema') != 'hepta-r25-phase-diagnostic-campaign/v2'
          or wrapper.get('schema') != 'hepta-monitored-private-phase/v2'
          or bootstrap.get('schema') != 'hepta-r25-phase-stdin-bootstrap/v2'):
        result['disposition'] = 'original_report_schema_mismatch'
    elif operation.get('state') != 'succeeded' or operation.get('native_logs_lossless_complete') is not True:
        result['disposition'] = 'outer_native_failed_or_output_incomplete'
    elif not (parent.get('passed') is True and parent.get('attribution_allowed') is True
              and wrapper.get('passed') is True and wrapper.get('attribution_allowed') is True
              and bootstrap.get('passed') is True and bootstrap.get('wrapper_returncode') == 0):
        result['disposition'] = 'completed_original_failure_or_rejection'
    elif not monitor_proof.get('independently_validated'):
        result['disposition'] = 'original_positive_flags_without_reproduced_monitor_proof'
    else:
        result['disposition'] = 'completed_original_positive_chain_external_admission_required'
        result['original_positive_chain_reproduced'] = True
    return result

TOOLS = {
    '03': {'manifest_sha256': '621516c47b473f4a6f1f5510ea51482e856f03b98b0437f39ce8dc0cdf58ee83',
           'install_receipt_sha256': '40a3f94091f6df6a3cfd4eaf403e4cbfece9f425f1c4f4700f2fa4413325fea5',
           'archive_sha256': 'b5c17cca11c156c675a179b95dae464d6eee174cc46c07052254673ff877f995'},
    '04': {'manifest_sha256': 'fdd728f347fd8f66897ba3554bfaf811f3d262cc8c2b5fec93305da3c3d913cb',
           'install_receipt_sha256': 'dab7ee150d874a38b4d466879c42809567fbe314f568f100ac1332201254cbdc',
           'archive_sha256': '2461a61fd5269bdd08ff3f5fe419183761716035c76ce0e44feef6924006b4f5'},
    '05': {'manifest_sha256': 'ea379a186a0b0bdb214f5fd2e79233add3e685faa7b6f3a97de8d1e9dede2eb5',
           'install_receipt_sha256': '3cf38e63b50ae739ad80d2cda9a9d97d828728614ffc9629861cb433c53fc490',
           'archive_sha256': 'c9f13862968536b3fddcd930a516ae475f1e8f80a1783ea2b1846f1d4bd2c7cf'},
}
FAILED03_SHA = 'b310b80933680dfb0f7802570be83394980e4f56ca06538c382f918417d82f39'
QUALIFICATION_SHA = '72a4001ed303d565f5c3300ea8786acf1c4e9d7991e0a1f0486fabc140900e3c'
MONITOR02 = {
    'manifest_sha256': '58a0a8aabd591fd9305eb260cf77aea23c9a3d247f78f56acef4ec5fe3562ec1',
    'archive': {'bytes': 24258, 'sha256': '8dba7b85f33b47126f1a82297bde212a6694fccaf17afb787578ae5367c1d31c'},
    'bootstrap': {'bytes': 7133, 'sha256': '776fef341b0006af71277e4a2fe0aae31410475182f2f8a299747eb36be3b0b3'},
    'installer': {'bytes': 8380, 'sha256': '60c14a9f80a20433a76bc39fadb4d756e3b1f9220f61c75787d778c1ff684e43'},
    'install_receipt': {'bytes': 9598, 'sha256': 'c9f849cf67048a7f87d101646d56ce4a3c1afa97a2c27b19e672a0bf9634df37'},
    'install_job_id': '1a1ab622e6e-fc05-4d2d',
    'plan_sha256': '755b7321d6b156777b750d399169a106409f14984a0925bac707ca8fae348a82',
    'wrapper_sha256': 'a976bdc708bcf55942ada41fd181a4d3a2d877d87ead5778bf39d1db261179a8',
}


PHASE02_PINS = {'parent_report': {'relative': 'mechanism-diagnostic-05/phase-parent-01/report.json', 'bytes': 24571, 'sha256': '629889038bdf9127c7395787a376f2ed96866aa338adb386f7d50def919fc98b'}, 'wrapper_report': {'relative': 'mechanism-monitor-campaign-02/report.json', 'bytes': 8075, 'sha256': '7fdf83d5cf82da25e71e012c0ceacac108706921ff543bd556d40bd07a681804'}, 'bootstrap_entry': {'relative': 'mechanism-monitor-bootstrap-entry-02.json', 'bytes': 2802, 'sha256': '2a448b5b87dbd743a2d1c0a09846a8f2b5e2bc434c719812ab5f10b6926eda13'}, 'bootstrap_final': {'relative': 'mechanism-monitor-bootstrap-report-02.json', 'bytes': 3070, 'sha256': '144f126a85a93f6bad3564a89d624e2963847456a56baeb869de6531c0dacc2e'}, 'ledger': {'relative': 'mechanism-monitor-campaign-02/compiler-monitor.json', 'bytes': 45014, 'sha256': 'e07dbb5fa6a258ea5d87393f598d45d785edbddcf2121112ff883106e67ce7f4'}, 'validation': {'relative': 'mechanism-monitor-campaign-02/compiler-monitor-validation.json', 'bytes': 448, 'sha256': '509568d4f81729fdc1e340034fe1ac6634dd1e33245898294a5ad80f35dc101b'}}

COST03 = {'archive': {'bytes': 10138, 'sha256': 'e8aba68c9c84eb27d577d1b0e354f9aabd1789b3637f159b4cc76bc515b03dbc'}, 'capacity_attribution_allowed': False, 'cost_output': '/home/qian/hepta-runtime-optimization-20261105-r25/mechanism-monitor-cost-03', 'delivery_revision': '02', 'expanded_bytes': 37290, 'files': {'compiler_monitor.py': {'bytes': 12510, 'sha256': 'afb514362a9d8dd573b806f0dc87df16bd3a906e4574d10d91bf483b2e76cdcf'}, 'compiler_state.py': {'bytes': 6243, 'sha256': '9da718654db04a646e081d2d719a2d6d4655ffe337bc0e3f906e736e4d77a251'}, 'measure_cost_03.py': {'bytes': 10614, 'sha256': '6768c43bb5f6dd38c61685ee6454595db7868860e2b272375cc2e1c4761b2624'}, 'validate_compiler_monitor.py': {'bytes': 7055, 'sha256': 'd2cd009adf1f35a394ffddcc8f8646cc0c1b856b78181ca321ea68f6468218b2'}}, 'formal_measurement_passed': False, 'installer': {'bytes': 21045, 'sha256': '054d3e3660f227bc89eb3d8cceec11047d9d3e20c59f3ef026d135584f1c55d4'}, 'manifest': {'bytes': 868, 'sha256': '45761181d7be6ffe4399e2bd560f4cfcd98dc3267b3d1c45877adfd38af7a062'}, 'members': 5, 'native_key': 'hepta-r25-monitor-cost-20261105-03', 'native_timeout_seconds': 180, 'new_files_before_cost': ['/home/qian/hepta-runtime-optimization-20261105-r25/mechanism-monitor-cost-install-03.py', '/home/qian/hepta-runtime-optimization-20261105-r25/mechanism-monitor-cost-install-03.json', '/home/qian/hepta-runtime-optimization-20261105-r25/mechanism-monitor-cost-tools-03/compiler_monitor.py', '/home/qian/hepta-runtime-optimization-20261105-r25/mechanism-monitor-cost-tools-03/compiler_state.py', '/home/qian/hepta-runtime-optimization-20261105-r25/mechanism-monitor-cost-tools-03/measure_cost_03.py', '/home/qian/hepta-runtime-optimization-20261105-r25/mechanism-monitor-cost-tools-03/package-manifest.json', '/home/qian/hepta-runtime-optimization-20261105-r25/mechanism-monitor-cost-tools-03/validate_compiler_monitor.py'], 'remote_action_owner': 'root', 'remote_invocations_started': 0, 'request': {'bytes': 22329, 'sha256': '52bcafc4ca08ee2ad42e036c90b6a7e4d685c180463f5d14ad2e90d52fdf71e8'}, 'schema': 'hepta-monitor03-frozen-cost-inputs/v1', 'sole_delivery_correction': 'save_new binds original output descriptor, pathname, bytes and retained readback', 'supersedes_unexecuted_first_delivery': {'bytes': 21964, 'sha256': 'f16a268c2850f95a19da234a5b17678225b83b7aecb6128f37a4fc697db32360'}, 'tests_not_repeated': 'six metadata and two pure cost/validator tests retained in parent directory; narrow save_new correction reviewed separately', 'actual_files': {'report.json': {'bytes': 4037, 'sha256': 'e520a7d40ab5a8a0e4579a1c4157273997c723dcebd902ca7c13c30795a19d79'}, 'compiler-monitor.json': {'bytes': 30413, 'sha256': 'f517a9864fcf4cf612b0046430fea4fbbd74c97f88862b921ff5b2b89936c689'}, 'compiler-monitor-validation.json': {'bytes': 221, 'sha256': '7637c21a45ecd1052c5f0853b9d6beee0bc29ed00c6e5ce653f56e2a86c05e86'}, 'mechanism-monitor-cost-install-03.json': {'bytes': 3012, 'sha256': '48c3835e9eec5fe9fe067cfa6ad63fb9db5d9212afc328236e1781f62ccce310'}}}

PHASE03 = {'actual_cost_qualification': {'cost_bound': 0.02, 'job_id': '1a1ab903556-fc05-4eac', 'report': {'bytes': 4037, 'sha256': 'e520a7d40ab5a8a0e4579a1c4157273997c723dcebd902ca7c13c30795a19d79'}, 'thread_cpu_ns': 451997360, 'wall_ns': 60009485125}, 'actual_source_model': 'unchanged holder stdin-buffer binding -> new03 bootstrap -> new03 wrapper -> new03 parent, original05 native scripts and ELF', 'archive': {'bytes': 30909, 'sha256': 'e2a052108964e68038cb6b8960c10caaa6793f8d2aa0a0244d40d2b4e624c138'}, 'bootstrap': {'bytes': 7133, 'sha256': '79989ebf185f9d2cead0ba60ecd1a7edebd91ca8c07c541cdab5ef64d1f69fbf'}, 'data_install_creates': {'payload_files': 18, 'root_archive': 1, 'root_bootstrap': 1, 'root_receipt': 1, 'root_retained_installer_source': 1, 'total_regular_files': 22}, 'expanded_bytes': 131686, 'files': {'actual-cost-ledger-03.json': {'bytes': 30413, 'sha256': 'f517a9864fcf4cf612b0046430fea4fbbd74c97f88862b921ff5b2b89936c689'}, 'actual-cost-report-03.json': {'bytes': 4037, 'sha256': 'e520a7d40ab5a8a0e4579a1c4157273997c723dcebd902ca7c13c30795a19d79'}, 'actual-cost-root-verification-03.json': {'bytes': 1562, 'sha256': '85050b8161b46922ad21c112358eadb8ab35c7352c0dc56580eb1210a0afbf71'}, 'actual-cost-validator-03.json': {'bytes': 221, 'sha256': '7637c21a45ecd1052c5f0853b9d6beee0bc29ed00c6e5ce653f56e2a86c05e86'}, 'compiler_monitor.py': {'bytes': 12510, 'sha256': 'afb514362a9d8dd573b806f0dc87df16bd3a906e4574d10d91bf483b2e76cdcf'}, 'compiler_state.py': {'bytes': 6243, 'sha256': '9da718654db04a646e081d2d719a2d6d4655ffe337bc0e3f906e736e4d77a251'}, 'local-closure-03.json': {'bytes': 503, 'sha256': '31e353ad5e890712fe063b9c65a5bbe5da01c341e5283add1e67a2473ac6b27a'}, 'owned_socket_parent03.py': {'bytes': 3303, 'sha256': '78661a19adfb6ad605642c27452491e612237143f83da7de5d74ece91f5af871'}, 'parent-03.diff': {'bytes': 4146, 'sha256': 'b8e4ad8f8616d603e99382897932d566e43f710091e2b0787c0a229cff4b36da'}, 'phase-plan-03.json': {'bytes': 12632, 'sha256': '06494239576740053f8031e32080c6844b99462cd2c04324c7dd461fc4136807'}, 'run_monitored_phase_03.py': {'bytes': 17337, 'sha256': '293dde7bf6608b34eb1741aac44ba373b3362edc5bcc1f96e31ac663d9332103'}, 'run_phase_observation_03.py': {'bytes': 17472, 'sha256': '77be22e97ae599b5ca43e81c234f399430a2121664729547219dc64457d3a327'}, 'socket-tests-03.stderr': {'bytes': 590, 'sha256': '6240983f069c6bc0f6186918366e40a9e830a82a7dcc6f242c408c409f4c2fb8'}, 'socket-tests-03.stdout': {'bytes': 0, 'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}, 'test_owned_socket_parent03.py': {'bytes': 2122, 'sha256': '020c6240033714530a3401c2d41b63456622f7b04cbfb7b98c188c0e8f20d5f4'}, 'validate_compiler_monitor.py': {'bytes': 7055, 'sha256': 'd2cd009adf1f35a394ffddcc8f8646cc0c1b856b78181ca321ea68f6468218b2'}, 'wrapper-03.diff': {'bytes': 8886, 'sha256': 'beb1af019f490989b1634c36743e5ef1131c5b9cd4526e92d0ada596c8dd3f16'}}, 'install_has_no_payload_or_measurement_execution': True, 'install_request': {'bytes': 60817, 'sha256': '6e8d352f4b090e56235d95473de40125c4065afd32b843de9a7a60651c26a63d'}, 'installer': {'bytes': 59503, 'sha256': '036ffdfeff55dbe9644c729da46e582cb0eee2a1f9c2200d833a29693fe0f1f8'}, 'local_remote_actions': 0, 'manifest': {'bytes': 2654, 'sha256': '5a0efdf879e9eb9889caea2176db220e8b0f33806fc1835d2257549309678016'}, 'member_count': 18, 'phase_request': {'bytes': 469, 'sha256': '9d0e997f20d3e0b94288b244e8cd8c73f5fe3b4df07114ead53c94201189a465'}, 'root_launch_preconditions': ['independent review of exact new source/helper/package', 'data-only installation receipt and Mac bootstrap bytes hash checked', 'new wrapper/parent/native/socket/bootstrap-entry/bootstrap-final/Mac output paths absent', 'all owned compiler, runtime workloads and bulk evidence I/O stopped', 'root exclusive coordination note persisted before unique original holder launch', 'original parent90s quiescence and continuous1Hz monitor retained; any monitor invalidation forbids attribution'], 'schema': 'hepta-phase03-frozen-delivery/v1', 'status': 'frozen_unlaunched_pending_root_schedule'}


PRIOR_UNKNOWN_INSTALL = {'schema': 'hepta-private-phase03-prior-unknown-installation/v1', 'original_job_id': '1a1abaf7904-fc05-4fba', 'original_launch_state': 'launch_unknown', 'original_native_terminal': None, 'original_strong_terminal_inferred': False, 'actual_samekey_reconciliation_reused': True, 'actual_samekey_retried_launch': False, 'original_start_text': '{\n  "audit_recorded": true,\n  "job": {\n    "args": [\n      "-I",\n      "-B",\n      "-c",\n      "import hashlib,os,sys\\nfrom pathlib import Path\\nraw=sys.stdin.buffer.read(65537)\\nif len(raw)!=59503 or hashlib.sha256(raw).hexdigest()!=\'036ffdfeff55dbe9644c729da46e582cb0eee2a1f9c2200d833a29693fe0f1f8\':raise SystemExit(\'frozen phase03 installer identity mismatch\')\\nroot=Path(\'/home/qian/hepta-runtime-optimization-20261105-r25\')\\nif os.geteuid()==0 or root.resolve(strict=True)!=root:raise SystemExit(\'unprivileged direct task root required\')\\npath=root/\'mechanism-monitor-tools-install-03.py\'\\nfd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)\\nwith os.fdopen(fd,\'wb\') as stream:\\n stream.write(raw);stream.flush();os.fsync(stream.fileno())\\nos.execv(\'/usr/bin/python3\',[\'/usr/bin/python3\',\'-I\',\'-B\',str(path)])\\n"\n    ],\n    "created_unix_ms": 1793881766148,\n    "cwd": "/home/qian/hepta-runtime-optimization-20261105-r25",\n    "env_keys": [\n      "PYTHONDONTWRITEBYTECODE"\n    ],\n    "executable": "/usr/bin/python3",\n    "execution_mode": "operator",\n    "host": "x230",\n    "id": "1a1abaf7904-fc05-4fba",\n    "idempotency_key": "hepta-r25-phase-monitor-tools-install-20261105-03",\n    "launch_error": "Remote launch outcome unavailable",\n    "launch_state": "launch_unknown",\n    "remote_job_dir": "/home/qian/.local/state/hepta-runtime-mac-worker/jobs/1a1abaf7904-fc05-4fba",\n    "request_digest": "8ac8c5d30d2e62cab6fc29f193ab037e06500e4fbfa4428ebaa51d6b3bb4b59c",\n    "request_fingerprint": 10000460482826101450,\n    "ssh_target": "x230-ts",\n    "system_jobctl": false,\n    "unit": "hepta-runtime-job-1a1abaf7904-fc05-4fba"\n  },\n  "launch": {\n    "automatic_retry": false,\n    "job_id": "1a1abaf7904-fc05-4fba",\n    "outcome": "unknown",\n    "reconcile_via": "process_status",\n    "state": "launch_unknown",\n    "status_authoritative": false\n  },\n  "local_record_pending": false,\n  "reused": false\n}', 'original_samekey_reconcile_text': '{\n  "audit_recorded": true,\n  "job": {\n    "args": [\n      "-I",\n      "-B",\n      "-c",\n      "import hashlib,os,sys\\nfrom pathlib import Path\\nraw=sys.stdin.buffer.read(65537)\\nif len(raw)!=59503 or hashlib.sha256(raw).hexdigest()!=\'036ffdfeff55dbe9644c729da46e582cb0eee2a1f9c2200d833a29693fe0f1f8\':raise SystemExit(\'frozen phase03 installer identity mismatch\')\\nroot=Path(\'/home/qian/hepta-runtime-optimization-20261105-r25\')\\nif os.geteuid()==0 or root.resolve(strict=True)!=root:raise SystemExit(\'unprivileged direct task root required\')\\npath=root/\'mechanism-monitor-tools-install-03.py\'\\nfd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)\\nwith os.fdopen(fd,\'wb\') as stream:\\n stream.write(raw);stream.flush();os.fsync(stream.fileno())\\nos.execv(\'/usr/bin/python3\',[\'/usr/bin/python3\',\'-I\',\'-B\',str(path)])\\n"\n    ],\n    "created_unix_ms": 1793881766148,\n    "cwd": "/home/qian/hepta-runtime-optimization-20261105-r25",\n    "env_keys": [\n      "PYTHONDONTWRITEBYTECODE"\n    ],\n    "executable": "/usr/bin/python3",\n    "execution_mode": "operator",\n    "host": "x230",\n    "id": "1a1abaf7904-fc05-4fba",\n    "idempotency_key": "hepta-r25-phase-monitor-tools-install-20261105-03",\n    "launch_error": "Remote launch outcome unavailable",\n    "launch_state": "launch_unknown",\n    "remote_job_dir": "/home/qian/.local/state/hepta-runtime-mac-worker/jobs/1a1abaf7904-fc05-4fba",\n    "request_digest": "8ac8c5d30d2e62cab6fc29f193ab037e06500e4fbfa4428ebaa51d6b3bb4b59c",\n    "request_fingerprint": 10000460482826101450,\n    "ssh_target": "x230-ts",\n    "system_jobctl": false,\n    "unit": "hepta-runtime-job-1a1abaf7904-fc05-4fba"\n  },\n  "launch": null,\n  "retried_launch": false,\n  "reused": true,\n  "status": {\n    "automatic_retry": false,\n    "job_id": "1a1abaf7904-fc05-4fba",\n    "outcome": "unknown",\n    "state": "status_unavailable",\n    "status_authoritative": false\n  }\n}', 'original_status_error_text': 'remote helper on x230-ts failed with 1\nstdout:\n\nstderr:\nTraceback (most recent call last):\n  File "<string>", line 6, in <module>\n  File "<string>", line 25, in private_job_directory\nFileNotFoundError: [Errno 2] No such file or directory: \'1a1abaf7904-fc05-4fba\'', 'separate_readonly_probe_job': '1a1abb1469c-fc05-4fd0', 'separate_probe_original_terminal_text': '{\n  "at_unix_ms": 1793881892037,\n  "audit_recorded": true,\n  "automatic_retry": false,\n  "cancelled": false,\n  "exit_code": 0,\n  "job_id": "1a1abb1469c-fc05-4fd0",\n  "launch_nonce": "338f13ac061e56b02a2b5d9befc2c1a8",\n  "log_bytes": {\n    "stderr": {\n      "seen": 0,\n      "stored": 0\n    },\n    "stdout": {\n      "seen": 1380,\n      "stored": 1380\n    }\n  },\n  "log_errors": {\n    "stderr": null,\n    "stdout": null\n  },\n  "log_synced": {\n    "stderr": true,\n    "stdout": true\n  },\n  "log_truncated": {\n    "stderr": false,\n    "stdout": false\n  },\n  "output_complete": true,\n  "output_durable": true,\n  "state": "succeeded",\n  "terminal_publication_confirmed": true,\n  "terminal_publication_protocol": 1,\n  "timed_out": false\n}', 'separate_probe_original_stdout': '{"schema": "hepta-exact-uncertain-installer-readonly-reconciliation/v1", "paths": [{"path": "/home/qian/.local/state/hepta-runtime-mac-worker/jobs/1a1abaf7904-fc05-4fba", "exists": false}, {"path": "/home/qian/hepta-runtime-optimization-20261105-r25/mechanism-monitor-tools-install-03.py", "exists": false}, {"path": "/home/qian/hepta-runtime-optimization-20261105-r25/mechanism-monitor-tools-install-03.json", "exists": false}, {"path": "/home/qian/hepta-runtime-optimization-20261105-r25/mechanism-monitor-tools-03", "exists": false}, {"path": "/home/qian/hepta-runtime-optimization-20261105-r25/mechanism-monitor-tools-03.tar.gz", "exists": false}, {"path": "/home/qian/hepta-runtime-optimization-20261105-r25/mechanism-monitor-bootstrap-03.py", "exists": false}], "exact_unit_query": {"argv": ["systemctl", "--user", "show", "hepta-runtime-job-1a1abaf7904-fc05-4fba.service", "--property=Id,LoadState,ActiveState,SubState,MainPID,ControlPID,InvocationID,ExecMainStartTimestampMonotonic,ExecMainExitTimestampMonotonic,Result"], "returncode": 0, "stdout": "MainPID=0\\nControlPID=0\\nResult=success\\nExecMainStartTimestampMonotonic=0\\nExecMainExitTimestampMonotonic=0\\nId=hepta-runtime-job-1a1abaf7904-fc05-4fba.service\\nLoadState=not-found\\nActiveState=inactive\\nSubState=dead\\nInvocationID=\\n", "stderr": ""}, "signals_sent": 0, "workloads_started": 0, "state_modified": false}\n', 'separate_probe_stdout_pin': {'bytes': 1380, 'sha256': '121dd02991601711b21142530387f76be514bf5d59d0833d77a3e3cdaddd5335'}, 'full_raw_native_companion_files': {'root-actual-install-start-01.json': {'bytes': 63102, 'sha256': 'c881d59b50732e0be19b6c20496d3c39936636549e5cce8dca8008b076af9cac'}, 'root-actual-install-samekey-reconcile-01.json': {'bytes': 63076, 'sha256': '7355f136114d1ead6f6339021fb00e6b352dd87bbe955a3a77e9125d2ee1314f'}, 'root-actual-install-status-01.json': {'bytes': 551, 'sha256': 'b63912d1ac0a2a8f3afc32d88d8d94da2585be6985ed66cd02804d711abaffdb'}, 'root-uncertain-install-readonly-probe-start-01.json': {'bytes': 4344, 'sha256': '635ab17e236f442f6d16cf56438664820647baeb4c0b3f20ff7638ea48fb2162'}, 'root-uncertain-install-probe-status-01.json': {'bytes': 1132, 'sha256': '6c0d476719f500f6f254affdbd2cbf1fc20ba1a02e619056078b3f2373aa9900'}, 'root-uncertain-install-probe-read-01.json': {'bytes': 5141, 'sha256': 'f081b547d934339be2bced2bf53c0acf3daab4ce83619addb50e92070818cd02'}}, 'scope': 'The separate probe records six absent paths and an inactive/not-found exact unit at its observation. Probe success is not a terminal for the original unknown installation. The corrected data-only entry is a separate late-bound operation; no benchmark attempt is inferred.'}

FUTURE_REPORTS = {
    'install_receipt': 'mechanism-monitor-tools-install-03.json',
    'parent_report': 'mechanism-diagnostic-05/phase-parent-03/report.json',
    'parent_checkpoint': 'mechanism-diagnostic-05/phase-parent-03/launch-input.json',
    'wrapper_report': 'mechanism-monitor-campaign-03/report.json',
    'bootstrap_entry': 'mechanism-monitor-bootstrap-entry-03.json',
    'bootstrap_final': 'mechanism-monitor-bootstrap-report-03.json',
    'ledger': 'mechanism-monitor-campaign-03/compiler-monitor.json',
    'validation': 'mechanism-monitor-campaign-03/compiler-monitor-validation.json',
    'native_report': 'mechanism-diagnostic-05/observation-03/report.json',
    'native_analysis': 'mechanism-diagnostic-05/phase-parent-03/native-analysis.json',
}
FUTURE_TREES = ('mechanism-diagnostic-05/phase-parent-03',
                'mechanism-diagnostic-05/observation-03', 'mechanism-monitor-campaign-03')
PRIVATE_NAMES = {'runtime.json', 'ssh_config', 'known_hosts', 'profile.json'}
KEY_NAMES = {'id_rsa', 'id_ed25519', 'id_ecdsa', 'id_dsa'}


def checked_json(path, expected_sha):
    identity, raw = read(path, retain=True)
    need(identity['sha256'] == expected_sha, 'fixed original JSON identity differs: ' + str(path))
    return identity, json.loads(raw)


def compiler_source_map(directory):
    paths = [directory / name for name in ('Cargo.toml', 'Cargo.lock', 'rustfmt.toml')]
    for name in ('src', 'examples'):
        paths.extend(listing(directory / name)[0])
    return {path.relative_to(directory).as_posix(): read(path)[0]['sha256'] for path in sorted(paths)}


def original_elf_identity(path):
    """Identity-only original Cargo artifacts may have hard-linked aliases; never archive ELF bodies."""
    H.direct(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and before.st_nlink >= 1
             and not before.st_mode & (stat.S_ISUID | stat.S_ISGID)
             and 4 <= before.st_size <= H.MAX_FILE_BYTES, 'unsafe original binary descriptor')
        digest, total, header = hashlib.sha256(), 0, b''
        while block := os.read(fd, H.BLOCK):
            if not header:
                header = block[:4]
                need(header == b'\x7fELF', 'named binary identity is not an ELF')
            total += len(block)
            need(total <= before.st_size, 'original binary grew during identity read')
            digest.update(block)
        need(total == before.st_size and stamp(before) == stamp(os.fstat(fd)) == stamp(path.lstat()),
             'original binary changed during identity read')
        return {'source_path': str(path), 'bytes': total, 'sha256': digest.hexdigest(),
                'original_identity': stamp(before), 'is_elf': True}
    finally:
        os.close(fd)


def socket_metadata(path):
    """Only the known attempt-owned socket tree's metadata; never connect or read entries."""
    if not os.path.lexists(path):
        return {'path': str(path), 'present': False}
    H.direct(path)
    need(stat.S_ISDIR(path.lstat().st_mode) and path.lstat().st_uid == os.geteuid(), 'unsafe attempt socket root')
    entries = {str(path): stamp(path.lstat())}
    for current, dirs, names in os.walk(path, followlinks=False):
        directory = Path(current)
        for name in list(dirs) + names:
            item = directory / name
            value = item.lstat()
            need(value.st_uid == os.geteuid(), 'non-owned entry in attempt socket tree')
            entries[str(item)] = stamp(value)
            need(len(entries) <= 1024, 'socket metadata inventory exceeds bound')
        dirs[:] = [name for name in dirs if not (directory / name).is_symlink()]
    return {'path': str(path), 'present': True, 'entries': entries,
            'entry_bodies_read': False, 'connections_or_signals_sent': 0}


def main():
    global H
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input-sha256', required=True)
    parser.add_argument('--exporter-sha256', required=True)
    args = parser.parse_args()
    need(sys.platform == 'linux' and os.geteuid() != 0 and Path(__file__).resolve() == EXPORTER,
         'fixed unprivileged native exporter path required')
    H = load_stable_helper()
    H.direct(ROOT)
    self_identity = read(EXPORTER)[0]
    helper_identity = read(HELPER)[0]
    input_identity, input_raw = read(INPUT, retain=True)
    need(re.fullmatch('[0-9a-f]{64}', args.exporter_sha256) and self_identity['sha256'] == args.exporter_sha256
         and helper_identity['sha256'] == HELPER_SHA, 'frozen exporter/helper identity differs')
    need(re.fullmatch('[0-9a-f]{64}', args.input_sha256) and input_identity['sha256'] == args.input_sha256,
         'late-bound original input differs')
    inputs = json.loads(input_raw)
    need(inputs.get('schema') == 'hepta-private-diagnostic-export-input/v3' and inputs.get('root') == str(ROOT)
         and inputs.get('all_owned_workloads_stopped') is True
         and inputs.get('native_and_mac_companions_required') is True,
         'explicit completed scheduling/custody input required before archive I/O')
    phase_input = inputs['phase03']
    need(isinstance(phase_input, dict) and set(phase_input) == {'installation', 'operation', 'file_pins'}
         and set(phase_input['file_pins']) == set(FUTURE_REPORTS), 'exact future phase input fields required')
    installation = validate_operation(phase_input['installation'])
    operation = validate_operation(phase_input['operation'])
    need(not operation['executed'] or installation['executed'], 'phase cannot predate its original installation')
    need(not os.path.lexists(OUT), 'fresh export directory required; no automatic reuse')
    OUT.mkdir(mode=0o700)
    report = {'schema': 'hepta-r25-private-diagnostic-export/v3', 'passed': False,
              'export_completed': False, 'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'no_workload_executed': True, 'automatic_retries': 0, 'diagnostic_only': True,
              'production_candidate': False, 'baseline_adoption_status': 'qualified_but_unadopted_R25',
              'capacity_admission_made_here': False, 'input': input_identity, 'exporter': self_identity,
              'archive_helper': helper_identity, 'original04_private_directory_absent': None,
              'native_terminal_and_complete_launcher_streams': 'require independently verified local native and complete Mac holder companions',
              'previous_installation_submission': PRIOR_UNKNOWN_INSTALL,
              'known_original_jobs': {'build03': '1a1aaf52e1d-fc05-4905', 'build04': '1a1ab0912c9-fc05-499e',
                  'build05': '1a1ab216326-fc05-4ac1', 'phase02': '1a1ab6ef44c-fc05-4dd3', 'cost03': '1a1ab903556-fc05-4eac'}}
    files, omissions, inventories, cache_exclusions, metadata_only = {}, [], {}, [], []
    observed, absences, discrepancies = {}, [], []

    def add(path, name, expected_sha=None, omission=None, binary=False):
        H.safe_name(name)
        need(name not in files and all(row['archive_path'] != name for row in omissions), 'duplicate archive path')
        path = Path(path)
        if binary:
            identity = original_elf_identity(path)
        else:
            identity = read(path)[0]
        need(expected_sha is None or identity['sha256'] == expected_sha, 'fixed original SHA differs: ' + str(path))
        need(str(path) not in observed or observed[str(path)] == identity, 'one source changed between reads')
        observed[str(path)] = identity
        if identity['is_elf']:
            omission = 'ELF body excluded; complete original descriptor/size/SHA identity retained'
        if omission:
            omissions.append({**identity, 'archive_path': name, 'omission_reason': omission})
        else:
            files[name] = identity
        return identity

    def absent(path):
        need(not os.path.lexists(path), 'declared absent/unrun path unexpectedly exists: ' + str(path))
        absences.append(str(path))

    def tree(directory, prefix, measurement=False):
        paths, directories = listing(directory)
        inventories[str(directory)] = {'files': [str(path) for path in paths], 'directories': directories}
        for path in paths:
            relative = path.relative_to(directory).as_posix()
            if path.name in KEY_NAMES or path.suffix in ('.key', '.pem', '.plist'):
                metadata_only.append({'source_path': str(path), 'archive_path': prefix + '/' + relative,
                    'original_identity': stamp(path.lstat()), 'body_read': False,
                    'omission_reason': 'unexpected private credential/service body excluded without reading'})
                continue
            omit = None
            if measurement and (path.name in PRIVATE_NAMES or path.name in ('ssh', 'ssh-original') and path.parent.name == 'bin'):
                omit = 'private transport fixture configuration/wrapper body excluded; identity retained'
            add(path, prefix + '/' + relative, omission=omit)

    def optional_document(path, expected):
        if expected is None:
            absent(path)
            return {'status': 'absent', 'value': None}, None
        need(isinstance(expected, dict) and set(expected) == {'bytes', 'sha256'}
             and type(expected['bytes']) is int and expected['bytes'] >= 0
             and isinstance(expected['sha256'], str) and re.fullmatch('[0-9a-f]{64}', expected['sha256']),
             'actual future file requires exact byte/hash pin or null')
        identity, raw = read(path, retain=True)
        need({key: identity[key] for key in ('bytes', 'sha256')} == expected, 'actual late-bound report bytes differ')
        return {**parse_original(raw), 'identity': identity}, identity

    def monitor_proof(documents, source_directory, validator_sha, expected_limits):
        result = {'independently_validated': False, 'raw_ledger_preserved': documents.get('ledger', {}).get('identity') is not None}
        try:
            ledger = documents['ledger']['value']
            audit = documents['validation']['value']
            wrapper = documents['wrapper_report']['value']
            need(isinstance(ledger, dict) and isinstance(audit, dict) and isinstance(wrapper, dict),
                 'monitor ledger/audit/wrapper absent, partial or non-object')
            source_identity, raw = read(source_directory / 'validate_compiler_monitor.py', retain=True)
            need(source_identity['sha256'] == validator_sha, 'pure validator differs from frozen source')
            module = types.ModuleType('_hepta_export_bound_phase_validator')
            module.__file__ = str(source_directory / 'validate_compiler_monitor.py')
            exec(compile(raw, module.__file__, 'exec'), module.__dict__)
            validated = module.validate(ledger, expected_limits, ledger['parent_started_monotonic_ns'],
                                        ledger['parent_finished_monotonic_ns'])
            for label, field in [('ledger', 'monitor_result'), ('validation', 'monitor_validation')]:
                original = wrapper[field]; actual = documents[label]['identity']
                need((original['path'], original['bytes'], original['sha256']) ==
                     (actual['source_path'], actual['bytes'], actual['sha256'])
                     and original['descriptor_identity'] == actual['original_identity'],
                     'original wrapper monitor descriptor/hash binding differs')
            need(audit == validated, 'retained independent monitor validation differs from recomputation')
            result.update(independent_validation=validated, source=source_identity,
                          independently_validated=validated['passed'] is True and ledger.get('passed') is True)
        except (KeyError, TypeError, ValueError, RuntimeError, OSError) as error:
            result['verification_error'] = {'type': type(error).__name__, 'reason': str(error)}
        return result

    try:
        qualification_identity, qualification = checked_json(ROOT / 'qualification-02/report.json', QUALIFICATION_SHA)
        failed_identity, failed = checked_json(ROOT / 'mechanism-diagnostic-03/build-report.json', FAILED03_SHA)
        current_identity, current = checked_json(PRIVATE05 / 'build-report.json', BUILD05_SHA)
        need(qualification['qualified'] is True and qualification['source_after'] == qualification['source_tested']
             and len(qualification['source_after']) == 221 and len(qualification['harness_after']) == 19,
             'actual qualified R25 baseline differs')
        need(failed['passed'] is False and failed.get('finished_utc') and current.get('finished_utc')
             and [row['name'] for row in failed['stages']] == ['diagnostic-tool-tests', 'format', 'fmt-check', 'clippy']
             and failed['stages'][-1]['returncode'] == 101, 'original failed03 build differs')
        need(current['passed'] is True and current['diagnostic_only'] is True and current['production_candidate'] is False
             and current['automatic_retries'] == 0 and current['source02_or_qualified_target_writes'] is False,
             'actual private05 successful isolated build differs')
        absent(ROOT / 'mechanism-diagnostic-04')
        report['original04_private_directory_absent'] = True
        report['original03_build_passed'] = False
        report['original05_build_passed'] = True
        report['original_build_report_inputs'] = {'qualification': qualification_identity, 'failed03': failed_identity, 'private05': current_identity}
        for revision, pins in TOOLS.items():
            directory = ROOT / ('mechanism-tools-' + revision)
            _, manifest = checked_json(directory / 'package-manifest-02.json', pins['manifest_sha256'])
            paths, _ = listing(directory)
            assert {path.relative_to(directory).as_posix() for path in paths} == set(manifest['files']) | {'package-manifest-02.json'}
            for relative, expected in manifest['files'].items():
                actual, _ = read(directory / relative)
                assert (actual['bytes'], actual['sha256']) == (expected['bytes'], expected['sha256'])
            tree(directory, 'tools-' + revision)
            for suffix in ('.json', '.py'):
                path = ROOT / ('mechanism-tools-install-' + revision + suffix)
                add(path, 'install/' + path.name, pins['install_receipt_sha256'] if suffix == '.json' else None)
            archive = ROOT.parent / ('hepta-runtime-r25-phase-tools-' + revision + '.tar.gz')
            add(archive, 'frozen-packages/' + archive.name, pins['archive_sha256'])
        monitor_tools = ROOT / 'mechanism-monitor-tools-02'
        _, monitor_manifest = checked_json(monitor_tools / 'package-manifest.json', MONITOR02['manifest_sha256'])
        assert monitor_manifest['tool_revision'] == '02' and monitor_manifest['diagnostic_only'] is True
        monitor_paths, _ = listing(monitor_tools)
        assert len(monitor_paths) == 19
        assert {path.name for path in monitor_paths} == set(monitor_manifest['files']) | {'package-manifest.json'}
        assert all(path.parent == monitor_tools for path in monitor_paths)
        for name, expected in monitor_manifest['files'].items():
            actual, _ = read(monitor_tools / name)
            assert (actual['bytes'], actual['sha256']) == (expected['bytes'], expected['sha256'])
        tree(monitor_tools, 'monitor-tools-02')
        for filename, label, prefix in [
                ('mechanism-monitor-tools-02.tar.gz', 'archive', 'frozen-packages'),
                ('mechanism-monitor-bootstrap-02.py', 'bootstrap', 'monitor-entry-02'),
                ('mechanism-monitor-tools-install-02.py', 'installer', 'monitor-install-02'),
                ('mechanism-monitor-tools-install-02.json', 'install_receipt', 'monitor-install-02')]:
            path = ROOT / filename
            actual, _ = read(path)
            assert (actual['bytes'], actual['sha256']) == (MONITOR02[label]['bytes'], MONITOR02[label]['sha256'])
            add(path, prefix + '/' + filename, MONITOR02[label]['sha256'])
        _, monitor_install = checked_json(ROOT / 'mechanism-monitor-tools-install-02.json', MONITOR02['install_receipt']['sha256'])
        assert monitor_install['passed'] is True and monitor_install['regular_files_created'] == 19
        assert monitor_install['measurement_started'] is False and monitor_install['source_or_cache_modified'] is False
        assert monitor_install['manifest_sha256'] == MONITOR02['manifest_sha256']
        assert monitor_install['bootstrap_verified_without_rewrite']['sha256'] == MONITOR02['bootstrap']['sha256']
        for revision, build, expected_report in [('03', failed, failed_identity), ('05', current, current_identity)]:
            private = ROOT / ('mechanism-diagnostic-' + revision)
            add(private / 'build-report.json', 'build-' + revision + '/build-report.json', expected_report['sha256'])
            tree(private / 'build-logs', 'build-' + revision + '/build-logs')
            for stage in build['stages']:
                for stream in ('stdout', 'stderr'):
                    expected = stage.get(stream)
                    if expected is None:
                        continue
                    path = Path(expected['path'])
                    assert path.parent == private / 'build-logs'
                    actual, _ = read(path)
                    assert (actual['bytes'], actual['sha256']) == (expected['bytes'], expected['sha256'])
            source = private / 'source'
            expected_map = build['diagnostic'].get('source_after', build['diagnostic'].get('source_tested', build['diagnostic'].get('source_before_format')))
            assert expected_map and compiler_source_map(source) == expected_map
            assert len(expected_map) == 224
            for relative, digest in expected_map.items():
                add(source / relative, 'source-' + revision + '/' + relative, digest)
            for name, digest in qualification['harness_after'].items():
                assert Path(name).name == name and name.endswith('.py')
                add(source / 'tools/x230/20261028' / name, 'source-' + revision + '/tools/x230/20261028/' + name, digest)
            target = private / 'target-build'
            assert target.resolve() == target and stat.S_ISDIR(target.lstat().st_mode)
            cache_exclusions.append({'path': str(target), 'directory_identity': stamp(target.lstat()),
                                     'reason': 'private reproducible Cargo cache payload excluded; referenced actual test/runtime/release ELF identities retained'})
            binaries = []
            if build.get('test_binary'):
                binary = build['test_binary']; path = Path(binary['path'])
                assert path.parent == target / 'debug/deps' and path.name.startswith('hepta_runtime-')
                binaries.append((path, 'test-library', binary))
            if build['diagnostic'].get('binary'):
                binary = build['diagnostic']['binary']; path = Path(binary['path'])
                assert path == private / 'hepta-runtime-diagnostic'
                binaries.append((path, 'retained-runtime', binary))
            if any(stage['name'] == 'release' and stage.get('returncode') == 0 for stage in build['stages']):
                for relative in ('release/hepta-runtime', 'release/hepta-runtime-jobctl', 'release/examples/native_process_driver'):
                    binaries.append((target / relative, relative, None))
            for path, label, expected in binaries:
                actual = original_elf_identity(path)
                assert actual['is_elf']
                if expected:
                    assert (actual['bytes'], actual['sha256']) == (expected['bytes'], expected['sha256'])
                add(path, 'binary-identities-' + revision + '/' + label, actual['sha256'], binary=True)
        # The original phase02 did finish as a failure before any Controller.
        phase02_documents, phase02_identities = {}, {}
        for label, expected in PHASE02_PINS.items():
            path = ROOT / expected['relative']
            identity, raw = read(path, retain=True)
            need({key: identity[key] for key in ('bytes', 'sha256')} ==
                 {key: expected[key] for key in ('bytes', 'sha256')}, 'known original phase02 bytes differ')
            phase02_documents[label] = {**parse_original(raw), 'identity': identity}
            phase02_identities[label] = identity
        for relative, prefix in [('mechanism-diagnostic-05/phase-parent-01', 'phase02-parent'),
                                 ('mechanism-diagnostic-05/observation-01', 'phase02-observation'),
                                 ('mechanism-monitor-campaign-02', 'phase02-monitor')]:
            path = ROOT / relative
            if os.path.lexists(path): tree(path, prefix, measurement=True)
            else: absent(path)
        for label in ('bootstrap_entry', 'bootstrap_final'):
            expected = PHASE02_PINS[label]
            add(ROOT / expected['relative'], 'phase02-entry/' + Path(expected['relative']).name, expected['sha256'])
        report['phase02_original_reports'] = {label: project_original(value) for label, value in phase02_documents.items()}
        report['phase02_original_report_inputs'] = phase02_identities
        need(phase02_documents['parent_report']['value']['passed'] is False
             and phase02_documents['wrapper_report']['value']['passed'] is False
             and phase02_documents['bootstrap_final']['value']['passed'] is False,
             'known original phase02 failure was changed')

        # Actual cost03 was a separate read-only probe, never a runtime gate.
        cost_directory = ROOT / 'mechanism-monitor-cost-tools-03'
        _, cost_manifest = checked_json(cost_directory / 'package-manifest.json', COST03['manifest']['sha256'])
        cost_paths, _ = listing(cost_directory)
        need({path.name for path in cost_paths} == set(cost_manifest['files']) | {'package-manifest.json'}
             and all(path.parent == cost_directory for path in cost_paths), 'actual cost tool inventory differs')
        for name, expected in cost_manifest['files'].items():
            actual = read(cost_directory / name)[0]
            need({key: actual[key] for key in ('bytes', 'sha256')} == expected == COST03['files'][name],
                 'actual cost tool source differs')
        tree(cost_directory, 'cost03-tools')
        add(ROOT / 'mechanism-monitor-cost-install-03.py', 'cost03-install/installer.py', COST03['installer']['sha256'])
        add(ROOT / 'mechanism-monitor-cost-install-03.json', 'cost03-install/receipt.json',
            COST03['actual_files']['mechanism-monitor-cost-install-03.json']['sha256'])
        tree(ROOT / 'mechanism-monitor-cost-03', 'cost03-output', measurement=True)
        cost_documents = {}
        for name in ('report.json', 'compiler-monitor.json', 'compiler-monitor-validation.json'):
            identity, raw = read(ROOT / 'mechanism-monitor-cost-03' / name, retain=True)
            need({key: identity[key] for key in ('bytes', 'sha256')} == COST03['actual_files'][name],
                 'actual cost03 output identity differs')
            cost_documents[name] = json.loads(raw)
        cost_report = cost_documents['report.json']; cost_ledger = cost_documents['compiler-monitor.json']
        need(cost_report['cost_probe_passed'] is True and cost_report['formal_measurement_passed'] is False
             and cost_report['capacity_attribution_allowed'] is False and cost_report['source_pins_stable'] is True,
             'known cost result/scope differs')
        _, validator_raw = read(cost_directory / 'validate_compiler_monitor.py', retain=True)
        validator = types.ModuleType('_hepta_cost03_export_validator')
        validator.__file__ = str(cost_directory / 'validate_compiler_monitor.py')
        exec(compile(validator_raw, validator.__file__, 'exec'), validator.__dict__)
        cost_validation = validator.validate(cost_ledger, cost_report['limits_unchanged'],
            cost_ledger['parent_started_monotonic_ns'], cost_ledger['parent_finished_monotonic_ns'])
        need(cost_validation == cost_documents['compiler-monitor-validation.json'] and cost_validation['passed'] is True,
             'actual cost ledger cannot reproduce the retained validation')
        report['cost03'] = {'original_passed': True, 'independent_validation': cost_validation,
                            'raw_cost': cost_report['raw_cost'], 'formal_runtime_performance': False,
                            'original_report': COST03['actual_files']['report.json']}
        report['phase02_monitor_proof'] = monitor_proof(phase02_documents, ROOT / 'mechanism-monitor-tools-02',
            'f6887620b5b421da497f709dcd02110cc1e89ab47bb00ac4087f82d3bf3cb4fe', cost_report['limits_unchanged'])

        # Future installation may be unrun, partial or failed. Preserve its real
        # files and original terminal without requiring an invented final receipt.
        phase_tools = ROOT / 'mechanism-monitor-tools-03'
        future_root_files = {
            'mechanism-monitor-tools-03.tar.gz': PHASE03['archive'],
            'mechanism-monitor-bootstrap-03.py': PHASE03['bootstrap'],
            'mechanism-monitor-tools-install-03.py': PHASE03['installer'],
        }
        if not installation['executed']:
            absent(phase_tools)
            for name in future_root_files: absent(ROOT / name)
            absent(ROOT / 'mechanism-monitor-tools-install-03.json')
        else:
            if os.path.lexists(phase_tools):
                tree(phase_tools, 'phase03-tools')
                paths, _ = listing(phase_tools)
                expected_members = {**PHASE03['files'], 'package-manifest.json': PHASE03['manifest']}
                for path in paths:
                    expected = expected_members.get(path.relative_to(phase_tools).as_posix())
                    actual = read(path)[0]
                    if expected is None or {key: actual[key] for key in ('bytes', 'sha256')} != expected:
                        discrepancies.append({'path': str(path), 'reason': 'partial/changed future tool differs from frozen source',
                                              'expected': expected, 'actual': actual})
                if installation.get('state') == 'succeeded' and {path.relative_to(phase_tools).as_posix() for path in paths} != set(expected_members):
                    discrepancies.append({'stage': 'phase03_installation', 'reason': 'successful installation lacks the frozen exact inventory'})
            else:
                absent(phase_tools)
                if installation.get('state') == 'succeeded':
                    discrepancies.append({'stage': 'phase03_installation', 'reason': 'successful installation has no tools directory'})
            for name, expected in future_root_files.items():
                path = ROOT / name
                if os.path.lexists(path):
                    actual = add(path, 'phase03-install/' + name)
                    if {key: actual[key] for key in ('bytes', 'sha256')} != expected:
                        discrepancies.append({'path': str(path), 'reason': 'retained future install source/archive differs',
                                              'expected': expected, 'actual': actual})
                else:
                    absent(path)
                    if installation.get('state') == 'succeeded':
                        discrepancies.append({'path': str(path), 'reason': 'successful future install lacks required source/archive'})

        phase03_documents, phase03_identities = {}, {}
        for label, relative in FUTURE_REPORTS.items():
            document, identity = optional_document(ROOT / relative, phase_input['file_pins'][label])
            phase03_documents[label] = document
            if identity is not None: phase03_identities[label] = identity
        if not installation['executed']:
            need(phase03_documents['install_receipt']['status'] == 'absent', 'unrun installation has a receipt')
        if installation.get('state') == 'succeeded':
            value = phase03_documents['install_receipt']['value']
            if not isinstance(value, dict) or value.get('passed') is not True or value.get('manifest_sha256') != PHASE03['manifest']['sha256']:
                discrepancies.append({'stage': 'phase03_installation', 'reason': 'successful native install has no matching positive original receipt'})
        if not operation['executed']:
            for label, relative in FUTURE_REPORTS.items():
                if label != 'install_receipt': absent(ROOT / relative)
            for relative in FUTURE_TREES: absent(ROOT / relative)
            absent(Path('/home/qian/hr-r25-ph03'))
        else:
            for relative, prefix in zip(FUTURE_TREES, ('phase03-parent', 'phase03-observation', 'phase03-monitor')):
                path = ROOT / relative
                if os.path.lexists(path): tree(path, prefix, measurement=True)
                else: absent(path)
        for label in ('install_receipt', 'bootstrap_entry', 'bootstrap_final'):
            if label in phase03_identities:
                add(ROOT / FUTURE_REPORTS[label], 'phase03-entry/' + Path(FUTURE_REPORTS[label]).name,
                    phase03_identities[label]['sha256'])
        report['phase03_original_report_inputs'] = phase03_identities
        phase03_monitor = monitor_proof(phase03_documents, phase_tools,
            PHASE03['files']['validate_compiler_monitor.py']['sha256'], cost_report['limits_unchanged'])
        report['phase03_monitor_proof'] = phase03_monitor
        report['phase03_installation'] = installation
        report['phase03'] = classify_phase(operation, phase03_documents, phase03_monitor)
        for label, document in phase03_documents.items():
            value = document.get('value')
            if label in ('parent_report', 'wrapper_report') and isinstance(value, dict):
                if not value.get('finished_utc') and (value.get('passed') is True or value.get('attribution_allowed') is True):
                    discrepancies.append({'stage': 'phase03', 'label': label,
                                          'reason': 'unfinished original report contains unsupported positive flags; preserved without promotion'})
        if report['phase03']['original_positive_chain_reproduced'] and discrepancies:
            report['phase03']['original_positive_chain_reproduced'] = False
            report['phase03']['disposition'] = 'original_positive_flags_with_recorded_evidence_discrepancies'
        socket_before = socket_metadata(Path('/home/qian/hr-r25-ph03'))
        report['phase03_socket_metadata'] = socket_before

        # Recheck any original published stream seals without making absent
        # failure-time seals a prerequisite for lossless failure export.
        for revision, documents, directory in [('02', phase02_documents, ROOT / 'mechanism-monitor-campaign-02'),
                                               ('03', phase03_documents, ROOT / 'mechanism-monitor-campaign-03')]:
            wrapper = documents.get('wrapper_report', {}).get('value')
            if not isinstance(wrapper, dict): continue
            for stream in ('stdout', 'stderr'):
                expected = wrapper.get('original_parent_' + stream)
                if expected is None: continue
                actual_path = directory / ('original-parent.' + stream)
                actual = observed.get(str(actual_path))
                valid = (isinstance(expected, dict) and actual is not None
                         and (expected.get('path'), expected.get('bytes'), expected.get('sha256')) ==
                             (str(actual_path), actual['bytes'], actual['sha256'])
                         and expected.get('descriptor_identity') == expected.get('final_descriptor_identity') == actual['original_identity'])
                if not valid:
                    discrepancies.append({'stage': 'phase' + revision, 'stream': stream,
                                          'reason': 'original stream seal does not match retained complete current bytes; raw bytes preserved'})
        add(ROOT / 'qualification-02/report.json', 'baseline/qualification-02-report.json', QUALIFICATION_SHA)
        add(EXPORTER, 'export-tools/export_private_diagnostic_06.py', self_identity['sha256'])
        add(HELPER, 'export-tools/stable_archive.py', HELPER_SHA)
        add(INPUT, 'export-tools/actual-input-06.json', input_identity['sha256'])
        report['integrity_discrepancies'] = discrepancies
        if report['phase03']['original_positive_chain_reproduced'] and discrepancies:
            report['phase03']['original_positive_chain_reproduced'] = False
            report['phase03']['disposition'] = 'original_positive_flags_with_recorded_evidence_discrepancies'
        manifest = {'schema': 'hepta-r25-private-diagnostic-archive/v3', 'files': files, 'omitted_bodies': omissions,
                    'metadata_only_omissions': metadata_only, 'source_trees': inventories, 'excluded_cache_trees': cache_exclusions,
                    'recorded_absent_paths': sorted(set(absences)), 'original_build_report_inputs': report['original_build_report_inputs'],
                    'phase02_original_report_inputs': phase02_identities, 'phase02_original_reports': report['phase02_original_reports'],
                    'cost03': report['cost03'], 'phase03_original_report_inputs': phase03_identities,
                    'previous_installation_submission': PRIOR_UNKNOWN_INSTALL,
                    'phase03_installation': installation, 'phase03': report['phase03'], 'phase03_monitor_proof': phase03_monitor,
                    'phase03_socket_metadata': socket_before, 'integrity_discrepancies': discrepancies,
                    'native_and_mac_companions_required': True, 'capacity_admission_made_here': False,
                    'baseline_adoption_status': 'qualified_but_unadopted_R25', 'diagnostic_only': True,
                    'production_candidate': False, 'original_failed_or_partial_reports_rewritten': False}
        archive = OUT / 'private-diagnostic-full-06.tar.gz'
        manifest_raw, archive_proof = H.write_archive(archive, manifest, files,
            secret_prefixes=('phase02-', 'phase03-parent/', 'phase03-observation/', 'phase03-monitor/', 'cost03-output/'))
        for directory, expected in inventories.items():
            need(H.listing(Path(directory)) == expected, 'original source directory inventory changed')
        for expected in list(files.values()) + omissions:
            path = Path(expected['source_path'])
            actual = original_elf_identity(path) if expected['is_elf'] else read(path)[0]
            need(all(actual[key] == expected[key] for key in actual), 'original input changed after archive')
        for value in metadata_only:
            need(stamp(Path(value['source_path']).lstat()) == value['original_identity'], 'metadata-only omitted file changed')
        for path in absences: need(not os.path.lexists(path), 'original absent path appeared during export')
        need(socket_metadata(Path('/home/qian/hr-r25-ph03')) == socket_before, 'attempt socket metadata changed during export')
        need(compiler_source_map(ROOT / 'mechanism-diagnostic-03/source') == failed['diagnostic']['source_tested']
             and compiler_source_map(PRIVATE05 / 'source') == current['diagnostic']['source_after'],
             'original compiler source map changed during export')
        H.create(OUT / 'manifest.json', manifest_raw)
        report.update(export_completed=True, passed=not discrepancies, every_member_verified=True,
                      included_files=len(files), omitted_body_count=len(omissions), metadata_only_omissions=len(metadata_only),
                      archive=archive_proof['identity'], archive_verification=archive_proof,
                      manifest=read(OUT / 'manifest.json')[0], transfer=H.transfer_chunks(archive, OUT))
    except BaseException as error:
        report['error'] = {'type': type(error).__name__, 'reason': str(error)}
        H.create(OUT / 'failure.traceback', traceback.format_exc().encode())
    report['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    H.create(OUT / 'report.json', H.encode(report))
    print(json.dumps({'passed': report['passed'], 'export_completed': report['export_completed'],
                      'report': read(OUT / 'report.json')[0]}), flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.dont_write_bytecode = True
    raise SystemExit(main())
