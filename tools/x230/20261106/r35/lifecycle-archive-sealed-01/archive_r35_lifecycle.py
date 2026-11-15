#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Archive the original R35 normal lifecycle evidence, including failed attempts.

Fixed reports, logs, tools and inputs only. No tests, benchmarks, SSH or archived
programs are executed. Failed and successful workflow/gate outcomes stay distinct.
Creation is create-only; local verification is bounded and does not extract files.
"""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tarfile

ROOT = Path('/home/qian/hepta-runtime-optimization-20261106-r35')
R16 = Path('/home/qian/hepta-runtime-optimization-20261104-r16')
EXTERNAL_PREFIX = 'external/r16/'
MAX_TOTAL = 64 * 1024 * 1024
MAX_FILE = 8 * 1024 * 1024
MAX_MANIFEST = 2 * 1024 * 1024
MAX_FILES = 8192
MAX_TAR = MAX_TOTAL + MAX_MANIFEST + MAX_FILES * 1024 + 1024 * 1024
REFERENCE_SHA = '96fa3ff43180ec0e922c4b6373ec9d7a902037d97ae06d9a774ebf318d9f1f2c'
QUALIFICATION_ARCHIVE_SHA = 'a40f7d42c4c17bad59e81f07736ba6999f66d35973ce8c62c9655b9d88476b3a'
CI_ARCHIVE_SHA = 'f5f569ccd51d3f2f8cdb11aee115967f0df367a04cf0fd9f50c21a8b5d86d42f'
ACTUAL = {'bytes': {'campaign-01/compiler-monitor.audit.json': 841,
           'campaign-01/compiler-monitor.json': 198175,
           'campaign-01/report.json': 143570,
           'campaign-01/summary.json': 14469,
           'campaign-inputs-01.json': 17898,
           'candidate/candidate.patch': 3774,
           'external/frozen-jobs/1a16a4035ad-b1270-1.json': 880,
           'external/frozen-jobs/1a16a403e55-b1270-2.json': 877,
           'external/frozen-jobs/1a16a4046ac-b1270-3.json': 881,
           'external/frozen-jobs/1a16a40534e-b1270-4.json': 890,
           'external/frozen-jobs/1a16a405d21-b1270-5.json': 877,
           'external/frozen-jobs/1a16a40671b-b1270-6.json': 878,
           'external/r16/benchmark-topology.json': 796,
           'lifecycle-abba-01/audit-0-A.stderr': 0,
           'lifecycle-abba-01/audit-0-A.stdout': 107,
           'lifecycle-abba-01/audit-1-B.stderr': 0,
           'lifecycle-abba-01/audit-1-B.stdout': 107,
           'lifecycle-abba-01/audit-2-B.stderr': 0,
           'lifecycle-abba-01/audit-2-B.stdout': 107,
           'lifecycle-abba-01/audit-3-A.stderr': 0,
           'lifecycle-abba-01/audit-3-A.stdout': 105,
           'lifecycle-abba-01/canary-0-A.stderr': 0,
           'lifecycle-abba-01/canary-0-A.stdout': 136,
           'lifecycle-abba-01/canary-1-B.stderr': 0,
           'lifecycle-abba-01/canary-1-B.stdout': 136,
           'lifecycle-abba-01/canary-2-B.stderr': 0,
           'lifecycle-abba-01/canary-2-B.stdout': 136,
           'lifecycle-abba-01/canary-3-A.stderr': 0,
           'lifecycle-abba-01/canary-3-A.stdout': 136,
           'lifecycle-abba-01/gates.json': 17120,
           'lifecycle-abba-01/normal-lifecycle-gates.stderr': 0,
           'lifecycle-abba-01/normal-lifecycle-gates.stdout': 129,
           'lifecycle-abba-01/plan.json': 10818,
           'lifecycle-abba-01/report.json': 32393,
           'lifecycle-abba-01/round-0-A/independent-summary.json': 14379,
           'lifecycle-abba-01/round-0-A/phase-after_crash_running.json': 1813,
           'lifecycle-abba-01/round-0-A/phase-after_transport_running.json': 1808,
           'lifecycle-abba-01/round-0-A/phase-before_crash_running.json': 1798,
           'lifecycle-abba-01/round-0-A/phase-cancel_after_terminal.json': 1831,
           'lifecycle-abba-01/round-0-A/phase-concurrent_cancel.json': 1823,
           'lifecycle-abba-01/round-0-A/phase-launch.json': 1774,
           'lifecycle-abba-01/round-0-A/phase-prepare.json': 501,
           'lifecycle-abba-01/round-0-A/phase-same_key_after_cancel.json': 1830,
           'lifecycle-abba-01/round-0-A/phase-same_key_after_crash.json': 1823,
           'lifecycle-abba-01/round-0-A/phase-terminal.json': 1815,
           'lifecycle-abba-01/round-0-A/phase-terminal_after_restart.json': 1821,
           'lifecycle-abba-01/round-0-A/report.json': 568400,
           'lifecycle-abba-01/round-1-B/independent-summary.json': 14397,
           'lifecycle-abba-01/round-1-B/phase-after_crash_running.json': 1815,
           'lifecycle-abba-01/round-1-B/phase-after_transport_running.json': 1808,
           'lifecycle-abba-01/round-1-B/phase-before_crash_running.json': 1798,
           'lifecycle-abba-01/round-1-B/phase-cancel_after_terminal.json': 1831,
           'lifecycle-abba-01/round-1-B/phase-concurrent_cancel.json': 1823,
           'lifecycle-abba-01/round-1-B/phase-launch.json': 1774,
           'lifecycle-abba-01/round-1-B/phase-prepare.json': 501,
           'lifecycle-abba-01/round-1-B/phase-same_key_after_cancel.json': 1830,
           'lifecycle-abba-01/round-1-B/phase-same_key_after_crash.json': 1825,
           'lifecycle-abba-01/round-1-B/phase-terminal.json': 1815,
           'lifecycle-abba-01/round-1-B/phase-terminal_after_restart.json': 1821,
           'lifecycle-abba-01/round-1-B/report.json': 568239,
           'lifecycle-abba-01/round-2-B/independent-summary.json': 14831,
           'lifecycle-abba-01/round-2-B/phase-after_crash_running.json': 1815,
           'lifecycle-abba-01/round-2-B/phase-after_transport_running.json': 1808,
           'lifecycle-abba-01/round-2-B/phase-before_crash_running.json': 1798,
           'lifecycle-abba-01/round-2-B/phase-cancel_after_terminal.json': 1831,
           'lifecycle-abba-01/round-2-B/phase-concurrent_cancel.json': 1823,
           'lifecycle-abba-01/round-2-B/phase-launch.json': 1774,
           'lifecycle-abba-01/round-2-B/phase-prepare.json': 501,
           'lifecycle-abba-01/round-2-B/phase-same_key_after_cancel.json': 1830,
           'lifecycle-abba-01/round-2-B/phase-same_key_after_crash.json': 1825,
           'lifecycle-abba-01/round-2-B/phase-terminal.json': 1815,
           'lifecycle-abba-01/round-2-B/phase-terminal_after_restart.json': 1821,
           'lifecycle-abba-01/round-2-B/report.json': 568595,
           'lifecycle-abba-01/round-3-A/independent-summary.json': 13802,
           'lifecycle-abba-01/round-3-A/phase-after_crash_running.json': 1815,
           'lifecycle-abba-01/round-3-A/phase-after_transport_running.json': 1818,
           'lifecycle-abba-01/round-3-A/phase-before_crash_running.json': 1808,
           'lifecycle-abba-01/round-3-A/phase-cancel_after_terminal.json': 1821,
           'lifecycle-abba-01/round-3-A/phase-concurrent_cancel.json': 1823,
           'lifecycle-abba-01/round-3-A/phase-launch.json': 1784,
           'lifecycle-abba-01/round-3-A/phase-prepare.json': 501,
           'lifecycle-abba-01/round-3-A/phase-same_key_after_cancel.json': 1820,
           'lifecycle-abba-01/round-3-A/phase-same_key_after_crash.json': 1825,
           'lifecycle-abba-01/round-3-A/phase-terminal.json': 1815,
           'lifecycle-abba-01/round-3-A/phase-terminal_after_restart.json': 1811,
           'lifecycle-abba-01/round-3-A/report.json': 567889,
           'lifecycle-abba-01/round-index.json': 15137,
           'lifecycle-abba-01/summary.json': 61099,
           'lifecycle-abba-01/summary.stderr': 0,
           'lifecycle-abba-01/summary.stdout': 132,
           'lifecycle-campaign-01/baseline-source-inputs.json': 34902,
           'lifecycle-campaign-01/compiler-monitor.audit.json': 850,
           'lifecycle-campaign-01/compiler-monitor.json': 99515,
           'lifecycle-campaign-01/lifecycle-tool-tests.stderr': 0,
           'lifecycle-campaign-01/lifecycle-tool-tests.stdout': 423,
           'lifecycle-campaign-01/normal-lifecycle-abba.stderr': 0,
           'lifecycle-campaign-01/normal-lifecycle-abba.stdout': 198,
           'lifecycle-campaign-01/plan.json': 4560,
           'lifecycle-campaign-01/report.json': 104245,
           'lifecycle-campaign-01/source-inputs.json': 34902,
           'lifecycle-holder-native-01.json': 726,
           'lifecycle-holder-read-01.json': 1231,
           'lifecycle-holder-report-01.json': 9217,
           'lifecycle-inputs-01.example.json': 3246,
           'lifecycle-inputs-01.json': 5748,
           'lifecycle-materialization-native-01.json': 729,
           'lifecycle-materialization-read-01.json': 2809,
           'lifecycle-tool-tests-01/report.json': 463,
           'lifecycle-tools-01/README.md': 9053,
           'lifecycle-tools-01/allocator_environment.py': 5879,
           'lifecycle-tools-01/allocator_environment_audit.py': 6709,
           'lifecycle-tools-01/analyze_lifecycle_gates.py': 7581,
           'lifecycle-tools-01/analyze_native_observation.py': 8708,
           'lifecycle-tools-01/audit_native_evidence.py': 17065,
           'lifecycle-tools-01/cancel_saturation_gate.py': 15789,
           'lifecycle-tools-01/lifecycle-gate-policy.json': 1575,
           'lifecycle-tools-01/lifecycle-tools-manifest-01.json': 4066,
           'lifecycle-tools-01/observation_resources.py': 12382,
           'lifecycle-tools-01/owned_ssh_interruption.py': 7892,
           'lifecycle-tools-01/run_lifecycle_abba_01.py': 14787,
           'lifecycle-tools-01/run_lifecycle_tool_tests.py': 2224,
           'lifecycle-tools-01/run_native_observation.py': 3279,
           'lifecycle-tools-01/run_six_host_cancel_recovery.py': 27847,
           'lifecycle-tools-01/run_six_host_cancel_recovery_timed.py': 30163,
           'lifecycle-tools-01/run_six_host_cancel_saturation.py': 31325,
           'lifecycle-tools-01/source-provenance.json': 2510,
           'lifecycle-tools-01/status-predicate.json': 875,
           'lifecycle-tools-01/summarize_lifecycle_abba_01.py': 16065,
           'lifecycle-tools-01/test_native_harness.py': 13286,
           'lifecycle-tools-01/test_r25_lifecycle_tools.py': 10026,
           'lifecycle-tools-01/test_verify_saturation_extension.py': 8187,
           'lifecycle-tools-01/verify_cancel_recovery.py': 16634,
           'lifecycle-tools-01/verify_cancel_saturation.py': 17123,
           'lifecycle-tools-01/verify_saturation_extension.py': 9418,
           'lifecycle-tools-01/x230_observation_benchmark.py': 37006,
           'lifecycle-tools-01/x230_six_running_recovery_canary.py': 47298,
           'preparation.json': 62335,
           'prepare_qualify.py': 32838,
           'qualification-01/isolated-tests/summary.json': 6878,
           'qualification-01/report.json': 83363,
           'qualification-01/source-map.json': 24156,
           'qualification-input.json': 3742,
           'qualification-terminal-status-01.json': 731,
           'tools-01/compiler-monitor-policy-01.json': 1001,
           'tools-01/compiler_monitor.py': 12510,
           'tools-01/compiler_state.py': 6243,
           'tools-01/prepare_lifecycle_inputs.py': 12203,
           'tools-01/r35_campaign.py': 84362,
           'tools-01/r35_lifecycle_campaign.py': 25109,
           'tools-01/validate_compiler_monitor.py': 7055},
 'candidate_adopted_by_sealer': False,
 'collector_or_original_auditors_executed': False,
 'compiler_monitor_sample_count': 149,
 'future_archive_receipt': None,
 'holder_job_id': '1a1afc4fb4a-fc05-6b7f',
 'holder_read_members': ['lifecycle-holder-read-01.json'],
 'identity_only_remote_bodies_read_by_sealer': False,
 'local_absence_is_not_remote_absence': True,
 'local_optional_originals_not_supplied': ['lifecycle-campaign-01/inputs.json',
                                           'lifecycle-campaign-01/plan.json',
                                           'lifecycle-campaign-01/source-inputs.json',
                                           'lifecycle-campaign-01/baseline-source-inputs.json',
                                           'lifecycle-campaign-01/compiler-monitor.json',
                                           'lifecycle-abba-01/plan.json'],
 'local_original_parse_errors': [],
 'local_originals': {'lifecycle-abba-01/gates.json': {'bytes': 17120,
                                                      'local_path': '/tmp/hepta-runtime-recovery-20261106/r35-lifecycle-originals-recovered-01/lifecycle-abba-01/gates.json',
                                                      'sha256': '22a2a35b0d9813c275626239bc315bd9666880056556d0c746e51426d34a0518'},
                     'lifecycle-abba-01/report.json': {'bytes': 32393,
                                                       'local_path': '/tmp/hepta-runtime-recovery-20261106/r35-lifecycle-originals-recovered-01/lifecycle-abba-01/report.json',
                                                       'sha256': 'f064d5daa533b57277efc329db2e5b5a71e12ac1313f458ec7f771ac4b80b402'},
                     'lifecycle-abba-01/round-0-A/independent-summary.json': {'bytes': 14379,
                                                                              'local_path': '/tmp/hepta-runtime-recovery-20261106/r35-lifecycle-originals-recovered-01/lifecycle-abba-01/round-0-A/independent-summary.json',
                                                                              'sha256': '7998a595a26aed6bb9e4fd09b19ebcd608a4945f71124f2c21c22222f7517249'},
                     'lifecycle-abba-01/round-1-B/independent-summary.json': {'bytes': 14397,
                                                                              'local_path': '/tmp/hepta-runtime-recovery-20261106/r35-lifecycle-originals-recovered-01/lifecycle-abba-01/round-1-B/independent-summary.json',
                                                                              'sha256': '6ab234da1fb44738d0e185e3c9b0a8370ddb4ca4ab4726a1e8d8c45afac04fdc'},
                     'lifecycle-abba-01/round-2-B/independent-summary.json': {'bytes': 14831,
                                                                              'local_path': '/tmp/hepta-runtime-recovery-20261106/r35-lifecycle-originals-recovered-01/lifecycle-abba-01/round-2-B/independent-summary.json',
                                                                              'sha256': 'ed110c454ea47fe98d940b938e0be98a06edddc90a420e7ef02129bf8ec9d1bd'},
                     'lifecycle-abba-01/round-3-A/independent-summary.json': {'bytes': 13802,
                                                                              'local_path': '/tmp/hepta-runtime-recovery-20261106/r35-lifecycle-originals-recovered-01/lifecycle-abba-01/round-3-A/independent-summary.json',
                                                                              'sha256': 'd7ee9d06dd4dc5500ecc82a57bef3cc6a678112d50dd8e72a863c7aa50c50043'},
                     'lifecycle-abba-01/round-index.json': {'bytes': 15137,
                                                            'local_path': '/tmp/hepta-runtime-recovery-20261106/r35-lifecycle-originals-recovered-01/lifecycle-abba-01/round-index.json',
                                                            'sha256': 'a8468aa002225177edf6762fde4ad2ef41f8648b509a41e64cea7294c58e45a6'},
                     'lifecycle-abba-01/summary.json': {'bytes': 61099,
                                                        'local_path': '/tmp/hepta-runtime-recovery-20261106/r35-lifecycle-originals-recovered-01/lifecycle-abba-01/summary.json',
                                                        'sha256': '395910074c4df762c12ff028cd0caae27b530123cf97dd63eb873f0afaafcd81'},
                     'lifecycle-campaign-01/compiler-monitor.audit.json': {'bytes': 850,
                                                                           'local_path': '/tmp/hepta-runtime-recovery-20261106/r35-lifecycle-originals-recovered-01/lifecycle-campaign-01/compiler-monitor.audit.json',
                                                                           'sha256': '6d1f4b8cc59335f05c0cd8ca688138a17747fa78b416dafc56f42304928b8db3'},
                     'lifecycle-campaign-01/report.json': {'bytes': 104245,
                                                           'local_path': '/tmp/hepta-runtime-recovery-20261106/r35-lifecycle-originals-recovered-01/lifecycle-campaign-01/report.json',
                                                           'sha256': 'c90c0de71aafb9ef3a6f6ecefbd6b482ce5399e2fa345ae126f0f0f9d9aaab92'},
                     'lifecycle-holder-native-01.json': {'bytes': 726,
                                                         'local_path': '/tmp/hepta-runtime-recovery-20261106/r35-lifecycle-originals-recovered-01/lifecycle-holder-native-01.json',
                                                         'sha256': 'bd6715663970570781f50c9c6dd66bf27562fbd550fe29c3972cc6ccba684440'},
                     'lifecycle-holder-read-01.json': {'bytes': 1231,
                                                       'local_path': '/tmp/hepta-runtime-recovery-20261106/r35-lifecycle-originals-recovered-01/lifecycle-holder-read-01.json',
                                                       'sha256': 'd3ca9a90ebf17f039ffead27bde735c47569a4ff3ea898c4510309409596c306'},
                     'lifecycle-holder-report-01.json': {'bytes': 9217,
                                                         'local_path': '/tmp/hepta-runtime-recovery-20261106/r35-lifecycle-originals-recovered-01/lifecycle-holder-report-01.json',
                                                         'sha256': 'df8b6e9f8e2e766603b8d86535d4aaabf2333e3cbe9ccb67c347305c74c5a509'},
                     'lifecycle-inputs-01.json': {'bytes': 5748,
                                                  'local_path': '/tmp/hepta-runtime-recovery-20261106/r35-lifecycle-originals-recovered-01/lifecycle-inputs-01.json',
                                                  'sha256': '96e728ffe35848497b694a9925e48523d9f468b349da18fb5b40c437329a2a86'},
                     'lifecycle-materialization-native-01.json': {'bytes': 729,
                                                                  'local_path': '/tmp/hepta-runtime-recovery-20261106/r35-lifecycle-originals-recovered-01/lifecycle-materialization-native-01.json',
                                                                  'sha256': 'e9d1ce496f8533ee0af67854e7c01ecf5c06a51efbe1a7ad00129ca3c2575a51'},
                     'lifecycle-materialization-read-01.json': {'bytes': 2809,
                                                                'local_path': '/tmp/hepta-runtime-recovery-20261106/r35-lifecycle-originals-recovered-01/lifecycle-materialization-read-01.json',
                                                                'sha256': '8fe6e9c170d72f4434e9748dbfab9157e9824cbc9e2e6803720a9d80cf027da0'},
                     'lifecycle-tool-tests-01/report.json': {'bytes': 463,
                                                             'local_path': '/tmp/hepta-runtime-recovery-20261106/r35-lifecycle-originals-recovered-01/lifecycle-tool-tests-01/report.json',
                                                             'sha256': '1234700154119515e2e483a1b63a7d2be5c2d59904e58a3528891cc143a53893'}},
 'original_native_terminal': {'automatic_retry': False,
                              'cancelled': False,
                              'exit_code': 1,
                              'job_id': '1a1afc4fb4a-fc05-6b7f',
                              'log_bytes': {'stderr': {'seen': 0, 'stored': 0}, 'stdout': {'seen': 296, 'stored': 296}},
                              'log_errors': {'stderr': None, 'stdout': None},
                              'log_synced': {'stderr': True, 'stdout': True},
                              'log_truncated': {'stderr': False, 'stdout': False},
                              'original_streams': {'stderr': {'bytes': 0,
                                                              'complete_to_final_stored_bytes': True,
                                                              'contiguous_from_zero': True,
                                                              'pages': 1,
                                                              'seen_equals_stored': True,
                                                              'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'},
                                                   'stdout': {'bytes': 296,
                                                              'complete_to_final_stored_bytes': True,
                                                              'contiguous_from_zero': True,
                                                              'pages': 1,
                                                              'seen_equals_stored': True,
                                                              'sha256': '3257b090a5ba065f9bca09587491e288995b2b2711983eb81d04e8e6b0ac20b8'}},
                              'output_complete': True,
                              'output_durable': True,
                              'state': 'failed',
                              'terminal_publication_confirmed': True,
                              'timed_out': False},
 'original_normal_reported_passed': False,
 'original_round_audit_reported_counts': {'lifecycle-abba-01/round-0-A/independent-summary.json': {'automatic_rpc_retries': 0,
                                                                                                   'cancellations': 12,
                                                                                                   'independent_ssh_calls': 36,
                                                                                                   'native_calls': 90,
                                                                                                   'new_starts': 6,
                                                                                                   'same_key_lookups': 12},
                                          'lifecycle-abba-01/round-1-B/independent-summary.json': {'automatic_rpc_retries': 0,
                                                                                                   'cancellations': 12,
                                                                                                   'independent_ssh_calls': 36,
                                                                                                   'native_calls': 90,
                                                                                                   'new_starts': 6,
                                                                                                   'same_key_lookups': 12},
                                          'lifecycle-abba-01/round-2-B/independent-summary.json': {'automatic_rpc_retries': 0,
                                                                                                   'cancellations': 12,
                                                                                                   'independent_ssh_calls': 36,
                                                                                                   'native_calls': 90,
                                                                                                   'new_starts': 6,
                                                                                                   'same_key_lookups': 12},
                                          'lifecycle-abba-01/round-3-A/independent-summary.json': {'automatic_rpc_retries': 0,
                                                                                                   'cancellations': 12,
                                                                                                   'independent_ssh_calls': 36,
                                                                                                   'native_calls': 90,
                                                                                                   'new_starts': 6,
                                                                                                   'same_key_lookups': 12}},
 'outcomes': {'normal_lifecycle_gate_passed': False,
              'normal_lifecycle_gate_verified': True,
              'parent_reported_adoption_passed': False,
              'workflow_reported_passed': False},
 'schema': 'hepta-r35-normal-lifecycle-archive-bindings/v1',
 'sha256': {'campaign-01/compiler-monitor.audit.json': '66c850ff22dbadcd81a385aa4431c437f004b4c26eb61761004a8268088846e2',
            'campaign-01/compiler-monitor.json': '4314521f6e8479cdc5a56941e1335999039d8d03c7919d6ccbfd5714cd892452',
            'campaign-01/report.json': '3923115d1a8ba2aeb2fc00405bcd01f8d0f92e509b23e17ba6413634d47dba00',
            'campaign-01/summary.json': '0845c8ef6fb7d82350b00f594a68eb523c171b539f588ae1b4e7f12fe1aae3ce',
            'campaign-inputs-01.json': 'eec0348217f6c679d1f965004f1bd8ecded2886fc1c654d45a9ad6ea700391e4',
            'candidate/candidate.patch': '89eed62593e1b3c5a675221d1df998d27aae4b6a0fdfa028e297544838fa049a',
            'external/frozen-jobs/1a16a4035ad-b1270-1.json': 'a8982325aea4833461e2b6a76ca83f846b80b99a227298e97a0b279e2d9dfdb8',
            'external/frozen-jobs/1a16a403e55-b1270-2.json': 'bbb8a86161837ff0f197b345c25bc66224e3404473dea2ac46d1f44f3af43609',
            'external/frozen-jobs/1a16a4046ac-b1270-3.json': '4badc323518a6db1567162a2d7ef5d1209aa88375aba201ec6f3aab34bec61a8',
            'external/frozen-jobs/1a16a40534e-b1270-4.json': '79e18b1a42d84f8024b692dfd98a9f06fa1d6886bf5dc230248cfbde674f011c',
            'external/frozen-jobs/1a16a405d21-b1270-5.json': '9c89c598f35f6bc94572852fcc03feed6e8c798ee34db5095bd3b48813562dc6',
            'external/frozen-jobs/1a16a40671b-b1270-6.json': '5b737330fa5a75a458138e1848a044d2a77c062175d8eb9694a510ff20b53cde',
            'external/r16/benchmark-topology.json': '8c0767d3318131a7d470d9cde8e327a59ce18adf022c8bc1b1d5a0fa9a865287',
            'lifecycle-abba-01/audit-0-A.stderr': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            'lifecycle-abba-01/audit-0-A.stdout': 'cb725a111e5bc0291b3fa207755a5bf5f41d06f1600d6b1112fe481c21ed61f5',
            'lifecycle-abba-01/audit-1-B.stderr': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            'lifecycle-abba-01/audit-1-B.stdout': 'ae483d8ba42b0827f8a4fec472cd70f147170582a30dff035f1cf6f4c63687e3',
            'lifecycle-abba-01/audit-2-B.stderr': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            'lifecycle-abba-01/audit-2-B.stdout': 'fccfba26f2686f9efb022d190f7837c247f80c21af61a32db260b13986dcd53b',
            'lifecycle-abba-01/audit-3-A.stderr': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            'lifecycle-abba-01/audit-3-A.stdout': 'f8dc84b05e08f66688d75ba92c3e6832c1677492642284ea8c7e3124c34af288',
            'lifecycle-abba-01/canary-0-A.stderr': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            'lifecycle-abba-01/canary-0-A.stdout': 'a228a7764d8f749c6f65ad92c834c78ff84c955b2a1458306da92c789d782aef',
            'lifecycle-abba-01/canary-1-B.stderr': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            'lifecycle-abba-01/canary-1-B.stdout': '74b9791840d934dd3ed13b4bf68c5d1918ac3db0d5f193d1024d9ccc216a8031',
            'lifecycle-abba-01/canary-2-B.stderr': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            'lifecycle-abba-01/canary-2-B.stdout': '2ec33d4039269896a1fc9f60a67dc6e49000bf375d509f4327bac937210d82e3',
            'lifecycle-abba-01/canary-3-A.stderr': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            'lifecycle-abba-01/canary-3-A.stdout': '52dc9f255ad127e7a678c6cc4e07d1466dbc24d1d495f2704196ce7c030b4d76',
            'lifecycle-abba-01/gates.json': '22a2a35b0d9813c275626239bc315bd9666880056556d0c746e51426d34a0518',
            'lifecycle-abba-01/normal-lifecycle-gates.stderr': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            'lifecycle-abba-01/normal-lifecycle-gates.stdout': 'b3ffad719f3d808b24dee84f626f43777ce7bdd3d0df2636408bb86bbeaef808',
            'lifecycle-abba-01/plan.json': 'd3338aa1600f459c6157bb89182bce204fa107927af5e929d70f6f19b30a6ce3',
            'lifecycle-abba-01/report.json': 'f064d5daa533b57277efc329db2e5b5a71e12ac1313f458ec7f771ac4b80b402',
            'lifecycle-abba-01/round-0-A/independent-summary.json': '7998a595a26aed6bb9e4fd09b19ebcd608a4945f71124f2c21c22222f7517249',
            'lifecycle-abba-01/round-0-A/phase-after_crash_running.json': 'a94501cbd1e0cf22746578c49f8efa2a1845cb59a58d313cda19890102a37bd5',
            'lifecycle-abba-01/round-0-A/phase-after_transport_running.json': 'b57d68e260fdbc94d1484875c0c953b3e302b769851bf27eebfb877ae218c4c5',
            'lifecycle-abba-01/round-0-A/phase-before_crash_running.json': '9dbfd5edbec3f4eb010f9efecafa2d9bc885106b74248208ae384ca3feec5ad4',
            'lifecycle-abba-01/round-0-A/phase-cancel_after_terminal.json': 'ffe6bc811310bb89c010736929246e434b3644c26085b814ddf964673bb83740',
            'lifecycle-abba-01/round-0-A/phase-concurrent_cancel.json': '02d87b8802a515f1b9f696c33d8e3ab1cc739d669ed8acb2a236f60ff10def7a',
            'lifecycle-abba-01/round-0-A/phase-launch.json': 'ffcee67b9967f7e3e643d7a8d1fe6cfe966d8b9a4e9a8be15cca3c2a193a2bcf',
            'lifecycle-abba-01/round-0-A/phase-prepare.json': 'ee8a02be9cba8444a61988161c6e799ce19bf48ec4236286d06aec9266dc8fa2',
            'lifecycle-abba-01/round-0-A/phase-same_key_after_cancel.json': 'ddf5b71b3c7c1afd4161db252bc9dcfb869b2dede452834f4ce4c1bdd32cfea7',
            'lifecycle-abba-01/round-0-A/phase-same_key_after_crash.json': 'bbfc8a2e68ccdabb4c940a6a47686134fc6f1a24971a2d41741f80a060a22bf1',
            'lifecycle-abba-01/round-0-A/phase-terminal.json': 'a911cb554da1e3eb351463e4c71633aca0735bb384a96e7d20410d57f04b6e16',
            'lifecycle-abba-01/round-0-A/phase-terminal_after_restart.json': '2761d0eaf8f85b2b7a697e3ed10b362bb306207c36406ea8039c11a2013c6462',
            'lifecycle-abba-01/round-0-A/report.json': '21bcd67d731cca3163bbcee77dcecdbd778794ce2bff3fc18e496f4a7e248808',
            'lifecycle-abba-01/round-1-B/independent-summary.json': '6ab234da1fb44738d0e185e3c9b0a8370ddb4ca4ab4726a1e8d8c45afac04fdc',
            'lifecycle-abba-01/round-1-B/phase-after_crash_running.json': 'bd07c7e08f2d9806812aedacf6ee6a563dd819e8f36b94f870983b21c80bb01b',
            'lifecycle-abba-01/round-1-B/phase-after_transport_running.json': 'f9a1dccc9e2f287f37eae23faac7633fae53bb65a9184c48dffb7137ca16751d',
            'lifecycle-abba-01/round-1-B/phase-before_crash_running.json': '1520c54b029345ba3dd08400abd3474922dd3675b1e49a1df0e86dd78c08669f',
            'lifecycle-abba-01/round-1-B/phase-cancel_after_terminal.json': 'a3922b739a0af476b924ca00a8146ef5b605c3d5af2381fcea97ddd4a6fa2171',
            'lifecycle-abba-01/round-1-B/phase-concurrent_cancel.json': '23b542f87484f6d5a59a4c75c0242c2be2d24daabca48c431a7d2b0b7cb38afb',
            'lifecycle-abba-01/round-1-B/phase-launch.json': '8f5401f793a327429138d6df65ef80de1d51e80a684aa8034d26a73e3f91d784',
            'lifecycle-abba-01/round-1-B/phase-prepare.json': 'cd53d89adffabf98da9495bdddd43167b08ae7eb30b79516d71ef46673986cfb',
            'lifecycle-abba-01/round-1-B/phase-same_key_after_cancel.json': '4bb02bdd0d347b9d78865acbfb27db10ab9dc45411906ce66c141606acbb1a38',
            'lifecycle-abba-01/round-1-B/phase-same_key_after_crash.json': '649335bbe9fe70d3d0124ba54bd3a9e8c204bf0415e7887c74937d7b2a02286d',
            'lifecycle-abba-01/round-1-B/phase-terminal.json': '9d3813c4389556f5aa2ccfc569728986af8e8ec0f9ef5252add7d54bd90143cd',
            'lifecycle-abba-01/round-1-B/phase-terminal_after_restart.json': '1565861b35076a675318749b34c041fdcf0a933898b3486b5a431fed53017158',
            'lifecycle-abba-01/round-1-B/report.json': '8df9c91a71f85dfe1f73c7edce71567d6e0525f7845768532f8a33433fa76782',
            'lifecycle-abba-01/round-2-B/independent-summary.json': 'ed110c454ea47fe98d940b938e0be98a06edddc90a420e7ef02129bf8ec9d1bd',
            'lifecycle-abba-01/round-2-B/phase-after_crash_running.json': '640bc2d2895130a02650033cf5b8d2b1931f6384c4f64ff569ac7f904045da6e',
            'lifecycle-abba-01/round-2-B/phase-after_transport_running.json': '11397426177162cefa1949ba8c47a572de7bb2fc7fdf8d80f28af282c09e32fa',
            'lifecycle-abba-01/round-2-B/phase-before_crash_running.json': '527daa275cab3dc2d66821b1ec8b99770d8fb5b8d5b04ce478fd4a98abcaab51',
            'lifecycle-abba-01/round-2-B/phase-cancel_after_terminal.json': '027f255538df94024ab3be6f267552f739e1b51c2e94c5b3f2b8a942c6695e8f',
            'lifecycle-abba-01/round-2-B/phase-concurrent_cancel.json': '67be4de84bc7e22c1f55a01a875002a623c711817bfa8f95d6fd3c07b3934066',
            'lifecycle-abba-01/round-2-B/phase-launch.json': '387c1af755ae5a5d84cf724ba80f1ce6cab80001b75012f596f044b48ac5ae90',
            'lifecycle-abba-01/round-2-B/phase-prepare.json': 'c3728d5872068310e6f261de43b28160da2e66576b622c9e10667fa24aa060ed',
            'lifecycle-abba-01/round-2-B/phase-same_key_after_cancel.json': '0299dd721e5a74f1c53d24dc875083f65477295130ff12c1f2efa3dde537c664',
            'lifecycle-abba-01/round-2-B/phase-same_key_after_crash.json': '60d90c2aac3d315817a4214094fd9e3cf451a2a5ed2ebe71b2fce4715bfe1c44',
            'lifecycle-abba-01/round-2-B/phase-terminal.json': 'ab8d9b48b07464b4554be698a4802b55d3a720193da56798fcda009a9df221da',
            'lifecycle-abba-01/round-2-B/phase-terminal_after_restart.json': '52d6860169b6be293495cf5f6017cc67bb0a6ca0db8cec3bc6e7dac04da93a35',
            'lifecycle-abba-01/round-2-B/report.json': 'f63ded9be27bca2c741c6caf2767bbcda4af1acd4a5fcc0ea43865eb487c19a7',
            'lifecycle-abba-01/round-3-A/independent-summary.json': 'd7ee9d06dd4dc5500ecc82a57bef3cc6a678112d50dd8e72a863c7aa50c50043',
            'lifecycle-abba-01/round-3-A/phase-after_crash_running.json': '505c5ed1f70048eb2ced63824d184b7047de2260a9982605e073732a30caa72c',
            'lifecycle-abba-01/round-3-A/phase-after_transport_running.json': 'b53a180c48925eccb0623c11911fdd2ec55e77ac38691404c4b989bcbdcc1b6d',
            'lifecycle-abba-01/round-3-A/phase-before_crash_running.json': '179984a1ae04168664167452cc1d19ac503c7bb2ecc2036d33ba050825cee6bc',
            'lifecycle-abba-01/round-3-A/phase-cancel_after_terminal.json': '003f967ad0b4e10eebc29289dfafa69f422ea5bd835af74186be091c9cfcb37a',
            'lifecycle-abba-01/round-3-A/phase-concurrent_cancel.json': '82e28b3691ddd6d4b7b4ecf2c92c709f4adfdd110b31bc84954c0304578a40a7',
            'lifecycle-abba-01/round-3-A/phase-launch.json': 'a9badf1897eb918026e70fc56e45a6049a6148f55bbbe80399b15a27b80703c3',
            'lifecycle-abba-01/round-3-A/phase-prepare.json': 'b4d90c2df8687d2f16790168cecad1b497da5bb7da8bf864790a0f0d4b4f78f7',
            'lifecycle-abba-01/round-3-A/phase-same_key_after_cancel.json': 'e3a10c2e6875db96d9afc0787df0eb5512bda8c1fbdee7d6ca49627c966fa6bb',
            'lifecycle-abba-01/round-3-A/phase-same_key_after_crash.json': 'a56b091f10bc057ee8f262a1482b02b15e700705d9bd14b21dbfb903db95726e',
            'lifecycle-abba-01/round-3-A/phase-terminal.json': 'ecb41d8d989c157adc8ded50c654f5e9ea326029a64b0cefda61161a6930fdd5',
            'lifecycle-abba-01/round-3-A/phase-terminal_after_restart.json': 'a0bfa6f6e2d63800c21e2e15742e2f3b9de2b1f81279c361dba8a87fc584296a',
            'lifecycle-abba-01/round-3-A/report.json': '64c7ebdc1da9b771d0bb7972fe6bf0f75354e6eab7fe0413c0fddfdcd7284f31',
            'lifecycle-abba-01/round-index.json': 'a8468aa002225177edf6762fde4ad2ef41f8648b509a41e64cea7294c58e45a6',
            'lifecycle-abba-01/summary.json': '395910074c4df762c12ff028cd0caae27b530123cf97dd63eb873f0afaafcd81',
            'lifecycle-abba-01/summary.stderr': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            'lifecycle-abba-01/summary.stdout': '318bfa7b7d7047ecd22d3065c977202549a56238632e05b9001602c694e7fd36',
            'lifecycle-campaign-01/baseline-source-inputs.json': 'db2896451a01108553c3b5fdb44322ba72ba16a61274f344437ddf129d63a33b',
            'lifecycle-campaign-01/compiler-monitor.audit.json': '6d1f4b8cc59335f05c0cd8ca688138a17747fa78b416dafc56f42304928b8db3',
            'lifecycle-campaign-01/compiler-monitor.json': 'd7da91a88b37bc5779ff1d3665aa734a3c8235ab75ce68bd47b7ac2347b83e2f',
            'lifecycle-campaign-01/lifecycle-tool-tests.stderr': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            'lifecycle-campaign-01/lifecycle-tool-tests.stdout': 'be61201a338d466989aa7abb0bcbc08a5194304138b5cc22c2f2de94f4539ab5',
            'lifecycle-campaign-01/normal-lifecycle-abba.stderr': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            'lifecycle-campaign-01/normal-lifecycle-abba.stdout': 'db7e93381fbb67c8f41e18b6ab6e605f625b2dd831e5b0f638a504193acb0389',
            'lifecycle-campaign-01/plan.json': '8972853027acfb34c24022822655ef9dc58665ded777faa46b2d74ecd3161107',
            'lifecycle-campaign-01/report.json': 'c90c0de71aafb9ef3a6f6ecefbd6b482ce5399e2fa345ae126f0f0f9d9aaab92',
            'lifecycle-campaign-01/source-inputs.json': '332775ab6ffcb664099d5fdb0a1203c779e65f9786518c8d9332d4aa4ae289f7',
            'lifecycle-holder-native-01.json': 'bd6715663970570781f50c9c6dd66bf27562fbd550fe29c3972cc6ccba684440',
            'lifecycle-holder-read-01.json': 'd3ca9a90ebf17f039ffead27bde735c47569a4ff3ea898c4510309409596c306',
            'lifecycle-holder-report-01.json': 'df8b6e9f8e2e766603b8d86535d4aaabf2333e3cbe9ccb67c347305c74c5a509',
            'lifecycle-inputs-01.example.json': '7b4d6ef124a2ada384100d59fdd71a325ae2f8c162d6ef2656bcbd2a41c9173a',
            'lifecycle-inputs-01.json': '96e728ffe35848497b694a9925e48523d9f468b349da18fb5b40c437329a2a86',
            'lifecycle-materialization-native-01.json': 'e9d1ce496f8533ee0af67854e7c01ecf5c06a51efbe1a7ad00129ca3c2575a51',
            'lifecycle-materialization-read-01.json': '8fe6e9c170d72f4434e9748dbfab9157e9824cbc9e2e6803720a9d80cf027da0',
            'lifecycle-tool-tests-01/report.json': '1234700154119515e2e483a1b63a7d2be5c2d59904e58a3528891cc143a53893',
            'lifecycle-tools-01/README.md': 'bf5ece8988afa5a91f01da1df0e1740add1390f6653d32c7bd562d99b11529be',
            'lifecycle-tools-01/allocator_environment.py': 'f5c8e879c540b3f7cb1b7d3a7a0f5002c2f40c1a87963174b0b00470fa3a4525',
            'lifecycle-tools-01/allocator_environment_audit.py': '4b082ce343ae3943e3098baa58af2f5def7198881b9c087d63d88360e9763727',
            'lifecycle-tools-01/analyze_lifecycle_gates.py': 'c7a861a94a89dd81debb5c055773918d89a1c9c29b699e2e5a0341e51be69553',
            'lifecycle-tools-01/analyze_native_observation.py': 'cc7f6884d581cd1ced430437350e808de51931c50d12441797205501b20cae66',
            'lifecycle-tools-01/audit_native_evidence.py': 'b69f6902d2de81eab41b21506f024c002d2f8264d60e86df6b1086623a77fd28',
            'lifecycle-tools-01/cancel_saturation_gate.py': '536ebdc5f2b090a8c007f189a895ed2e19d7b8b7e41530ccba94dd826742ef7f',
            'lifecycle-tools-01/lifecycle-gate-policy.json': '36658346c4e265bf551a1ae1a4c6210bec8e4729f7961302a203008741cd381e',
            'lifecycle-tools-01/lifecycle-tools-manifest-01.json': 'eb50cd7ab0376c4b3dc768e8d184fdc23eeaa90c2ce5bdd4b9e9ac551448504e',
            'lifecycle-tools-01/observation_resources.py': 'f3402d51cb37b2fe20f4351b3a81ec5990a9fdaff93a846d21c07ccd557cb894',
            'lifecycle-tools-01/owned_ssh_interruption.py': '1989c57f0b944afae1ed759d6529b8f1cc26197e269e2c34c4fd49e43a32aa7b',
            'lifecycle-tools-01/run_lifecycle_abba_01.py': 'e01357cfb04f72f1ee1d56747df81b572e55c1528d2941f8dbbb0aa5e9a2ac84',
            'lifecycle-tools-01/run_lifecycle_tool_tests.py': 'e3c1e8163249dba14672a3a82b43a2d7b8b4c0802b94b8511bf3db668f865a2d',
            'lifecycle-tools-01/run_native_observation.py': '7606648c99b2ff2bbf0bba58384e8cab609ac3899f838c0b80ba54d6288d20bb',
            'lifecycle-tools-01/run_six_host_cancel_recovery.py': '698eb7801cde3f2bd5ff202412c0833fc218fd7e912c3c949d2b37fde7a56a12',
            'lifecycle-tools-01/run_six_host_cancel_recovery_timed.py': '54186d9750952061b54b255a509848ce72a252d676f584dd288edd263883c0d8',
            'lifecycle-tools-01/run_six_host_cancel_saturation.py': 'ae195c895ab58d3bf067e37f30520bf572fd86b6282722dee9a56acc62df85a0',
            'lifecycle-tools-01/source-provenance.json': '58d276c8df05dcd95a0a25e6264c3de1b248e8bb821651fb1b52859dd707dbbe',
            'lifecycle-tools-01/status-predicate.json': '5828c7ba2990f38531cce7e1a42b44315ee42278ccaee361ace8d9472a96da34',
            'lifecycle-tools-01/summarize_lifecycle_abba_01.py': '9e050343bb32e7f57148f633ff94bbcfb3a7452b2872ae68404ca642e937af89',
            'lifecycle-tools-01/test_native_harness.py': '2b450175b9e6122248ac1bcb51860aa8a6d3eff55f6ac8c877c0a905e3dd7d00',
            'lifecycle-tools-01/test_r25_lifecycle_tools.py': '1845cdb48440a03146e337af7baf916bb9cdb76fb46ea0699f79144cf7197566',
            'lifecycle-tools-01/test_verify_saturation_extension.py': '10f2dcbfa9e2b5c625f22c3edc32c9f8a969509345b20d9b135cebc2235c16fb',
            'lifecycle-tools-01/verify_cancel_recovery.py': '0116652a0b489dc462f005e01d7c943feda9ba784563d7317c92bb5beb9a701c',
            'lifecycle-tools-01/verify_cancel_saturation.py': 'd3b6772ddffc711a23aa4aa9566f903c149535a3d3c4cc3466ee73690cbc1e75',
            'lifecycle-tools-01/verify_saturation_extension.py': '23dfd25517b517067a4fbb3f4a3227f12bafff46b828eb05f7bf322596124e6a',
            'lifecycle-tools-01/x230_observation_benchmark.py': '4d96f0bf2da2562e788f48be7c37589ab3a513be5f9d8b2d741afe5c08ea9eed',
            'lifecycle-tools-01/x230_six_running_recovery_canary.py': '6219bc556b0ac6d142bd4c731466b959e8a410f0b4b55f3d8b303f8fdbfbaaf4',
            'preparation.json': '4770faa3c73ec2e9287fd43154ad5f9b6df149d85767ddb5f18e6aeb153ea1cc',
            'prepare_qualify.py': '6870655895432c8bd3ca266d00eb4a68b3150619352306c997a81ca0487130f4',
            'qualification-01/isolated-tests/summary.json': '10eb5d260f26f15cfea9334ddc6f22456f22dea54ad1b755e118fd49cc67d904',
            'qualification-01/report.json': '5369433b6eb2db62a907593f1b679f968b411d0cde96ce9eabe8e124420cf8e1',
            'qualification-01/source-map.json': '87f085a95a1c1925ecc444b46c996a0aec399c74ce7d0c32afff572e24055313',
            'qualification-input.json': '652541a8f461af9cc7dccd80b5989ffd6e151a8885dea4cc4675f2d054a8be63',
            'qualification-terminal-status-01.json': '8b171dde1644b1c9cacfc126be053484a3649031f946c648db7a69f9be404844',
            'tools-01/compiler-monitor-policy-01.json': 'ddb2e03d4a1a1610466a5dc2d1a544f554ad12fc31412483101b48a235402368',
            'tools-01/compiler_monitor.py': 'afb514362a9d8dd573b806f0dc87df16bd3a906e4574d10d91bf483b2e76cdcf',
            'tools-01/compiler_state.py': '9da718654db04a646e081d2d719a2d6d4655ffe337bc0e3f906e736e4d77a251',
            'tools-01/prepare_lifecycle_inputs.py': '4c2a58793760c106cafbff5ca21813e85372a92391d9c3d3510ba8e46e58210c',
            'tools-01/r35_campaign.py': '3707cbc2e3307a29aa6e645afdf8f6da7a5e80d36e90a86d505bd8f18061778c',
            'tools-01/r35_lifecycle_campaign.py': '372f880ec4679147b06ae89e0df8ec64be74ac79a171704715e6499e79191e29',
            'tools-01/validate_compiler_monitor.py': 'd2cd009adf1f35a394ffddcc8f8646cc0c1b856b78181ca321ea68f6468218b2'},
 'unselected_reported_identity_references': [{'identity': {'bytes': 14373416,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261105-r24/qualification-01/hepta-runtime',
                                                           'sha256': 'bc14cab1e632d6cd703f6a0f65d1a8e513b4471c09a403186d72e989e3f74c13'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 739016,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261105-r24/qualification-01/hepta-runtime-jobctl',
                                                           'sha256': '61c90260057a405626a24a36ad43303c632f72d2d97929296acdffd748b79d62'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 2896456,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261105-r24/qualification-01/native_process_driver',
                                                           'sha256': '51165c1e38409248f5fdb7da2036ebe5e05eec7576035e95bd4b8e2a5c675530'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 14373416,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/qualification-01/hepta-runtime',
                                                           'sha256': '416662310fef6ca6d68907658bb1b882584d1e431bf4ed4263f62984495d8251'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 739016,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/qualification-01/hepta-runtime-jobctl',
                                                           'sha256': '61c90260057a405626a24a36ad43303c632f72d2d97929296acdffd748b79d62'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 2896240,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/qualification-01/native_process_driver',
                                                           'sha256': '31d90610e618041faa5f562c029e496afc39c603fbe3a51d740e4eec3aacd54e'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 83365,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261105-r24/qualification-01/report.json',
                                                           'sha256': 'bf0c5814d28b163e4a90405026cd4d90e399370d1f910f8ac48cb580af1e4971'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 1419928,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/qualification-01/isolated-tests.audit.json',
                                                           'sha256': 'cdd5497f7646ddca0ba028cf2d93d4df76c737a87569e19e9596625620397894'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 5378,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/cache-owner-closure-inputs.json',
                                                           'sha256': '2bc6f84cc6f26b8f10306b8a7310f21e64b52b6c3a2a86f7191bc239801dcd47'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 841,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r34/campaign-01/compiler-monitor.audit.json',
                                                           'sha256': '6e9d2dfaf877205e49ce53d9235224b7fa71c3e573e561d1af5815e1b3d13c0e'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 731,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r34/rust-ci-native-01.json',
                                                           'sha256': 'eb3e72135d77c9787b6d052fff7865266e2e347736d80167d485c72517d780b8'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 5126,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r34/rust-ci-native-read-01.json',
                                                           'sha256': 'ccbd0b0981d2119c7a03d07cd2c0c2df5d3cab05c2d398acb755eea705f6ba47'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 14129,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r34/rust-ci-01/report.json',
                                                           'sha256': 'f9be0abb116e162cba37b610701ad8474e52bd057159d68349ebae08bd970337'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 61488,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r34/campaign-01/native-observation/independent-summary.json',
                                                           'sha256': 'a131c180e5c11ccf16ca81f19247eda83532b939705c417c96fccf9d53fb807a'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 1234,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r34/observation-holder-read-01.json',
                                                           'sha256': '6d7e61c8714c59d6723cb89c20debd99f8d6474bdf8462f0b664073c4bccbf23'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 9076,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r34/observation-holder-report-01.json',
                                                           'sha256': 'fbf9ca986ecb2a4300c8d17c90c9ac8fecf6a3571e00bd6f9e7e2de1c31f5993'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 729,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r34/observation-holder-native-01.json',
                                                           'sha256': '0768c436438c6d8945ff80730444dbad65c8e9b15fd25debf3d350d46b7d8f66'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 139111,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r34/campaign-01/report.json',
                                                           'sha256': '79b2ccf81a5470ac75fdd5ee4b9d4a6eee0b8af4116818be45fd38a361585a4e'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 3571863,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r34/campaign-01/native-observation/report.json',
                                                           'sha256': '3cc5bb8757f2b5d0cfd84d51ec91d1084c509d62696056a8ae94edf97bf6d2ef'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 13933,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r34/campaign-01/summary.json',
                                                           'sha256': '91dc92426ac74a7802f827df05ae93a59e97b97f5e6b915a1e927ac96bec7a33'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 24156,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r34/qualification-01/source-map.json',
                                                           'sha256': '13cc2b374aff950e840b1d6914b70b92380cbe625f70d6002f6231e260d0de0d'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 731,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r34/qualification-terminal-status-01.json',
                                                           'sha256': '0be0d08ef301d3a119d307940f324e52b6b6c8b29fbf94ad6ee69fca2637c14c'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 61305,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r34/preparation.json',
                                                           'sha256': '16193325e19f7025631a2802d6322c332a1b79eb6c6b2c2112740c4e602d9db6'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 83362,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r34/qualification-01/report.json',
                                                           'sha256': 'a63cdd8cdcb5d6844d3f2ae5cf53e11e041f43a74278a5dd2a6fe2f9b7246e8a'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 53380,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/candidate/input.json',
                                                           'sha256': '7089775ed203f2a9d93dbb3528e63826c0b295c35c1aad782e51c99c9e5e059d'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 5225,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/candidate/manifest.json',
                                                           'sha256': 'e5f4338e3581ecc4560269a417941b4802a8b58307eb60eea6e04dd7a4f5102b'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 10053,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/candidate/README.md',
                                                           'sha256': '06b15279ff326150fd9bcead7625cea410fe3eec05993026e7c254cb29ccbdbd'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 69305,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/candidate/baseline/Cargo.lock',
                                                           'sha256': '15b9fb468eb34a210238657d132cbf19e961552d1313de488e1f14936bfa4e5f'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 3097,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/candidate/baseline/Cargo.toml',
                                                           'sha256': '3121870fbf66f65ce6b1925b3500eae8a05fc2d8019a2694da7d6fe941ad4d28'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 17,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/candidate/baseline/rustfmt.toml',
                                                           'sha256': 'bce79651b2e2ff42e1c54b9a26c5e17af5222f9f65ab51d9563a48fd159dae84'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 186456,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/candidate/baseline/src/mcp/runtime/jobs.rs',
                                                           'sha256': 'c9080de8aa9a35f7495aa2822a1495d297903900ae0f0de26d7b0c86d043d3c9'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 107312,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/candidate/baseline/src/mcp/runtime/jobs_tests.rs',
                                                           'sha256': '32009d5f85267026cc56e67d888ccd10e5043b8865904fade3578214340348f5'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 63329,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/candidate/baseline/src/mcp/runtime/ssh_observation_pool.rs',
                                                           'sha256': '92592431b6f4f0d3561c039ed86d9129f3942fb677ba9a336f639003b16b71d9'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 91747,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/candidate/baseline/src/mcp/runtime/ssh_observation_pool_tests.rs',
                                                           'sha256': 'c41347b04e3697503dd0f75237b66c7bb24c512b5bc9362cf7d9a5525e843a7c'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 24156,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/candidate/baseline-compile-inputs.json',
                                                           'sha256': 'c3415beaf7697b3eb07a763ef24f424138de80af31acfd6c224cf682f3c67cbd'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 24156,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/candidate/candidate-compile-inputs.json',
                                                           'sha256': '02843e761ae69211b0e0ccb75f8273017e432c3b75708a9edf6cad6fd0d78e05'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 5593,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/candidate/history/historical-overlap-review-01.json',
                                                           'sha256': '04f6a7ae3f7a07c0ee7f881509e50f7fbe3b12a5e827e358be36381221caa7e8'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 63445,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/candidate/history/originals/capacity12-pool.rs',
                                                           'sha256': '547169e952957ceea8a3a6d9ef35630529fd0e579f0eb9cea3f8a15b3e3c8add'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 27465,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/candidate/history/originals/r25-full.patch',
                                                           'sha256': 'e1f0fd01ca3289ba87b35a46fcc27ba5ef229e65d4475afd28b724c5e3c61966'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 24452,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/candidate/history/originals/r26-README.md',
                                                           'sha256': 'cac449f7473cffcc45888506aab3ff0c042e77fd690207f76c510aba6f4abd05'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 29666,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/candidate/history/originals/r26-full.patch',
                                                           'sha256': '1253b7fe0e9a5948582ceb011eb5814fa889a26c0c8d237dbc652828fba534ad'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 1368,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/candidate/history/originals/r26-selected-change.patch',
                                                           'sha256': 'f06843dd9ba9026ac240ab6761e1abc16b32bcd3dc771d6a2754ff5eeebcb94f'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 8033,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/candidate/history/originals/r28-README.md',
                                                           'sha256': '18837aa54f6edac75e3fd82a06c83d136691cef55c5cdd59692ed4e8aeb173bd'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 31533,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/candidate/history/originals/r28-full.patch',
                                                           'sha256': '2655e1cbde509a2802015315bb1dd514671f83a852fe032a9073a9ee4329f446'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 52436,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/candidate/reference-r33-input.json',
                                                           'sha256': '3753078ae1fa3dd7c9b2582d2d5a6e01335937b6651c5094314955e16b1af48d'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 3438,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/candidate/review/R35_INDEPENDENT_REVIEW.md',
                                                           'sha256': 'ac5f9df62ad1788fae90d74391069fed7ed934edfc6cddb79244bbadf20575a4'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 7659,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/candidate/review/independent-review-01.json',
                                                           'sha256': '121ead46cf04b5adfdc01792a86afe63afdccb70a18dd28e159a22b6d75f1fd8'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 186465,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/candidate/source/src/mcp/runtime/jobs.rs',
                                                           'sha256': '17c8bb5c27c6bcc2e466dbfc31951183e9b694fa6e180865477cb2a322743629'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 63354,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/candidate/source/src/mcp/runtime/ssh_observation_pool.rs',
                                                           'sha256': 'cd7c737faac90b9f2ec7a7faf73df38b63836854105600183e2140340ebc6dbd'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 91763,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/candidate/source/src/mcp/runtime/ssh_observation_pool_tests.rs',
                                                           'sha256': '318bbd4566f0d08531d7886fbd0166906df63c2d2b990d165a51e9a2ac280baa'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 4206,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/candidate/static-checks.json',
                                                           'sha256': 'b606f99d28f1da74a47bf40eb15535b7c5683b0a5f06cbdf8f30faa23cad2bd5'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 9880,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/candidate/verify_candidate.py',
                                                           'sha256': '6b798a9dcfc51e01689c64a30de666c0c3ea57c42a6480c1e49c71ce1a44e1df'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 5064,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/owner-closure-provenance/observation-postflight-01.json',
                                                           'sha256': '17a371b24de733c7e412afdcf31a1fdad1745bbe2b560177e010816ee5193cc1'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 17433,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/source/tools/x230/20261028/audit_isolated_tests.py',
                                                           'sha256': '736b2dcc85fbd5214b855813b6c1f0ceed3dedc1cc0957e709a9ee6cb0110c40'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 12740,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/source/tools/x230/20261028/audit_isolated_tests_tests.py',
                                                           'sha256': '00901b875e6642d79353954ae5bd78aff9d4f0e2a2a2ea28c5416b11bad19207'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 26398,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/source/tools/x230/20261028/forwarded_validation_lease.py',
                                                           'sha256': '61d80c44029971e634d3645fb1b7a4e3e211affffafb16909a57174c604ce85d'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 10589,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/source/tools/x230/20261028/forwarded_validation_lease_tests.py',
                                                           'sha256': 'e7113c43849f5d2fb66a4e6466f5fbc8d60ae93e787b5c17e61957a499660090'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 50581,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/source/tools/x230/20261028/pinned_native_protocol.py',
                                                           'sha256': '2a88c03591908b1054b492d2d717027cb180d176c78eed4de280d7a6a193e956'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 18832,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/source/tools/x230/20261028/pinned_resource_sampler.py',
                                                           'sha256': 'a9554e63416504428439a6cf3fe1f5b8ede090c2ef856bda3f1add413d06d40a'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 7661,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/source/tools/x230/20261028/qualify.py',
                                                           'sha256': '95717717fd5421f2e31dbce24e2f8821696f57d779ce93e988ed66764159552d'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 14515,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/source/tools/x230/20261028/run_extended_file_soak.py',
                                                           'sha256': '30c3ed04a24d718a9cf777fbf5c01b7f77aba2af3fd0b58276b6f4bc0fe82a14'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 4848,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/source/tools/x230/20261028/run_extended_file_soak_tests.py',
                                                           'sha256': '86c8169852af9190cd3a33aef4e8395cece7865f73aa17ebe7090c11659f9821'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 9355,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/source/tools/x230/20261028/run_isolated_tests.py',
                                                           'sha256': '9e1439b27e630aa8a00aa34f02248800dd929314fa0041532294df106f189c62'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 30027,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/source/tools/x230/20261028/run_native_validation.py',
                                                           'sha256': '309afefe719d63e52377930db5d997b3ac3c244873fbb83055e9950b956903f6'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 5200,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/source/tools/x230/20261028/run_native_validation_tests.py',
                                                           'sha256': '8ca4b7e72dcb79dcd169bd236332248cf4bd1f1f8a6c60bc2255f11a067844b9'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 7371,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/source/tools/x230/20261028/run_registry_abba.py',
                                                           'sha256': '2ef81f36a3b11f244e53068a8f039d57e7056e19d7e03973850d839caae159c3'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 28348,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/source/tools/x230/20261028/run_registry_cohort_abba.py',
                                                           'sha256': '637f5ef973ff58c3dbad62ef14a3fce27d75337e090811992e38b5b57d489cea'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 13345,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/source/tools/x230/20261028/run_registry_cohort_abba_tests.py',
                                                           'sha256': '1384b672b959f483beb181a45d9d075c5cc21b374a818fc29f27d62d81e82298'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 10357,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/source/tools/x230/20261028/run_registry_microbench_abba.py',
                                                           'sha256': '268bc954ebe0366c602402b938c0d1986a7d34ba1309bff3ba398281ca947d21'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 3435,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/source/tools/x230/20261028/run_registry_microbench_abba_tests.py',
                                                           'sha256': '922428cc053ed1de58fa07c23d1b188e2a6f77cc039f3fa0d8ae7fe4415de94b'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 27032,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/source/tools/x230/20261028/run_reuse_throughput.py',
                                                           'sha256': 'e0ba8cd46b9f88844bf0dadafcfc605b5c05cd0b734f7f3cb5ca5fb04603de5a'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 30878,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/source/tools/x230/20261028/x230_observation_benchmark.py',
                                                           'sha256': '0c4a06ed1613039d703bb575a8440c9030eac2dc51fcc2c96e96fc90a609da3e'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 0,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/qualification-01/format.stdout',
                                                           'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 0,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/qualification-01/format.stderr',
                                                           'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 0,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/qualification-01/fmt-check.stdout',
                                                           'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 0,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/qualification-01/fmt-check.stderr',
                                                           'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 0,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/qualification-01/harness-tests.stdout',
                                                           'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 9518,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/qualification-01/harness-tests.stderr',
                                                           'sha256': '98bdbd415c60ce9dec7f6ec08792a9b4f3ea8b37865953c6e55e102e49706870'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 0,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/qualification-01/clippy.stdout',
                                                           'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 165,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/qualification-01/clippy.stderr',
                                                           'sha256': '86161e7ca8169804b824cee41265957c960db82ca67f72a8cea5bf6cdca51135'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 269935,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/qualification-01/cargo-no-run.jsonl',
                                                           'sha256': 'f12045a4cb89d7263660d852ef7f456cae681da391d506ae5849f573267e4ff1'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 167,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/qualification-01/test-build.stderr',
                                                           'sha256': 'd13065a6b81300871603dd7c179edbf2065c4686c2b524edccacb0f16dfa8c34'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 4244,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/qualification-01/isolated-tests.stdout',
                                                           'sha256': '7d49cedd1ed039e8d81d14f2e3d1c2a36c699a5647d22dc7ca7be8ca414202b6'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 0,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/qualification-01/isolated-tests.stderr',
                                                           'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 174,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/qualification-01/audit-isolated-tests.stdout',
                                                           'sha256': '27534727d0faea3b5e547ad157f09aa59a2fd75d93d3c9bb026b9d1b87fa84f4'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 0,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/qualification-01/audit-isolated-tests.stderr',
                                                           'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 0,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/qualification-01/release.stdout',
                                                           'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 157,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/qualification-01/release.stderr',
                                                           'sha256': 'e622d780f04b48f0b7445c0b7d186cc985f50b64a2b7b1ae9d92abee6c6d1652'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 282350,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/qualification-01/isolated-tests/cargo-artifacts.jsonl',
                                                           'sha256': 'b3bf46deb47f29835c8f7dd8d7ebe5bbda95143c8b5b0c073955183658c0afa8'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 24156,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/qualification-01/isolated-tests/source-manifest.input',
                                                           'sha256': '87f085a95a1c1925ecc444b46c996a0aec399c74ce7d0c32afff572e24055313'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 878124,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/qualification-01/isolated-tests/commands.jsonl',
                                                           'sha256': 'c15a011fe2284ebe01276718ff4a9bf4c9755ee92c29a68660d58a5a8cce383c'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 2224659,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/qualification-01/isolated-tests/tests.jsonl',
                                                           'sha256': 'd7a5b146d2c83502545fd0d0d059f7f5ffea0f2a3a85308a7985e65a06227528'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 100033,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261105-r24/campaign-01/report.json',
                                                           'sha256': '066952f12414e8f7291e21e58a77d53d4cd712104557bd6bdfdd7c383f9f1e2a'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 1022,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261105-r24/final-publication-readback.json',
                                                           'sha256': '38866c01fac54133c8a88e25bee90ea4a551e7273614f493bf44522a8273d3ca'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'},
                                             {'identity': {'bytes': 836,
                                                           'path': '/home/qian/hepta-runtime-optimization-20261023/r11-native-observation-abba-20261103-02/profile/profile.json',
                                                           'sha256': 'fe1e9551b5b8812ad6ed3da018c282b7261f7caeb2f49e4dcfefba7ff784ab08'},
                                              'scope': 'source/ELF/profile or outside fixed selection; body is not '
                                                       'read by this sealer'}]}
HOLDER_JOB = ACTUAL['holder_job_id'] if ACTUAL is not None else None
SEALED = ACTUAL is not None
STAGES = ('lifecycle-tool-tests', 'normal-lifecycle-abba')
SKIP_DIRS = {'source', 'target', 'target-build', 'test-binaries', 'profile', 'profiles',
             '.ssh', 'credentials', 'secrets', 'keys', '.git', '__pycache__'}
SKIP_FILES = {'profile.json', 'runtime.json', 'runtime-config.json', 'ssh_config', 'known_hosts',
              'credentials.json', 'secrets.json', 'id_rsa', 'id_ed25519', 'id_ecdsa',
              'agent.sock', 'hepta-runtime', 'hepta-runtime-jobctl', 'native_process_driver'}
SELECTED_DIRS = ('lifecycle-campaign-01', 'lifecycle-abba-01', 'lifecycle-tool-tests-01', 'tools-01', 'lifecycle-tools-01')
EXTERNAL_DIRS = ()
OPTIONAL_FILES = ()
FROZEN = Path('/home/qian/hepta-runtime-optimization-20261023/a31-frozen-originals-r01')
FROZEN_PREFIX = 'external/frozen-jobs/'
PROTOCOL_REFERENCE_SHA = 'c9fd58c7aaebd51f60f1a2fdc3a01c52629b41d5a5818be124c79a547735872e'
HOLDER_SHA = '715e996217c7d33a7483354f16f2d39c9a033f51f3a20a52484495a00262dd65'
OBSERVATION_ARCHIVE_SHA = '941e03e20ddcab8baa6049b806e2b447242055abb2f72eefb2a6ed87a9a74b8c'
RESULT_DIRS = ('lifecycle-campaign-01', 'lifecycle-abba-01', 'lifecycle-tool-tests-01')
REQUIRED_DIRS = ('tools-01', 'lifecycle-tools-01')
CORE_FILES = ('lifecycle-holder-native-01.json',
 'lifecycle-holder-read-01.json',
 'lifecycle-holder-report-01.json',
 'lifecycle-materialization-native-01.json',
 'lifecycle-materialization-read-01.json',
 'lifecycle-inputs-01.json',
 'lifecycle-campaign-01/report.json',
 'lifecycle-campaign-01/inputs.json',
 'lifecycle-campaign-01/plan.json',
 'lifecycle-campaign-01/source-inputs.json',
 'lifecycle-campaign-01/baseline-source-inputs.json',
 'lifecycle-campaign-01/compiler-monitor.json',
 'lifecycle-campaign-01/compiler-monitor.audit.json',
 'lifecycle-abba-01/report.json',
 'lifecycle-abba-01/plan.json',
 'lifecycle-abba-01/round-index.json',
 'lifecycle-abba-01/summary.json',
 'lifecycle-abba-01/gates.json',
 'lifecycle-tool-tests-01/report.json')
NORMAL_STAGES = tuple(name for n, arm in enumerate('ABBA') for name in (f'canary-{n}-{arm}', f'audit-{n}-{arm}')) + ('summary', 'normal-lifecycle-gates')
LIFECYCLE_PHASES = ('prepare', 'launch', 'before_crash_running', 'after_transport_running', 'after_crash_running', 'same_key_after_crash', 'concurrent_cancel', 'terminal', 'terminal_after_restart', 'same_key_after_cancel', 'cancel_after_terminal')
COUNTER_KEYS = ('native_calls', 'independent_ssh_calls', 'new_starts', 'same_key_lookups', 'cancellations', 'automatic_rpc_retries')
NAMESPACE_PATHS = CORE_FILES + RESULT_DIRS + ('cancel-saturation-01',)

STATIC_PINS = {'campaign-01/compiler-monitor.audit.json': '66c850ff22dbadcd81a385aa4431c437f004b4c26eb61761004a8268088846e2',
 'campaign-01/compiler-monitor.json': '4314521f6e8479cdc5a56941e1335999039d8d03c7919d6ccbfd5714cd892452',
 'campaign-01/report.json': '3923115d1a8ba2aeb2fc00405bcd01f8d0f92e509b23e17ba6413634d47dba00',
 'campaign-01/summary.json': '0845c8ef6fb7d82350b00f594a68eb523c171b539f588ae1b4e7f12fe1aae3ce',
 'campaign-inputs-01.example.json': '27897ee74e6abd9a7aff24359eaa16c86a4b9471eb95b15117721d7eaef059c1',
 'campaign-inputs-01.json': 'eec0348217f6c679d1f965004f1bd8ecded2886fc1c654d45a9ad6ea700391e4',
 'candidate/candidate.patch': '89eed62593e1b3c5a675221d1df998d27aae4b6a0fdfa028e297544838fa049a',
 'external/frozen-jobs/1a16a4035ad-b1270-1.json': 'a8982325aea4833461e2b6a76ca83f846b80b99a227298e97a0b279e2d9dfdb8',
 'external/frozen-jobs/1a16a403e55-b1270-2.json': 'bbb8a86161837ff0f197b345c25bc66224e3404473dea2ac46d1f44f3af43609',
 'external/frozen-jobs/1a16a4046ac-b1270-3.json': '4badc323518a6db1567162a2d7ef5d1209aa88375aba201ec6f3aab34bec61a8',
 'external/frozen-jobs/1a16a40534e-b1270-4.json': '79e18b1a42d84f8024b692dfd98a9f06fa1d6886bf5dc230248cfbde674f011c',
 'external/frozen-jobs/1a16a405d21-b1270-5.json': '9c89c598f35f6bc94572852fcc03feed6e8c798ee34db5095bd3b48813562dc6',
 'external/frozen-jobs/1a16a40671b-b1270-6.json': '5b737330fa5a75a458138e1848a044d2a77c062175d8eb9694a510ff20b53cde',
 'external/r16/benchmark-topology.json': '8c0767d3318131a7d470d9cde8e327a59ce18adf022c8bc1b1d5a0fa9a865287',
 'lifecycle-inputs-01.example.json': '7b4d6ef124a2ada384100d59fdd71a325ae2f8c162d6ef2656bcbd2a41c9173a',
 'lifecycle-inputs-01.json': '96e728ffe35848497b694a9925e48523d9f468b349da18fb5b40c437329a2a86',
 'lifecycle-tools-01/README.md': 'bf5ece8988afa5a91f01da1df0e1740add1390f6653d32c7bd562d99b11529be',
 'lifecycle-tools-01/allocator_environment.py': 'f5c8e879c540b3f7cb1b7d3a7a0f5002c2f40c1a87963174b0b00470fa3a4525',
 'lifecycle-tools-01/allocator_environment_audit.py': '4b082ce343ae3943e3098baa58af2f5def7198881b9c087d63d88360e9763727',
 'lifecycle-tools-01/analyze_lifecycle_gates.py': 'c7a861a94a89dd81debb5c055773918d89a1c9c29b699e2e5a0341e51be69553',
 'lifecycle-tools-01/analyze_native_observation.py': 'cc7f6884d581cd1ced430437350e808de51931c50d12441797205501b20cae66',
 'lifecycle-tools-01/audit_native_evidence.py': 'b69f6902d2de81eab41b21506f024c002d2f8264d60e86df6b1086623a77fd28',
 'lifecycle-tools-01/cancel_saturation_gate.py': '536ebdc5f2b090a8c007f189a895ed2e19d7b8b7e41530ccba94dd826742ef7f',
 'lifecycle-tools-01/lifecycle-gate-policy.json': '36658346c4e265bf551a1ae1a4c6210bec8e4729f7961302a203008741cd381e',
 'lifecycle-tools-01/lifecycle-tools-manifest-01.json': 'eb50cd7ab0376c4b3dc768e8d184fdc23eeaa90c2ce5bdd4b9e9ac551448504e',
 'lifecycle-tools-01/observation_resources.py': 'f3402d51cb37b2fe20f4351b3a81ec5990a9fdaff93a846d21c07ccd557cb894',
 'lifecycle-tools-01/owned_ssh_interruption.py': '1989c57f0b944afae1ed759d6529b8f1cc26197e269e2c34c4fd49e43a32aa7b',
 'lifecycle-tools-01/run_lifecycle_abba_01.py': 'e01357cfb04f72f1ee1d56747df81b572e55c1528d2941f8dbbb0aa5e9a2ac84',
 'lifecycle-tools-01/run_lifecycle_tool_tests.py': 'e3c1e8163249dba14672a3a82b43a2d7b8b4c0802b94b8511bf3db668f865a2d',
 'lifecycle-tools-01/run_native_observation.py': '7606648c99b2ff2bbf0bba58384e8cab609ac3899f838c0b80ba54d6288d20bb',
 'lifecycle-tools-01/run_six_host_cancel_recovery.py': '698eb7801cde3f2bd5ff202412c0833fc218fd7e912c3c949d2b37fde7a56a12',
 'lifecycle-tools-01/run_six_host_cancel_recovery_timed.py': '54186d9750952061b54b255a509848ce72a252d676f584dd288edd263883c0d8',
 'lifecycle-tools-01/run_six_host_cancel_saturation.py': 'ae195c895ab58d3bf067e37f30520bf572fd86b6282722dee9a56acc62df85a0',
 'lifecycle-tools-01/source-provenance.json': '58d276c8df05dcd95a0a25e6264c3de1b248e8bb821651fb1b52859dd707dbbe',
 'lifecycle-tools-01/status-predicate.json': '5828c7ba2990f38531cce7e1a42b44315ee42278ccaee361ace8d9472a96da34',
 'lifecycle-tools-01/summarize_lifecycle_abba_01.py': '9e050343bb32e7f57148f633ff94bbcfb3a7452b2872ae68404ca642e937af89',
 'lifecycle-tools-01/test_native_harness.py': '2b450175b9e6122248ac1bcb51860aa8a6d3eff55f6ac8c877c0a905e3dd7d00',
 'lifecycle-tools-01/test_r25_lifecycle_tools.py': '1845cdb48440a03146e337af7baf916bb9cdb76fb46ea0699f79144cf7197566',
 'lifecycle-tools-01/test_verify_saturation_extension.py': '10f2dcbfa9e2b5c625f22c3edc32c9f8a969509345b20d9b135cebc2235c16fb',
 'lifecycle-tools-01/verify_cancel_recovery.py': '0116652a0b489dc462f005e01d7c943feda9ba784563d7317c92bb5beb9a701c',
 'lifecycle-tools-01/verify_cancel_saturation.py': 'd3b6772ddffc711a23aa4aa9566f903c149535a3d3c4cc3466ee73690cbc1e75',
 'lifecycle-tools-01/verify_saturation_extension.py': '23dfd25517b517067a4fbb3f4a3227f12bafff46b828eb05f7bf322596124e6a',
 'lifecycle-tools-01/x230_observation_benchmark.py': '4d96f0bf2da2562e788f48be7c37589ab3a513be5f9d8b2d741afe5c08ea9eed',
 'lifecycle-tools-01/x230_six_running_recovery_canary.py': '6219bc556b0ac6d142bd4c731466b959e8a410f0b4b55f3d8b303f8fdbfbaaf4',
 'observation-postflight-01.json': '9a95bf8e9b8de880c15f9fa979f0f4f03dfc0ca1fb50e2270836420f5a97b977',
 'parent-tools-install-01.json': '542fee8a1f146105125e402be5d7892709b76ff29ae273b162ffc4bff4f16bed',
 'preparation.json': '4770faa3c73ec2e9287fd43154ad5f9b6df149d85767ddb5f18e6aeb153ea1cc',
 'prepare_qualify.py': '6870655895432c8bd3ca266d00eb4a68b3150619352306c997a81ca0487130f4',
 'qualification-01/isolated-tests/summary.json': '10eb5d260f26f15cfea9334ddc6f22456f22dea54ad1b755e118fd49cc67d904',
 'qualification-01/report.json': '5369433b6eb2db62a907593f1b679f968b411d0cde96ce9eabe8e124420cf8e1',
 'qualification-01/source-map.json': '87f085a95a1c1925ecc444b46c996a0aec399c74ce7d0c32afff572e24055313',
 'qualification-input.json': '652541a8f461af9cc7dccd80b5989ffd6e151a8885dea4cc4675f2d054a8be63',
 'qualification-native-read-01.json': '4275444d755edf7b4893827ff2224fa1d70aee529a6ac2e1be4c0c5989a5a043',
 'qualification-postflight-01.json': '99e198adfeecb2f09b25d928a157a5067ef4a10315b1ead52134721665df630d',
 'qualification-terminal-status-01.json': '8b171dde1644b1c9cacfc126be053484a3649031f946c648db7a69f9be404844',
 'rust-ci-01/nextest-output-audit.json': '545fd10013d912be0e9297429b606e376cbea7bac55b62f78f76c881fe1ffba3',
 'rust-ci-01/report.json': 'b619804c79479d2bb529e363d8fa48520b8ef9f351a99729ccba77d5510fec5f',
 'rust-ci-native-01.json': 'c19d3490b283df287ba2743d3385f26a83144505ef36ccc874e218359cc94746',
 'rust-ci-native-read-01.json': '31a962dfcbc55ce22b4bb81f5fa05aaacf018c13f17d2dc3f3b49e933d30977b',
 'rust-ci-plan-01.json': '4cc92edbd1b8052e73aed5ede9987a6d56684e2a621b1cf5b0577ad4b307bb28',
 'tools-01/compiler-monitor-policy-01.json': 'ddb2e03d4a1a1610466a5dc2d1a544f554ad12fc31412483101b48a235402368',
 'tools-01/compiler_monitor.py': 'afb514362a9d8dd573b806f0dc87df16bd3a906e4574d10d91bf483b2e76cdcf',
 'tools-01/compiler_state.py': '9da718654db04a646e081d2d719a2d6d4655ffe337bc0e3f906e736e4d77a251',
 'tools-01/install_measurement_tools.py': '1564f7069cab27c6a99806dc07f326d71f8e0da6392fb7b78696c8a2d3ba62f7',
 'tools-01/prepare_campaign_inputs.py': '1449776932b014d70de282d234d82c1a104f3b2f90ddf2c846371d180091f707',
 'tools-01/prepare_lifecycle_inputs.py': '4c2a58793760c106cafbff5ca21813e85372a92391d9c3d3510ba8e46e58210c',
 'tools-01/r35_campaign.py': '3707cbc2e3307a29aa6e645afdf8f6da7a5e80d36e90a86d505bd8f18061778c',
 'tools-01/r35_lifecycle_campaign.py': '372f880ec4679147b06ae89e0df8ec64be74ac79a171704715e6499e79191e29',
 'tools-01/runner-bundle-manifest.json': '0e1ad9df3ae5caddc4edb47ecf1dbf1f41f3c00ad243c197c34d6c136f0597f4',
 'tools-01/summarize_r25_campaign.py': '2418bad36fe4aef75d52c5a00c898ff93fef9bb4b6efb10028105143106a1864',
 'tools-01/validate_compiler_monitor.py': 'd2cd009adf1f35a394ffddcc8f8646cc0c1b856b78181ca321ea68f6468218b2'}
DYNAMIC_REQUIRED = ('lifecycle-holder-native-01.json', 'lifecycle-holder-read-01.json')
PINNED = {**STATIC_PINS, **(ACTUAL['sha256'] if ACTUAL is not None else {})}
REQUIRED = tuple(sorted(set(STATIC_PINS) | set(ACTUAL['sha256'] if ACTUAL is not None else {})))


def need(value, reason):
    if not value:
        raise ValueError(reason)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()

def stamp(value):
    return tuple(getattr(value, key) for key in
        ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))

def terminal(value, job_id):
    need(value.get('job_id') == job_id and value.get('state') in {'succeeded', 'failed', 'cancelled', 'timed_out'}
         and (value.get('exit_code') is None or type(value['exit_code']) is int)
         and value.get('terminal_publication_confirmed') is True,
         'original completed native terminal required: ' + job_id)
    for stream in ('stdout', 'stderr'):
        counts = value['log_bytes'][stream]
        need(set(counts) == {'seen', 'stored'} and all(type(n) is int and n >= 0 for n in counts.values())
             and counts['seen'] >= counts['stored'], 'invalid native log counts: ' + job_id)
    return {key: value.get(key) for key in ('job_id', 'state', 'exit_code', 'automatic_retry',
        'timed_out', 'cancelled', 'output_complete', 'output_durable', 'log_synced',
        'log_errors', 'log_truncated', 'log_bytes', 'terminal_publication_confirmed')}

def streams_from_reads(native, reads):
    cursors = {'stdout': 0, 'stderr': 0}
    chunks = {'stdout': [], 'stderr': []}
    for receipt in reads:
        need(receipt.get('job_id') == native['job_id'], 'native process_read job differs')
        for name in cursors:
            part = receipt[name]
            body = bytes.fromhex(part['bytes_hex'])
            need(part['offset'] == cursors[name] and part['next_offset'] == cursors[name] + len(body)
                 and part['next_offset'] <= part['size']
                 and (not part['eof'] or part['next_offset'] == part['size'])
                 and part['text'].encode() == body, 'native stream gap or byte/text mismatch: ' + name)
            chunks[name].append(body)
            cursors[name] = part['next_offset']
    result = {}
    for name in cursors:
        body = b''.join(chunks[name])
        final = reads[-1][name]
        need(final['eof'] is True and final['size'] == cursors[name] == native['log_bytes'][name]['stored'],
             'native read does not cover all final stored bytes: ' + name)
        result[name] = {'bytes': len(body), 'sha256': sha(body), 'pages': len(reads),
            'contiguous_from_zero': True, 'complete_to_final_stored_bytes': True,
            'seen_equals_stored': native['log_bytes'][name]['seen'] == len(body)}
    return result


def member_path(path):
    path = PurePosixPath(str(path))
    need(path.is_absolute() and '..' not in path.parts, 'unsafe source identity')
    if path.is_relative_to(PurePosixPath(str(ROOT))):
        return path.relative_to(PurePosixPath(str(ROOT))).as_posix()
    if path.is_relative_to(PurePosixPath(str(FROZEN))):
        return FROZEN_PREFIX + path.relative_to(PurePosixPath(str(FROZEN))).as_posix()
    need(path.is_relative_to(PurePosixPath(str(R16))), 'source outside explicit R35/R16/frozen mapping')
    return EXTERNAL_PREFIX + path.relative_to(PurePosixPath(str(R16))).as_posix()


def source_path(name):
    relative = PurePosixPath(name)
    need(not relative.is_absolute() and '..' not in relative.parts and relative.as_posix() == name,
         'unsafe selected archive member')
    if name.startswith(FROZEN_PREFIX):
        return FROZEN / name[len(FROZEN_PREFIX):]
    if name.startswith(EXTERNAL_PREFIX):
        return R16 / name[len(EXTERNAL_PREFIX):]
    need(relative.parts[0] != 'external', 'unexpected external source mapping')
    return ROOT / name




def collect():
    require_sealed()
    need(SEALED, 'unsealed R35 lifecycle collector: actual original receipts are missing')
    need(ROOT.resolve(strict=True) == ROOT and R16.resolve(strict=True) == R16
         and FROZEN.resolve(strict=True) == FROZEN, 'indirect source root')
    payloads, excluded, snapshots = {}, {}, {}
    namespace = {name: os.path.lexists(ROOT / name) for name in NAMESPACE_PATHS}
    total = visited = 0

    def file(path, required=False):
        nonlocal total, visited
        relative = member_path(path)
        if relative in payloads:
            return
        visited += 1
        need(visited <= MAX_FILES * 2 + 256, 'source traversal exceeds bounded inventory')
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
             and path.resolve(strict=True) == path, 'nonregular/link input: ' + relative)
        if path.name in SKIP_FILES or path.suffix.lower() in {'.pem', '.key', '.p12', '.pfx'}:
            need(not required, 'required receipt has a credential/binary filename')
            excluded[relative] = 'credential/configuration/binary filename'
            return
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            need(stamp(before) == stamp(info), 'input changed before open: ' + relative)
            head = stream.read(4)
            if head == b'\x7fELF':
                need(not required, 'required receipt is an ELF')
                excluded[relative] = 'ELF executable'
                return
            need(before.st_size <= MAX_FILE, 'file exceeds 8 MiB: ' + relative)
            data = head + stream.read(MAX_FILE + 1 - len(head))
            need(len(data) == before.st_size and stamp(before) == stamp(os.fstat(stream.fileno()))
                 == stamp(path.lstat()), 'input changed while read: ' + relative)
        need(b'PRIVATE KEY-----' not in data and b'openssh-key-v1\x00' not in data,
             'private-key material detected; archive was not written: ' + relative)
        total += len(data)
        need(total <= MAX_TOTAL and len(payloads) < MAX_FILES, 'selected bytes/files exceed 64 MiB/8192')
        payloads[relative] = data
        snapshots[path] = stamp(info)

    def directory(path, depth=0):
        nonlocal visited
        visited += 1
        need(visited <= MAX_FILES * 2 + 256 and depth <= 32, 'source directory traversal exceeds limits')
        info = path.lstat()
        need(stat.S_ISDIR(info.st_mode) and path.resolve(strict=True) == path, 'non-directory/symlink input')
        snapshots[path] = stamp(info)
        for child in sorted(path.iterdir()):
            mode = child.lstat().st_mode
            need(not stat.S_ISLNK(mode), 'symlink input: ' + str(child))
            if stat.S_ISDIR(mode):
                if child.name in SKIP_DIRS:
                    excluded[member_path(child) + '/'] = 'excluded source/target/binary/profile/credential subtree'
                else:
                    directory(child, depth + 1)
            else:
                file(child)

    for name in REQUIRED:
        file(source_path(name), required=True)
    for name in CORE_FILES:
        if os.path.lexists(ROOT / name):
            file(ROOT / name, required=True)
    for name in SELECTED_DIRS:
        if os.path.lexists(ROOT / name):
            directory(ROOT / name)
        else:
            need(name not in REQUIRED_DIRS, 'required frozen tools directory absent: ' + name)
    for name in EXTERNAL_DIRS:
        directory(R16 / name)
    for name in OPTIONAL_FILES:
        if os.path.lexists(ROOT / name):
            file(ROOT / name, required=True)
    need(all(stamp(path.lstat()) == value for path, value in snapshots.items()), 'source changed during collection')
    need(namespace == {name: os.path.lexists(ROOT / name) for name in NAMESPACE_PATHS},
         'lifecycle evidence presence changed during collection')
    return payloads, excluded, namespace

# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
# Source fragment assembled into the collector. No target program is imported.
def require_sealed():
    need(type(ACTUAL) is dict and ACTUAL.get('schema') == 'hepta-r35-normal-lifecycle-archive-bindings/v1',
         'unsealed lifecycle collector: actual original receipts required')
    need(type(HOLDER_JOB) is str and HOLDER_JOB and ACTUAL.get('holder_job_id') == HOLDER_JOB,
         'actual lifecycle holder job required')
    pins, sizes = ACTUAL.get('sha256'), ACTUAL.get('bytes')
    need(type(pins) is dict and type(sizes) is dict and set(pins) == set(sizes)
         and {'lifecycle-holder-native-01.json', 'lifecycle-holder-read-01.json'} <= set(pins),
         'actual native original identities missing')
    need(all(type(v) is str and len(v) == 64 and all(c in '0123456789abcdef' for c in v) for v in pins.values())
         and all(type(v) is int and 0 <= v <= MAX_FILE for v in sizes.values()),
         'malformed lifecycle original identities')
    need(all(allowed_binding_name(name) for name in pins), 'actual binding escaped fixed lifecycle selection')
    reads = ACTUAL.get('holder_read_members')
    need(type(reads) is list and reads and reads[0] == 'lifecycle-holder-read-01.json'
         and len(reads) == len(set(reads)) and set(reads) <= set(pins),
         'complete original lifecycle holder read pages required')
    need(type(ACTUAL.get('outcomes')) is dict, 'actual reported outcome object required')
    for key in ('workflow_reported_passed', 'parent_reported_adoption_passed',
                'normal_lifecycle_gate_verified', 'normal_lifecycle_gate_passed'):
        need(ACTUAL['outcomes'].get(key) is None or type(ACTUAL['outcomes'][key]) is bool,
             'reported lifecycle outcome must be a boolean or unavailable')


def allowed_binding_name(name):
    path = PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts or path.as_posix() != name or not path.parts:
        return False
    if any(part in SKIP_DIRS for part in path.parts) or path.name in SKIP_FILES:
        return False
    if path.suffix.lower() in {'.pem', '.key', '.p12', '.pfx'}:
        return False
    return (name in STATIC_PINS or name in CORE_FILES
            or name.startswith('lifecycle-holder-read-01-page-') and name.endswith('.json')
            and '/' not in name
            or any(name.startswith(directory + '/') for directory in SELECTED_DIRS))


def summary(kind, data, namespace):
    require_sealed()
    need(kind == 'lifecycle' and all(name in data for name in REQUIRED), 'missing fixed lifecycle input')
    need(all(sha(data[name]) == expected for name, expected in PINNED.items()), 'frozen lifecycle input differs')
    need(all(len(data[name]) == size for name, size in ACTUAL['bytes'].items()), 'actual original byte lengths differ')
    need(set(namespace) == set(NAMESPACE_PATHS) and all(type(v) is bool for v in namespace.values()),
         'invalid captured lifecycle namespace')
    errors, limitations, parse_errors, external = [], [], [], {}

    def check(value, reason):
        if not value:
            errors.append(reason)
        return bool(value)

    def maybe(name):
        if name not in data:
            return None
        try:
            value = json.loads(data[name])
            if not isinstance(value, dict):
                raise ValueError('original is not a JSON object')
            return value
        except (ValueError, UnicodeError, TypeError) as error:
            parse_errors.append({'member': name, 'type': type(error).__name__, 'reason': str(error)[:300]})
            return None

    def identity(name):
        return {'path': str(source_path(name)), 'bytes': len(data[name]), 'sha256': sha(data[name])}

    def binding(value, label, expected_name=None):
        if not isinstance(value, dict) or not {'path', 'bytes', 'sha256'} <= set(value):
            errors.append(label + ': original identity is unavailable or malformed')
            return False
        try:
            name = member_path(value['path'])
        except (ValueError, TypeError):
            external[(str(value.get('path')), str(value.get('sha256')))] = {
                'identity': value, 'scope': 'outside the fixed archive roots; body not copied'}
            return None
        if expected_name is not None and name != expected_name:
            errors.append(label + ': reported path differs from the original fixed protocol path')
            return False
        if not allowed_binding_name(name):
            external[(str(value.get('path')), str(value.get('sha256')))] = {
                'identity': value, 'scope': 'source/ELF/profile or separately archived prerequisite; body not repeated'}
            return None
        return check(name in data and type(value['bytes']) is int and value['bytes'] == len(data[name])
                     and value['sha256'] == sha(data[name]), label + ': archived original identity differs')

    def walk(value, label):
        if isinstance(value, dict):
            if {'path', 'bytes', 'sha256'} <= set(value):
                binding(value, label)
                return
            for key, child in value.items():
                walk(child, label + '/' + str(key))
        elif isinstance(value, list):
            for number, child in enumerate(value):
                walk(child, label + '/' + str(number))

    parent = maybe('lifecycle-campaign-01/report.json')
    normal = maybe('lifecycle-abba-01/report.json')
    index = maybe('lifecycle-abba-01/round-index.json')
    gates = maybe('lifecycle-abba-01/gates.json')
    descriptive = maybe('lifecycle-abba-01/summary.json')
    tests = maybe('lifecycle-tool-tests-01/report.json')
    monitor = maybe('lifecycle-campaign-01/compiler-monitor.json')
    monitor_audit = maybe('lifecycle-campaign-01/compiler-monitor.audit.json')
    holder = maybe('lifecycle-holder-report-01.json')
    inputs = maybe('lifecycle-inputs-01.json')
    observation = maybe('campaign-01/report.json')
    qualified_map = maybe('qualification-01/source-map.json')
    native = json.loads(data['lifecycle-holder-native-01.json'])
    pages = [json.loads(data[name]) for name in ACTUAL['holder_read_members']]
    native_receipt = terminal(native, HOLDER_JOB)
    native_receipt['original_streams'] = streams_from_reads(native, pages)
    complete_native = (native.get('output_complete') is True and native.get('output_durable') is True
        and native.get('automatic_retry') is False
        and native.get('log_synced') == {'stdout': True, 'stderr': True}
        and native.get('log_errors') == {'stdout': None, 'stderr': None}
        and native.get('log_truncated') == {'stdout': False, 'stderr': False}
        and all(row['seen_equals_stored'] for row in native_receipt['original_streams'].values()))
    native_receipt['all_native_output_completeness_fields_closed'] = complete_native
    materializer_receipt = None
    materializer_native = maybe('lifecycle-materialization-native-01.json')
    materializer_read = maybe('lifecycle-materialization-read-01.json')
    if materializer_native is not None and materializer_read is not None:
        try:
            materializer_receipt = terminal(materializer_native, materializer_native['job_id'])
            materializer_receipt['original_streams'] = streams_from_reads(materializer_native, [materializer_read])
        except (ValueError, KeyError, TypeError) as error:
            errors.append('original materializer terminal/read binding: ' + str(error)[:300])
    elif materializer_native is not None or materializer_read is not None:
        limitations.append('Only one materializer native/read original is present; no complete stream claim.')
    stdout = b''.join(bytes.fromhex(page['stdout']['bytes_hex']) for page in pages)
    completion = None
    try:
        lines = [json.loads(line) for line in stdout.decode().splitlines() if line]
        completion = lines[-1] if lines else None
    except (ValueError, UnicodeError):
        limitations.append('Original holder stdout is retained but is not a complete JSON completion stream.')
    if holder is not None:
        check(holder.get('schema') == 'hepta-x230-r21-held-agent-campaign/v1', 'holder report schema differs')
        check(holder.get('holder_script_sha256') == HOLDER_SHA, 'holder source identity differs')
        check(holder.get('remote_script_sha256') == STATIC_PINS['tools-01/r35_lifecycle_campaign.py'],
              'holder used a different lifecycle parent source')
        if isinstance(completion, dict):
            check(all(completion.get(key) == holder.get(key) for key in
                      ('passed', 'remote_returncode', 'owned_agent_reaped')),
                  'original holder completion and full report differ')
        elif holder.get('passed') is True:
            errors.append('positive holder report lacks matching original native completion')
    else:
        limitations.append('Full holder report unavailable; original terminal/read bytes remain retained.')

    reported_parent_passed = parent.get('passed') if parent is not None else None
    reported_adoption = parent.get('adoption_passed') if parent is not None else None
    gate_verified = gates.get('verified') if gates is not None else None
    gate_passed = gates.get('passed') if gates is not None else None
    observed_outcomes = {'workflow_reported_passed': reported_parent_passed,
        'parent_reported_adoption_passed': reported_adoption,
        'normal_lifecycle_gate_verified': gate_verified, 'normal_lifecycle_gate_passed': gate_passed}
    for key, expected in ACTUAL['outcomes'].items():
        if expected is not None and key in observed_outcomes:
            check(observed_outcomes[key] == expected, 'sealed and captured reported outcome differs: ' + key)
    positive = (reported_parent_passed is True and reported_adoption is True
                and native.get('state') == 'succeeded' and native.get('exit_code') == 0
                and complete_native
                and holder is not None and holder.get('passed') is True
                and holder.get('owned_agent_reaped') is True)
    if reported_parent_passed is True:
        check(positive, 'positive parent report lacks complete original holder/native custody')

    def stages(value, directory, expected_names, require_positive, process_key='owned_process_absent'):
        if value is None:
            return []
        rows = value.get('stages', [])
        if not check(isinstance(rows, list) and len(rows) <= len(expected_names)
                     and all(isinstance(row, dict) for row in rows)
                     and [row.get('name') for row in rows] == list(expected_names[:len(rows)]),
                     directory + ': original stage order/prefix differs'):
            return []
        result = []
        for number, row in enumerate(rows):
            label = directory + '/' + row['name']
            for stream in ('stdout', 'stderr'):
                if stream in row:
                    binding(row[stream], label + ' ' + stream, directory + '/' + row['name'] + '.' + stream)
                elif require_positive:
                    errors.append(label + ': positive stage lacks ' + stream)
            for pin in row.get('output_bindings', []):
                binding(pin, label + ' output')
            if require_positive:
                check(row.get('returncode') == 0 and row.get('waited_and_reaped') is True
                      and row.get(process_key) is True and row.get('owned_process_group_absent') is True
                      and row.get('cleanup_error') is None and row.get('passed', True) is True,
                      label + ': positive stage custody did not close')
            result.append({key: row.get(key) for key in
                ('name', 'passed', 'returncode', 'timed_out', 'waited_and_reaped', process_key,
                 'owned_process_group_absent', 'cleanup_signals', 'cleanup_error', 'error', 'automatic_retry')})
        if require_positive:
            check(len(rows) == len(expected_names), directory + ': positive stage inventory is incomplete')
        return result

    parent_stages = stages(parent, 'lifecycle-campaign-01', STAGES, positive)
    normal_stages = stages(normal, 'lifecycle-abba-01', NORMAL_STAGES, positive, 'proc_absent')
    for name, value in (('parent', parent), ('normal', normal), ('round-index', index),
                        ('normal-gates', gates), ('descriptive-summary', descriptive),
                        ('original-tool-tests', tests), ('compiler-monitor-audit', monitor_audit)):
        if value is not None:
            walk(value, name)
    if parent is not None:
        check(parent.get('schema') == 'hepta-r35-normal-lifecycle-campaign-control/v1', 'LC parent schema differs')
        check(parent.get('launcher_sha256') == STATIC_PINS['tools-01/r35_lifecycle_campaign.py'],
              'LC parent source identity differs')
        check(parent.get('automatic_retries') == 0 and parent.get('production_services_modified') is False,
              'LC parent retry/production scope differs')
        if inputs is not None:
            check(inputs.get('schema') == 'hepta-r25-lifecycle-inputs/v1' and inputs.get('attempt') == '01'
                  and inputs.get('launcher_sha256') == parent.get('launcher_sha256'),
                  'original LC input/parent source differs')
            binding(parent.get('input_receipt'), 'parent input', 'lifecycle-inputs-01.json')
            if 'lifecycle-campaign-01/inputs.json' in data:
                check(data['lifecycle-campaign-01/inputs.json'] == data['lifecycle-inputs-01.json'],
                      'retained parent input copy differs')
        if observation is not None and parent.get('binaries'):
            check(parent['binaries'] == observation.get('binaries'), 'LC/OBS original A/B artifacts differ')
        if positive:
            check(all(parent.get(key) is True for key in ('inputs_unchanged', 'source_inputs_unchanged',
                  'baseline_source_inputs_unchanged', 'measurement_attribution_valid', 'observation_gate_verified')),
                  'positive LC lacks original source/input/measurement closure')
            check(observation is not None and observation.get('passed') is True
                  and observation.get('observation_gate_passed') is True,
                  'positive LC lacks its completed OBS prerequisite')
            check(parent.get('source_inputs_sha256') == inputs.get('source_inputs_sha256')
                  == observation.get('source_inputs_sha256')
                  and parent.get('baseline_source_inputs_sha256') == observation.get('baseline_source_inputs_sha256'),
                  'positive LC source digests differ from original OBS')
    snapshots = {}
    for name in ('source-inputs.json', 'baseline-source-inputs.json'):
        member = 'lifecycle-campaign-01/' + name
        value = maybe(member)
        if value is not None:
            snapshots[name] = {'identity': identity(member), 'root': value.get('root'),
                               'file_count': value.get('file_count'), 'sha256': value.get('sha256')}
            if name == 'source-inputs.json' and qualified_map is not None and isinstance(value.get('files'), dict):
                check({key: pin.get('sha256') for key, pin in value['files'].items()} == qualified_map
                      and value.get('file_count') == len(qualified_map) == 220,
                      'LC source snapshot differs from all actual qualified inputs')
    if normal is not None:
        check(normal.get('schema') == 'hepta-r25-lifecycle-abba-control/v1'
              and normal.get('order') == 'ABBA' and normal.get('automatic_retries') == 0,
              'normal LC schema/order/retries differ')
        binding(normal.get('tools_manifest'), 'normal tools manifest', 'lifecycle-tools-01/lifecycle-tools-manifest-01.json')
        if parent is not None and parent.get('binaries'):
            check(normal.get('baseline') == parent['binaries']['A']['hepta-runtime']
                  and normal.get('candidate') == parent['binaries']['B']['hepta-runtime'],
                  'normal LC artifacts differ from its parent')
    if index is not None:
        check(index.get('schema') == 'hepta-r25-lifecycle-round-index/v1'
              and index.get('order') == 'ABBA' and index.get('automatic_retries') == 0,
              'LC round-index schema/order/retries differ')
        if index.get('closed') is True:
            check(index.get('round_count') == 4 and isinstance(index.get('rounds'), list)
                  and len(index['rounds']) == 4, 'closed original LC index is incomplete')
        if normal is not None:
            check(all(index.get(key) == normal.get(key) for key in
                      ('rounds', 'baseline', 'candidate', 'tools_manifest', 'plan')),
                  'normal report/index original identities differ')
    if gates is not None:
        check(gates.get('schema') == 'hepta-r25-lifecycle-gates/v1'
              and type(gates.get('verified')) is bool and type(gates.get('passed')) is bool,
              'normal LC gate schema/outcome shape differs')
        binding(gates.get('round_index'), 'LC gate round index', 'lifecycle-abba-01/round-index.json')
        binding(gates.get('gate_policy'), 'LC gate policy', 'lifecycle-tools-01/lifecycle-gate-policy.json')
    if descriptive is not None and 'lifecycle-abba-01/round-index.json' in data:
        check(descriptive.get('round_index_sha256') == sha(data['lifecycle-abba-01/round-index.json']),
              'descriptive LC summary index hash differs')

    rounds, shutdowns, intentional_crashes, missing_shutdowns = [], [], [], []
    declared = index.get('rounds', []) if index is not None else normal.get('rounds', []) if normal is not None else []
    if not isinstance(declared, list):
        errors.append('original declared LC rounds is not a list')
        declared = []
    if len(declared) > 4:
        errors.append('original declared LC round count exceeds ABBA')
    for number, arm in enumerate('ABBA'):
        directory = 'lifecycle-abba-01/round-%d-%s' % (number, arm)
        raw_name, audit_name = directory + '/report.json', directory + '/independent-summary.json'
        raw, audit = maybe(raw_name), maybe(audit_name)
        declaration = declared[number] if number < len(declared) else None
        if raw is None and audit is None and declaration is None:
            continue
        item = {'index': number, 'arm': arm, 'directory': directory, 'declared_in_original_index': declaration is not None,
                'raw_report_present': raw_name in data, 'raw_report_structured': raw is not None,
                'independent_analysis_present': audit_name in data, 'independent_analysis_structured': audit is not None,
                'reported_raw_passed': raw.get('passed') if raw is not None else None,
                'reported_audit_verified': audit.get('verified') if audit is not None else None}
        if declaration is not None:
            check(isinstance(declaration, dict) and declaration.get('index') == number and declaration.get('arm') == arm
                  and declaration.get('directory') == directory.split('/')[-1],
                  directory + ': original declared round path/order differs')
            if isinstance(declaration, dict):
                binding(declaration.get('report'), directory + ' declared report', raw_name)
                binding(declaration.get('independent_analysis'), directory + ' declared audit', audit_name)
                phases = declaration.get('phase_files', [])
                check(isinstance(phases, list) and len(phases) == 11
                      and {PurePosixPath(p.get('path', '')).name for p in phases if isinstance(p, dict)}
                         == {'phase-' + phase + '.json' for phase in LIFECYCLE_PHASES},
                      directory + ': declared 11-phase inventory differs')
                for pin in phases if isinstance(phases, list) else []:
                    binding(pin, directory + ' original phase',
                            directory + '/' + PurePosixPath(pin.get('path', '')).name)
                item['phase_files_reported'] = len(phases) if isinstance(phases, list) else None
        item['phase_files_captured'] = [phase for phase in LIFECYCLE_PHASES if directory + '/phase-' + phase + '.json' in data]
        if raw is not None:
            if parent is not None and parent.get('binaries'):
                check(raw.get('candidate_sha256') == parent['binaries'][arm]['hepta-runtime']['sha256'],
                      directory + ': raw runtime differs from original arm')
            for phase in ('shutdown', 'after_cancel_shutdown'):
                value = raw.get(phase)
                if not isinstance(value, dict):
                    missing_shutdowns.append(directory + '/' + phase)
                    continue
                capture = value.get('transport_capture', {})
                row = {key: value.get(key) for key in ('exit_code', 'shutdown_method',
                    'observed_descendant_survivors', 'reader_error', 'unmatched_responses')}
                row.update(round=number, arm=arm, phase=phase, reader_eof=capture.get('reader_eof'))
                row['reported_clean_shutdown'] = (row['exit_code'] == 0 and row['shutdown_method'] == 'stdin_eof'
                    and row['observed_descendant_survivors'] == [] and row['reader_error'] is None
                    and row['unmatched_responses'] == 0 and row['reader_eof'] is True)
                shutdowns.append(row)
            crash = raw.get('intentional_crash')
            if isinstance(crash, dict):
                intentional_crashes.append({'round': number, 'arm': arm,
                    'reported_fields': {key: crash.get(key) for key in ('exit_code', 'shutdown_method',
                        'observed_descendant_survivors', 'reader_error', 'unmatched_responses')},
                    'full_original_retained_in': raw_name})
        if audit is not None:
            item['original_audit_counts'] = {key: audit.get(key) for key in COUNTER_KEYS}
            item['original_audit_limitations'] = audit.get('not_covered', audit.get('limitations'))
            if raw_name in data:
                check(audit.get('source_sha256') == sha(data[raw_name])
                      and audit.get('source_bytes') == len(data[raw_name]),
                      directory + ': original independent audit source identity differs')
            if raw is not None:
                check(audit.get('candidate_sha256') == raw.get('candidate_sha256'),
                      directory + ': raw/audit candidate identity differs')
            if positive:
                check(raw is not None and raw.get('passed') is True and audit.get('verified') is True
                      and raw.get('automatic_rpc_retries') == audit.get('automatic_rpc_retries') == 0,
                      directory + ': positive original raw/audit closure incomplete')
        elif positive:
            errors.append(directory + ': positive original independent audit missing')
        rounds.append(item)
    counters = {}
    for key in COUNTER_KEYS:
        values = [row.get('original_audit_counts', {}).get(key) for row in rounds]
        counters[key] = sum(values) if values and all(type(value) is int for value in values) else None
    counts = {'captured_round_reports': sum(row['raw_report_present'] for row in rounds),
              'captured_round_audits': sum(row['independent_analysis_present'] for row in rounds),
              'original_declared_rounds': len(declared), 'original_audit_count_sums': counters,
              'count_sums_cover_all_four_round_audits': len(rounds) == 4
                  and all(row['independent_analysis_structured'] for row in rounds)}
    monitor_count = monitor.get('sample_count') if monitor is not None else None
    if monitor is not None:
        check(type(monitor_count) is int and isinstance(monitor.get('samples'), list)
              and monitor_count == len(monitor['samples']), 'LC monitor declared/raw sample count differs')
    if monitor_audit is not None:
        binding(monitor_audit.get('ledger'), 'LC monitor audit ledger', 'lifecycle-campaign-01/compiler-monitor.json')
        if monitor_count is not None:
            check(monitor_audit.get('validation', {}).get('validated_sample_count') == monitor_count,
                  'LC monitor original audit sample count differs')
    expected_count = ACTUAL.get('compiler_monitor_sample_count')
    if expected_count is not None:
        check(monitor_count == expected_count, 'sealed and captured LC monitor count differs')
    if positive:
        check(tests is not None and tests.get('passed') is True and tests.get('tests_run') == 14
              and tests.get('skipped') == tests.get('errors') == tests.get('failures') == 0,
              'positive LC lacks all 14 original tool-test results')
        check(normal is not None and normal.get('passed') is True and normal.get('inputs_unchanged') is True
              and index is not None and index.get('closed') is True and len(rounds) == 4
              and descriptive is not None and descriptive.get('verified') is True
              and gate_verified is True and gate_passed is True,
              'positive LC parent lacks complete original normal ABBA gates')
        check(monitor is not None and monitor_audit is not None
              and monitor_audit.get('validation', {}).get('passed') is True,
              'positive LC parent lacks original compiler-monitor closure')
    failed_comparison_flags = []
    for name, comparison in (gates.get('comparisons', {}) if gates is not None else {}).items():
        if isinstance(comparison, dict):
            for gate_name, passed in comparison.get('gates', {}).items():
                if passed is False:
                    failed_comparison_flags.append({'comparison': name, 'gate': gate_name,
                        'adoption_required': comparison.get('adoption_required'), 'reported_passed': False})
    errors.extend(row['member'] + ': retained original JSON cannot be interpreted' for row in parse_errors)
    return {'kind': kind, 'original_lifecycle_holder_job_id': HOLDER_JOB,
        'workflow_reported_passed': reported_parent_passed, 'parent_reported_adoption_passed': reported_adoption,
        'normal_lifecycle_gate_verified': gate_verified, 'normal_lifecycle_gate_passed': gate_passed,
        'reported_rejection_reasons': gates.get('rejection_reasons', gates.get('failures')) if gates is not None else None,
        'derived_failed_original_comparison_flags': failed_comparison_flags,
        'derived_flags_scope': 'Lists false flags in the original gate report; thresholds and performance are not recomputed.',
        'candidate_adopted_by_archiver': False, 'final_publication_or_adoption_decision': None,
        'original_native_terminal': native_receipt, 'original_holder_completion': completion,
        'original_materializer_terminal': materializer_receipt,
        'original_holder_report': {key: holder.get(key) for key in ('schema', 'passed', 'remote_returncode',
            'holder_script_sha256', 'remote_script_sha256', 'automatic_ssh_retries', 'services_modified',
            'owned_agent_reaped', 'owned_agent_returncode', 'owned_agent_socket_absent_after_context',
            'owned_agent_directory_absent_after_context')} if holder is not None else None,
        'full_Mac_holder_log_bodies_copied_here': False,
        'Mac_holder_log_identities_retained_in_original_holder_report': holder is not None,
        'parent_stages': parent_stages, 'normal_ABBA_stages': normal_stages,
        'tool_tests_reported': {key: tests.get(key) for key in ('schema', 'passed', 'tests_run',
            'skipped', 'errors', 'failures')} if tests is not None else None,
        'counts': counts, 'rounds': rounds, 'original_normal_lifecycle_gates': gates,
        'normal_descriptive_summary': {'identity': identity('lifecycle-abba-01/summary.json'),
            'schema': descriptive.get('schema'), 'verified': descriptive.get('verified')} if descriptive is not None else None,
        'compiler_monitor': {'sample_count': monitor_count,
            'original_ledger_identity': identity('lifecycle-campaign-01/compiler-monitor.json') if monitor is not None else None,
            'original_audit': monitor_audit,
            'reported_parent_monitor': parent.get('compiler_monitor') if parent is not None else None},
        'shutdowns': shutdowns, 'missing_standard_shutdown_evidence': missing_shutdowns,
        'all_observed_standard_shutdowns_clean': all(row['reported_clean_shutdown'] for row in shutdowns) if shutdowns else None,
        'all_four_rounds_and_eight_standard_shutdowns_observed': len(rounds) == 4 and len(shutdowns) == 8,
        'intentional_crashes': intentional_crashes, 'source_snapshots': snapshots,
        'original_parent_error': parent.get('error') if parent is not None else None,
        'original_parent_finalization_error': parent.get('finalization_error') if parent is not None else None,
        'original_normal_error': normal.get('error') if normal is not None else None,
        'original_saturation_verified_field': parent.get('saturated_cancellation_verified') if parent is not None else None,
        'source_and_measurement_flags': {key: parent.get(key) for key in ('inputs_unchanged', 'source_inputs_unchanged',
            'baseline_source_inputs_unchanged', 'measurement_attribution_valid', 'automatic_retries',
            'production_services_modified')} if parent is not None else None,
        'captured_namespace_presence': namespace,
        'unavailable_core_originals_at_capture': [name for name in CORE_FILES if name not in data],
        'unarchived_identity_references': list(external.values()),
        'original_json_parse_errors': parse_errors, 'archived_receipt_binding_errors': errors,
        'original_qualification_archive_sha256': QUALIFICATION_ARCHIVE_SHA,
        'original_exact_ci_archive_sha256': CI_ARCHIVE_SHA,
        'original_observation_archive_sha256': OBSERVATION_ARCHIVE_SHA,
        'scope': {'raw_results_modified': False, 'tests_or_benchmarks_rerun': False,
            'original_auditors_reexecuted': False, 'archived_programs_executed': False,
            'separate_saturation_campaign_included': False, 'qualification_ELFs_or_source_trees_repeated': False,
            'known_OBS_success_is_not_lifecycle_success': True, 'limits_and_original_thresholds_changed': False},
        'limitations': limitations}

def create_archive():
    require_sealed()
    need(SEALED and HOLDER_JOB is not None and set(DYNAMIC_REQUIRED) <= set(PINNED)
         and all(isinstance(value, str) and len(value) == 64 for value in PINNED.values()),
         'unsealed R35 lifecycle collector: original receipt identities are still missing')
    base = ROOT / 'lifecycle-evidence-01'
    outputs = [Path(str(base) + suffix) for suffix in ('.tar.gz', '.manifest.json', '.compact.json')]
    need(not any(os.path.lexists(path) for path in outputs), 'create-only output already exists; no overwrite/retry')
    data, excluded, namespace = collect()
    compact = summary('lifecycle', data, namespace)
    manifest = {'schema': 'hepta-r35-normal-lifecycle-evidence-archive/v1', 'kind': 'lifecycle',
        'source_root': str(ROOT), 'external_source_root': str(R16), 'external_archive_prefix': EXTERNAL_PREFIX,
        'tool_sha256': sha(Path(__file__).read_bytes()), 'source_reference_sha256': REFERENCE_SHA,
        'protocol_reference_sha256': PROTOCOL_REFERENCE_SHA,
        'frozen_fixture_source_root': str(FROZEN), 'frozen_fixture_archive_prefix': FROZEN_PREFIX,
        'selected_bytes': sum(map(len, data.values())),
        'limits': {'total_bytes': MAX_TOTAL, 'file_bytes': MAX_FILE, 'files': MAX_FILES},
        'selection': {'required_files': list(REQUIRED), 'r35_directories': list(SELECTED_DIRS),
            'r16_directories': list(EXTERNAL_DIRS), 'optional_r35_files': list(OPTIONAL_FILES)},
        'namespace_state': namespace, 'excluded': excluded,
        'files': {name: {'bytes': len(raw), 'sha256': sha(raw)} for name, raw in sorted(data.items())},
        'summary': compact, 'no_tests_or_benchmarks_run': True}
    manifest_raw, compact_raw = encoded(manifest), encoded(compact)
    need(len(manifest_raw) <= MAX_MANIFEST, 'manifest exceeds 2 MiB')
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode='wb', mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            for name, raw in [('manifest.json', manifest_raw), *sorted(data.items())]:
                entry = tarfile.TarInfo(name)
                entry.size, entry.mode, entry.mtime = len(raw), 0o600, 0
                archive.addfile(entry, io.BytesIO(raw))
    archive_raw = buffer.getvalue()
    need(len(archive_raw) + len(manifest_raw) + len(compact_raw) <= MAX_TOTAL, 'archive/sidecars exceed 64 MiB')
    for path, raw in zip(outputs, (archive_raw, manifest_raw, compact_raw)):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    return {'archived': True, 'kind': 'lifecycle', 'archive': str(outputs[0]), 'bytes': len(archive_raw),
        'sha256': sha(archive_raw), 'manifest_sha256': sha(manifest_raw), 'compact_sha256': sha(compact_raw),
        'original_job_id': HOLDER_JOB, 'workflow_reported_passed': compact['workflow_reported_passed'],
        'normal_lifecycle_gate_passed': compact['normal_lifecycle_gate_passed'], 'counts': compact['counts'],
        'receipt_binding_errors': compact['archived_receipt_binding_errors']}


def verify_archive(path, expected_sha):
    require_sealed()
    need(SEALED, 'unsealed R35 lifecycle collector: actual original receipts are missing')
    need(path.is_absolute() and path.resolve(strict=True) == path, 'indirect archive path')
    initial = path.lstat()
    need(stat.S_ISREG(initial.st_mode) and initial.st_nlink == 1 and initial.st_size <= MAX_TOTAL,
         'unsafe/oversized archive')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stamp(before) == stamp(initial), 'archive changed before open')
        raw = stream.read(MAX_TOTAL + 1)
        need(len(raw) <= MAX_TOTAL and len(raw) == before.st_size
             and stamp(before) == stamp(os.fstat(stream.fileno())) == stamp(path.lstat()),
             'archive changed while read or exceeded 64 MiB')
    need(sha(raw) == expected_sha, 'archive SHA256 differs from the remote receipt')
    with gzip.GzipFile(fileobj=io.BytesIO(raw), mode='rb') as compressed:
        tar_raw = compressed.read(MAX_TAR + 1)
    need(len(tar_raw) <= MAX_TAR, 'expanded tar exceeds bounded size')
    data, manifest, manifest_sha, total = {}, None, None, 0
    with tarfile.open(fileobj=io.BytesIO(tar_raw), mode='r:') as archive:
        for number, entry in enumerate(archive):
            name = PurePosixPath(entry.name)
            need(entry.isfile() and not name.is_absolute() and '..' not in name.parts
                 and str(name) == entry.name and number <= MAX_FILES, 'unsafe/nonregular/oversized tar inventory')
            cap = MAX_MANIFEST if number == 0 else MAX_FILE
            need(0 <= entry.size <= cap, 'oversized tar member')
            value = archive.extractfile(entry).read(cap + 1)
            need(len(value) == entry.size, 'truncated tar member')
            if number == 0:
                need(entry.name == 'manifest.json', 'manifest must be first')
                manifest, manifest_sha = json.loads(value), sha(value)
                need(manifest['schema'] == 'hepta-r35-normal-lifecycle-evidence-archive/v1'
                     and manifest['kind'] == 'lifecycle'
                     and manifest.get('tool_sha256') == sha(Path(__file__).read_bytes()),
                     'unexpected evidence manifest/tool identity')
            else:
                need(entry.name not in data and entry.name != 'manifest.json', 'duplicate tar member')
                need(not value.startswith(b'\x7fELF') and not any(part in SKIP_DIRS for part in name.parts)
                     and name.name not in SKIP_FILES and name.suffix.lower() not in {'.pem', '.key', '.p12', '.pfx'}
                     and b'PRIVATE KEY-----' not in value and b'openssh-key-v1\x00' not in value,
                     'excluded source/binary/profile/credential content appeared in archive')
                expected = manifest['files'].get(entry.name)
                need(expected == {'bytes': len(value), 'sha256': sha(value)}, 'manifest entry mismatch: ' + entry.name)
                data[entry.name] = value
                total += len(value)
                need(total <= MAX_TOTAL, 'total tar payload exceeds 64 MiB')
    need(manifest is not None and set(data) == set(manifest['files'])
         and sum(map(len, data.values())) == manifest['selected_bytes'], 'manifest membership/byte count differs')
    compact = summary(manifest['kind'], data, manifest['namespace_state'])
    need(compact == manifest['summary'], 'compact summary differs from retained raw receipts')
    return {'verified': True, 'kind': manifest['kind'], 'archive': str(path), 'bytes': len(raw),
        'sha256': sha(raw), 'manifest_sha256': manifest_sha, 'files': len(data), 'selected_bytes': total,
        'original_job_id': HOLDER_JOB, 'workflow_reported_passed': compact['workflow_reported_passed'],
        'normal_lifecycle_gate_passed': compact['normal_lifecycle_gate_passed'], 'counts': compact['counts'],
        'receipt_binding_errors': compact['archived_receipt_binding_errors'], 'files_extracted': 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--kind', choices=('lifecycle',))
    mode.add_argument('--verify', type=Path)
    parser.add_argument('--expected-sha256')
    args = parser.parse_args()
    if args.verify is not None:
        need(args.expected_sha256 is not None, '--expected-sha256 from the original archive receipt is required')
        result = verify_archive(args.verify.absolute(), args.expected_sha256)
    else:
        need(args.expected_sha256 is None, '--expected-sha256 is only for verification')
        result = create_archive()
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        print(type(error).__name__ + ': ' + str(error), file=sys.stderr)
        raise SystemExit(1)
