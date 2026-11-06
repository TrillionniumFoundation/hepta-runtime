#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Fixed complete R29 observation/lifecycle/saturation originals; no workloads or adoption."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import traceback
import types

ROOT = Path("/home/qian/hepta-runtime-optimization-20261105-r29")
STAGE_ROOT = Path("/home/qian/hepta-runtime-optimization-20261105-r25")
R16 = Path("/home/qian/hepta-runtime-optimization-20261104-r16")
SOURCE = ROOT / "source"
OUT = ROOT / "performance-evidence-01"
EXPORTER = STAGE_ROOT / "tools/export_r29_performance_01.py"
HELPER = STAGE_ROOT / "tools/r29_qualification_ci_stable_xz_01.py"
INPUT = STAGE_ROOT / "tools/r29-performance-export-input-01.json"
HELPER_SHA256 = "8b7aa7ef3b3772da13ea4f7009d8c478e0c92bc207d65db3f45c23453097d7a2"
MONITOR_VALIDATOR_SHA256 = "d2cd009adf1f35a394ffddcc8f8646cc0c1b856b78181ca321ea68f6468218b2"
ARCHIVE_NAME = "performance-01.tar.xz"
HEX = re.compile(r"[0-9a-f]{64}\Z")
JOB = re.compile(r"[0-9a-f]+-[0-9a-f]+-[0-9a-f]+\Z")
NATIVE_TERMINAL_STATES = {"succeeded", "failed", "cancelled", "timed_out", "effect_unknown"}
PRIVATE_NAMES = {"ssh_config", "known_hosts", "profile.json", "runtime.json"}
STAGES = ("observation01", "lifecycle01")
ORIGINAL_OBSERVATION_JOB = '1a1ad77dfe5-fc05-59f9'
NATIVE_PATHS = {"observation01": ROOT / "observation-native-terminal-01.json",
                "lifecycle01": ROOT / "lifecycle-native-terminal-01.json"}
REPORT_PATHS = {"observation01": ROOT / "campaign-01/report.json",
                "lifecycle01": ROOT / "lifecycle-campaign-01/report.json"}
REPORT_SCHEMAS = {"observation01": "hepta-r25-observation-campaign-control/v1",
                  "lifecycle01": "hepta-r25-lifecycle-campaign-control/v1"}
RECOVERY = R16 / "r29-cancel-recovery-01"
DIRECTORIES = {
    "observation": ROOT / "campaign-01",
    "recovery": RECOVERY,
    "lifecycle": ROOT / "lifecycle-campaign-01",
    "lifecycle-abba": ROOT / "lifecycle-abba-01",
    "saturation": ROOT / "cancel-saturation-01",
    "lifecycle-tool-tests": ROOT / "lifecycle-tool-tests-01",
    "campaign-tools": ROOT / "tools-01",
    "boundary-tools": ROOT / "boundary-tools-01",
    "lifecycle-tools": ROOT / "lifecycle-tools-01",
    "lifecycle-launcher-bundle": ROOT / "lifecycle-launcher-bundle-01",
}
UNEXECUTED_PATHS = ()
ROOT_FILES = ("campaign-inputs-01.json", "campaign-inputs-01.example.json",
              "observation-plan-01.json", "observation-tools-manifest-01.json",
              "lifecycle-inputs-01.example.json", "lifecycle-inputs-01.json",
              "tools-install-01-receipt.json")
OPTIONAL_ROOT_FILES = {"lifecycle-inputs-01.json"}
PROFILE = Path("/home/qian/hepta-runtime-optimization-20261023/r11-native-observation-abba-20261103-02/profile/profile.json")
TOPOLOGY = R16 / "benchmark-topology.json"
OBSERVATION_STAGES = ("native-observation", "native-audit", "native-boundary", "boundary-audit",
                      "cancel-recovery", "recovery-audit", "observation-summary")
MONITOR_COMPONENTS = {"module": "compiler_monitor.py", "reader": "compiler_state.py",
                      "validator": "validate_compiler_monitor.py", "policy": "compiler-monitor-policy-01.json"}
OUTPUT_PREFIXES = ('observation/', 'recovery/', 'lifecycle/', 'lifecycle-abba/', 'saturation/', 'lifecycle-tool-tests/')
KNOWN_SUMMARY = None
FROZEN_GATES = {'all_concurrency': [1, 8, 16],
 'cache_cap_evidence_scope': 'source and qualification; RSS gate measures the actual process',
 'controller_cpu_b_over_a_max': 1.1,
 'controller_rss_b_over_a_max': 1.05,
 'controller_rss_extra_kib_max': 512,
 'p95_b_over_a_max': 1.1,
 'primary_concurrency': 8,
 'rss_aggregation': 'maximum sampled controller RSS across all four native controllers per arm, '
                    'including restarts',
 'rss_combination': 'both limits; B <= min(A + 512 KiB, A * 1.05)',
 'ssh_cache_hard_cap_bytes': 2097152,
 'ssh_cache_target': '/usr/bin/ssh',
 'ssh_cache_target_bytes': 846888,
 'throughput_b_over_a_min': 0.95}
FROZEN_INSTALLED_ASSETS = {'/home/qian/hepta-runtime-optimization-20261105-r29/campaign-inputs-01.example.json': {'bytes': 3818,
                                                                                        'sha256': '04b0c7008b9ed7eb82135c5ceaf69d60d6bffbac66bfad8569aac3a29085e40b'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/lifecycle-inputs-01.example.json': {'bytes': 2585,
                                                                                         'sha256': '0d3a7896921a75d64462e09a562b5bba57d34caf4f914c4eb2bc876eeccc7243'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/lifecycle-launcher-bundle-01/README.md': {'bytes': 704,
                                                                                               'sha256': '1ba763663ea2dd4dd600819b5a12b5278c4b55cad47e90330f47bc5605dd0fe8'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/lifecycle-launcher-bundle-01/derivation-inputs-01.json': {'bytes': 4236,
                                                                                                               'sha256': 'a0569d3e86743a7d2fa7a4dec6b6dc1e02786d8f93371875c663dfe5b6b2b811'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/lifecycle-launcher-bundle-01/lifecycle-inputs-01.example.json': {'bytes': 2585,
                                                                                                                      'sha256': '0d3a7896921a75d64462e09a562b5bba57d34caf4f914c4eb2bc876eeccc7243'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/lifecycle-launcher-bundle-01/lifecycle-launcher-manifest-01.json': {'bytes': 2338,
                                                                                                                         'sha256': '2e22e99768f4d0ab2f18db5188837ea21cd2b2afb59475738dff0cd7e5b9f777'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/lifecycle-launcher-bundle-01/lifecycle-plan-01.json': {'bytes': 11749,
                                                                                                            'sha256': 'edb087e787766f2026a8cb06050a5337f75e76555e6d398d55232ac5f38d8bd6'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/lifecycle-launcher-bundle-01/local-verification-01.json': {'bytes': 1568,
                                                                                                                'sha256': '5340250044dbef95288bad1a3b8175fc4cb71365d855a18914a5f528e256989d'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/lifecycle-launcher-bundle-01/source-delta-01.patch': {'bytes': 8038,
                                                                                                           'sha256': '5150caf6ac8a8fc4bf45238a78edee31d6f3958ad0d2e35937724939e7a1f137'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/lifecycle-launcher-bundle-01/tools-01/prepare_lifecycle_inputs.py': {'bytes': 12066,
                                                                                                                          'sha256': '45efacd48c7b27141f036340c0b9b8f504fb41b43a8b1ddb66dc5fb8172c64f6'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/lifecycle-launcher-bundle-01/tools-01/r29_lifecycle_campaign.py': {'bytes': 26760,
                                                                                                                        'sha256': '12b9ad142d95148e9d08a69d44be3e4e3d17a03877eadc956a020602aa22e846'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/lifecycle-tools-01/README.md': {'bytes': 9053,
                                                                                     'sha256': 'bf5ece8988afa5a91f01da1df0e1740add1390f6653d32c7bd562d99b11529be'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/lifecycle-tools-01/allocator_environment.py': {'bytes': 5879,
                                                                                                    'sha256': 'f5c8e879c540b3f7cb1b7d3a7a0f5002c2f40c1a87963174b0b00470fa3a4525'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/lifecycle-tools-01/allocator_environment_audit.py': {'bytes': 6709,
                                                                                                          'sha256': '4b082ce343ae3943e3098baa58af2f5def7198881b9c087d63d88360e9763727'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/lifecycle-tools-01/analyze_lifecycle_gates.py': {'bytes': 7581,
                                                                                                      'sha256': 'c7a861a94a89dd81debb5c055773918d89a1c9c29b699e2e5a0341e51be69553'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/lifecycle-tools-01/analyze_native_observation.py': {'bytes': 8708,
                                                                                                         'sha256': 'cc7f6884d581cd1ced430437350e808de51931c50d12441797205501b20cae66'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/lifecycle-tools-01/audit_native_evidence.py': {'bytes': 17065,
                                                                                                    'sha256': 'b69f6902d2de81eab41b21506f024c002d2f8264d60e86df6b1086623a77fd28'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/lifecycle-tools-01/cancel_saturation_gate.py': {'bytes': 15789,
                                                                                                     'sha256': '536ebdc5f2b090a8c007f189a895ed2e19d7b8b7e41530ccba94dd826742ef7f'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/lifecycle-tools-01/lifecycle-gate-policy.json': {'bytes': 1575,
                                                                                                      'sha256': '36658346c4e265bf551a1ae1a4c6210bec8e4729f7961302a203008741cd381e'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/lifecycle-tools-01/lifecycle-tools-manifest-01.json': {'bytes': 4066,
                                                                                                            'sha256': 'a377791a94e1327bdf3c7da98f30b379caafe6948295d81871f06287bf7c5ef0'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/lifecycle-tools-01/observation_resources.py': {'bytes': 12382,
                                                                                                    'sha256': 'f3402d51cb37b2fe20f4351b3a81ec5990a9fdaff93a846d21c07ccd557cb894'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/lifecycle-tools-01/owned_ssh_interruption.py': {'bytes': 7892,
                                                                                                     'sha256': '1989c57f0b944afae1ed759d6529b8f1cc26197e269e2c34c4fd49e43a32aa7b'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/lifecycle-tools-01/run_lifecycle_abba_01.py': {'bytes': 14787,
                                                                                                    'sha256': '06ff6660bac7f7f97c368a3546d329c40e5f0a30b28545e73f6e9cd5ff30d984'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/lifecycle-tools-01/run_lifecycle_tool_tests.py': {'bytes': 2224,
                                                                                                       'sha256': 'e3c1e8163249dba14672a3a82b43a2d7b8b4c0802b94b8511bf3db668f865a2d'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/lifecycle-tools-01/run_native_observation.py': {'bytes': 3279,
                                                                                                     'sha256': '7606648c99b2ff2bbf0bba58384e8cab609ac3899f838c0b80ba54d6288d20bb'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/lifecycle-tools-01/run_six_host_cancel_recovery.py': {'bytes': 27847,
                                                                                                           'sha256': '698eb7801cde3f2bd5ff202412c0833fc218fd7e912c3c949d2b37fde7a56a12'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/lifecycle-tools-01/run_six_host_cancel_recovery_timed.py': {'bytes': 30163,
                                                                                                                 'sha256': 'a46e54fec23e34133ddbe789deb171492e8e1c665c3dd8ca5fb1ce44db51620e'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/lifecycle-tools-01/run_six_host_cancel_saturation.py': {'bytes': 31325,
                                                                                                             'sha256': 'ae195c895ab58d3bf067e37f30520bf572fd86b6282722dee9a56acc62df85a0'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/lifecycle-tools-01/source-provenance.json': {'bytes': 2510,
                                                                                                  'sha256': '58d276c8df05dcd95a0a25e6264c3de1b248e8bb821651fb1b52859dd707dbbe'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/lifecycle-tools-01/status-predicate.json': {'bytes': 875,
                                                                                                 'sha256': '5828c7ba2990f38531cce7e1a42b44315ee42278ccaee361ace8d9472a96da34'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/lifecycle-tools-01/summarize_lifecycle_abba_01.py': {'bytes': 16065,
                                                                                                          'sha256': '9e050343bb32e7f57148f633ff94bbcfb3a7452b2872ae68404ca642e937af89'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/lifecycle-tools-01/test_native_harness.py': {'bytes': 13286,
                                                                                                  'sha256': '2b450175b9e6122248ac1bcb51860aa8a6d3eff55f6ac8c877c0a905e3dd7d00'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/lifecycle-tools-01/test_r25_lifecycle_tools.py': {'bytes': 10026,
                                                                                                       'sha256': '1845cdb48440a03146e337af7baf916bb9cdb76fb46ea0699f79144cf7197566'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/lifecycle-tools-01/test_verify_saturation_extension.py': {'bytes': 8187,
                                                                                                               'sha256': '10f2dcbfa9e2b5c625f22c3edc32c9f8a969509345b20d9b135cebc2235c16fb'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/lifecycle-tools-01/verify_cancel_recovery.py': {'bytes': 16634,
                                                                                                     'sha256': '0116652a0b489dc462f005e01d7c943feda9ba784563d7317c92bb5beb9a701c'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/lifecycle-tools-01/verify_cancel_saturation.py': {'bytes': 17123,
                                                                                                       'sha256': 'd3b6772ddffc711a23aa4aa9566f903c149535a3d3c4cc3466ee73690cbc1e75'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/lifecycle-tools-01/verify_saturation_extension.py': {'bytes': 9418,
                                                                                                          'sha256': '23dfd25517b517067a4fbb3f4a3227f12bafff46b828eb05f7bf322596124e6a'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/lifecycle-tools-01/x230_observation_benchmark.py': {'bytes': 37006,
                                                                                                         'sha256': '4d96f0bf2da2562e788f48be7c37589ab3a513be5f9d8b2d741afe5c08ea9eed'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/lifecycle-tools-01/x230_six_running_recovery_canary.py': {'bytes': 47298,
                                                                                                               'sha256': '6219bc556b0ac6d142bd4c731466b959e8a410f0b4b55f3d8b303f8fdbfbaaf4'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/observation-plan-01.json': {'bytes': 12542,
                                                                                 'sha256': 'de24734d5a53bc4fdd28e46fb87d5545e8909aff31a60b1891ba767aa3bb117b'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/observation-tools-manifest-01.json': {'bytes': 1901,
                                                                                           'sha256': '22b0f0d2b3c175e0a1f12660b05adcdf34ab4fae780347fafd63a6869c3607e4'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/tools-01/compiler-monitor-policy-01.json': {'bytes': 1001,
                                                                                                 'sha256': 'ddb2e03d4a1a1610466a5dc2d1a544f554ad12fc31412483101b48a235402368'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/tools-01/compiler_monitor.py': {'bytes': 12510,
                                                                                     'sha256': 'afb514362a9d8dd573b806f0dc87df16bd3a906e4574d10d91bf483b2e76cdcf'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/tools-01/compiler_state.py': {'bytes': 6243,
                                                                                   'sha256': '9da718654db04a646e081d2d719a2d6d4655ffe337bc0e3f906e736e4d77a251'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/tools-01/prepare_campaign_inputs.py': {'bytes': 9964,
                                                                                            'sha256': '48dad8915c0bce00085590011873a1146840c32ae0a7620f300d6981c7d800c1'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/tools-01/prepare_lifecycle_inputs.py': {'bytes': 12066,
                                                                                             'sha256': '45efacd48c7b27141f036340c0b9b8f504fb41b43a8b1ddb66dc5fb8172c64f6'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/tools-01/r29_campaign.py': {'bytes': 66141,
                                                                                 'sha256': '0eaf6dd96e6a69eba4ef382360febefd58e1f0370baf7cd79bb817ac2ce266ec'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/tools-01/r29_lifecycle_campaign.py': {'bytes': 26760,
                                                                                           'sha256': '12b9ad142d95148e9d08a69d44be3e4e3d17a03877eadc956a020602aa22e846'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/tools-01/summarize_r25_campaign.py': {'bytes': 14456,
                                                                                           'sha256': '2418bad36fe4aef75d52c5a00c898ff93fef9bb4b6efb10028105143106a1864'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/tools-01/validate_compiler_monitor.py': {'bytes': 7055,
                                                                                              'sha256': 'd2cd009adf1f35a394ffddcc8f8646cc0c1b856b78181ca321ea68f6468218b2'}}
QUALIFICATION_REFERENCES = {'/home/qian/hepta-runtime-optimization-20261105-r29/preparation-01.json': {'bytes': 350182,
                                                                            'sha256': 'fcc7bd5ee050a60b38c047ea9b06ac0bae1d7ebf927b67af60b620af18012782'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/qualification-01/report.json': {'bytes': 83733,
                                                                                     'sha256': '942a570097ab3c751e9969f3d13924dec474888e85e0ce176ee7943547d12b62'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/qualification-01/source-map.json': {'bytes': 24278,
                                                                                         'sha256': '58ca6700a4378d14912358f9bb787d395ef5f86f17d7bf373af2525ee55ae88b'},
 '/home/qian/hepta-runtime-optimization-20261105-r29/qualification-terminal-status-01.json': {'bytes': 731,
                                                                                              'sha256': '582adb11fde3f248411fa5daf25a235cc352bfae28fa3605f2898779b8b48462'}}
HARNESS_SHAS = {'allocator_environment.py': 'f5c8e879c540b3f7cb1b7d3a7a0f5002c2f40c1a87963174b0b00470fa3a4525',
 'allocator_environment_audit.py': '4b082ce343ae3943e3098baa58af2f5def7198881b9c087d63d88360e9763727',
 'analyze_native_observation.py': 'cc7f6884d581cd1ced430437350e808de51931c50d12441797205501b20cae66',
 'audit_native_evidence.py': 'b69f6902d2de81eab41b21506f024c002d2f8264d60e86df6b1086623a77fd28',
 'observation_resources.py': 'f3402d51cb37b2fe20f4351b3a81ec5990a9fdaff93a846d21c07ccd557cb894',
 'owned_ssh_interruption.py': '1989c57f0b944afae1ed759d6529b8f1cc26197e269e2c34c4fd49e43a32aa7b',
 'run_native_observation.py': '7606648c99b2ff2bbf0bba58384e8cab609ac3899f838c0b80ba54d6288d20bb',
 'run_six_host_cancel_recovery.py': '698eb7801cde3f2bd5ff202412c0833fc218fd7e912c3c949d2b37fde7a56a12',
 'test_native_harness.py': '2b450175b9e6122248ac1bcb51860aa8a6d3eff55f6ac8c877c0a905e3dd7d00',
 'verify_cancel_recovery.py': '0116652a0b489dc462f005e01d7c943feda9ba784563d7317c92bb5beb9a701c',
 'x230_observation_benchmark.py': '4d96f0bf2da2562e788f48be7c37589ab3a513be5f9d8b2d741afe5c08ea9eed',
 'x230_six_running_recovery_canary.py': '6219bc556b0ac6d142bd4c731466b959e8a410f0b4b55f3d8b303f8fdbfbaaf4'}
BOUNDARY_SHAS = {'audit_native_boundary.py': '8ad8f6d97a5bd2e4850b02cd66fa5d2ac7d237ea0eef043daf9c88d3c9c152ee',
 'capacity-policy.json': '206d1a99abc328948d8df893daa77a862b25de878a8b97379090da7ce84393d3',
 'harness-freeze.json': '77ea90d5d2f45ed4d724f087353a3c8e603abcd0a8bd1d4bceb31179bef174b1',
 'run_native_boundary.py': '2af83ebba8b7ea5550e7549da795556eb8328622bcfbf563019654e202a53329',
 'test_native_boundary.py': 'cda0bbef1704c374b49cc3cf5ea7b9a873687e547eed5c927bed801cf15156bd'}
INSTALL_RECEIPT_PIN = {'bytes': 83027, 'sha256': '8ab0a2737703d9032060c0fed4f2aaafb3553ae4a804c7302cf38a419a9642ae'}
FIXED_SUPPORT = {
    **{"measurement-tools/" + name: R16 / "measurement-tools" / name for name in HARNESS_SHAS},
    **{"boundary-original/" + name: R16 / "boundary-tools" / name for name in BOUNDARY_SHAS},
    "benchmark-topology.json": TOPOLOGY,
    "profile-template.json": PROFILE,
    "install_r29_reviewed_tools_01.py": STAGE_ROOT / "tools/install_r29_reviewed_tools_01.py",
    "r29-installation-qualification-01.json": STAGE_ROOT / "tools/r29-installation-qualification-01.json",
}
FIXED_SUPPORT_SHAS = {
    **{str(R16 / "measurement-tools" / name): value for name, value in HARNESS_SHAS.items()},
    **{str(R16 / "boundary-tools" / name): value for name, value in BOUNDARY_SHAS.items()},
    str(TOPOLOGY): "8c0767d3318131a7d470d9cde8e327a59ce18adf022c8bc1b1d5a0fa9a865287",
    str(PROFILE): "fe1e9551b5b8812ad6ed3da018c282b7261f7caeb2f49e4dcfefba7ff784ab08",
    str(STAGE_ROOT / "tools/install_r29_reviewed_tools_01.py"): "6fef2a7cdc8a8aa8da508663c9ecaa17235c2b4ec9a8fa7e25d707dcd601984a",
    str(STAGE_ROOT / "tools/r29-installation-qualification-01.json"): "425fbe8867e5aa30921fa9acbb05850ce410eac79dae97075dca8797dd757722",
}


OUTPUT_DIRECTORIES = tuple(DIRECTORIES[name] for name in ("observation", "recovery", "lifecycle", "lifecycle-abba", "saturation", "lifecycle-tool-tests"))
REQUIRED_DIRECTORIES = {"campaign-tools", "lifecycle-tools", "lifecycle-launcher-bundle"}
STAGE_OUTPUT_DIRECTORIES = {"observation01": (ROOT / "campaign-01", RECOVERY),
    "lifecycle01": (ROOT / "lifecycle-campaign-01", ROOT / "lifecycle-abba-01", ROOT / "cancel-saturation-01", ROOT / "lifecycle-tool-tests-01")}
LIFECYCLE_STAGES = ("lifecycle-tool-tests", "normal-lifecycle-abba", "cancel-saturation", "audit-cancel-saturation")
NORMAL_STAGES = tuple(name for n, arm in enumerate("ABBA") for name in (f"canary-{n}-{arm}", f"audit-{n}-{arm}")) + ("summary", "normal-lifecycle-gates")
LIFECYCLE_PHASES = ("prepare", "launch", "before_crash_running", "after_transport_running", "after_crash_running", "same_key_after_crash", "concurrent_cancel", "terminal", "terminal_after_restart", "same_key_after_cancel", "cancel_after_terminal")
BASELINE_RUNTIME_SHA256 = "bc14cab1e632d6cd703f6a0f65d1a8e513b4471c09a403186d72e989e3f74c13"
CANONICAL_PREPARATION_VALIDATOR_SHA256 = "2892bd35bb5f1b5a90919e74453a18d5ae6ad738d08fcc780f3c0ac01c67c923"

def need(value, reason):
    if not value:
        raise RuntimeError(reason)

def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def descriptor(value, expected_path):
    need(isinstance(value, dict) and set(value) == {"path", "bytes", "sha256"}
         and value["path"] == str(expected_path)
         and type(value["bytes"]) is int and 0 <= value["bytes"] <= 16 * 1024**2
         and isinstance(value["sha256"], str) and HEX.fullmatch(value["sha256"]),
         "actual bounded input identity required: " + str(expected_path))
    return value

def validate_terminal(value, job_id):
    """Require an authoritative terminal, while preserving negative original fields."""
    need(value.get("job_id") == job_id and value.get("state") in NATIVE_TERMINAL_STATES,
         "same original authoritative native terminal required")
    need(value.get("terminal_publication_confirmed") is True
         and type(value.get("terminal_publication_protocol")) is int
         and value["terminal_publication_protocol"] == 1
         and value.get("automatic_retry") is False,
         "unresolved/retried original terminal cannot authorize stable evidence capture")
    need((type(value.get("exit_code")) is int or value.get("exit_code") is None)
         and all(type(value.get(key)) is bool for key in ("cancelled", "timed_out", "output_complete", "output_durable")),
         "native outcome fields are missing")
    if value["state"] == "succeeded":
        need(value["exit_code"] == 0 and value["cancelled"] is False and value["timed_out"] is False,
             "successful native state contradicts original flags")
    log_complete = value["output_complete"] and value["output_durable"]
    for stream in ("stdout", "stderr"):
        counts = value["log_bytes"][stream]
        need(type(counts.get("seen")) is int and type(counts.get("stored")) is int
             and 0 <= counts["stored"] <= counts["seen"], "invalid original log byte counts")
        need(type(value["log_synced"][stream]) is bool and type(value["log_truncated"][stream]) is bool
             and (value["log_errors"][stream] is None or isinstance(value["log_errors"][stream], str)),
             "invalid original log metadata")
        log_complete = (log_complete and value["log_synced"][stream]
                        and not value["log_truncated"][stream] and value["log_errors"][stream] is None
                        and counts["stored"] == counts["seen"])
    return {"state": value["state"], "exit_code": value["exit_code"],
            "cancelled": value["cancelled"], "timed_out": value["timed_out"],
            "native_logs_lossless_complete": bool(log_complete), "automatic_retry": False}

def omission_reason(path, group, identity):
    if identity["is_elf"]:
        return "ELF body omitted; complete observed file identity retained"
    if path.name in PRIVATE_NAMES or (path.parent.name == "bin" and path.name in ("ssh", "ssh-original")):
        return "private transport configuration or session wrapper body omitted; identity retained"
    if path.name in ("id_rsa", "id_ed25519", "id_ecdsa", "id_dsa") or path.suffix in (".key", ".pem", ".plist"):
        return "private credential or service configuration body is outside approved export scope"
    if path.name == "cargo-nextest-0.9.137.tar.gz.partial":
        return "verified upstream tool archive body omitted; recorded identity and install receipt retained"
    return None

def load_helper(digest):
    """Only the exact reviewed local helper definitions may be loaded."""
    need(isinstance(digest, str) and HEX.fullmatch(digest) and HELPER.resolve(strict=True) == HELPER,
         "fixed hash-bound archive helper required")
    fd = os.open(HELPER, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
             and before.st_nlink == 1 and before.st_size <= 128 * 1024,
             "unsafe archive helper")
        raw = b""
        while block := os.read(fd, 65536):
            raw += block
            need(len(raw) <= before.st_size, "archive helper grew")
        fields = ("st_dev", "st_ino", "st_uid", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        stamp = lambda item: tuple(getattr(item, key) for key in fields)
        need(len(raw) == before.st_size and stamp(before) == stamp(os.fstat(fd)) == stamp(HELPER.lstat())
             and hashlib.sha256(raw).hexdigest() == digest, "archive helper differs")
    finally:
        os.close(fd)
    # Execute the checked in-memory bytes, not a second path read after hashing.
    spec = importlib.util.spec_from_loader("r29_bound_stable_xz_archive", loader=None)
    module = importlib.util.module_from_spec(spec)
    module.__file__ = str(HELPER)
    exec(compile(raw, str(HELPER), "exec"), module.__dict__)
    return module

def validate_input(value):
    need(isinstance(value, dict) and value.get("schema") == "hepta-r29-performance-export-input/v1"
         and value.get("root") == str(ROOT) and value.get("actual_outcomes_supplied") is True
         and all(value.get(k) is True for k in ("native_raw_companion_required", "Mac_holder_companion_required",
                                                "qualification_ci_companion_required"))
         and value.get("adoption_decision_made_here") is False
         and set(value.get("stages", {})) == set(STAGES), "actual fixed R29 performance outcomes required")
    rows = value["stages"]
    for name in STAGES:
        row = rows[name]
        need(isinstance(row, dict) and set(row) == {"executed", "job_id", "native_terminal", "report", "reason"}
             and type(row["executed"]) is bool, "fixed stage declaration fields differ")
        if row["executed"]:
            need(isinstance(row["job_id"], str) and JOB.fullmatch(row["job_id"]), "actual original job identity required")
            descriptor(row["native_terminal"], NATIVE_PATHS[name])
            if row["report"] is not None:
                descriptor(row["report"], REPORT_PATHS[name])
            else:
                need(isinstance(row["reason"], str) and row["reason"].strip(),
                     "original report absence needs an explicit actual reason")
        else:
            need(row["job_id"] is row["native_terminal"] is row["report"] is None
                 and isinstance(row["reason"], str) and row["reason"].strip(),
                 "unsubmitted stage must not acquire invented outcomes")
    need(rows["observation01"]["executed"] is True
         and rows["observation01"]["job_id"] == ORIGINAL_OBSERVATION_JOB,
         "the one actual original R29 observation must be retained")
    if rows["lifecycle01"]["executed"]:
        need(rows["lifecycle01"]["job_id"] != ORIGINAL_OBSERVATION_JOB,
             "lifecycle and observation cannot share a native job")
    summary = value.get("known_original_summary")
    if summary is not None:
        descriptor(summary, ROOT / "campaign-01/summary.json")
    return rows


def required_absent_paths(declarations):
    paths = []
    for name in STAGES:
        row = declarations[name]
        if not row["executed"]:
            paths.append(NATIVE_PATHS[name])
            paths.extend(STAGE_OUTPUT_DIRECTORIES[name])
        elif row["report"] is None:
            paths.append(REPORT_PATHS[name])
    return sorted(set(paths), key=str)


def report_projection(value):
    if not isinstance(value, dict):
        return {"structured_object": False, "original_type": type(value).__name__}
    keys = ("schema", "passed", "finished_utc", "observation_gate_passed", "adoption_passed",
            "measurement_attribution_valid", "result_before_compiler_monitor", "rejection_reasons", "error",
            "automatic_retries", "inputs_unchanged", "source_inputs_unchanged", "baseline_source_inputs_unchanged",
            "correctness_stages_completed", "baseline_enablement_verified", "compiler_monitor_finalization_error",
            "stages", "candidate_binary_sha256")
    return {"structured_object": True, **{k: value[k] for k in keys if k in value}}


def original_outcome(name, declaration, terminal, original):
    if not declaration["executed"]:
        return {"executed": False, "reason": declaration["reason"], "success_inferred": False}
    native = validate_terminal(terminal, declaration["job_id"])
    finished = isinstance(original, dict) and isinstance(original.get("finished_utc"), str) and bool(original["finished_utc"].strip())
    schema_matches = isinstance(original, dict) and original.get("schema") == REPORT_SCHEMAS[name]
    return {"executed": True, "job_id": declaration["job_id"], "native_outcome": native,
            "original_report": report_projection(original), "original_report_finished": bool(finished),
            "original_report_schema_matches": bool(schema_matches),
            "original_positive_report_and_closed_native": bool(
                native["state"] == "succeeded" and native["exit_code"] == 0 and native["native_logs_lossless_complete"]
                and finished and schema_matches and original.get("passed") is True)}


def inspect_monitor(name, original, get_json, identities, validator):
    """Use only the independently pinned pure validator; preserve unsupported original claims."""
    output = REPORT_PATHS[name].parent
    ledger_path, audit_path = output / "compiler-monitor.json", output / "compiler-monitor.audit.json"
    result = {"original_parent_authorized_attribution": isinstance(original, dict) and original.get("measurement_attribution_valid") is True,
              "raw_ledger_present": str(ledger_path) in identities, "independently_validated": False}
    try:
        ledger = get_json(ledger_path) if str(ledger_path) in identities else None
        audit = get_json(audit_path) if str(audit_path) in identities else None
        monitor = original.get("compiler_monitor") if isinstance(original, dict) else None
        need(isinstance(ledger, dict), "original monitor ledger is absent, malformed or not an object")
        need(isinstance(audit, dict), "original monitor audit is absent, malformed or not an object")
        need(isinstance(monitor, dict), "original parent monitor is absent or not an object")
        sources = {}
        for label, filename in MONITOR_COMPONENTS.items():
            path = ROOT / "tools-01" / filename
            identity = identities[str(path)]
            need({k: identity[k] for k in ("bytes", "sha256")} == FROZEN_INSTALLED_ASSETS[str(path)],
                 "reviewed monitor component differs")
            sources[label] = {"path": str(path), "bytes": identity["bytes"], "sha256": identity["sha256"]}
        policy = get_json(ROOT / "tools-01/compiler-monitor-policy-01.json")
        validation = validator.validate(ledger, policy["limits"], monitor["guarded_body_start_monotonic_ns"],
                                        monitor["guarded_body_end_monotonic_ns"])
        source_match = (monitor.get("sources") == sources and ledger.get("source_bindings") == {
            "schema": "hepta-r26-compiler-monitor-input-binding/v1", "sources": sources, "limits": policy["limits"]})
        def short(path):
            r = identities[str(path)]
            return {"path": str(path), "bytes": r["bytes"], "sha256": r["sha256"]}
        lp, ap = short(ledger_path), short(audit_path)
        binding_match = (monitor.get("ledger") == lp and monitor.get("independent_audit") == ap
                         and audit.get("ledger") == lp and audit.get("validator") == sources["validator"]
                         and audit.get("validation") == validation and audit.get("monitor_sources_unchanged") is True
                         and audit.get("source_recheck_errors") == [] and monitor.get("monitor_sources_unchanged") is True
                         and monitor.get("limits") == policy["limits"])
        valid = validation["passed"] is True and source_match and binding_match and monitor.get("passed") is True
        result.update(independent_validation=validation, source_bindings_match=source_match,
                      original_audit_and_parent_bindings_match=binding_match, independently_validated=valid)
    except (KeyError, TypeError, ValueError, RuntimeError, OSError) as error:
        result["verification_error"] = {"type": type(error).__name__, "reason": str(error)}
    result["unsupported_original_attribution"] = result["original_parent_authorized_attribution"] and not result["independently_validated"]
    return result


def disposition(outcomes, monitors, bindings):
    obs, life = outcomes["observation01"], outcomes["lifecycle01"]
    observation = bindings["campaigns"]["observation01"]
    if observation.get("completed_positive_original_verified") is not True:
        return "observation_failed_incomplete_or_binding_invalid_original_retained"
    if monitors["observation01"].get("independently_validated") is not True or obs["original_report"].get("measurement_attribution_valid") is not True:
        return "observation_measurement_invalid_original_retained"
    if obs["original_report"].get("observation_gate_passed") is False:
        return "observation_rejected_original_retained_lifecycle_unrun" if not life["executed"] else "observation_rejected_lifecycle_execution_discrepancy_retained"
    if not life["executed"]:
        return "observation_passed_lifecycle_unrun_no_adoption"
    lifecycle = bindings["campaigns"]["lifecycle01"]
    if lifecycle.get("completed_positive_original_verified") is not True:
        return "lifecycle_failed_incomplete_or_rejected_original_retained"
    if monitors["lifecycle01"].get("independently_validated") is not True or life["original_report"].get("measurement_attribution_valid") is not True:
        return "lifecycle_measurement_invalid_original_retained"
    return "original_observation_lifecycle_saturation_passed_external_custody_and_QC_still_required"


def check_original_bindings(get_json, identities, declarations, outcomes, monitors):
    """Bind full original producer files. Negative/partial reports remain negative evidence."""
    def same(path, recorded):
        need(str(path) in identities and isinstance(recorded, dict),
             "original recorded body/identity was not captured: " + str(path))
        actual = identities[str(path)]
        need(actual["sha256"] == recorded["sha256"]
             and ("bytes" not in recorded or actual["bytes"] == recorded["bytes"]),
             "original producer identity differs: " + str(path))
        if "path" in recorded:
            need(recorded["path"] == str(path), "original descriptor path differs: " + str(path))
        return actual

    def maybe(path):
        if str(path) not in identities:
            return None
        try:
            return get_json(path)
        except (ValueError, UnicodeError):
            return None

    def stage_streams(value, directory, expected_names, positive, process_key="owned_process_absent"):
        rows = value.get("stages", [])
        need(isinstance(rows, list) and len(rows) <= len(expected_names)
             and [r.get("name") for r in rows] == list(expected_names[:len(rows)]),
             "original stage order/prefix differs")
        for row in rows:
            for stream in ("stdout", "stderr"):
                if stream in row:
                    same(directory / (row["name"] + "." + stream), row[stream])
                elif positive:
                    need(False, "positive original stage lacks its complete stream binding")
            for record in row.get("output_bindings", []):
                path = Path(record["path"])
                need(any(path.is_relative_to(p) for p in OUTPUT_DIRECTORIES),
                     "original stage output escaped fixed scope")
                same(path, record)
            if positive:
                need(row.get("returncode") == 0 and row.get("waited_and_reaped") is True
                     and row.get(process_key) is True and row.get("owned_process_group_absent") is True
                     and row.get("cleanup_error") is None
                     and ("passed" not in row or row["passed"] is True),
                     "positive original stage custody did not close")
        if positive:
            need(len(rows) == len(expected_names), "positive original stage inventory is incomplete")
        return [r["name"] for r in rows]

    def source_and_binary_bindings(parent, inputs, directory):
        snapshot = get_json(directory / "source-inputs.json")
        need(snapshot["root"] == str(SOURCE) and snapshot["file_count"] == 221
             and {name: pin["sha256"] for name, pin in snapshot["files"].items()} == source_map
             and snapshot["sha256"] == parent["source_inputs_sha256"] == inputs["source_inputs_sha256"],
             "campaign source snapshot is not the actual qualified candidate")
        same(directory / "source-inputs.json", parent["source_inputs"])
        same(directory / "baseline-source-inputs.json", parent["baseline_source_inputs"])
        for name, pin in qualification["binaries"].items():
            need({k: parent["binaries"]["B"][name][k] for k in ("path", "sha256")} ==
                 {k: pin[k] for k in ("path", "sha256")}, "campaign used a different qualified candidate")
            need({k: parent["binaries"]["B"][name][k] for k in ("bytes", "sha256")} ==
                 inputs["candidate_binaries"][name], "campaign candidate size or input hash differs")
        need(parent["binaries"]["A"]["hepta-runtime"]["sha256"] == BASELINE_RUNTIME_SHA256,
             "accepted R24 baseline runtime differs")

    for pathname, pin in FROZEN_INSTALLED_ASSETS.items():
        same(Path(pathname), pin)
    installation = get_json(ROOT / "tools-install-01-receipt.json")
    same(ROOT / "tools-install-01-receipt.json", INSTALL_RECEIPT_PIN)
    need(installation["installed"] is True and installation["installed_file_count"] == 50
         and len(installation["files"]) == 50 and installation["all_files_and_archives_rehashed"] is True
         and {r["path"]: {k: r[k] for k in ("bytes", "sha256")} for r in installation["files"]} == FROZEN_INSTALLED_ASSETS,
         "original 50 installed acceptance assets differ")
    for pathname, expected in FIXED_SUPPORT_SHAS.items():
        same(Path(pathname), {"sha256": expected})
    boundary_present = any(path.startswith(str(ROOT / "boundary-tools-01") + "/") for path in identities)
    if boundary_present:
        for name, expected in BOUNDARY_SHAS.items():
            same(ROOT / "boundary-tools-01" / name, {"sha256": expected})
    for pathname, pin in QUALIFICATION_REFERENCES.items():
        same(Path(pathname), pin)
    qualification = get_json(ROOT / "qualification-01/report.json")
    prep = get_json(ROOT / "preparation-01.json")
    source_map = get_json(ROOT / "qualification-01/source-map.json")
    need(qualification["qualified"] is True and qualification["source"] == str(SOURCE)
         and len(source_map) == 221 and source_map == qualification["source_after"] == qualification["source_tested"] == prep["source_tested"]
         and prep["candidate_qualified"] is True and prep["selected_proposal"] == "shared unfiltered ToolRouter"
         and prep["optional_pidfd_selected"] is False,
         "actual qualified R29 source identity differs")
    input_value = get_json(INPUT)
    if input_value["known_original_summary"] is not None:
        same(ROOT / "campaign-01/summary.json", input_value["known_original_summary"])
    results = {}
    for name in STAGES:
        row, outcome = declarations[name], outcomes[name]
        result = {"executed": row["executed"], "original_bindings_verified": False,
                  "completed_positive_original_verified": False}
        results[name] = result
        if not row["executed"]:
            result.update(unexecuted_original_retained=True, success_inferred=False)
            continue
        parent = maybe(REPORT_PATHS[name])
        result["original_report_present"] = parent is not None
        result["original_report_structured_object"] = isinstance(parent, dict)
        if not isinstance(parent, dict):
            result["binding_error"] = {"type": "OriginalReportUnavailable", "reason": "absent, malformed or nonobject original retained"}
            continue
        positive = outcome["original_positive_report_and_closed_native"]
        try:
            directory = REPORT_PATHS[name].parent
            input_path = ROOT / ("campaign-inputs-01.json" if name == "observation01" else "lifecycle-inputs-01.json")
            parent_path = ROOT / "tools-01" / ("r29_campaign.py" if name == "observation01" else "r29_lifecycle_campaign.py")
            need(parent["schema"] == REPORT_SCHEMAS[name]
                 and parent["launcher_sha256"] == FROZEN_INSTALLED_ASSETS[str(parent_path)]["sha256"],
                 "original source-bound campaign parent differs")
            inputs = get_json(input_path)
            need(inputs["launcher_sha256"] == parent["launcher_sha256"] and inputs["attempt"] == "01",
                 "original campaign input/holder source differs")
            same(input_path, parent["input_receipt"])
            same(directory / "inputs.json", parent["input_receipt"] | {"path": str(directory / "inputs.json")})
            need(parent["automatic_retries"] == 0 and parent["production_services_modified"] is False,
                 "original campaign was retried or changed production")
            expected = OBSERVATION_STAGES if name == "observation01" else LIFECYCLE_STAGES
            result["entered_stages"] = stage_streams(parent, directory, expected, positive)
            if positive:
                need(all(parent.get(k) is True for k in ("inputs_unchanged", "source_inputs_unchanged", "baseline_source_inputs_unchanged")),
                     "positive original lacks final source/input preservation")
                source_and_binary_bindings(parent, inputs, directory)
            if name == "observation01":
                summary = maybe(ROOT / "campaign-01/summary.json")
                result["original_observation_gate_passed"] = parent.get("observation_gate_passed")
                result["original_rejection_reasons"] = parent.get("rejection_reasons")
                if isinstance(summary, dict):
                    need(summary["schema"] == "hepta-r25-observation-gates/v1" and summary["thresholds"] == FROZEN_GATES,
                         "original observation summary thresholds/schema differ")
                    result["original_summary_gate_passed"] = summary.get("observation_gate_passed")
                    result["original_summary_rejection_reasons"] = summary.get("rejection_reasons")
                    for record in summary.get("evidence", {}).values():
                        path = Path(record["path"])
                        need(path.is_relative_to(ROOT / "campaign-01") or path.is_relative_to(RECOVERY),
                             "original summary evidence escaped fixed scope")
                        same(path, record)
                if positive:
                    need(isinstance(summary, dict) and all(parent.get(k) is True for k in
                         ("correctness_stages_completed", "baseline_enablement_verified"))
                         and summary["evidence_verified"] is True and summary["correctness_verified"] is True
                         and type(summary["observation_gate_passed"]) is bool
                         and parent["observation_gate_passed"] is summary["observation_gate_passed"]
                         and parent["rejection_reasons"] == summary["rejection_reasons"]
                         and parent["thresholds"] == FROZEN_GATES,
                         "completed observation result/summary consistency differs")
                    same(ROOT / "campaign-01/summary.json", parent["summary"])
                    need(summary["binary_sha256"]["B"] == qualification["binaries"]["hepta-runtime"]["sha256"]
                         and summary["binary_sha256"]["A"] == BASELINE_RUNTIME_SHA256,
                         "original summary A/B identities differ")
                    if summary["observation_gate_passed"]:
                        need(summary["performance_gates_passed"] is True and summary["rejection_reasons"] == [],
                             "positive observation summary has an original rejection")
            else:
                result["saturation_stage_entered"] = "cancel-saturation" in result["entered_stages"]
                result["saturation_audit_stage_entered"] = "audit-cancel-saturation" in result["entered_stages"]
                normal = maybe(ROOT / "lifecycle-abba-01/report.json")
                index = maybe(ROOT / "lifecycle-abba-01/round-index.json")
                gates = maybe(ROOT / "lifecycle-abba-01/gates.json")
                descriptive = maybe(ROOT / "lifecycle-abba-01/summary.json")
                if isinstance(normal, dict):
                    need(normal["schema"] == "hepta-r25-lifecycle-abba-control/v1"
                         and normal["automatic_retries"] == 0 and normal["order"] == "ABBA",
                         "original normal lifecycle schema/order/retries differ")
                    same(ROOT / "lifecycle-tools-01/lifecycle-tools-manifest-01.json", normal["tools_manifest"])
                    need(normal["baseline"] == parent["binaries"]["A"]["hepta-runtime"]
                         and normal["candidate"] == parent["binaries"]["B"]["hepta-runtime"],
                         "original normal lifecycle A/B artifacts differ from its parent")
                    stage_streams(normal, ROOT / "lifecycle-abba-01", NORMAL_STAGES, positive, "proc_absent")
                    for key, filename in (("plan", "plan.json"), ("round_index", "round-index.json"),
                                          ("summary", "summary.json"), ("normal_lifecycle_gates", "gates.json")):
                        if key in normal:
                            same(ROOT / "lifecycle-abba-01" / filename, normal[key])
                if isinstance(index, dict):
                    need(index["schema"] == "hepta-r25-lifecycle-round-index/v1" and index["closed"] is True
                         and index["order"] == "ABBA" and index["round_count"] == 4 and len(index["rounds"]) == 4
                         and index["automatic_retries"] == 0, "original ABBA round index is not complete")
                    if isinstance(normal, dict):
                        need(all(index[key] == normal[key] for key in ("rounds", "baseline", "candidate", "tools_manifest", "plan")),
                             "original normal/index round or input inventory differs")
                    for number, arm in enumerate("ABBA"):
                        item = index["rounds"][number]
                        round_dir = ROOT / "lifecycle-abba-01" / f"round-{number}-{arm}"
                        need(item["index"] == number and item["arm"] == arm and item["directory"] == round_dir.name,
                             "original round path/order differs")
                        raw_identity = same(round_dir / "report.json", item["report"])
                        same(round_dir / "independent-summary.json", item["independent_analysis"])
                        raw, audit = get_json(round_dir / "report.json"), get_json(round_dir / "independent-summary.json")
                        expected_sha = BASELINE_RUNTIME_SHA256 if arm == "A" else qualification["binaries"]["hepta-runtime"]["sha256"]
                        need(raw["passed"] is True and audit["verified"] is True
                             and raw["candidate_sha256"] == audit["candidate_sha256"] == expected_sha
                             and audit["source_sha256"] == raw_identity["sha256"] and audit["source_bytes"] == raw_identity["bytes"]
                             and raw["automatic_rpc_retries"] == audit["automatic_rpc_retries"] == 0,
                             "original lifecycle raw report/audit binding differs")
                        need(len(item["phase_files"]) == 11 and {Path(p["path"]).name for p in item["phase_files"]} ==
                             {"phase-" + phase + ".json" for phase in LIFECYCLE_PHASES}, "original phase inventory differs")
                        for pin in item["phase_files"]:
                            same(round_dir / Path(pin["path"]).name, pin)
                    if isinstance(descriptive, dict):
                        need(descriptive["verified"] is True and descriptive["round_index_sha256"] ==
                             identities[str(ROOT / "lifecycle-abba-01/round-index.json")]["sha256"],
                             "original descriptive lifecycle summary index differs")
                if isinstance(gates, dict):
                    need(gates["schema"] == "hepta-r25-lifecycle-gates/v1" and gates["verified"] is True,
                         "original normal lifecycle gate schema differs")
                    same(ROOT / "lifecycle-abba-01/round-index.json", gates["round_index"])
                    same(ROOT / "lifecycle-tools-01/lifecycle-gate-policy.json", gates["gate_policy"])
                    result["original_normal_lifecycle_gate_passed"] = gates["passed"]
                saturation = maybe(ROOT / "cancel-saturation-01/report.json")
                independent = maybe(ROOT / "cancel-saturation-01/independent-summary.json")
                if isinstance(independent, dict):
                    pin = identities[str(ROOT / "cancel-saturation-01/report.json")]
                    need(independent["source_sha256"] == pin["sha256"] and independent["source_bytes"] == pin["bytes"],
                         "original saturation independent source differs")
                    result["original_saturation_independently_verified"] = independent.get("verified")
                if positive:
                    obs = get_json(REPORT_PATHS["observation01"])
                    need(results["observation01"]["completed_positive_original_verified"] is True
                         and obs["observation_gate_passed"] is True
                         and monitors["observation01"]["independently_validated"] is True,
                         "positive lifecycle lacks a completed valid observation")
                    same(REPORT_PATHS["observation01"], inputs["observation_campaign"])
                    need(parent["binaries"] == obs["binaries"] and parent["source_inputs_sha256"] == obs["source_inputs_sha256"]
                         and parent["baseline_source_inputs_sha256"] == obs["baseline_source_inputs_sha256"]
                         and parent["observation_gate_verified"] is True and parent["adoption_passed"] is True,
                         "positive lifecycle candidate/observation/adoption binding differs")
                    tests = get_json(ROOT / "lifecycle-tool-tests-01/report.json")
                    need(tests["passed"] is True and tests["tests_run"] == 14
                         and tests["skipped"] == tests["errors"] == tests["failures"] == 0,
                         "the original 14 native harness tests did not all pass")
                    need(isinstance(normal, dict) and normal["passed"] is True and normal["inputs_unchanged"] is True
                         and isinstance(gates, dict) and gates["passed"] is True
                         and isinstance(index, dict) and isinstance(descriptive, dict),
                         "positive original lifecycle lacks complete normal gates")
                    need(isinstance(saturation, dict) and saturation["passed"] is True
                         and isinstance(independent, dict) and independent["verified"] is True
                         and independent["candidate_sha256"] == qualification["binaries"]["hepta-runtime"]["sha256"]
                         and independent["saturation_verification"]["verified"] is True
                         and independent["saturation_verification"]["retired_after_drain_before_restart"] is True,
                         "positive lifecycle lacks the original real saturation proof")
                    same(ROOT / "lifecycle-abba-01/gates.json", parent["normal_lifecycle_gate"])
                    same(ROOT / "cancel-saturation-01/independent-summary.json", parent["saturation_analysis"])
            result["original_bindings_verified"] = True
            result["completed_positive_original_verified"] = bool(positive)
        except (KeyError, TypeError, ValueError, RuntimeError, OSError) as error:
            result["binding_error"] = {"type": type(error).__name__, "reason": str(error)}
    return {"installed_acceptance_assets": 50, "qualified_source_identity_files": 221,
            "canonical_preparation_validator_sha256": CANONICAL_PREPARATION_VALIDATOR_SHA256,
            "canonical_reaudited_here": False,
            "qualified_source_full_bodies_and_tests_in_separate_companion": True,
            "campaigns": results, "original_native_holder_success_is_not_performance_adoption": True,
            "thresholds_modified": False, "tests_or_workloads_reexecuted": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exporter-sha256", required=True)
    parser.add_argument("--archive-helper-sha256", required=True)
    parser.add_argument("--input-sha256", required=True)
    args = parser.parse_args()
    need(sys.platform == "linux" and os.geteuid() != 0 and Path(__file__).resolve() == EXPORTER,
         "fixed native operator exporter path required")
    need(args.archive_helper_sha256 == HELPER_SHA256, "reviewed archive helper pin differs")
    helper = load_helper(args.archive_helper_sha256)
    source_identity = helper.read(EXPORTER)[0]
    need(HEX.fullmatch(args.exporter_sha256) and source_identity["sha256"] == args.exporter_sha256,
         "actual exporter source differs")
    input_identity, input_raw = helper.read(INPUT, retain=True)
    need(HEX.fullmatch(args.input_sha256) and input_identity["sha256"] == args.input_sha256, "actual input differs")
    value = json.loads(input_raw)
    declarations = validate_input(value)
    helper.direct(ROOT)
    need(stat.S_ISDIR(ROOT.lstat().st_mode) and ROOT.lstat().st_uid == os.geteuid()
         and not os.path.lexists(OUT), "fresh fixed owned evidence output required")
    OUT.mkdir(mode=0o700)
    report = {"schema": "hepta-r29-performance-evidence-export/v1", "passed": False,
              "started_utc": utc(), "exporter": source_identity, "input": input_identity,
              "archive_helper": helper.read(HELPER)[0], "original_outcomes": {}, "archive": None,
              "no_workload_executed": True, "automatic_retries": 0, "candidate_adopted": False,
              "hosted_actions_passed_inferred": False, "native_original_raw_companion_required": True,
              "Mac_holder_companion_required": True, "qualification_ci_companion_required": True}
    identities, payloads, omitted, inventories, absent, originals = {}, {}, {}, {}, [], {}
    def remember(record):
        key = record["source_path"]
        need(key not in identities or identities[key] == record, "original changed between reads")
        identities[key] = record
        return record
    def expect_absent(path):
        need(not os.path.lexists(path), "declared unexecuted output unexpectedly exists: " + str(path))
        absent.append(str(path))
    def include(path, name, scan=False):
        helper.safe_name(name)
        need(name not in payloads and name not in omitted, "duplicate archive member")
        identity = remember(helper.read(path)[0])
        reason = omission_reason(path, "performance", identity)
        if reason:
            omitted[name] = {"identity": identity, "reason": reason}
        else:
            if scan:
                remember(helper.read(path, expected=identity, scan_private_markers=True)[0])
            payloads[name] = identity
        return identity
    def bound(pin):
        identity, raw = helper.read(Path(pin["path"]), retain=True)
        need(all(identity[k] == pin[k] for k in ("bytes", "sha256")), "actual original receipt identity differs")
        remember(identity)
        return raw
    def get_json(path):
        record, raw = helper.read(path, retain=True, expected=identities.get(str(path)))
        remember(record)
        return json.loads(raw)
    try:
        for path in required_absent_paths(declarations):
            expect_absent(path)
        for name in STAGES:
            row = declarations[name]
            if not row["executed"]:
                report["original_outcomes"][name] = original_outcome(name, row, None, None)
                continue
            terminal = json.loads(bound(row["native_terminal"]))
            original = None
            if row["report"] is not None:
                raw = bound(row["report"])
                try:
                    original = json.loads(raw)
                except (ValueError, UnicodeError):
                    pass
            originals[name] = original
            report["original_outcomes"][name] = original_outcome(name, row, terminal, original)
            include(NATIVE_PATHS[name], "native-terminals/" + NATIVE_PATHS[name].name)
        for label, directory in DIRECTORIES.items():
            if not os.path.lexists(directory):
                need(label not in REQUIRED_DIRECTORIES, "required installed tool directory is absent")
                expect_absent(directory)
                continue
            snapshot = helper.listing(directory)
            inventories[str(directory)] = snapshot
            for pathname in snapshot["files"]:
                path = Path(pathname)
                include(path, label + "/" + path.relative_to(directory).as_posix(), label + "/" in OUTPUT_PREFIXES)
        for name in ROOT_FILES:
            path = ROOT / name
            if not os.path.lexists(path):
                need(name in OPTIONAL_ROOT_FILES, "required fixed root receipt absent")
                expect_absent(path)
            else:
                include(path, "root-receipts/" + name)
        for name, path in FIXED_SUPPORT.items():
            include(path, "fixed-support/" + name)
        for pathname, pin in QUALIFICATION_REFERENCES.items():
            path = Path(pathname)
            identity = include(path, "qualification-reference/" + path.relative_to(ROOT).as_posix())
            need(all(identity[k] == pin[k] for k in ("bytes", "sha256")), "fixed actual qualification reference differs")
        include(EXPORTER, "capture-tools/export_r29_performance_01.py")
        include(HELPER, "capture-tools/stable_xz_archive.py")
        include(INPUT, "capture-tools/actual-input.json")
        validator_path = ROOT / "tools-01/validate_compiler_monitor.py"
        validator_identity, validator_raw = helper.read(validator_path, retain=True)
        remember(validator_identity)
        need(validator_identity["sha256"] == MONITOR_VALIDATOR_SHA256, "pure monitor validator source differs")
        validator = types.ModuleType("r29_capture_bound_pure_monitor_validator")
        validator.__file__ = str(validator_path)
        exec(compile(validator_raw, str(validator_path), "exec"), validator.__dict__)
        monitors = {name: inspect_monitor(name, originals.get(name), get_json, identities, validator)
                    for name in STAGES if declarations[name]["executed"]}
        report["compiler_monitor_verification"] = monitors
        bindings = check_original_bindings(get_json, identities, declarations, report["original_outcomes"], monitors)
        report["candidate_disposition"] = disposition(report["original_outcomes"], monitors, bindings)
        manifest = {"schema": "hepta-r29-performance-archive-manifest/v1", "root": str(ROOT),
                    "archive_name": ARCHIVE_NAME, "exporter": source_identity,
                    "archive_helper": report["archive_helper"], "input": input_identity,
                    "declarations": declarations, "original_outcomes": report["original_outcomes"],
                    "compiler_monitor_verification": monitors, "candidate_disposition": report["candidate_disposition"],
                    "original_bindings": bindings, "payloads": payloads, "omissions": omitted,
                    "fixed_directory_inventories": inventories, "observed_absent_paths": sorted(set(absent)),
                    "exact_original_bytes_preserved": True, "qualification_ci_companion_required": True,
                    "qualification_full_test_logs_source_and_ELF_identities_reaudited_here": False,
                    "accepted_R24_baseline_original_references_in_campaign_input": True,
                    "native_original_raw_companion_required": True, "Mac_holder_companion_required": True,
                    "candidate_adopted": False}
        raw, archive_proof = helper.write_archive(OUT / ARCHIVE_NAME, manifest, payloads, secret_prefixes=OUTPUT_PREFIXES)
        helper.create(OUT / "manifest.json", raw)
        report["manifest"] = helper.read(OUT / "manifest.json")[0]
        report["archive"] = archive_proof
        report["transfer"] = helper.transfer_chunks(OUT / ARCHIVE_NAME, OUT)
        for pathname, expected in identities.items():
            helper.read(Path(pathname), expected=expected)
        for pathname, expected in inventories.items():
            need(helper.listing(Path(pathname)) == expected, "fixed original inventory changed during capture")
        for pathname in absent:
            need(not os.path.lexists(pathname), "original absent path appeared during capture")
        report.update(passed=True, original_bindings=bindings, payload_count=len(payloads), omission_count=len(omitted),
                      original_inputs_unchanged=True, original_outcomes_preserved=True,
                      actual_output_inventory_and_absence_verified=True)
    except Exception as error:
        report["error"] = {"type": type(error).__name__, "message": str(error), "traceback": traceback.format_exc()}
    report["finished_utc"] = utc()
    helper.create(OUT / "report.json", helper.encode(report))
    report_identity = helper.read(OUT / "report.json")[0]
    print(json.dumps({"report": report_identity, "passed": report["passed"],
                      "candidate_adopted": False, "no_workload_executed": True}), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
