#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Preserve one actual R26 outcome, including failure; run no original operation.

Future native IDs/report hashes must be materialized from original receipts.
Archive success is distinct from qualification, performance or adoption success.
"""
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

ROOT = Path("/home/qian/hepta-runtime-optimization-20261105-r26")
STAGE_ROOT = Path("/home/qian/hepta-runtime-optimization-20261105-r25")
BASELINE = Path("/home/qian/hepta-runtime-optimization-20261105-r24")
R16 = Path("/home/qian/hepta-runtime-optimization-20261104-r16")
RECOVERY = R16 / "r26-cancel-recovery-01"
OUT = ROOT / "evidence-export-01"
EXPORTER = STAGE_ROOT / "tools/export_r26_evidence_03.py"
HELPER = STAGE_ROOT / "tools/r26_export_stable_archive_03.py"
INPUT = STAGE_ROOT / "tools/r26-evidence-export-input-03.json"
HEX = re.compile(r"[0-9a-f]{64}\Z")
JOB = re.compile(r"[0-9a-f]+-[0-9a-f]+-[0-9a-f]+\Z")
STAGES = ("qualification", "rust_ci", "observation", "lifecycle", "lifecycle02_quiet",
          "lifecycle_attempt02", "python_ci")
TOOL04_ASSETS_BOUND = True  # exact final52 asset map bound; actual original outcomes remain late-bound
NATIVE_PATHS = {
    "qualification": ROOT / "qualification-terminal-status-01.json",
    "rust_ci": ROOT / "rust-ci-terminal-status-01.json",
    "observation": ROOT / "observation-native-terminal-01.json",
    "lifecycle": ROOT / "lifecycle-native-terminal-01.json",
    "lifecycle02_quiet": ROOT / "lifecycle-02-compiler-quiet-native-terminal-01.json",
    "lifecycle_attempt02": ROOT / "lifecycle-native-terminal-02.json",
}
REPORT_PATHS = {
    "qualification": ROOT / "qualification-01/report.json",
    "rust_ci": ROOT / "rust-ci-01/report.json",
    "observation": ROOT / "campaign-01/report.json",
    "lifecycle": ROOT / "lifecycle-campaign-01/report.json",
    "lifecycle02_quiet": ROOT / "lifecycle-02-compiler-quiet-01/report.json",
    "lifecycle_attempt02": ROOT / "lifecycle-campaign-02/report.json",
}
REPORT_SCHEMAS = {"qualification": "hepta-x230-composed-qualification/v1",
                  "rust_ci": "hepta-r26-external-rust-ci/v1",
                  "observation": "hepta-r25-observation-campaign-control/v1",
                  "lifecycle": "hepta-r25-lifecycle-campaign-control/v1",
                  "lifecycle02_quiet": "hepta-r26-lifecycle-natural-compiler-quiet/v1",
                  "lifecycle_attempt02": "hepta-r25-lifecycle-campaign-control/v1"}
EFFECT_PATHS = {
    "qualification": (ROOT / "qualification-01",),
    "rust_ci": (ROOT / "rust-ci-01",),
    "observation": (ROOT / "campaign-01", RECOVERY),
    "lifecycle": tuple(ROOT / name for name in (
        "lifecycle-campaign-01", "lifecycle-abba-01", "cancel-saturation-01", "lifecycle-tool-tests-01")),
    "lifecycle02_quiet": (ROOT / "lifecycle-02-compiler-quiet-01",),
    "lifecycle_attempt02": tuple(ROOT / name for name in (
        "lifecycle-campaign-02", "lifecycle-abba-02", "cancel-saturation-02", "lifecycle-tool-tests-02")),
    "python_ci": (ROOT / "python-ci-01",),
}
NATIVE_TERMINAL_STATES = {"succeeded", "failed", "cancelled", "timed_out", "effect_unknown"}
PRIVATE_NAMES = {"ssh_config", "known_hosts", "profile.json", "runtime.json"}
ORIGINAL_QUALIFICATION_JOB = "1a1ab4cb0fc-fc05-4c3c"
ORIGINAL_LIFECYCLE01_JOB = "1a1ababc175-fc05-4f94"
ORIGINAL_QUIET_JOB = "1a1abb2b75b-fc05-4fde"
FROZEN_ASSETS = {'/home/qian/hepta-runtime-optimization-20261105-r24/final-publication-readback.json': {'group': 'qualification',
                                                                                        'identity': {'bytes': 1022,
                                                                                                     'sha256': '38866c01fac54133c8a88e25bee90ea4a551e7273614f493bf44522a8273d3ca'},
                                                                                        'member': 'qualified-parent-inputs/00-final-publication-readback.json'},
 '/home/qian/hepta-runtime-optimization-20261105-r25/campaign-02/report.json': {'group': 'qualification',
                                                                                'identity': {'bytes': 100309,
                                                                                             'sha256': '1e06d6bbf06e391505ef8937e304190a4a333f03903c12a9a833ea5133610603'},
                                                                                'member': 'qualified-parent-inputs/01-report.json'},
 '/home/qian/hepta-runtime-optimization-20261105-r25/campaign-02/summary.json': {'group': 'qualification',
                                                                                 'identity': {'bytes': 14430,
                                                                                              'sha256': '68fd9d1cc05d2c0eab670ccd6d3d99ec4922a3eb369b02cb3b3d16e70bc9737c'},
                                                                                 'member': 'qualified-parent-inputs/02-summary.json'},
 '/home/qian/hepta-runtime-optimization-20261105-r25/qualification-02/hepta-runtime': {'group': 'qualification',
                                                                                       'identity': {'bytes': 14378216,
                                                                                                    'sha256': 'c8c1fc3a38923e240bcc18bd8c79bb1f3e9831beb8e59067c6ea41f86878b811'},
                                                                                       'member': 'qualified-parent-inputs/03-hepta-runtime'},
 '/home/qian/hepta-runtime-optimization-20261105-r25/qualification-02/hepta-runtime-jobctl': {'group': 'qualification',
                                                                                              'identity': {'bytes': 739016,
                                                                                                           'sha256': '61c90260057a405626a24a36ad43303c632f72d2d97929296acdffd748b79d62'},
                                                                                              'member': 'qualified-parent-inputs/04-hepta-runtime-jobctl'},
 '/home/qian/hepta-runtime-optimization-20261105-r25/qualification-02/native_process_driver': {'group': 'qualification',
                                                                                               'identity': {'bytes': 2902448,
                                                                                                            'sha256': '34a57c811ea661ad926e97ef7e4b2992068c47c21c25c3e7839d81fd02be35f8'},
                                                                                               'member': 'qualified-parent-inputs/05-native_process_driver'},
 '/home/qian/hepta-runtime-optimization-20261105-r25/qualification-02/report.json': {'group': 'qualification',
                                                                                     'identity': {'bytes': 83748,
                                                                                                  'sha256': '72a4001ed303d565f5c3300ea8786acf1c4e9d7991e0a1f0486fabc140900e3c'},
                                                                                     'member': 'qualified-parent-inputs/06-report.json'},
 '/home/qian/hepta-runtime-optimization-20261105-r25/qualification-02/source-map.json': {'group': 'qualification',
                                                                                         'identity': {'bytes': 24278,
                                                                                                      'sha256': '3933df57e42f8341ef7c7dd3faba6776ce2b34245e3d765ce8da0814207e3ee0'},
                                                                                         'member': 'qualified-parent-inputs/07-source-map.json'},
 '/home/qian/hepta-runtime-optimization-20261105-r25/qualification-terminal-status-02.json': {'group': 'qualification',
                                                                                              'identity': {'bytes': 731,
                                                                                                           'sha256': '87db6a4da3004f8fe62c94825136a253c6a63b461f0c22cb493462c1f0c48e85'},
                                                                                              'member': 'qualified-parent-inputs/08-qualification-terminal-status-02.json'},
 '/home/qian/hepta-runtime-optimization-20261105-r25/staged-r26-lifecycle-attempt02-tools-04.tar.gz': {'group': 'lifecycle',
                                                                                                       'identity': {'bytes': 118902,
                                                                                                                    'sha256': 'a3c40c20120cdaed2a9150fb3b8c01da938adf0efe5921721d775d0f0c793819'},
                                                                                                       'member': 'attempt02-revision04/staged/staged-r26-lifecycle-attempt02-tools-04.tar.gz'},
 '/home/qian/hepta-runtime-optimization-20261105-r25/staged-r26-lifecycle-launcher-bundle-01.tar.gz': {'group': 'lifecycle',
                                                                                                       'identity': {'bytes': 28060,
                                                                                                                    'sha256': '8c181b9055fbda562528730d532abbede2f45301f3034ab17bbf822abf2e24da'},
                                                                                                       'member': 'staged-revision01/staged-r26-lifecycle-launcher-bundle-01.tar.gz'},
 '/home/qian/hepta-runtime-optimization-20261105-r25/staged-r26-lifecycle-launcher-bundle-02.tar.gz': {'group': 'lifecycle',
                                                                                                       'identity': {'bytes': 38694,
                                                                                                                    'sha256': '146fbfa2923d8b40e8960e86794778c3dbae5b79a31e6db1cbdd4b8f43a98de9'},
                                                                                                       'member': 'staged-revision02/staged-r26-lifecycle-launcher-bundle-02.tar.gz'},
 '/home/qian/hepta-runtime-optimization-20261105-r25/staged-r26-lifecycle-launcher-bundle-03.tar.gz': {'group': 'lifecycle',
                                                                                                       'identity': {'bytes': 32507,
                                                                                                                    'sha256': '0130cfd36ff92632e84086d284276b8a766e9d485d94bff861de256b1ab7cc80'},
                                                                                                       'member': 'staged-revision03/staged-r26-lifecycle-launcher-bundle-03.tar.gz'},
 '/home/qian/hepta-runtime-optimization-20261105-r25/staged-r26-lifecycle-tools-01.tar.gz': {'group': 'lifecycle',
                                                                                             'identity': {'bytes': 83481,
                                                                                                          'sha256': '77e808515f424ec204ec7f3df69a94b0f370e674a5d37a6a43c272cde743f21b'},
                                                                                             'member': 'staged-revision01/staged-r26-lifecycle-tools-01.tar.gz'},
 '/home/qian/hepta-runtime-optimization-20261105-r25/staged-r26-lifecycle-tools-02.tar.gz': {'group': 'lifecycle',
                                                                                             'identity': {'bytes': 83481,
                                                                                                          'sha256': '77e808515f424ec204ec7f3df69a94b0f370e674a5d37a6a43c272cde743f21b'},
                                                                                             'member': 'staged-revision02/staged-r26-lifecycle-tools-02.tar.gz'},
 '/home/qian/hepta-runtime-optimization-20261105-r25/staged-r26-lifecycle-tools-03.tar.gz': {'group': 'lifecycle',
                                                                                             'identity': {'bytes': 83481,
                                                                                                          'sha256': '77e808515f424ec204ec7f3df69a94b0f370e674a5d37a6a43c272cde743f21b'},
                                                                                             'member': 'staged-revision03/staged-r26-lifecycle-tools-03.tar.gz'},
 '/home/qian/hepta-runtime-optimization-20261105-r25/staged-r26-observation-tools-01.tar.gz': {'group': 'observation',
                                                                                               'identity': {'bytes': 21940,
                                                                                                            'sha256': 'e489b2c5f163ffb0aa8b0737ffcb6a94665af5cb87b100665df98c544233679b'},
                                                                                               'member': 'staged-revision01/staged-r26-observation-tools-01.tar.gz'},
 '/home/qian/hepta-runtime-optimization-20261105-r25/staged-r26-observation-tools-02.tar.gz': {'group': 'observation',
                                                                                               'identity': {'bytes': 32759,
                                                                                                            'sha256': 'c7d0da048c21b52d3c27159b2a8ded89fe634bff2a0dd7d4f58141850445f98c'},
                                                                                               'member': 'staged-revision02/staged-r26-observation-tools-02.tar.gz'},
 '/home/qian/hepta-runtime-optimization-20261105-r25/staged-r26-observation-tools-03.tar.gz': {'group': 'observation',
                                                                                               'identity': {'bytes': 33764,
                                                                                                            'sha256': 'a64271f70afd0ea559ad832b6b084becda8d3245a9b00db95b724d0a1b6fd912'},
                                                                                               'member': 'staged-revision03/staged-r26-observation-tools-03.tar.gz'},
 '/home/qian/hepta-runtime-optimization-20261105-r25/tools/install_r26_lifecycle_attempt02_tools_04.py': {'group': 'lifecycle',
                                                                                                          'identity': {'bytes': 38365,
                                                                                                                       'sha256': '9c92b48a37547eb1f991f11ab4c5d9a0c041aff1863207ee536a15eb4d05c54f'},
                                                                                                          'member': 'attempt02-revision04/staged/tools/install_r26_lifecycle_attempt02_tools_04.py'},
 '/home/qian/hepta-runtime-optimization-20261105-r25/tools/install_r26_reviewed_tools_01.py': {'group': 'observation',
                                                                                               'identity': {'bytes': 32736,
                                                                                                            'sha256': '41a0018dfa35cdb37a4132dd3102db934c0fee60a9f41191df83a24f69744e2c'},
                                                                                               'member': 'install-tools/install_r26_reviewed_tools_01.py'},
 '/home/qian/hepta-runtime-optimization-20261105-r25/tools/install_r26_reviewed_tools_02.py': {'group': 'observation',
                                                                                               'identity': {'bytes': 39851,
                                                                                                            'sha256': '87397f1d33b6b6483aa29cdeb5d06a4ed485015bbdc84543ecf00a5645ee8444'},
                                                                                               'member': 'install-tools/install_r26_reviewed_tools_02.py'},
 '/home/qian/hepta-runtime-optimization-20261105-r25/tools/install_r26_reviewed_tools_03.py': {'group': 'observation',
                                                                                               'identity': {'bytes': 39853,
                                                                                                            'sha256': 'd5a16a669a83888e72f194c079a366c27d11e7004ba14dc76c37ea250a693702'},
                                                                                               'member': 'install-tools/install_r26_reviewed_tools_03.py'},
 '/home/qian/hepta-runtime-optimization-20261105-r25/tools/prepare_and_qualify_r26_01.py': {'group': 'qualification',
                                                                                            'identity': {'bytes': 14305,
                                                                                                         'sha256': '5306935cc2771a1138dc0a641ee4b9d359e00fd152d4be746a630db0b9bb72f7'},
                                                                                            'member': 'bootstrap/prepare_and_qualify_r26_01.py'},
 '/home/qian/hepta-runtime-optimization-20261105-r25/tools/r26-installation-qualification-02.json': {'group': 'observation',
                                                                                                     'identity': {'bytes': 1512,
                                                                                                                  'sha256': 'a7fff2eebd922c170d68304dc56f3b5213efdcaa50e8a7459b7eb8551d73528d'},
                                                                                                     'member': 'install-tools/r26-installation-qualification-02.json'},
 '/home/qian/hepta-runtime-optimization-20261105-r25/tools/r26-installation-qualification-03.json': {'group': 'observation',
                                                                                                     'identity': {'bytes': 1512,
                                                                                                                  'sha256': 'a7fff2eebd922c170d68304dc56f3b5213efdcaa50e8a7459b7eb8551d73528d'},
                                                                                                     'member': 'install-tools/r26-installation-qualification-03.json'},
 '/home/qian/hepta-runtime-optimization-20261105-r25/tools/r26-qualification-01-input.json': {'group': 'qualification',
                                                                                              'identity': {'bytes': 27079,
                                                                                                           'sha256': '3b6e6a119f09c649c11d4170e59c6d63831d824a2280b435a2ea57defd949111'},
                                                                                              'member': 'bootstrap/r26-qualification-01-input.json'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-attempt02-protocol-04/README.md': {'group': 'lifecycle',
                                                                                                  'identity': {'bytes': 2269,
                                                                                                               'sha256': '4f8fe1ca57de54f7907911e68f05a0fac30cb89b93d43634881360abba2f6065'},
                                                                                                  'member': 'attempt02-revision04/lifecycle-attempt02-protocol-04/README.md'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-attempt02-protocol-04/admission-checks-01.stderr': {'group': 'lifecycle',
                                                                                                                   'identity': {'bytes': 1022,
                                                                                                                                'sha256': '54024f19f4a555eb752f69dd9b77ea6fbff484d41f2686fbbd5347c47ead51c2'},
                                                                                                                   'member': 'attempt02-revision04/lifecycle-attempt02-protocol-04/admission-checks-01.stderr'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-attempt02-protocol-04/admission-checks-01.stdout': {'group': 'lifecycle',
                                                                                                                   'identity': {'bytes': 0,
                                                                                                                                'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'},
                                                                                                                   'member': 'attempt02-revision04/lifecycle-attempt02-protocol-04/admission-checks-01.stdout'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-attempt02-protocol-04/derivation-proof-04.json': {'group': 'lifecycle',
                                                                                                                 'identity': {'bytes': 5718,
                                                                                                                              'sha256': '83ca66c49e6704c117fab0ba2cf9c65862255f039fda42bc58cf0ab497ba4098'},
                                                                                                                 'member': 'attempt02-revision04/lifecycle-attempt02-protocol-04/derivation-proof-04.json'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-attempt02-protocol-04/package-manifest-04.json': {'group': 'lifecycle',
                                                                                                                 'identity': {'bytes': 9687,
                                                                                                                              'sha256': '72ac824593af5d530935d1f005dbab0f382ab2a1cc794257b19e75b95f797811'},
                                                                                                                 'member': 'attempt02-revision04/lifecycle-attempt02-protocol-04/package-manifest-04.json'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-attempt02-protocol-04/source-delta-04.diff': {'group': 'lifecycle',
                                                                                                             'identity': {'bytes': 18209,
                                                                                                                          'sha256': '509d1d5cba3d2e8fc45e6d970ccec717261275e57301bc003a5fe7d2f9bd6ba7'},
                                                                                                             'member': 'attempt02-revision04/lifecycle-attempt02-protocol-04/source-delta-04.diff'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-attempt02-protocol-04/test_original01_admission.py': {'group': 'lifecycle',
                                                                                                                     'identity': {'bytes': 3224,
                                                                                                                                  'sha256': '8536913788aa84a13b4c1bd32eb4af81f73cd85675e0392d83706846d96c0b96'},
                                                                                                                     'member': 'attempt02-revision04/lifecycle-attempt02-protocol-04/test_original01_admission.py'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-inputs-02.example.json': {'group': 'lifecycle',
                                                                                         'identity': {'bytes': 4406,
                                                                                                      'sha256': 'e73f1bc295d29094a6f9fa7cf6142cb6e036693ef6819c15d89aa3794a328851'},
                                                                                         'member': 'attempt02-revision04/lifecycle-inputs-02.example.json'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-original01-failure-evidence-04/compiler-monitor.audit.json': {'group': 'lifecycle',
                                                                                                                             'identity': {'bytes': 1325,
                                                                                                                                          'sha256': '52ed7b65204004a81a80603278a5264bd4d42e6e89ed0232a9e5528a1be962a2'},
                                                                                                                             'member': 'attempt02-revision04/lifecycle-original01-failure-evidence-04/compiler-monitor.audit.json'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-original01-failure-evidence-04/compiler-monitor.json': {'group': 'lifecycle',
                                                                                                                       'identity': {'bytes': 7342,
                                                                                                                                    'sha256': '279709edf6508b3573d6948fb1edbf2dbb00eb315aae010066aadf8c7b1bd674'},
                                                                                                                       'member': 'attempt02-revision04/lifecycle-original01-failure-evidence-04/compiler-monitor.json'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-original01-failure-evidence-04/mac-forwarded.stderr': {'group': 'lifecycle',
                                                                                                                      'identity': {'bytes': 0,
                                                                                                                                   'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'},
                                                                                                                      'member': 'attempt02-revision04/lifecycle-original01-failure-evidence-04/mac-forwarded.stderr'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-original01-failure-evidence-04/mac-forwarded.stdout': {'group': 'lifecycle',
                                                                                                                      'identity': {'bytes': 261,
                                                                                                                                   'sha256': '24b543d0849eb16d41fef7aa2c804faba99da8630a25f42fd566778a810ea1e2'},
                                                                                                                      'member': 'attempt02-revision04/lifecycle-original01-failure-evidence-04/mac-forwarded.stdout'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-original01-failure-evidence-04/mac-remote-script.py': {'group': 'lifecycle',
                                                                                                                      'identity': {'bytes': 26760,
                                                                                                                                   'sha256': '2970725473f7dab854a9d13326aa0ca792b9442615d325ebb0e767065bd08f37'},
                                                                                                                      'member': 'attempt02-revision04/lifecycle-original01-failure-evidence-04/mac-remote-script.py'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-original01-failure-evidence-04/mac-report.json': {'group': 'lifecycle',
                                                                                                                 'identity': {'bytes': 9213,
                                                                                                                              'sha256': 'c5569b1fbeb40acd5f8c10ff33f6bd7afc58c9862ef949309d6c88387bf1bd69'},
                                                                                                                 'member': 'attempt02-revision04/lifecycle-original01-failure-evidence-04/mac-report.json'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-original01-failure-evidence-04/native-terminal.json': {'group': 'lifecycle',
                                                                                                                      'identity': {'bytes': 726,
                                                                                                                                   'sha256': '87f52ad158e945f95976b31d85b720938374bf52ec010acee045e4a819c65aea'},
                                                                                                                      'member': 'attempt02-revision04/lifecycle-original01-failure-evidence-04/native-terminal.json'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-original01-failure-evidence-04/native.stderr': {'group': 'lifecycle',
                                                                                                               'identity': {'bytes': 0,
                                                                                                                            'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'},
                                                                                                               'member': 'attempt02-revision04/lifecycle-original01-failure-evidence-04/native.stderr'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-original01-failure-evidence-04/native.stdout': {'group': 'lifecycle',
                                                                                                               'identity': {'bytes': 298,
                                                                                                                            'sha256': 'aaa28ad2cd7a3de525f3427d150b65f59f20b76ef45bfdace7de266c5cc02ff7'},
                                                                                                               'member': 'attempt02-revision04/lifecycle-original01-failure-evidence-04/native.stdout'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-original01-failure-evidence-04/report.json': {'group': 'lifecycle',
                                                                                                             'identity': {'bytes': 7004,
                                                                                                                          'sha256': '95fe29cf6c69fc98f65d3c12e7c819d9c5a6817c587aad7b7dea7a34093d6270'},
                                                                                                             'member': 'attempt02-revision04/lifecycle-original01-failure-evidence-04/report.json'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-original01-failure-evidence-04/root-failure-receipt-01.json': {'group': 'lifecycle',
                                                                                                                              'identity': {'bytes': 2324,
                                                                                                                                           'sha256': 'd137a981f1463ee6dc6f9135f89d488db8fc3b68a8f2990ab5f5320dccceeec2'},
                                                                                                                              'member': 'attempt02-revision04/lifecycle-original01-failure-evidence-04/root-failure-receipt-01.json'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-tools-04/README.md': {'group': 'lifecycle',
                                                                                     'identity': {'bytes': 9053,
                                                                                                  'sha256': '02d016a50e76d58031b07b881bc82440ea49e667e79e21164ca11919a9583eec'},
                                                                                     'member': 'attempt02-revision04/lifecycle-tools-04/README.md'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-tools-04/allocator_environment.py': {'group': 'lifecycle',
                                                                                                    'identity': {'bytes': 5879,
                                                                                                                 'sha256': 'f5c8e879c540b3f7cb1b7d3a7a0f5002c2f40c1a87963174b0b00470fa3a4525'},
                                                                                                    'member': 'attempt02-revision04/lifecycle-tools-04/allocator_environment.py'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-tools-04/allocator_environment_audit.py': {'group': 'lifecycle',
                                                                                                          'identity': {'bytes': 6709,
                                                                                                                       'sha256': '4b082ce343ae3943e3098baa58af2f5def7198881b9c087d63d88360e9763727'},
                                                                                                          'member': 'attempt02-revision04/lifecycle-tools-04/allocator_environment_audit.py'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-tools-04/analyze_lifecycle_gates.py': {'group': 'lifecycle',
                                                                                                      'identity': {'bytes': 7581,
                                                                                                                   'sha256': 'c7a861a94a89dd81debb5c055773918d89a1c9c29b699e2e5a0341e51be69553'},
                                                                                                      'member': 'attempt02-revision04/lifecycle-tools-04/analyze_lifecycle_gates.py'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-tools-04/analyze_native_observation.py': {'group': 'lifecycle',
                                                                                                         'identity': {'bytes': 8708,
                                                                                                                      'sha256': 'cc7f6884d581cd1ced430437350e808de51931c50d12441797205501b20cae66'},
                                                                                                         'member': 'attempt02-revision04/lifecycle-tools-04/analyze_native_observation.py'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-tools-04/audit_native_evidence.py': {'group': 'lifecycle',
                                                                                                    'identity': {'bytes': 17065,
                                                                                                                 'sha256': 'b69f6902d2de81eab41b21506f024c002d2f8264d60e86df6b1086623a77fd28'},
                                                                                                    'member': 'attempt02-revision04/lifecycle-tools-04/audit_native_evidence.py'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-tools-04/cancel_saturation_gate.py': {'group': 'lifecycle',
                                                                                                     'identity': {'bytes': 15789,
                                                                                                                  'sha256': '536ebdc5f2b090a8c007f189a895ed2e19d7b8b7e41530ccba94dd826742ef7f'},
                                                                                                     'member': 'attempt02-revision04/lifecycle-tools-04/cancel_saturation_gate.py'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-tools-04/lifecycle-gate-policy.json': {'group': 'lifecycle',
                                                                                                      'identity': {'bytes': 1575,
                                                                                                                   'sha256': '36658346c4e265bf551a1ae1a4c6210bec8e4729f7961302a203008741cd381e'},
                                                                                                      'member': 'attempt02-revision04/lifecycle-tools-04/lifecycle-gate-policy.json'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-tools-04/lifecycle-tools-manifest-01.json': {'group': 'lifecycle',
                                                                                                            'identity': {'bytes': 4066,
                                                                                                                         'sha256': '4b87b1b7e0430f7419051c0a2716904dbea2baaecf49efc9077eccb1e64d272b'},
                                                                                                            'member': 'attempt02-revision04/lifecycle-tools-04/lifecycle-tools-manifest-01.json'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-tools-04/observation_resources.py': {'group': 'lifecycle',
                                                                                                    'identity': {'bytes': 12382,
                                                                                                                 'sha256': 'f3402d51cb37b2fe20f4351b3a81ec5990a9fdaff93a846d21c07ccd557cb894'},
                                                                                                    'member': 'attempt02-revision04/lifecycle-tools-04/observation_resources.py'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-tools-04/owned_ssh_interruption.py': {'group': 'lifecycle',
                                                                                                     'identity': {'bytes': 7892,
                                                                                                                  'sha256': '1989c57f0b944afae1ed759d6529b8f1cc26197e269e2c34c4fd49e43a32aa7b'},
                                                                                                     'member': 'attempt02-revision04/lifecycle-tools-04/owned_ssh_interruption.py'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-tools-04/run_lifecycle_abba_01.py': {'group': 'lifecycle',
                                                                                                    'identity': {'bytes': 14787,
                                                                                                                 'sha256': 'f24c358effd4de71e6a68b971fcab3b9fda6db000b79888c48ad364147c1768d'},
                                                                                                    'member': 'attempt02-revision04/lifecycle-tools-04/run_lifecycle_abba_01.py'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-tools-04/run_lifecycle_tool_tests.py': {'group': 'lifecycle',
                                                                                                       'identity': {'bytes': 2224,
                                                                                                                    'sha256': 'e3c1e8163249dba14672a3a82b43a2d7b8b4c0802b94b8511bf3db668f865a2d'},
                                                                                                       'member': 'attempt02-revision04/lifecycle-tools-04/run_lifecycle_tool_tests.py'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-tools-04/run_native_observation.py': {'group': 'lifecycle',
                                                                                                     'identity': {'bytes': 3279,
                                                                                                                  'sha256': '7606648c99b2ff2bbf0bba58384e8cab609ac3899f838c0b80ba54d6288d20bb'},
                                                                                                     'member': 'attempt02-revision04/lifecycle-tools-04/run_native_observation.py'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-tools-04/run_six_host_cancel_recovery.py': {'group': 'lifecycle',
                                                                                                           'identity': {'bytes': 27847,
                                                                                                                        'sha256': '698eb7801cde3f2bd5ff202412c0833fc218fd7e912c3c949d2b37fde7a56a12'},
                                                                                                           'member': 'attempt02-revision04/lifecycle-tools-04/run_six_host_cancel_recovery.py'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-tools-04/run_six_host_cancel_recovery_timed.py': {'group': 'lifecycle',
                                                                                                                 'identity': {'bytes': 30163,
                                                                                                                              'sha256': '898bbbc5a30f5dba0f67992e299a5d904b71a1f4a97129c646ef6076a7fc2372'},
                                                                                                                 'member': 'attempt02-revision04/lifecycle-tools-04/run_six_host_cancel_recovery_timed.py'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-tools-04/run_six_host_cancel_saturation.py': {'group': 'lifecycle',
                                                                                                             'identity': {'bytes': 31325,
                                                                                                                          'sha256': 'ec0c84295477619568fb38867d1c3e3101e42746950f4d0cd104b4c0daf006ff'},
                                                                                                             'member': 'attempt02-revision04/lifecycle-tools-04/run_six_host_cancel_saturation.py'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-tools-04/source-provenance.json': {'group': 'lifecycle',
                                                                                                  'identity': {'bytes': 2510,
                                                                                                               'sha256': '58d276c8df05dcd95a0a25e6264c3de1b248e8bb821651fb1b52859dd707dbbe'},
                                                                                                  'member': 'attempt02-revision04/lifecycle-tools-04/source-provenance.json'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-tools-04/status-predicate.json': {'group': 'lifecycle',
                                                                                                 'identity': {'bytes': 875,
                                                                                                              'sha256': '5828c7ba2990f38531cce7e1a42b44315ee42278ccaee361ace8d9472a96da34'},
                                                                                                 'member': 'attempt02-revision04/lifecycle-tools-04/status-predicate.json'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-tools-04/summarize_lifecycle_abba_01.py': {'group': 'lifecycle',
                                                                                                          'identity': {'bytes': 16065,
                                                                                                                       'sha256': '9e050343bb32e7f57148f633ff94bbcfb3a7452b2872ae68404ca642e937af89'},
                                                                                                          'member': 'attempt02-revision04/lifecycle-tools-04/summarize_lifecycle_abba_01.py'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-tools-04/test_native_harness.py': {'group': 'lifecycle',
                                                                                                  'identity': {'bytes': 13286,
                                                                                                               'sha256': '2b450175b9e6122248ac1bcb51860aa8a6d3eff55f6ac8c877c0a905e3dd7d00'},
                                                                                                  'member': 'attempt02-revision04/lifecycle-tools-04/test_native_harness.py'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-tools-04/test_r25_lifecycle_tools.py': {'group': 'lifecycle',
                                                                                                       'identity': {'bytes': 10026,
                                                                                                                    'sha256': '1845cdb48440a03146e337af7baf916bb9cdb76fb46ea0699f79144cf7197566'},
                                                                                                       'member': 'attempt02-revision04/lifecycle-tools-04/test_r25_lifecycle_tools.py'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-tools-04/test_verify_saturation_extension.py': {'group': 'lifecycle',
                                                                                                               'identity': {'bytes': 8187,
                                                                                                                            'sha256': '10f2dcbfa9e2b5c625f22c3edc32c9f8a969509345b20d9b135cebc2235c16fb'},
                                                                                                               'member': 'attempt02-revision04/lifecycle-tools-04/test_verify_saturation_extension.py'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-tools-04/verify_cancel_recovery.py': {'group': 'lifecycle',
                                                                                                     'identity': {'bytes': 16634,
                                                                                                                  'sha256': '0116652a0b489dc462f005e01d7c943feda9ba784563d7317c92bb5beb9a701c'},
                                                                                                     'member': 'attempt02-revision04/lifecycle-tools-04/verify_cancel_recovery.py'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-tools-04/verify_cancel_saturation.py': {'group': 'lifecycle',
                                                                                                       'identity': {'bytes': 17123,
                                                                                                                    'sha256': 'd3b6772ddffc711a23aa4aa9566f903c149535a3d3c4cc3466ee73690cbc1e75'},
                                                                                                       'member': 'attempt02-revision04/lifecycle-tools-04/verify_cancel_saturation.py'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-tools-04/verify_saturation_extension.py': {'group': 'lifecycle',
                                                                                                          'identity': {'bytes': 9418,
                                                                                                                       'sha256': '23dfd25517b517067a4fbb3f4a3227f12bafff46b828eb05f7bf322596124e6a'},
                                                                                                          'member': 'attempt02-revision04/lifecycle-tools-04/verify_saturation_extension.py'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-tools-04/x230_observation_benchmark.py': {'group': 'lifecycle',
                                                                                                         'identity': {'bytes': 37006,
                                                                                                                      'sha256': '4d96f0bf2da2562e788f48be7c37589ab3a513be5f9d8b2d741afe5c08ea9eed'},
                                                                                                         'member': 'attempt02-revision04/lifecycle-tools-04/x230_observation_benchmark.py'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/lifecycle-tools-04/x230_six_running_recovery_canary.py': {'group': 'lifecycle',
                                                                                                               'identity': {'bytes': 47298,
                                                                                                                            'sha256': '6219bc556b0ac6d142bd4c731466b959e8a410f0b4b55f3d8b303f8fdbfbaaf4'},
                                                                                                               'member': 'attempt02-revision04/lifecycle-tools-04/x230_six_running_recovery_canary.py'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/tools-03/compiler-monitor-policy-01.json': {'group': 'observation',
                                                                                                 'identity': {'bytes': 1001,
                                                                                                              'sha256': 'ddb2e03d4a1a1610466a5dc2d1a544f554ad12fc31412483101b48a235402368'},
                                                                                                 'member': 'installed-tools/compiler-monitor-policy-01.json'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/tools-03/compiler_monitor.py': {'group': 'observation',
                                                                                     'identity': {'bytes': 12510,
                                                                                                  'sha256': 'afb514362a9d8dd573b806f0dc87df16bd3a906e4574d10d91bf483b2e76cdcf'},
                                                                                     'member': 'installed-tools/compiler_monitor.py'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/tools-03/compiler_state.py': {'group': 'observation',
                                                                                   'identity': {'bytes': 6243,
                                                                                                'sha256': '9da718654db04a646e081d2d719a2d6d4655ffe337bc0e3f906e736e4d77a251'},
                                                                                   'member': 'installed-tools/compiler_state.py'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/tools-03/prepare_campaign_inputs.py': {'group': 'observation',
                                                                                            'identity': {'bytes': 9964,
                                                                                                         'sha256': '096f5968d145a4f2ba4b677582f167bd2f68f39694af4d036eccf4b217534914'},
                                                                                            'member': 'installed-tools/prepare_campaign_inputs.py'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/tools-03/prepare_lifecycle_inputs.py': {'group': 'observation',
                                                                                             'identity': {'bytes': 12066,
                                                                                                          'sha256': 'b1f2d581b9db84ef9633680116a1ab67b0c41e02f7f5977d128e14515a4f2619'},
                                                                                             'member': 'installed-tools/prepare_lifecycle_inputs.py'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/tools-03/r26_campaign.py': {'group': 'observation',
                                                                                 'identity': {'bytes': 55076,
                                                                                              'sha256': '34883c3b7bcae75e81604e7a3fb2845540eef979328010f4f597fdd218f79add'},
                                                                                 'member': 'installed-tools/r26_campaign.py'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/tools-03/r26_lifecycle_campaign.py': {'group': 'observation',
                                                                                           'identity': {'bytes': 26760,
                                                                                                        'sha256': '2970725473f7dab854a9d13326aa0ca792b9442615d325ebb0e767065bd08f37'},
                                                                                           'member': 'installed-tools/r26_lifecycle_campaign.py'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/tools-03/summarize_r25_campaign.py': {'group': 'observation',
                                                                                           'identity': {'bytes': 14456,
                                                                                                        'sha256': '2418bad36fe4aef75d52c5a00c898ff93fef9bb4b6efb10028105143106a1864'},
                                                                                           'member': 'installed-tools/summarize_r25_campaign.py'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/tools-03/validate_compiler_monitor.py': {'group': 'observation',
                                                                                              'identity': {'bytes': 7055,
                                                                                                           'sha256': 'd2cd009adf1f35a394ffddcc8f8646cc0c1b856b78181ca321ea68f6468218b2'},
                                                                                              'member': 'installed-tools/validate_compiler_monitor.py'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/tools-04/prepare_lifecycle_inputs.py': {'group': 'lifecycle',
                                                                                             'identity': {'bytes': 12238,
                                                                                                          'sha256': '379ae03a13aedeb16b99bc74234ec42fd72f41c262f6d9a0170ecdefaaddf4b4'},
                                                                                             'member': 'attempt02-revision04/tools-04/prepare_lifecycle_inputs.py'},
 '/home/qian/hepta-runtime-optimization-20261105-r26/tools-04/r26_lifecycle_campaign.py': {'group': 'lifecycle',
                                                                                           'identity': {'bytes': 37172,
                                                                                                        'sha256': '73435f80156d6b20b0ca8ffadbc7ae583182f3ae78b00949f77a16101522a182'},
                                                                                           'member': 'attempt02-revision04/tools-04/r26_lifecycle_campaign.py'}}
TREE_SCOPE = {
    "qualification": (("qualification", ROOT / "qualification-01"), ("source", ROOT / "source"),
                      ("early-receipt-export", ROOT / "evidence-receipts-01"),
                      ("early-receipt-export-tools", ROOT / "evidence-receipts-tools-01")),
    "ci": (("rust", ROOT / "rust-ci-01"), ("rust-tools", ROOT / "rust-ci-tools-01")),
    "observation": (("observation", ROOT / "campaign-01"), ("recovery", RECOVERY),
                    ("campaign-tools", ROOT / "tools-03"), ("boundary-tools", ROOT / "boundary-tools-01")),
    "lifecycle": (("control", ROOT / "lifecycle-campaign-01"), ("abba", ROOT / "lifecycle-abba-01"),
                  ("saturation", ROOT / "cancel-saturation-01"), ("tool-tests", ROOT / "lifecycle-tool-tests-01"),
                  ("input-receipts", ROOT / "lifecycle-inputs-01"),
                  ("native-tools", ROOT / "lifecycle-tools-03"),
                  ("launcher-bundle", ROOT / "lifecycle-launcher-bundle-03"),
                  ("attempt02/control", ROOT / "lifecycle-campaign-02"),
                  ("attempt02/abba", ROOT / "lifecycle-abba-02"),
                  ("attempt02/saturation", ROOT / "cancel-saturation-02"),
                  ("attempt02/tool-tests", ROOT / "lifecycle-tool-tests-02"),
                  ("attempt02/input-receipts", ROOT / "lifecycle-inputs-02"),
                  ("attempt02/native-tools", ROOT / "lifecycle-tools-04"),
                  ("attempt02/parent-tools", ROOT / "tools-04"),
                  ("attempt02/protocol", ROOT / "lifecycle-attempt02-protocol-04"),
                  ("attempt01-failure-copy", ROOT / "lifecycle-original01-failure-evidence-04"),
                  ("attempt02/natural-quiet", ROOT / "lifecycle-02-compiler-quiet-01")),
}
ROOT_RECEIPTS = {
    "qualification": ("preparation-01.json", "qualification-input-01.json", "qualification-terminal-status-01.json"),
    "ci": ("rust-ci-plan-01.json", "rust-ci-tools-install-01.json", "rust-ci-terminal-status-01.json"),
    "observation": ("campaign-inputs-01.json", "qualification-compact-01.json", "observation-plan-01.json",
                    "campaign-inputs-01.example.json", "observation-tools-manifest-02.json",
                    "tools-install-02-receipt.json", "observation-tools-manifest-03.json",
                    "tools-install-03-receipt.json", "observation-native-terminal-01.json"),
    "lifecycle": ("lifecycle-inputs-01.json", "lifecycle-inputs-01.example.json", "lifecycle-native-terminal-01.json",
                  "lifecycle-inputs-02.json", "lifecycle-inputs-02.example.json", "lifecycle-native-terminal-02.json",
                  "lifecycle-02-compiler-quiet-native-terminal-01.json", "lifecycle-tools-install-04-receipt.json"),
}
BOUND_INPUT_ROOTS = (
    ROOT / "source", ROOT / "qualification-01", ROOT / "tools-03", ROOT / "rust-ci-tools-01",
    ROOT / "lifecycle-tools-03", ROOT / "campaign-01", ROOT / "lifecycle-campaign-01",
    ROOT / "tools-04", ROOT / "lifecycle-tools-04", ROOT / "lifecycle-campaign-02",
    ROOT / "lifecycle-02-compiler-quiet-01", ROOT / "lifecycle-original01-failure-evidence-04",
    BASELINE, R16 / "measurement-tools", R16 / "boundary-tools",
    STAGE_ROOT / "ci-gates", STAGE_ROOT / "ci-toolchain/nextest-0.9.137",
    Path("/home/qian/hepta-runtime-optimization-20261023/a31-frozen-originals-r01"),
)
OMITTED_CACHE_ROOTS = (ROOT / "target-build",)
OUTPUT_PREFIXES = ("qualification/", "rust/", "observation/", "recovery/", "control/", "abba/", "saturation/", "tool-tests/",
                   "attempt02/control/", "attempt02/abba/", "attempt02/saturation/", "attempt02/tool-tests/",
                   "attempt02/natural-quiet/")


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


def validate_stage_contract(value):
    need(value.get("schema") == "hepta-r26-outcome-preserving-export-input/v1"
         and value.get("root") == str(ROOT) and value.get("release") == "R26"
         and value.get("actual_outcomes_supplied") is True
         and set(value.get("stages", {})) == set(STAGES), "actual R26 outcomes required")
    rows = value["stages"]
    for name in STAGES:
        row = rows[name]
        need(isinstance(row, dict) and set(row) == {
            "executed", "job_id", "native_terminal", "report", "reason"}, "stage fields differ: " + name)
        need(type(row["executed"]) is bool, "future execution state is unresolved: " + name)
        if row["executed"]:
            need(name != "python_ci" and isinstance(row["job_id"], str)
                 and JOB.fullmatch(row["job_id"]), "actual original native job required: " + name)
            descriptor(row["native_terminal"], NATIVE_PATHS[name])
            if row["report"] is None:
                need(isinstance(row["reason"], str) and row["reason"].strip(),
                     "missing report requires explicit original failure reason")
            else:
                descriptor(row["report"], REPORT_PATHS[name])
                need(row["reason"] is None, "present report must retain its own outcome")
        else:
            need(row["job_id"] is None and row["native_terminal"] is None and row["report"] is None
                 and isinstance(row["reason"], str) and row["reason"].strip(),
                 "unexecuted stage must not invent an original operation")
    need(rows["qualification"]["executed"] is True,
         "X230 export requires the original R26 qualifier to have created ROOT26")
    need(rows["qualification"]["job_id"] == ORIGINAL_QUALIFICATION_JOB,
         "only the observed original R26 qualification may be exported")
    need(rows["lifecycle"]["executed"] is True and rows["lifecycle"]["job_id"] == ORIGINAL_LIFECYCLE01_JOB,
         "the original failed lifecycle01 must not be replaced or declared unexecuted")
    need(rows["lifecycle02_quiet"]["executed"] is True
         and rows["lifecycle02_quiet"]["job_id"] == ORIGINAL_QUIET_JOB,
         "the original natural quiet wait must remain separately bound")
    need(rows["python_ci"]["executed"] is False, "R26 Python CI is explicitly unplanned")
    descriptor(value.get("preparation"), ROOT / "preparation-01.json")
    need(value.get("adoption_decision_made_here") is False
         and value.get("native_raw_companion_required") is True
         and value.get("mac_holder_packages_required_if_executed") is True,
         "export must not replace native raw streams or Mac holder evidence")
    return rows


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


def original_report_projection(value):
    """Project actual flags without converting incomplete or false results to true."""
    if not isinstance(value, dict):
        return {"structured_object": False}
    keys = ("qualified", "passed", "finished_utc", "observation_gate_passed", "adoption_passed",
            "measurement_attribution_valid", "result_before_compiler_monitor", "rejection_reasons", "error",
            "automatic_retries", "automatic_test_retries", "hosted_actions_passed", "inputs_unchanged",
            "source_inputs_unchanged", "owned_children_closed", "compiler_monitor_finalization_error",
            "stages", "candidate_binary_sha256")
    return {"structured_object": True, **{key: value[key] for key in keys if key in value}}


def disposition(stages, monitor_evidence):
    """Describe recorded outcomes; do not make or imply an adoption decision."""
    def flags(name):
        return stages.get(name, {}).get("original_result", {})
    def native_succeeded(name):
        return stages.get(name, {}).get("native_outcome", {}).get("state") == "succeeded"
    def completed_report(name):
        stage = stages.get(name, {})
        return (stage.get("executed") is True and stage.get("original_report_finished") is True
                and stage.get("original_report_schema_matches") is True
                and stage.get("native_outcome", {}).get("native_logs_lossless_complete") is True)
    def monitor_validated(name):
        return monitor_evidence.get(name, {}).get("independently_validated") is True
    if not native_succeeded("qualification"):
        return "qualification_native_operation_failed_or_incomplete"
    if not completed_report("qualification") or flags("qualification").get("qualified") is not True:
        return "qualification_failed_or_incomplete"
    if not stages.get("observation", {}).get("executed"):
        return "qualified_observation_not_executed"
    if not native_succeeded("observation"):
        return "observation_native_holder_failed_or_incomplete"
    observed = flags("observation")
    if not completed_report("observation"):
        return "observation_operation_failed_or_incomplete"
    if observed.get("measurement_attribution_valid") is not True or not monitor_validated("observation"):
        return "observation_measurement_invalid_or_incomplete"
    if observed.get("passed") is not True:
        return "observation_operation_failed_or_incomplete"
    if observed.get("observation_gate_passed") is not True:
        return "observation_performance_rejected_or_incomplete"
    lifecycle_name = "lifecycle_attempt02" if stages.get("lifecycle_attempt02", {}).get("executed") else "lifecycle"
    if not stages.get(lifecycle_name, {}).get("executed"):
        return "observation_passed_lifecycle_not_executed"
    if not native_succeeded(lifecycle_name):
        return lifecycle_name + "_native_holder_failed_or_incomplete"
    lifecycle = flags(lifecycle_name)
    if not completed_report(lifecycle_name):
        return lifecycle_name + "_failed_rejected_or_incomplete"
    if lifecycle.get("measurement_attribution_valid") is not True or not monitor_validated(lifecycle_name):
        return lifecycle_name + "_measurement_invalid_or_incomplete"
    if lifecycle.get("passed") is not True or lifecycle.get("adoption_passed") is not True:
        return lifecycle_name + "_failed_rejected_or_incomplete"
    if lifecycle_name == "lifecycle_attempt02":
        original = flags("lifecycle")
        native = stages.get("lifecycle", {}).get("native_outcome", {})
        if (not completed_report("lifecycle") or native.get("state") != "failed"
                or native.get("exit_code") != 1 or original.get("passed") is not False
                or original.get("adoption_passed") is not False
                or original.get("measurement_attribution_valid") is not False
                or original.get("stages") != [] or original.get("candidate_binary_sha256", "missing") is not None):
            return "lifecycle_attempt02_passed_original_attempt01_failure_not_proven"
    if (not native_succeeded("rust_ci") or not completed_report("rust_ci")
            or flags("rust_ci").get("passed") is not True):
        return "workload_gates_passed_rust_ci_not_proven"
    if lifecycle_name == "lifecycle_attempt02":
        return "recorded_qualification_rust_ci_and_attempt02_gates_passed_original_attempt01_failure_retained_adoption_external"
    return "recorded_qualification_rust_ci_and_workload_gates_passed_adoption_external"


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
    spec = importlib.util.spec_from_loader("r26_bound_stable_archive", loader=None)
    module = importlib.util.module_from_spec(spec)
    module.__file__ = str(HELPER)
    exec(compile(raw, str(HELPER), "exec"), module.__dict__)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exporter-sha256", required=True)
    parser.add_argument("--archive-helper-sha256", required=True)
    parser.add_argument("--input-sha256", required=True)
    args = parser.parse_args()
    need(TOOL04_ASSETS_BOUND is True, "final tools04/attempt02 asset binding is pending; prepared exporter must not execute")
    need(sys.platform == "linux" and os.geteuid() != 0
         and Path(__file__).resolve() == EXPORTER, "fixed native operator exporter path required")
    helper = load_helper(args.archive_helper_sha256)
    self_identity = helper.read(EXPORTER)[0]
    need(self_identity["sha256"] == args.exporter_sha256 and HEX.fullmatch(args.exporter_sha256),
         "actual exporter source differs")
    helper_identity = helper.read(HELPER)[0]
    need(helper_identity["sha256"] == args.archive_helper_sha256, "archive helper identity changed")
    input_identity, input_raw = helper.read(INPUT, retain=True)
    need(input_identity["sha256"] == args.input_sha256 and HEX.fullmatch(args.input_sha256),
         "actual export input differs")
    value = json.loads(input_raw)
    rows = validate_stage_contract(value)
    helper.direct(ROOT)
    need(stat.S_ISDIR(ROOT.lstat().st_mode) and ROOT.lstat().st_uid == os.geteuid(), "unsafe original R26 root")
    need(not os.path.lexists(OUT), "export output must be fresh; reconcile any prior attempt")
    OUT.mkdir(mode=0o700)
    report = {"schema": "hepta-r26-outcome-preserving-evidence-export/v1", "started_utc": utc(),
              "passed": False, "no_workload_executed": True, "automatic_retries": 0,
              "adoption_decision_made_here": False, "hosted_actions_passed_inferred": False,
              "all_optimization_blockers_closed_inferred": False,
              "input": input_identity, "exporter": self_identity, "archive_helper": helper_identity,
              "stages": {}, "archives": {}, "native_raw_companion_required": True,
              "mac_holder_packages_required_if_executed": True,
              "python_ci": {"executed": False, "reason": rows["python_ci"]["reason"],
                            "historical_r25_report_sha256": "11dd5af355f8e2f2730ae71d27b1c01b72ce75361e169f8d6c8d9646a052ae05",
                            "historical_report_is_not_R26_CI": True}}
    identities, inventories, absent, originals, metadata_only = {}, {}, [], {}, {}
    discrepancies = []

    def remember(identity):
        path = identity["source_path"]
        need(path not in identities or identities[path] == identity, "input changed between reads")
        identities[path] = identity
        return identity

    def bound_json(pin):
        identity, raw = helper.read(Path(pin["path"]), retain=True)
        need(identity["bytes"] == pin["bytes"] and identity["sha256"] == pin["sha256"],
             "original receipt differs: " + pin["path"])
        remember(identity)
        return identity, json.loads(raw)

    def expect_absent(path):
        need(not os.path.lexists(path), "unexecuted or absent output unexpectedly exists: " + str(path))
        absent.append(str(path))

    def optional_json(path):
        if not os.path.lexists(path):
            expect_absent(path)
            return None
        identity, raw = helper.read(path, retain=True)
        remember(identity)
        try:
            value = json.loads(raw)
        except (ValueError, UnicodeError) as error:
            discrepancies.append({"path": str(path), "reason": "original JSON is incomplete or malformed",
                                  "error_type": type(error).__name__})
            return None
        return value

    def compare_recorded(path, actual, recorded, context):
        if (("bytes" in recorded and actual["bytes"] != recorded["bytes"])
                or actual["sha256"] != recorded["sha256"]):
            discrepancies.append({"path": str(path), "context": context,
                                  "recorded": recorded, "observed": actual,
                                  "reason": "recorded original identity differs from current file"})

    def inspect_monitor(name, original):
        result = {"original_parent_authorized_attribution": original.get("measurement_attribution_valid") is True,
                  "raw_ledger_present": False, "independently_validated": False}
        output = REPORT_PATHS[name].parent
        ledger_path = output / "compiler-monitor.json"
        ledger = optional_json(ledger_path)
        audit = optional_json(output / "compiler-monitor.audit.json")
        result["raw_ledger_present"] = str(ledger_path) in identities
        monitor = original.get("compiler_monitor")
        try:
            need(isinstance(ledger, dict), "original monitor ledger is absent, malformed or not an object; no attribution proof")
            need(isinstance(audit, dict), "original monitor audit is absent, malformed or not an object; no attribution proof")
            need(isinstance(monitor, dict), "original parent compiler_monitor is absent or not an object; no attribution proof")
            component_paths = {"module": "compiler_monitor.py", "validator": "validate_compiler_monitor.py",
                               "reader": "compiler_state.py", "policy": "compiler-monitor-policy-01.json"}
            current_sources, source_raw = {}, {}
            for label, filename in component_paths.items():
                path = ROOT / "tools-03" / filename
                identity, raw = helper.read(path, retain=True)
                remember(identity)
                need({key: identity[key] for key in ("bytes", "sha256")} == FROZEN_ASSETS[str(path)]["identity"],
                     "reviewed monitor component source changed")
                current_sources[label] = {"path": str(path), "bytes": identity["bytes"], "sha256": identity["sha256"]}
                source_raw[label] = raw
            policy = json.loads(source_raw["policy"])
            module = types.ModuleType("r26_export_bound_pure_monitor_validator")
            module.__file__ = str(ROOT / "tools-03/validate_compiler_monitor.py")
            exec(compile(source_raw["validator"], module.__file__, "exec"), module.__dict__)
            validation = module.validate(ledger, policy["limits"],
                monitor["guarded_body_start_monotonic_ns"], monitor["guarded_body_end_monotonic_ns"])
            sources_match = (monitor.get("sources") == current_sources and ledger.get("source_bindings") == {
                "schema": "hepta-r26-compiler-monitor-input-binding/v1", "sources": current_sources,
                "limits": policy["limits"]})
            ledger_identity = identities[str(output / "compiler-monitor.json")]
            audit_identity = identities.get(str(output / "compiler-monitor.audit.json"))
            ledger_pin = {"path": str(output / "compiler-monitor.json"),
                          "bytes": ledger_identity["bytes"], "sha256": ledger_identity["sha256"]}
            audit_pin = None if audit_identity is None else {"path": str(output / "compiler-monitor.audit.json"),
                          "bytes": audit_identity["bytes"], "sha256": audit_identity["sha256"]}
            binding_valid = (monitor.get("ledger") == ledger_pin and monitor.get("independent_audit") == audit_pin
                             and audit is not None and audit.get("ledger") == ledger_pin
                             and audit.get("validator") == current_sources["validator"]
                             and audit.get("validation") == validation
                             and audit.get("monitor_sources_unchanged") is True
                             and audit.get("source_recheck_errors") == []
                             and monitor.get("monitor_sources_unchanged") is True
                             and monitor.get("limits") == policy["limits"])
            valid = validation["passed"] is True and sources_match and binding_valid and monitor.get("passed") is True
            result.update(independent_validation=validation, source_bindings_match=sources_match,
                          original_audit_and_parent_bindings_match=binding_valid, independently_validated=valid)
            if original.get("measurement_attribution_valid") is True and not valid:
                discrepancies.append({"stage": name, "reason": "parent attribution flag lacks matching original monitor proof"})
        except (KeyError, TypeError, ValueError, RuntimeError, OSError) as error:
            result["verification_error"] = {"type": type(error).__name__, "reason": str(error)}
            if original.get("measurement_attribution_valid") is True:
                discrepancies.append({"stage": name, "reason": "claimed original monitor proof cannot be reproduced"})
        return result

    try:
        remember(self_identity)
        remember(helper_identity)
        remember(input_identity)
        preparation_identity, preparation = bound_json(value["preparation"])
        need(preparation.get("schema") == "hepta-r26-qualified-parent-preparation/v1",
             "original qualifier preparation schema differs")
        originals["preparation"] = preparation
        report["preparation"] = {"identity": preparation_identity,
                                 "passed": preparation.get("passed"),
                                 "candidate_qualified": preparation.get("candidate_qualified"),
                                 "qualification_returncode": preparation.get("qualification_returncode")}
        for name in STAGES:
            row = rows[name]
            if not row["executed"]:
                for path in EFFECT_PATHS[name]:
                    expect_absent(path)
                if name != "python_ci":
                    expect_absent(NATIVE_PATHS[name])
                report["stages"][name] = {"executed": False, "reason": row["reason"]}
                continue
            native_identity, native = bound_json(row["native_terminal"])
            terminal_summary = validate_terminal(native, row["job_id"])
            entry = {"executed": True, "job_id": row["job_id"], "native_terminal": native_identity,
                     "native_outcome": terminal_summary, "report": None,
                     "original_report_finished": False, "original_report_schema_matches": False}
            if row["report"] is None:
                expect_absent(REPORT_PATHS[name])
                entry["report_absence_reason"] = row["reason"]
            else:
                report_identity, raw = helper.read(Path(row["report"]["path"]), retain=True)
                need(report_identity["bytes"] == row["report"]["bytes"]
                     and report_identity["sha256"] == row["report"]["sha256"], "original stage report bytes differ")
                remember(report_identity)
                try:
                    original = json.loads(raw)
                    originals[name] = original
                    entry.update(report=report_identity, original_result=original_report_projection(original))
                    entry["original_report_finished"] = isinstance(original, dict) and bool(original.get("finished_utc"))
                    entry["original_report_schema_matches"] = (isinstance(original, dict)
                                                               and original.get("schema") == REPORT_SCHEMAS[name])
                    if not entry["original_report_schema_matches"]:
                        discrepancies.append({"stage": name, "reason": "original report schema differs from fixed stage"})
                    elif not entry["original_report_finished"] and any(original.get(key) is True for key in (
                            "qualified", "passed", "observation_gate_passed", "adoption_passed")):
                        discrepancies.append({"stage": name, "reason": "unfinished original report contains an unsupported positive outcome"})
                except (ValueError, UnicodeError) as error:
                    entry.update(report=report_identity, original_report_finished=False,
                                 original_report_parse_error={"type": type(error).__name__, "reason": str(error)[:1000]})
            report["stages"][name] = entry
        report["all_original_native_logs_lossless"] = all(
            row["native_outcome"]["native_logs_lossless_complete"] for row in report["stages"].values() if row["executed"])
        report["monitor_evidence"] = {}
        for name in ("observation", "lifecycle", "lifecycle_attempt02"):
            if name in originals and isinstance(originals[name], dict):
                report["monitor_evidence"][name] = inspect_monitor(name, originals[name])
        report["candidate_disposition"] = disposition(report["stages"], report["monitor_evidence"])
        qualified = originals.get("qualification", {})
        if not isinstance(qualified, dict):
            qualified = {}
        report["qualified_source_verification"] = {"original_report_qualified": qualified.get("qualified") is True,
                                                   "current_source_matches_recorded": None}
        if qualified.get("qualified") is True:
            expected = qualified.get("source_after", {})
            source_paths = [ROOT / "source" / name for name in ("Cargo.toml", "Cargo.lock", "rustfmt.toml")]
            for name in ("src", "examples"):
                source_paths += [Path(path) for path in helper.listing(ROOT / "source" / name)["files"]]
            actual = {}
            for path in sorted(source_paths):
                identity, _ = helper.read(path)
                remember(identity)
                actual[path.relative_to(ROOT / "source").as_posix()] = identity["sha256"]
            source_match = (len(expected) == len(actual) == 221 and actual == expected
                            and qualified.get("source_tested") == expected)
            harness_paths = helper.listing(ROOT / "source/tools/x230/20261028")["files"]
            harness = {}
            for path in map(Path, harness_paths):
                if path.parent == ROOT / "source/tools/x230/20261028" and path.suffix == ".py":
                    identity, _ = helper.read(path)
                    remember(identity)
                    harness[path.name] = identity["sha256"]
            harness_match = len(harness) == 19 and harness == qualified.get("harness_after") == qualified.get("harness_before")
            report["qualified_source_verification"].update(current_source_matches_recorded=source_match,
                current_harness_matches_recorded=harness_match, observed_source_files=len(actual), observed_harness_files=len(harness))
            if not source_match or not harness_match:
                discrepancies.append({"reason": "current source or harness differs from the original qualified report"})
        # Actual CI/measurement plans contribute only bounded, allowlisted input files.
        bound_documents = [(name, original) for name, original in originals.items() if isinstance(original, dict)]
        ci_plan = optional_json(ROOT / "rust-ci-plan-01.json")
        if isinstance(ci_plan, dict):
            bound_documents.append(("ci-plan", ci_plan))
        recorded_external = []
        known_root_names = {OUT.name, *[path.name for path in OMITTED_CACHE_ROOTS]}
        for roots in TREE_SCOPE.values():
            known_root_names.update(path.relative_to(ROOT).parts[0] for _, path in roots if path.is_relative_to(ROOT))
        for names in ROOT_RECEIPTS.values():
            known_root_names.update(names)
        known_root_names.update(Path(path).relative_to(ROOT).parts[0] for path in FROZEN_ASSETS if Path(path).is_relative_to(ROOT))
        root_inventory = []
        with os.scandir(ROOT) as directory:
            for entry in directory:
                need(len(root_inventory) < 256, "unexpected unbounded R26 root inventory")
                if entry.name == OUT.name:
                    continue
                current = entry.stat(follow_symlinks=False)
                row = {"name": entry.name, "identity": helper.stamp(current), "body_read": False,
                       "selected_scope": entry.name in known_root_names,
                       "persistent_lock_metadata": bool(re.fullmatch(r"\.hepta-lock-[A-Za-z0-9._-]+", entry.name))
                            and stat.S_ISREG(current.st_mode) and current.st_size == 0}
                root_inventory.append(row)
                if not row["selected_scope"] and not row["persistent_lock_metadata"]:
                    discrepancies.append({"path": str(ROOT / entry.name), "reason": "original root entry is outside frozen evidence scope; metadata retained"})
        root_inventory.sort(key=lambda row: row["name"])
        report["original_root_inventory"] = root_inventory
        for group, roots in TREE_SCOPE.items():
            files, tree_rows, omitted, missing = {}, {}, [], []

            def add(path, member, expected=None):
                path = Path(path)
                helper.safe_name(member)
                need(member not in files and not any(row.get("archive_path") == member for row in omitted),
                     "duplicate archive destination")
                # Never open key/plist bodies, even for a digest. Preserve metadata only.
                if path.name in ("id_rsa", "id_ed25519", "id_ecdsa", "id_dsa") or path.suffix in (".key", ".pem", ".plist"):
                    helper.direct(path)
                    current = path.lstat()
                    need(stat.S_ISREG(current.st_mode) and current.st_uid == os.geteuid() and current.st_nlink == 1,
                         "unsafe private metadata-only file")
                    identity = {"source_path": str(path), "original_identity": helper.stamp(current)}
                    metadata_only[str(path)] = identity
                    omitted.append({**identity, "archive_path": member, "body_read": False,
                                    "omission_reason": "credential/service configuration metadata only; body not opened"})
                    return
                identity, _ = helper.read(path, scan_private_markers=member.startswith(OUTPUT_PREFIXES))
                remember(identity)
                if expected is not None:
                    compare_recorded(path, identity, expected, "bound original input")
                reason = omission_reason(path, group, identity)
                if reason:
                    omitted.append({**identity, "archive_path": member, "omission_reason": reason})
                else:
                    files[member] = identity

            for prefix, root in roots:
                if not os.path.lexists(root):
                    expect_absent(root)
                    missing.append(str(root))
                    continue
                inventory = helper.listing(root)
                inventories[str(root)] = tree_rows[str(root)] = inventory
                for path in map(Path, inventory["files"]):
                    add(path, prefix + "/" + path.relative_to(root).as_posix())
            for relative in ROOT_RECEIPTS[group]:
                path = ROOT / relative
                if os.path.lexists(path):
                    add(path, "receipts/" + relative)
                else:
                    expect_absent(path)
                    missing.append(str(path))
            for path, item in FROZEN_ASSETS.items():
                if item["group"] != group:
                    continue
                if not os.path.lexists(path):
                    expect_absent(path)
                    missing.append(path)
                    continue
                add(Path(path), "frozen-assets/" + item["member"], item["identity"])
            selected_documents = [row for row in bound_documents if (
                group == "qualification" and row[0] in ("preparation", "qualification")) or
                (group == "ci" and row[0] in ("rust_ci", "ci-plan")) or
                (group == "observation" and row[0] == "observation") or
                (group == "lifecycle" and row[0] in ("lifecycle", "lifecycle02_quiet", "lifecycle_attempt02"))]
            external_rows = []
            for label, original in selected_documents:
                recorded_inputs = list(original.get("input_bindings", []))
                if label == "preparation":
                    recorded_inputs += list(original.get("bound_parent_inputs", {}).values())
                    recorded_inputs += [original[key] for key in ("launcher", "input") if key in original]
                for index, recorded in enumerate(recorded_inputs):
                    need(isinstance(recorded, dict) and isinstance(recorded.get("path"), str)
                         and isinstance(recorded.get("sha256"), str) and HEX.fullmatch(recorded["sha256"]),
                         "malformed original bound input")
                    path = Path(recorded["path"])
                    need(path.is_absolute() and ".." not in path.parts, "noncanonical original bound input")
                    covered = any(str(path) in row["files"] for row in tree_rows.values()) or str(path) in identities
                    allowed = any(path.is_relative_to(root) for root in BOUND_INPUT_ROOTS) or str(path) in FROZEN_ASSETS
                    if covered:
                        current = identities.get(str(path))
                        if current is not None:
                            compare_recorded(path, current, recorded, label + " recorded original input")
                        external_rows.append({"recorded": recorded, "disposition": "covered by frozen tree/receipt identity"})
                    elif allowed and path.name not in PRIVATE_NAMES and path.suffix not in (".key", ".pem", ".plist"):
                        add(path, "bound-inputs/" + label + "-" + str(index).zfill(4) + "-" + path.name, recorded)
                        external_rows.append({"recorded": recorded, "disposition": "allowlisted current file captured or ELF identity retained"})
                    else:
                        external_rows.append({"recorded": recorded, "disposition": "recorded identity only; external system/profile/key input not reopened",
                                              "current_identity_verified": False, "body_read": False})
            recorded_external.extend(external_rows)
            for name, path in (("export_r26_evidence_03.py", EXPORTER), ("stable_archive.py", HELPER),
                               ("actual-export-input-01.json", INPUT)):
                add(path, "export-tools/" + name)
            manifest = {"schema": "hepta-r26-outcome-preserving-archive-manifest/v1", "group": group,
                        "files": files, "omitted_bodies": omitted, "source_trees": tree_rows,
                        "absent_optional_paths": sorted(set(missing)), "original_external_bindings": external_rows,
                        "original_stages": report["stages"], "candidate_disposition": report["candidate_disposition"],
                        "adoption_decision_made_here": False, "native_raw_companion_required": True,
                        "mac_holder_packages_required_if_executed": True,
                        "python_ci_executed": False, "archive_success_is_not_runtime_success": True}
            path = OUT / (group + "-01.tar.gz")
            raw_manifest, verified = helper.write_archive(path, manifest, files, OUTPUT_PREFIXES)
            manifest_path = OUT / (group + "-manifest-01.json")
            helper.create(manifest_path, raw_manifest)
            report["archives"][group] = {"archive": verified["identity"], "independent_archive_validation": verified,
                "manifest": helper.read(manifest_path)[0], "payload_files": len(files), "omitted_bodies": len(omitted),
                "source_bytes": sum(row["bytes"] for row in files.values()), "transfer": helper.transfer_chunks(path, OUT)}
        for path, expected in identities.items():
            need(helper.read(Path(path), expected=expected)[0] == expected, "original input changed across archives")
        for path, expected in inventories.items():
            need(helper.listing(Path(path)) == expected, "original tree inventory changed across archives")
        for path, expected in metadata_only.items():
            need(helper.stamp(Path(path).lstat()) == expected["original_identity"], "private metadata-only input changed")
        for path in set(absent):
            need(not os.path.lexists(path), "original absent input appeared while exporting")
        root_after = []
        with os.scandir(ROOT) as directory:
            for entry in directory:
                need(len(root_after) < 256, "unexpected unbounded final R26 root inventory")
                if entry.name != OUT.name:
                    root_after.append({"name": entry.name, "identity": helper.stamp(entry.stat(follow_symlinks=False))})
        need(sorted(root_after, key=lambda row: row["name"]) ==
             [{key: row[key] for key in ("name", "identity")} for row in root_inventory],
             "original R26 root entries changed across evidence capture")
        report["ignored_cache_trees"] = [{"path": str(path), "body_read": False,
            "reason": "private build cache excluded; retained qualification artifacts and original logs are captured"}
            for path in OMITTED_CACHE_ROOTS]
        report["all_original_inputs_unchanged_during_export"] = True
        report["recorded_identity_discrepancies"] = discrepancies
        report["archive_payload_capture_verified"] = True
        report["original_evidence_consistent"] = not discrepancies
        report["native_raw_companion_verified_here"] = False
        report["mac_holder_companions_verified_here"] = False
        report["passed"] = not discrepancies
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "reason": str(error)}
        report["error_trace"] = traceback.format_exc()
    finally:
        report["finished_utc"] = utc()
        helper.create(OUT / "report.json", helper.encode(report))
        print(json.dumps({"passed": report["passed"], "report": str(OUT / "report.json"),
                          "adoption_decision_made_here": False}), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    os.umask(0o077)
    sys.dont_write_bytecode = True
    raise SystemExit(main())
