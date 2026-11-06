#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
'Read-only R35 cache-owner postflight after the original rejected normal lifecycle; creates one new receipt.'
import datetime, hashlib, json, os, stat
from pathlib import Path

ROOT = Path('/home/qian/hepta-runtime-optimization-20261106-r35')
PINS = {'campaign-01/compiler-monitor.audit.json': {'bytes': 841,
                                             'sha256': '66c850ff22dbadcd81a385aa4431c437f004b4c26eb61761004a8268088846e2'},
 'campaign-01/compiler-monitor.json': {'bytes': 198175,
                                       'sha256': '4314521f6e8479cdc5a56941e1335999039d8d03c7919d6ccbfd5714cd892452'},
 'campaign-01/native-observation/independent-summary.json': {'bytes': 66140,
                                                             'sha256': '63dead2f66980366b83f302c2dff1fa7c27678fd44604fd21bf84a25e6f8a480'},
 'campaign-01/native-observation/report.json': {'bytes': 3557457,
                                                'sha256': '1cfb638f4c8983f73f9bbcfcc151be642383e9b6b0e81a0e1e9ba715506ee365'},
 'campaign-01/report.json': {'bytes': 143570,
                             'sha256': '3923115d1a8ba2aeb2fc00405bcd01f8d0f92e509b23e17ba6413634d47dba00'},
 'campaign-01/summary.json': {'bytes': 14469,
                              'sha256': '0845c8ef6fb7d82350b00f594a68eb523c171b539f588ae1b4e7f12fe1aae3ce'},
 'lifecycle-abba-01/gates.json': {'bytes': 17120,
                                  'sha256': '22a2a35b0d9813c275626239bc315bd9666880056556d0c746e51426d34a0518'},
 'lifecycle-abba-01/plan.json': {'bytes': 10818,
                                 'sha256': 'd3338aa1600f459c6157bb89182bce204fa107927af5e929d70f6f19b30a6ce3'},
 'lifecycle-abba-01/report.json': {'bytes': 32393,
                                   'sha256': 'f064d5daa533b57277efc329db2e5b5a71e12ac1313f458ec7f771ac4b80b402'},
 'lifecycle-abba-01/round-0-A/independent-summary.json': {'bytes': 14379,
                                                          'sha256': '7998a595a26aed6bb9e4fd09b19ebcd608a4945f71124f2c21c22222f7517249'},
 'lifecycle-abba-01/round-0-A/phase-after_crash_running.json': {'bytes': 1813,
                                                                'sha256': 'a94501cbd1e0cf22746578c49f8efa2a1845cb59a58d313cda19890102a37bd5'},
 'lifecycle-abba-01/round-0-A/phase-after_transport_running.json': {'bytes': 1808,
                                                                    'sha256': 'b57d68e260fdbc94d1484875c0c953b3e302b769851bf27eebfb877ae218c4c5'},
 'lifecycle-abba-01/round-0-A/phase-before_crash_running.json': {'bytes': 1798,
                                                                 'sha256': '9dbfd5edbec3f4eb010f9efecafa2d9bc885106b74248208ae384ca3feec5ad4'},
 'lifecycle-abba-01/round-0-A/phase-cancel_after_terminal.json': {'bytes': 1831,
                                                                  'sha256': 'ffe6bc811310bb89c010736929246e434b3644c26085b814ddf964673bb83740'},
 'lifecycle-abba-01/round-0-A/phase-concurrent_cancel.json': {'bytes': 1823,
                                                              'sha256': '02d87b8802a515f1b9f696c33d8e3ab1cc739d669ed8acb2a236f60ff10def7a'},
 'lifecycle-abba-01/round-0-A/phase-launch.json': {'bytes': 1774,
                                                   'sha256': 'ffcee67b9967f7e3e643d7a8d1fe6cfe966d8b9a4e9a8be15cca3c2a193a2bcf'},
 'lifecycle-abba-01/round-0-A/phase-prepare.json': {'bytes': 501,
                                                    'sha256': 'ee8a02be9cba8444a61988161c6e799ce19bf48ec4236286d06aec9266dc8fa2'},
 'lifecycle-abba-01/round-0-A/phase-same_key_after_cancel.json': {'bytes': 1830,
                                                                  'sha256': 'ddf5b71b3c7c1afd4161db252bc9dcfb869b2dede452834f4ce4c1bdd32cfea7'},
 'lifecycle-abba-01/round-0-A/phase-same_key_after_crash.json': {'bytes': 1823,
                                                                 'sha256': 'bbfc8a2e68ccdabb4c940a6a47686134fc6f1a24971a2d41741f80a060a22bf1'},
 'lifecycle-abba-01/round-0-A/phase-terminal.json': {'bytes': 1815,
                                                     'sha256': 'a911cb554da1e3eb351463e4c71633aca0735bb384a96e7d20410d57f04b6e16'},
 'lifecycle-abba-01/round-0-A/phase-terminal_after_restart.json': {'bytes': 1821,
                                                                   'sha256': '2761d0eaf8f85b2b7a697e3ed10b362bb306207c36406ea8039c11a2013c6462'},
 'lifecycle-abba-01/round-0-A/report.json': {'bytes': 568400,
                                             'sha256': '21bcd67d731cca3163bbcee77dcecdbd778794ce2bff3fc18e496f4a7e248808'},
 'lifecycle-abba-01/round-1-B/independent-summary.json': {'bytes': 14397,
                                                          'sha256': '6ab234da1fb44738d0e185e3c9b0a8370ddb4ca4ab4726a1e8d8c45afac04fdc'},
 'lifecycle-abba-01/round-1-B/phase-after_crash_running.json': {'bytes': 1815,
                                                                'sha256': 'bd07c7e08f2d9806812aedacf6ee6a563dd819e8f36b94f870983b21c80bb01b'},
 'lifecycle-abba-01/round-1-B/phase-after_transport_running.json': {'bytes': 1808,
                                                                    'sha256': 'f9a1dccc9e2f287f37eae23faac7633fae53bb65a9184c48dffb7137ca16751d'},
 'lifecycle-abba-01/round-1-B/phase-before_crash_running.json': {'bytes': 1798,
                                                                 'sha256': '1520c54b029345ba3dd08400abd3474922dd3675b1e49a1df0e86dd78c08669f'},
 'lifecycle-abba-01/round-1-B/phase-cancel_after_terminal.json': {'bytes': 1831,
                                                                  'sha256': 'a3922b739a0af476b924ca00a8146ef5b605c3d5af2381fcea97ddd4a6fa2171'},
 'lifecycle-abba-01/round-1-B/phase-concurrent_cancel.json': {'bytes': 1823,
                                                              'sha256': '23b542f87484f6d5a59a4c75c0242c2be2d24daabca48c431a7d2b0b7cb38afb'},
 'lifecycle-abba-01/round-1-B/phase-launch.json': {'bytes': 1774,
                                                   'sha256': '8f5401f793a327429138d6df65ef80de1d51e80a684aa8034d26a73e3f91d784'},
 'lifecycle-abba-01/round-1-B/phase-prepare.json': {'bytes': 501,
                                                    'sha256': 'cd53d89adffabf98da9495bdddd43167b08ae7eb30b79516d71ef46673986cfb'},
 'lifecycle-abba-01/round-1-B/phase-same_key_after_cancel.json': {'bytes': 1830,
                                                                  'sha256': '4bb02bdd0d347b9d78865acbfb27db10ab9dc45411906ce66c141606acbb1a38'},
 'lifecycle-abba-01/round-1-B/phase-same_key_after_crash.json': {'bytes': 1825,
                                                                 'sha256': '649335bbe9fe70d3d0124ba54bd3a9e8c204bf0415e7887c74937d7b2a02286d'},
 'lifecycle-abba-01/round-1-B/phase-terminal.json': {'bytes': 1815,
                                                     'sha256': '9d3813c4389556f5aa2ccfc569728986af8e8ec0f9ef5252add7d54bd90143cd'},
 'lifecycle-abba-01/round-1-B/phase-terminal_after_restart.json': {'bytes': 1821,
                                                                   'sha256': '1565861b35076a675318749b34c041fdcf0a933898b3486b5a431fed53017158'},
 'lifecycle-abba-01/round-1-B/report.json': {'bytes': 568239,
                                             'sha256': '8df9c91a71f85dfe1f73c7edce71567d6e0525f7845768532f8a33433fa76782'},
 'lifecycle-abba-01/round-2-B/independent-summary.json': {'bytes': 14831,
                                                          'sha256': 'ed110c454ea47fe98d940b938e0be98a06edddc90a420e7ef02129bf8ec9d1bd'},
 'lifecycle-abba-01/round-2-B/phase-after_crash_running.json': {'bytes': 1815,
                                                                'sha256': '640bc2d2895130a02650033cf5b8d2b1931f6384c4f64ff569ac7f904045da6e'},
 'lifecycle-abba-01/round-2-B/phase-after_transport_running.json': {'bytes': 1808,
                                                                    'sha256': '11397426177162cefa1949ba8c47a572de7bb2fc7fdf8d80f28af282c09e32fa'},
 'lifecycle-abba-01/round-2-B/phase-before_crash_running.json': {'bytes': 1798,
                                                                 'sha256': '527daa275cab3dc2d66821b1ec8b99770d8fb5b8d5b04ce478fd4a98abcaab51'},
 'lifecycle-abba-01/round-2-B/phase-cancel_after_terminal.json': {'bytes': 1831,
                                                                  'sha256': '027f255538df94024ab3be6f267552f739e1b51c2e94c5b3f2b8a942c6695e8f'},
 'lifecycle-abba-01/round-2-B/phase-concurrent_cancel.json': {'bytes': 1823,
                                                              'sha256': '67be4de84bc7e22c1f55a01a875002a623c711817bfa8f95d6fd3c07b3934066'},
 'lifecycle-abba-01/round-2-B/phase-launch.json': {'bytes': 1774,
                                                   'sha256': '387c1af755ae5a5d84cf724ba80f1ce6cab80001b75012f596f044b48ac5ae90'},
 'lifecycle-abba-01/round-2-B/phase-prepare.json': {'bytes': 501,
                                                    'sha256': 'c3728d5872068310e6f261de43b28160da2e66576b622c9e10667fa24aa060ed'},
 'lifecycle-abba-01/round-2-B/phase-same_key_after_cancel.json': {'bytes': 1830,
                                                                  'sha256': '0299dd721e5a74f1c53d24dc875083f65477295130ff12c1f2efa3dde537c664'},
 'lifecycle-abba-01/round-2-B/phase-same_key_after_crash.json': {'bytes': 1825,
                                                                 'sha256': '60d90c2aac3d315817a4214094fd9e3cf451a2a5ed2ebe71b2fce4715bfe1c44'},
 'lifecycle-abba-01/round-2-B/phase-terminal.json': {'bytes': 1815,
                                                     'sha256': 'ab8d9b48b07464b4554be698a4802b55d3a720193da56798fcda009a9df221da'},
 'lifecycle-abba-01/round-2-B/phase-terminal_after_restart.json': {'bytes': 1821,
                                                                   'sha256': '52d6860169b6be293495cf5f6017cc67bb0a6ca0db8cec3bc6e7dac04da93a35'},
 'lifecycle-abba-01/round-2-B/report.json': {'bytes': 568595,
                                             'sha256': 'f63ded9be27bca2c741c6caf2767bbcda4af1acd4a5fcc0ea43865eb487c19a7'},
 'lifecycle-abba-01/round-3-A/independent-summary.json': {'bytes': 13802,
                                                          'sha256': 'd7ee9d06dd4dc5500ecc82a57bef3cc6a678112d50dd8e72a863c7aa50c50043'},
 'lifecycle-abba-01/round-3-A/phase-after_crash_running.json': {'bytes': 1815,
                                                                'sha256': '505c5ed1f70048eb2ced63824d184b7047de2260a9982605e073732a30caa72c'},
 'lifecycle-abba-01/round-3-A/phase-after_transport_running.json': {'bytes': 1818,
                                                                    'sha256': 'b53a180c48925eccb0623c11911fdd2ec55e77ac38691404c4b989bcbdcc1b6d'},
 'lifecycle-abba-01/round-3-A/phase-before_crash_running.json': {'bytes': 1808,
                                                                 'sha256': '179984a1ae04168664167452cc1d19ac503c7bb2ecc2036d33ba050825cee6bc'},
 'lifecycle-abba-01/round-3-A/phase-cancel_after_terminal.json': {'bytes': 1821,
                                                                  'sha256': '003f967ad0b4e10eebc29289dfafa69f422ea5bd835af74186be091c9cfcb37a'},
 'lifecycle-abba-01/round-3-A/phase-concurrent_cancel.json': {'bytes': 1823,
                                                              'sha256': '82e28b3691ddd6d4b7b4ecf2c92c709f4adfdd110b31bc84954c0304578a40a7'},
 'lifecycle-abba-01/round-3-A/phase-launch.json': {'bytes': 1784,
                                                   'sha256': 'a9badf1897eb918026e70fc56e45a6049a6148f55bbbe80399b15a27b80703c3'},
 'lifecycle-abba-01/round-3-A/phase-prepare.json': {'bytes': 501,
                                                    'sha256': 'b4d90c2df8687d2f16790168cecad1b497da5bb7da8bf864790a0f0d4b4f78f7'},
 'lifecycle-abba-01/round-3-A/phase-same_key_after_cancel.json': {'bytes': 1820,
                                                                  'sha256': 'e3a10c2e6875db96d9afc0787df0eb5512bda8c1fbdee7d6ca49627c966fa6bb'},
 'lifecycle-abba-01/round-3-A/phase-same_key_after_crash.json': {'bytes': 1825,
                                                                 'sha256': 'a56b091f10bc057ee8f262a1482b02b15e700705d9bd14b21dbfb903db95726e'},
 'lifecycle-abba-01/round-3-A/phase-terminal.json': {'bytes': 1815,
                                                     'sha256': 'ecb41d8d989c157adc8ded50c654f5e9ea326029a64b0cefda61161a6930fdd5'},
 'lifecycle-abba-01/round-3-A/phase-terminal_after_restart.json': {'bytes': 1811,
                                                                   'sha256': 'a0bfa6f6e2d63800c21e2e15742e2f3b9de2b1f81279c361dba8a87fc584296a'},
 'lifecycle-abba-01/round-3-A/report.json': {'bytes': 567889,
                                             'sha256': '64c7ebdc1da9b771d0bb7972fe6bf0f75354e6eab7fe0413c0fddfdcd7284f31'},
 'lifecycle-abba-01/round-index.json': {'bytes': 15137,
                                        'sha256': 'a8468aa002225177edf6762fde4ad2ef41f8648b509a41e64cea7294c58e45a6'},
 'lifecycle-abba-01/summary.json': {'bytes': 61099,
                                    'sha256': '395910074c4df762c12ff028cd0caae27b530123cf97dd63eb873f0afaafcd81'},
 'lifecycle-campaign-01/baseline-source-inputs.json': {'bytes': 34902,
                                                       'sha256': 'db2896451a01108553c3b5fdb44322ba72ba16a61274f344437ddf129d63a33b'},
 'lifecycle-campaign-01/compiler-monitor.audit.json': {'bytes': 850,
                                                       'sha256': '6d1f4b8cc59335f05c0cd8ca688138a17747fa78b416dafc56f42304928b8db3'},
 'lifecycle-campaign-01/compiler-monitor.json': {'bytes': 99515,
                                                 'sha256': 'd7da91a88b37bc5779ff1d3665aa734a3c8235ab75ce68bd47b7ac2347b83e2f'},
 'lifecycle-campaign-01/plan.json': {'bytes': 4560,
                                     'sha256': '8972853027acfb34c24022822655ef9dc58665ded777faa46b2d74ecd3161107'},
 'lifecycle-campaign-01/report.json': {'bytes': 104245,
                                       'sha256': 'c90c0de71aafb9ef3a6f6ecefbd6b482ce5399e2fa345ae126f0f0f9d9aaab92'},
 'lifecycle-campaign-01/source-inputs.json': {'bytes': 34902,
                                              'sha256': '332775ab6ffcb664099d5fdb0a1203c779e65f9786518c8d9332d4aa4ae289f7'},
 'lifecycle-evidence-01.compact.json': {'bytes': 76870,
                                        'sha256': '6dbf49432ea30a379491e5cb4b95ba1d61a0fe20edc35a16bac1e79cd4896437'},
 'lifecycle-evidence-01.manifest.json': {'bytes': 433109,
                                         'sha256': 'ed38fa9be12f4e75cb0c683c12c5d1ec7853e1fac73be193de1111057fdfa2f9'},
 'lifecycle-evidence-01.tar.gz': {'bytes': 1269721,
                                  'sha256': 'b5eaadc62a6121e20cd6047f90d506c95374f8068cf77a03218d60484102df28'},
 'lifecycle-holder-native-01.json': {'bytes': 726,
                                     'sha256': 'bd6715663970570781f50c9c6dd66bf27562fbd550fe29c3972cc6ccba684440'},
 'lifecycle-holder-read-01.json': {'bytes': 1231,
                                   'sha256': 'd3ca9a90ebf17f039ffead27bde735c47569a4ff3ea898c4510309409596c306'},
 'lifecycle-holder-report-01.json': {'bytes': 9217,
                                     'sha256': 'df8b6e9f8e2e766603b8d86535d4aaabf2333e3cbe9ccb67c347305c74c5a509'},
 'lifecycle-inputs-01.json': {'bytes': 5748,
                              'sha256': '96e728ffe35848497b694a9925e48523d9f468b349da18fb5b40c437329a2a86'},
 'lifecycle-materialization-native-01.json': {'bytes': 729,
                                              'sha256': 'e9d1ce496f8533ee0af67854e7c01ecf5c06a51efbe1a7ad00129ca3c2575a51'},
 'lifecycle-materialization-read-01.json': {'bytes': 2809,
                                            'sha256': '8fe6e9c170d72f4434e9748dbfab9157e9824cbc9e2e6803720a9d80cf027da0'},
 'lifecycle-tool-tests-01/report.json': {'bytes': 463,
                                         'sha256': '1234700154119515e2e483a1b63a7d2be5c2d59904e58a3528891cc143a53893'},
 'lifecycle-tools-01/lifecycle-tools-manifest-01.json': {'bytes': 4066,
                                                         'sha256': 'eb50cd7ab0376c4b3dc768e8d184fdc23eeaa90c2ce5bdd4b9e9ac551448504e'},
 'observation-holder-native-01.json': {'bytes': 729,
                                       'sha256': '146c07d84c7a0430de12f08ead2bdecbe6b18785a1090e7bfc056bd2befc9bc5'},
 'observation-holder-read-01.json': {'bytes': 1234,
                                     'sha256': '6f712fac8424373b49d5ec2164ff7a33a82239bf64eff5e01e6620b51298495e'},
 'observation-holder-report-01.json': {'bytes': 9079,
                                       'sha256': '9b1310ad128e8c85559230ccf0934e732b7feb5d03cf526bfffdf8db3dc2a88f'},
 'observation-postflight-01.json': {'bytes': 6370,
                                    'sha256': '9a95bf8e9b8de880c15f9fa979f0f4f03dfc0ca1fb50e2270836420f5a97b977'},
 'preparation.json': {'bytes': 62335, 'sha256': '4770faa3c73ec2e9287fd43154ad5f9b6df149d85767ddb5f18e6aeb153ea1cc'},
 'qualification-01/isolated-tests/summary.json': {'bytes': 6878,
                                                  'sha256': '10eb5d260f26f15cfea9334ddc6f22456f22dea54ad1b755e118fd49cc67d904'},
 'qualification-01/report.json': {'bytes': 83363,
                                  'sha256': '5369433b6eb2db62a907593f1b679f968b411d0cde96ce9eabe8e124420cf8e1'},
 'qualification-01/source-map.json': {'bytes': 24156,
                                      'sha256': '87f085a95a1c1925ecc444b46c996a0aec399c74ce7d0c32afff572e24055313'},
 'qualification-native-read-01.json': {'bytes': 3812,
                                       'sha256': '4275444d755edf7b4893827ff2224fa1d70aee529a6ac2e1be4c0c5989a5a043'},
 'qualification-postflight-01.json': {'bytes': 8190,
                                      'sha256': '99e198adfeecb2f09b25d928a157a5067ef4a10315b1ead52134721665df630d'},
 'qualification-terminal-status-01.json': {'bytes': 731,
                                           'sha256': '8b171dde1644b1c9cacfc126be053484a3649031f946c648db7a69f9be404844'},
 'rust-ci-01/nextest-output-audit.json': {'bytes': 719,
                                          'sha256': '545fd10013d912be0e9297429b606e376cbea7bac55b62f78f76c881fe1ffba3'},
 'rust-ci-01/report.json': {'bytes': 14132,
                            'sha256': 'b619804c79479d2bb529e363d8fa48520b8ef9f351a99729ccba77d5510fec5f'},
 'rust-ci-native-01.json': {'bytes': 731, 'sha256': 'c19d3490b283df287ba2743d3385f26a83144505ef36ccc874e218359cc94746'},
 'rust-ci-native-read-01.json': {'bytes': 5126,
                                 'sha256': '31a962dfcbc55ce22b4bb81f5fa05aaacf018c13f17d2dc3f3b49e933d30977b'}}
BINARIES = {'hepta-runtime': {'bytes': 14373416,
                   'path': '/home/qian/hepta-runtime-optimization-20261106-r35/qualification-01/hepta-runtime',
                   'sha256': '416662310fef6ca6d68907658bb1b882584d1e431bf4ed4263f62984495d8251'},
 'hepta-runtime-jobctl': {'bytes': 739016,
                          'path': '/home/qian/hepta-runtime-optimization-20261106-r35/qualification-01/hepta-runtime-jobctl',
                          'sha256': '61c90260057a405626a24a36ad43303c632f72d2d97929296acdffd748b79d62'},
 'native_process_driver': {'bytes': 2896240,
                           'path': '/home/qian/hepta-runtime-optimization-20261106-r35/qualification-01/native_process_driver',
                           'sha256': '31d90610e618041faa5f562c029e496afc39c603fbe3a51d740e4eec3aacd54e'}}
JOBS = {'qualification': '1a1af619097-fc05-6813', 'exact_ci': '1a1af88c330-fc05-696f', 'observation': '1a1af9bb312-fc05-6a14', 'lifecycle_materialization': '1a1afb8c456-fc05-6b1d', 'normal_lifecycle': '1a1afc4fb4a-fc05-6b7f'}
COUNTS = {'passed': 1645, 'failed': 0, 'ignored': 34, 'selected': 1679, 'retries': 0}
OBS_COUNTS = {'measured_calls': 2304, 'warmup_calls': 288, 'preflight_restart_calls': 72, 'total_calls': 2664, 'failed_calls': 0}
LC_COUNTS = {'native_calls': 360, 'independent_ssh_calls': 144, 'new_starts': 24, 'same_key_lookups': 48, 'cancellations': 48, 'automatic_rpc_retries': 0}
LC_COUNT_KEYS = ('native_calls', 'independent_ssh_calls', 'new_starts', 'same_key_lookups', 'cancellations', 'automatic_rpc_retries')
Q_STAGES = ['format', 'fmt-check', 'harness-tests', 'clippy', 'test-build', 'isolated-tests', 'audit-isolated-tests', 'release']
OBS_STAGES = ['native-observation', 'native-audit', 'native-boundary', 'boundary-audit', 'cancel-recovery', 'recovery-audit', 'observation-summary']
NORMAL_STAGES = ['canary-0-A', 'audit-0-A', 'canary-1-B', 'audit-1-B', 'canary-2-B', 'audit-2-B', 'canary-3-A', 'audit-3-A', 'summary', 'normal-lifecycle-gates']
PHASE_FILES = ['phase-prepare.json', 'phase-launch.json', 'phase-before_crash_running.json', 'phase-after_transport_running.json', 'phase-after_crash_running.json', 'phase-same_key_after_crash.json', 'phase-concurrent_cancel.json', 'phase-terminal.json', 'phase-terminal_after_restart.json', 'phase-same_key_after_cancel.json', 'phase-cancel_after_terminal.json']
HOLDER_SHA = '715e996217c7d33a7483354f16f2d39c9a033f51f3a20a52484495a00262dd65'
OBS_PARENT_SHA = '3707cbc2e3307a29aa6e645afdf8f6da7a5e80d36e90a86d505bd8f18061778c'
LC_PARENT_SHA = '372f880ec4679147b06ae89e0df8ec64be74ac79a171704715e6499e79191e29'

def need(v,m):
    if not v: raise RuntimeError(m)

def ident(raw):
    return {"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}

def read(path,pin=None,cap=8*1024*1024):
    need(path.is_absolute() and path.resolve(strict=True)==path,"indirect input")
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,"rb") as f:
        a=os.fstat(f.fileno())
        need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and 0<=a.st_size<=cap,"unsafe original")
        raw=f.read(a.st_size+1); b=os.fstat(f.fileno())
    c=path.lstat(); fields=("st_dev","st_ino","st_mode","st_uid","st_nlink","st_size","st_mtime_ns","st_ctime_ns")
    need(len(raw)==a.st_size and all(getattr(a,k)==getattr(b,k)==getattr(c,k) for k in fields),"original changed")
    if pin: need(ident(raw)=={k:pin[k] for k in ("bytes","sha256")},"original identity mismatch "+str(path))
    return raw

def create(path,raw):
    need(path.parent.resolve(strict=True)==path.parent,"indirect output")
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(fd,"wb") as f:
        f.write(raw); f.flush(); os.fsync(f.fileno())
    read(path,ident(raw))
    return {"path":str(path),**ident(raw)}

def native(term,receipt,job,state,code):
    need(term["job_id"]==receipt["job_id"]==job and term["state"]==state and term["exit_code"]==code,"original native outcome differs")
    need(all(term[k] is False for k in ("automatic_retry","cancelled","timed_out")) and all(term[k] is True for k in ("output_complete","output_durable","terminal_publication_confirmed")),"native incomplete")
    need(term["terminal_publication_protocol"]==1 and term["log_synced"]=={"stdout":True,"stderr":True} and term["log_errors"]=={"stdout":None,"stderr":None} and term["log_truncated"]=={"stdout":False,"stderr":False},"native storage differs")
    for k in ("stdout","stderr"):
        v=receipt[k]; raw=bytes.fromhex(v["bytes_hex"])
        need(v["offset"]==0 and v["eof"] is True and len(raw)==v["size"]==v["next_offset"]==term["log_bytes"][k]["stored"]==term["log_bytes"][k]["seen"] and raw==v["text"].encode(),"native stream incomplete")

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
