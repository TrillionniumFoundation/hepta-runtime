#!/usr/bin/env python3
"""Local textual R29 derivation of reviewed R28 capture definitions; never run a payload."""
import ast
import difflib
import hashlib
import json
from pathlib import Path
import textwrap

BASE = Path('/workspace/scratch/806ba5f52f94')
HERE = Path(__file__).resolve().parent
ORIGIN = BASE / 'r25-integration-audit/r28-qualification-ci-export-02'
CANONICAL = BASE / 'r25-integration-audit/r29-qualification-final-01/canonical-preparation-validator.py'
PINS = {
    'export_r28_qualification_ci_02.py': '0878941cf72bf093e09019e82766fa60674ec39447b5858121c91612b9e3dd19',
    'verify_r28_qualification_ci_02.py': 'c949b88484f348a53e9aadde9b92c248d08c507347faea2e978ed0639dd3df73',
    'stable_xz_archive.py': '8b7aa7ef3b3772da13ea4f7009d8c478e0c92bc207d65db3f45c23453097d7a2',
}


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def put(name, body):
    with (HERE / name).open('xb') as stream:
        stream.write(body)
    assert (HERE / name).read_bytes() == body
    return identity(body)


def one(text, old, new):
    assert text.count(old) == 1, repr(old)
    return text.replace(old, new)


def between(text, start, end, new):
    assert text.count(start) == text.count(end) == 1
    left, right = text.index(start), text.index(end)
    assert left < right
    return text[:left] + new + text[right:]


def function(text, name):
    nodes = [n for n in ast.parse(text).body if isinstance(n, ast.FunctionDef) and n.name == name]
    assert len(nodes) == 1
    return ast.get_source_segment(text, nodes[0])


def main():
    original = {}
    for name, expected in PINS.items():
        raw = (ORIGIN / name).read_bytes()
        assert identity(raw)['sha256'] == expected
        original[name] = raw
    canonical = CANONICAL.read_bytes()
    assert identity(canonical) == {'bytes': 16992, 'sha256': '2892bd35bb5f1b5a90919e74453a18d5ae6ad738d08fcc780f3c0ac01c67c923'}
    old = original['export_r28_qualification_ci_02.py'].decode()
    source = old.replace('R28', 'R29').replace('r28', 'r29').replace('qualification_ci_02.py', 'qualification_ci_01.py')
    source = source.replace('r29-qualification-ci-export-input-02.json', 'r29-qualification-ci-export-input-01.json')
    source = one(source, 'SOURCE = ROOT / "source"', 'SOURCE = ROOT / "source"\nCANDIDATE_DIR = ROOT / "qualification-01"')
    source = between(source, 'STAGES = (', '\ndef need(', '''STAGES = ("qualification01", "rust_ci01", "python_ci01")
NATIVE_PATHS = {
    "qualification01": ROOT / "qualification-terminal-status-01.json",
    "rust_ci01": ROOT / "rust-ci-terminal-status-01.json",
    "python_ci01": ROOT / "python-ci-terminal-status-01.json",
}
REPORT_PATHS = {
    "qualification01": ROOT / "qualification-01/report.json",
    "rust_ci01": ROOT / "rust-ci-01/report.json",
    "python_ci01": ROOT / "python-ci-launch-01/receipt.json",
}
REPORT_SCHEMAS = {
    "qualification01": "hepta-x230-composed-qualification/v1",
    "rust_ci01": "hepta-r29-external-rust-ci/v1",
    "python_ci01": "hepta-r29-python-ci-one-time-launch-v1",
}
QUALIFICATION_STAGES = ("format", "fmt-check", "harness-tests", "clippy", "test-build", "isolated-tests", "audit-isolated-tests", "release")
DIRECTORIES = {
    "qualification": ROOT / "qualification-01",
    "rust-ci": ROOT / "rust-ci-01",
    "rust-ci-tools": ROOT / "rust-ci-tools-01",
    "python-ci01": ROOT / "python-ci-01",
    "python-launch01": ROOT / "python-ci-launch-01",
    "python-tools01": ROOT / "python-ci-tools-01",
    "published-python-inputs": STAGE_ROOT / "ci-gates",
}
OPTIONAL_TREES = {"rust-ci", "rust-ci-tools", "python-ci01", "python-launch01", "python-tools01"}
UNEXECUTED_OUTPUTS = {
    "rust_ci01": (ROOT / "rust-ci-01",),
    "python_ci01": (ROOT / "python-ci-launch-01", ROOT / "python-ci-01"),
}
ROOT_FILES = ("preparation-01.json", "qualification-input-01.json", "target-transfer-01.json",
              "rust-ci-plan-01.json", "rust-ci-tools-install-01.json", "python-ci-tools-install-01.json")
OPTIONAL_ROOT_FILES = {"rust-ci-plan-01.json", "rust-ci-tools-install-01.json", "python-ci-tools-install-01.json"}
QUALIFIER_ASSETS = (
    STAGE_ROOT / "tools/prepare_and_qualify_r29_01.py",
    STAGE_ROOT / "tools/r29-qualification-01-input.json",
    STAGE_ROOT / "tool-package-install-01.json",
    STAGE_ROOT / "ci-toolchain/nextest-0.9.137/receipt.json",
)
''')
    source = one(source, 'name == "python_ci02"', 'name in UNEXECUTED_OUTPUTS')
    source = one(source, '        if name in KNOWN_JOBS:\n            need(row["executed"] is True and row["job_id"] == KNOWN_JOBS[name], "known original job changed: " + name)\n',
        '        if name == "qualification01":\n            need(row["executed"] is True and row["report"] is not None,\n                 "this fixed capture requires an actual complete R29 qualification")\n')
    source = source.replace('preparation-02.json', 'preparation-01.json').replace('qualification02', 'qualification01')
    source = one(source, '\ndef report_projection(', '\n' + canonical.decode() + '\n\ndef report_projection(')
    source = one(source, 'def check_original_bindings(get_json, identities, stages):',
                 'def check_original_bindings(get_json, identities, stages, outcomes):')
    source = one(source, '         and preparation["selected_proposal"] == "cache only" and preparation["optional_pidfd_selected"] is False\n         and preparation["parent_lifecycle_rejection_preserved"] is True\n         and preparation["original_admission_failure_preserved"] is True,',
                 '         and preparation["selected_proposal"] == "shared unfiltered ToolRouter"\n         and preparation["optional_pidfd_selected"] is False\n         and preparation["parent_observation_rejection_preserved"] is True\n         and preparation["parent_candidate_adopted"] is False,')
    source = source.replace('== 1653', '== 1655').replace('== 1687', '== 1689').replace('{"PASS": 1653}', '{"PASS": 1655}')
    source = one(source, '    isolated = ROOT / "qualification-01/isolated-tests"', '''    preparation_contract = verify_r29_candidate_preparation(
        preparation, get_json(NATIVE_PATHS["qualification01"]), stages["qualification01"]["job_id"], qualification, summary)
    same(ROOT / "qualification-01/report.json", preparation["qualification_report"])
    same(ROOT / "target-transfer-01.json", preparation["cache_transfer_receipt"])
    need(get_json(ROOT / "target-transfer-01.json") == preparation["cache_transfer"],
         "actual closed transfer receipt differs from the preserved preparation")
    same(ROOT / "qualification-01/isolated-tests/tests.jsonl", preparation["original_test_ledger"])
    need(preparation["original_test_ledger"]["sha256"] == audit["input_sha256"]["tests.jsonl"],
         "two new original cases are not bound to the full audited test ledger")
    isolated = ROOT / "qualification-01/isolated-tests"''')
    source = one(source, '    for prep in (get_json(ROOT / "preparation-01.json"), preparation):\n', '    for prep in (preparation,):\n')
    rust_start = source.index('    rust = get_json(ROOT / "rust-ci-01/report.json")')
    rust_end = source.index('    manifest = get_json(STAGE_ROOT / "ci-gates/ci-gate-manifest.json")')
    rust = source[rust_start:rust_end]
    source = source[:rust_start] + '''    rust_positive = outcomes["rust_ci01"].get("original_positive_report_and_closed_native") is True
    python_positive = outcomes["python_ci01"].get("original_positive_report_and_closed_native") is True
    if rust_positive:
''' + textwrap.indent(rust, '    ') + source[rust_end:]
    source = one(source, '    for kind in ("rust", "python"):\n        installed = get_json(ROOT / (kind + "-ci-tools-install-01.json"))',
                 '    for kind in ("rust", "python"):\n        if str(ROOT / (kind + "-ci-tools-install-01.json")) not in identities:\n            continue\n        installed = get_json(ROOT / (kind + "-ci-tools-install-01.json"))')
    source = between(source, '    first = get_json(ROOT / "python-ci-launch-01/receipt.json")', '        if not stages[name]["executed"]:',
                     '    for name in ("python_ci01",):\n')
    source = one(source, '        attempt = "01" if name == "python_ci01" else "02"', '        attempt = "01"')
    source = between(source, '        if attempt == "02":', '\n\ndef main():', '''    return {"qualified_compiler_inputs": 221, "qualification_harness_inputs": 19,
            "qualification_stages": 8, "isolated_passed": 1655, "isolated_ignored": 34,
            "isolated_failed": 0, "isolated_retries": 0, "preparation_contract": preparation_contract,
            "exact_Rust_CI_stages": 6 if rust_positive else None,
            "nextest_plain_PASS": 1655 if rust_positive else None,
            "nextest_ignored": 34 if rust_positive else None,
            "nextest_retries": 0 if rust_positive else None,
            "published_Python_dependencies_preserved": 85,
            "published_Python_workflow_commands": 18,
            "actual_positive_Python_commands": 18 if python_positive else None,
            "original_Rust_CI_positive_producer_bindings_verified": rust_positive,
            "original_Python_CI_positive_producer_bindings_verified": python_positive,
            "negative_or_unexecuted_CI_outcomes_preserved": True, "tests_reexecuted": False}
''')
    source = one(source, '                for path in (NATIVE_PATHS[name], REPORT_PATHS[name].parent, ROOT / "python-ci-02"):',
                 '                for path in (NATIVE_PATHS[name],) + UNEXECUTED_OUTPUTS[name]:')
    source = between(source, '        need(report["original_outcomes"]["qualification_failed01"]', '        for label, directory in DIRECTORIES.items():',
                     '''        need(report["original_outcomes"]["qualification01"]["original_positive_report_and_closed_native"] is True,
             "actual complete qualification and its original strong terminal are required")
''')
    source = one(source, '        # The known first Python runner never launched; its 18 commands are not inferred.\n        expect_absent(ROOT / "python-ci-01")\n', '')
    source = one(source, 'bindings = check_original_bindings(get_json, identities, declarations)',
                 'bindings = check_original_bindings(get_json, identities, declarations, report["original_outcomes"])')
    source = source.replace(', "python-ci02"', '').replace(', "python-launch02"', '')
    source = source.replace(', "python-ci02/"', '').replace(', "python-launch02/"', '')
    ast.parse(source)
    assert function(source, 'verify_r29_candidate_preparation') == canonical.decode().rstrip()
    assert 'qualification_failed01' not in source and 'python_ci02' not in source
    assert 'python-ci-02' not in source and 'python-ci-tools-02' not in source
    exporter_pin = put('export_r29_qualification_ci_01.py', source.encode())
    helper_pin = put('stable_xz_archive.py', original['stable_xz_archive.py'])

    old_consumer = original['verify_r28_qualification_ci_02.py'].decode()
    consumer = old_consumer.replace('R28', 'R29').replace('r28', 'r29').replace('qualification_ci_02.py', 'qualification_ci_01.py')
    consumer = one(consumer, PINS['export_r28_qualification_ci_02.py'], exporter_pin['sha256'])
    consumer = one(consumer, '                for path in (original.NATIVE_PATHS[name], original.REPORT_PATHS[name].parent,\n                             original.ROOT / "python-ci-02"):',
                   '                for path in (original.NATIVE_PATHS[name],) + original.UNEXECUTED_OUTPUTS[name]:')
    consumer = one(consumer, 'bindings = original.check_original_bindings(get_json, identities, declarations)',
                   'bindings = original.check_original_bindings(get_json, identities, declarations, outcomes)')
    consumer = between(consumer, '    need(outcomes["qualification_failed01"]', '    need(helper.read(args.archive)[0] == archive_identity',
                       '''    need(outcomes["qualification01"]["original_positive_report_and_closed_native"] is True,
         "actual original qualification did not satisfy its complete source/log/native contract")
''')
    ast.parse(consumer)
    consumer_pin = put('verify_r29_qualification_ci_01.py', consumer.encode())
    root = '/home/qian/hepta-runtime-optimization-20261105-r29'
    native_paths = {'qualification01': 'qualification-terminal-status-01.json',
                    'rust_ci01': 'rust-ci-terminal-status-01.json', 'python_ci01': 'python-ci-terminal-status-01.json'}
    report_paths = {'qualification01': 'qualification-01/report.json', 'rust_ci01': 'rust-ci-01/report.json',
                    'python_ci01': 'python-ci-launch-01/receipt.json'}
    def unbound(path):
        return {'path': path, 'bytes': None, 'sha256': None}
    example = {'schema': 'hepta-r29-qualification-ci-export-input/v1', 'root': root,
               'actual_outcomes_supplied': False, 'adoption_decision_made_here': False,
               'native_raw_companion_required': True,
               'stages': {name: {'executed': None, 'job_id': None,
                    'native_terminal': unbound(root + '/' + native_paths[name]),
                    'report': unbound(root + '/' + report_paths[name]), 'reason': None} for name in native_paths},
               'preparation': unbound(root + '/preparation-01.json'),
               'source_map': unbound(root + '/qualification-01/source-map.json')}
    put('actual-export-input-01.example.json', (json.dumps(example, sort_keys=True, indent=2) + '\n').encode())
    reuse = {}
    for name in ('need', 'utc', 'descriptor', 'validate_terminal', 'omission_reason', 'report_projection'):
        assert function(source, name) == function(old, name)
        reuse[name] = {'byte_identical': True, **identity(function(source, name).encode())}
    consumer_reuse = {}
    for name in ('need', 'digest', 'local_read', 'reviewed', 'original_capture'):
        assert function(consumer, name) == function(old_consumer, name)
        consumer_reuse[name] = {'byte_identical': True, **identity(function(consumer, name).encode())}
    proof = {'schema': 'hepta-r29-qc-export-source-reuse/v1', 'origin': str(ORIGIN),
             'origin_files': {name: identity(raw) for name, raw in original.items()},
             'exporter_reused_functions': reuse, 'consumer_reused_functions': consumer_reuse,
             'stable_archive_helper_byte_identical': helper_pin,
             'canonical_byte_identical': identity(canonical),
             'changes': ['fixed R29 first qualification and Rust/Python first01 scope; no R28 retry/recovery assertions',
                         'actual canonical 2892 binding including transfer/source/two exact tests/counts1655+34',
                         'only actual positive CI reports receive the unchanged full producer/count/36-stream validation',
                         'unexecuted or negative CI states retained without manufacturing counts or success',
                         'fixed target-transfer receipt added; no original or moved cache traversal'],
             'executed_exporter_or_consumer_or_archive_or_workload': False,
             'actual_qualification_CI_or_performance_results_constructed': False, 'host_Git_actions': 0}
    put('source-reuse-proof-01.json', (json.dumps(proof, sort_keys=True, indent=2) + '\n').encode())
    patch = ''.join(difflib.unified_diff(old.splitlines(True), source.splitlines(True),
                    fromfile='r28/export_r28_qualification_ci_02.py', tofile='r29/export_r29_qualification_ci_01.py'))
    patch += ''.join(difflib.unified_diff(old_consumer.splitlines(True), consumer.splitlines(True),
                    fromfile='r28/verify_r28_qualification_ci_02.py', tofile='r29/verify_r29_qualification_ci_01.py'))
    put('source-delta-01.patch', patch.encode())
    print(json.dumps({'exporter': exporter_pin, 'consumer': consumer_pin, 'helper': helper_pin,
                      'actual_results': None, 'host_Git_actions': 0}, sort_keys=True))


if __name__ == '__main__':
    main()
