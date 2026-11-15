#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Bind unchanged A46 workloads to a new complete ordinary A48 qualification.

Does not run a workload. A46 failed results and files remain untouched. The
numeric gates, call inventory, original child custody and deadlines stay fixed.
The original qualification loader's six-stage ordinary branch verifies A48;
the final A48 guardian entry and worker are additionally pinned, copied and fenced.
"""
import argparse
import ast
import copy
import difflib
import hashlib
import json
import stat
from pathlib import Path

ROOT = Path(__file__).absolute().parent
TEMPLATES = ROOT / 'a46-bound'
BASE = '/home/qian/hepta-runtime-optimization-20261023/a41-phase-timing-20261025-r01'
QDIR = BASE + '/qualification-a48-page-fullscan-r01'
SOURCE = BASE + '/source-a48-page-fullscan-r01'
ENTRY = BASE + '/a48-page-fullscan-entry-r01/entry-report.json'
ENTRY_SCHEMA = 'hepta-a48-page-fullscan-qualification-entry/v1'
WORKER = BASE + '/a48-page-fullscan-entry-r01/worker-report.json'
WORKER_SCHEMA = 'hepta-a48-page-fullscan-guarded-qualifier-worker/v1'
LEGACY = 'runtime-candidate-qualification/v1'
PINS = {
    'run_small_archive_a46_composed_r01.py': 'e3308a8f0dfa2966d57402e3591e7e3f6fa7367cbf5f169fdcdb030e6d9388c5',
    'run_native_archive_cohort_a46_composed_r01.py': 'a007f0ff0dee7ed5e981953a440070aa3bbb6980662c968ecd2bbdd7ebc8e029',
    'evaluate_small_archive_a46_composed_r01.py': '4f14ed204765dfa3afb76653f422411212d4a874d714b678652ae3b2125a7442',
    'small-archive-a46-composed-r01.protocol.json': '3c51e1a579df39327022bc879de4b4d8e799555c15ba3839f2ed80227cea64ff',
    'native-archive-cohort-a46-composed-r01.protocol.json': 'e197b94d1e797ca367a5dbe93b7679fccefbc0aef9becf383e2a9c2f17cea90e',
}


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def replace(text, old, new, count=1):
    need(text.count(old) == count, 'binding occurrence differs: ' + repr(old))
    return text.replace(old, new)


def relabel(value):
    if isinstance(value, str):
        return value.replace('A42', 'A48').replace('a46-small-archive-comparison-r01',
            'a48-small-archive-comparison-r01').replace('a46-native-archive-cohort-r01',
            'a48-native-archive-cohort-r01').replace('hepta-a42-', 'hepta-a48-')
    if isinstance(value, list):
        return [relabel(v) for v in value]
    if isinstance(value, dict):
        return {relabel(k): relabel(v) for k, v in value.items()}
    return value


def entry_condition():
    return ("entry['schema'] == ENTRY_SCHEMA and entry['qualified'] is True\n"
            "             and entry['passed'] is True and entry['guarded_qualification_complete'] is True\n"
            "             and entry['parent_unchanged_after_attempt'] is True\n"
            "             and entry['reused_dependencies_unchanged'] is True\n"
            "             and not entry.get('error') and not entry.get('errors')")


def worker_condition():
    return ("worker['schema'] == WORKER_SCHEMA and worker['passed'] is True\n"
            "             and worker['strict_fresh_artifacts_verified'] is True\n"
            "             and worker['required_test_coverage_verified'] is True\n"
            "             and worker['reused_dependencies_unchanged'] is True\n"
            "             and not worker.get('error') and not worker.get('errors')")


def bound_receipt(value, path, raw):
    row = {key: value[key] for key in ('path', 'bytes', 'sha256', 'identity')}
    fields = row['identity']
    need(row['path'] == path and type(row['bytes']) is int and row['bytes'] == len(raw)
         and row['sha256'] == sha(raw), 'guardian receipt differs from actual captured body: ' + path)
    need(type(fields) is list and len(fields) == 9 and all(type(v) is int and v >= 0 for v in fields)
         and stat.S_ISREG(fields[2]) and fields[5] == 1 and fields[6] == len(raw),
         'complete regular-file stat9 receipt required: ' + path)
    return row


def guardian_chain_checks(indent, module, qreceipt, wreceipt, mapping):
    lines = [
        "for ref in (entry['qualification_report'], worker['qualifier_report'],",
        "            worker['strict_fresh_artifact_evidence']['qualification_report']):",
        "    need(" + module + ".same_receipt(ref, " + qreceipt + "), 'guardian qualification receipt differs')",
        "need(" + module + ".same_receipt(entry['guarded_worker_report'], " + wreceipt + "),",
        "     'guardian final worker receipt differs')",
        "if 'worker_report' in entry:",
        "    need(" + module + ".same_receipt(entry['worker_report'], " + wreceipt + "),",
        "         'guardian optional worker receipt differs')",
        "need(entry['source_after'] == " + mapping + ", 'guardian/candidate source differs')",
    ]
    return ''.join(' ' * indent + line + '\n' for line in lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qualification-file', type=Path, required=True)
    parser.add_argument('--expected-qualification-sha256', required=True)
    parser.add_argument('--entry-file', type=Path, required=True)
    parser.add_argument('--expected-entry-sha256', required=True)
    parser.add_argument('--worker-file', type=Path, required=True)
    parser.add_argument('--expected-worker-sha256', required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    qraw, eraw, wraw = (args.qualification_file.read_bytes(), args.entry_file.read_bytes(),
                       args.worker_file.read_bytes())
    need(sha(qraw) == args.expected_qualification_sha256 and sha(eraw) == args.expected_entry_sha256
         and sha(wraw) == args.expected_worker_sha256, 'actual report or guardian SHA differs')
    q, entry, worker = json.loads(qraw), json.loads(eraw), json.loads(wraw)
    need(q['schema'] == LEGACY and q['qualified'] is True and q['current_stage'] == 'complete'
         and not q.get('error') and q['source'] == SOURCE, 'complete ordinary A48 qualification required')
    need(entry['schema'] == ENTRY_SCHEMA and entry['qualified'] is True and entry['passed'] is True
         and entry['guarded_qualification_complete'] is True and entry['parent_unchanged_after_attempt'] is True
         and entry['reused_dependencies_unchanged'] is True
         and not entry.get('error') and not entry.get('errors'), 'complete independent A48 guardian required')
    need(worker['schema'] == WORKER_SCHEMA and worker['passed'] is True
         and worker['strict_fresh_artifacts_verified'] is True and worker['required_test_coverage_verified'] is True
         and worker['reused_dependencies_unchanged'] is True
         and not worker.get('error') and not worker.get('errors'), 'complete final A48 worker postchecks required')
    qreceipt = bound_receipt(entry['qualification_report'], QDIR + '/report.json', qraw)
    for ref in (worker['qualifier_report'], worker['strict_fresh_artifact_evidence']['qualification_report']):
        need(bound_receipt(ref, QDIR + '/report.json', qraw) == qreceipt,
             'entry and worker refer to different original qualification receipts')
    wreceipt = bound_receipt(entry['guarded_worker_report'], WORKER, wraw)
    if 'worker_report' in entry:
        need(bound_receipt(entry['worker_report'], WORKER, wraw) == wreceipt,
             'optional entry worker receipt differs')
    mapping = q['source_tested']
    need(len(mapping) == 168 and mapping == q['source_after'] == entry['source_after'],
         'complete 168-file tested/after/guardian maps differ')
    prepared = q['source_input']
    need(type(prepared) is dict and set(prepared) == set(mapping), 'complete prepared source inventory differs')
    need([s['name'] for s in q['stages']] == ['format', 'fmt-check', 'clean-package', 'clippy', 'test', 'release']
         and all(type(s['returncode']) is int and s['returncode'] == 0 for s in q['stages']),
         'all six actual original stages required')
    need(q['binary']['path'] == QDIR + '/hepta-runtime' and q['binary']['cached'] is False
         and q['test_binary']['cached'] is False, 'fresh stable A48 artifacts required')
    map_sha = sha(json.dumps(mapping, sort_keys=True, separators=(',', ':')).encode())
    prepared_sha = sha(json.dumps(prepared, sort_keys=True, separators=(',', ':')).encode())
    originals = {}
    for name, expected in PINS.items():
        raw = (TEMPLATES / name).read_bytes()
        need(sha(raw) == expected, 'frozen A46 template changed: ' + name)
        originals[name] = raw.decode()
    need(not args.out.exists(), 'new output directory required')
    args.out.mkdir(mode=0o700)
    outputs, diffs = {}, {}

    def emit(name, value, original=None):
        raw = value if isinstance(value, bytes) else value.encode()
        if name.endswith('.py'):
            ast.parse(raw)
        with (args.out / name).open('xb') as stream:
            stream.write(raw)
        outputs[name] = {'bytes': len(raw), 'sha256': sha(raw)}
        if original is not None:
            diffs[name] = ''.join(difflib.unified_diff(original.splitlines(True), raw.decode().splitlines(True),
                fromfile='retained-A46', tofile=name))

    entry_pin = {'path': ENTRY, 'bytes': len(eraw), 'sha256': sha(eraw), 'schema': ENTRY_SCHEMA}
    worker_pin = {'path': WORKER, 'bytes': len(wraw), 'sha256': sha(wraw), 'schema': WORKER_SCHEMA}
    protocols = {}
    for kind, stem in (('small', 'small-archive'), ('large', 'native-archive-cohort')):
        old = json.loads(originals[stem + '-a46-composed-r01.protocol.json'])
        value = relabel(copy.deepcopy(old))
        key = 'A48' if kind == 'small' else 'B'
        binding = value['bindings'][key]
        binding.update(qualification_path=QDIR + '/report.json', qualification_sha256=sha(qraw),
            qualification_schema=LEGACY, source_files=168, source_map_compact_sha256=map_sha,
            prepared_source_map_compact_sha256=prepared_sha,
            release_sha256=q['binary']['sha256'], qualification_state='all six newly completed A48 stages')
        binding.pop('composition_kind', None)
        value['continuation'] = entry_pin
        value['qualification_worker'] = worker_pin
        value['binding_state'] = 'Pinned complete A48 ordinary qualification and final guardian entry/worker postchecks; no performance result implied.'
        value['prior_failed_a46_report_sha256'] = 'f27bd56b054449768fe052749ae414b52114ada53890cbf5a8574612b0cd575b'
        value['prior_failed_a46_result_retained'] = True
        if kind == 'large':
            value['lineage'] = 'r07 versus A48 page fullscan; all six A48 qualification stages completed; A46 failed measurements remain separate.'
        gates = 'regression_gates' if kind == 'small' else 'numeric_gates'
        need(value[gates] == old[gates], 'fixed numerical gates changed')
        name = stem + '-a48-r01.protocol.json'
        emit(name, canonical(value))
        protocols[kind] = (name, outputs[name]['sha256'])

    constants = ('ENTRY_PATH = BASE / ' + repr(ENTRY[len(BASE)+1:]) + '\n'
        + 'ENTRY_SHA = ' + repr(sha(eraw)) + '\nENTRY_BYTES = ' + repr(len(eraw))
        + '\nENTRY_SCHEMA = ' + repr(ENTRY_SCHEMA) + '\n'
        + 'WORKER_PATH = BASE / ' + repr(WORKER[len(BASE)+1:]) + '\n'
        + 'WORKER_SHA = ' + repr(sha(wraw)) + '\nWORKER_BYTES = ' + repr(len(wraw))
        + '\nWORKER_SCHEMA = ' + repr(WORKER_SCHEMA) + '\n')
    for kind, stem in (('small', 'run_small_archive'), ('large', 'run_native_archive_cohort')):
        original = originals[stem + '_a46_composed_r01.py']
        code = relabel(original)
        code = replace(code, "PROTOCOL_SHA = '" + PINS[('small-archive' if kind == 'small' else 'native-archive-cohort') + '-a46-composed-r01.protocol.json'] + "'",
            'PROTOCOL_SHA = ' + repr(protocols[kind][1]) + '\n' + constants)
        if kind == 'small':
            code = replace(code, "'qualification-a46-a42-release-completion-r01/report.json'", "'qualification-a48-page-fullscan-r01/report.json'")
            code = replace(code, "'small-archive-a46-composed-r01.protocol.json'", "'small-archive-a48-r01.protocol.json'")
            anchor = "        for version, path in QUALIFICATIONS.items():\n"
            hook = ("        report['qualification_entry'], entry_raw = pin(ENTRY_PATH, ENTRY_SHA, 'qualification-entry.original.json')\n"
                    "        report['qualification_worker'], worker_raw = pin(WORKER_PATH, WORKER_SHA, 'qualification-worker.original.json')\n"
                    "        need(len(entry_raw) == ENTRY_BYTES and len(worker_raw) == WORKER_BYTES, 'original guardian length differs')\n"
                    "        entry, worker = json.loads(entry_raw), json.loads(worker_raw)\n"
                    "        need(" + entry_condition() + ", 'original A48 guardian is incomplete')\n"
                    "        need(" + worker_condition() + ", 'original A48 worker postchecks are incomplete')\n")
            code = replace(code, anchor, hook + anchor)
            code = replace(code, "            pin(path, expected['qualification_sha256'])\n",
                "            qualified_receipt, qualified_raw = pin(path, expected['qualification_sha256'])\n")
            anchor = "            bundles[version] = bundle\n"
            hook = ("            if version == 'A48':\n"
                    "                need(qualification_chain.same_receipt(qualified_receipt, bundle['report']), 'loaded qualification receipt changed')\n"
                    "                prepared = json.loads(qualified_raw)['source_input']\n"
                    "                need(set(prepared) == set(bundle['source_map'])\n"
                    "                     and qualification_chain.map_sha(prepared) == expected['prepared_source_map_compact_sha256'],\n"
                    "                     'prepared candidate source binding differs')\n"
                    + guardian_chain_checks(16, 'qualification_chain', "bundle['report']", "report['qualification_worker']", "bundle['source_map']"))
            code = replace(code, anchor, hook + anchor)
        else:
            anchor = "        for arm in ('A', 'B'):\n"
            hook = ("        entry_receipt, entry_raw = bytes_receipt(ENTRY_PATH, maximum=1024 * 1024, keep=True)\n"
                    "        worker_receipt, worker_raw = bytes_receipt(WORKER_PATH, maximum=1024 * 1024, keep=True)\n"
                    "        need(entry_receipt['sha256'] == ENTRY_SHA and worker_receipt['sha256'] == WORKER_SHA\n"
                    "             and len(entry_raw) == ENTRY_BYTES and len(worker_raw) == WORKER_BYTES, 'original A48 guardian pin differs')\n"
                    "        entry, worker = document(entry_raw), document(worker_raw)\n"
                    "        need(" + entry_condition() + ", 'original A48 guardian is incomplete')\n"
                    "        need(" + worker_condition() + ", 'original A48 worker postchecks are incomplete')\n"
                    "        inputs.extend((entry_receipt, worker_receipt))\n"
                    "        create(out / 'qualification-entry.original.json', entry_raw)\n"
                    "        create(out / 'qualification-worker.original.json', worker_raw)\n"
                    "        report['qualification_entry'], report['qualification_worker'] = entry_receipt, worker_receipt\n")
            code = replace(code, anchor, hook + anchor)
            code = replace(code, "            pinned = bytes_receipt(path)\n",
                "            pinned, qualified_raw = bytes_receipt(path, keep=True)\n")
            anchor = "            bundles[arm] = bundle\n"
            hook = ("            if arm == 'B':\n"
                    "                need(qualification_chain.same_receipt(pinned, bundle['report']), 'loaded qualification receipt changed')\n"
                    "                prepared = document(qualified_raw)['source_input']\n"
                    "                need(set(prepared) == set(bundle['source_map'])\n"
                    "                     and qualification_chain.map_sha(prepared) == binding['prepared_source_map_compact_sha256'],\n"
                    "                     'prepared candidate source binding differs')\n"
                    + guardian_chain_checks(16, 'qualification_chain', "bundle['report']", 'worker_receipt', "bundle['source_map']"))
            code = replace(code, anchor, hook + anchor)
        # All measurement/custody helpers must remain identical after labels.
        old_nodes = {n.name: ast.dump(n, include_attributes=False) for n in ast.parse(relabel(original)).body
            if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name != 'main'}
        new_nodes = {n.name: ast.dump(n, include_attributes=False) for n in ast.parse(code).body
            if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name != 'main'}
        need(old_nodes == new_nodes, 'measurement or owned-child helper changed')
        emit(stem + '_a48_r01.py', code, original)

    original = originals['evaluate_small_archive_a46_composed_r01.py']
    code = relabel(original)
    code = code.replace('/qualification-a46-a42-release-completion-r01/report.json', '/qualification-a48-page-fullscan-r01/report.json')
    code = code.replace('/source-a42-fresh-cohort-r03', '/source-a48-page-fullscan-r01')
    code = replace(code, "COMPOSED_SCHEMA = 'hepta-runtime-composed-qualification/v1'\n",
        "COMPOSED_SCHEMA = 'hepta-runtime-composed-qualification/v1'\nENTRY_PATH = " + repr(ENTRY)
        + "\nENTRY_SHA = " + repr(sha(eraw)) + "\nENTRY_BYTES = " + repr(len(eraw))
        + "\nENTRY_SCHEMA = " + repr(ENTRY_SCHEMA) + "\nWORKER_PATH = " + repr(WORKER)
        + "\nWORKER_SHA = " + repr(sha(wraw)) + "\nWORKER_BYTES = " + repr(len(wraw))
        + "\nWORKER_SCHEMA = " + repr(WORKER_SCHEMA) + "\n")
    code = replace(code, "and new['source_files'] == 168 and new['qualification_schema'] == COMPOSED_SCHEMA\n         and new['composition_kind'] == COMPOSITION_KIND",
        "and new['source_files'] == 168 and new['qualification_schema'] == LEGACY_SCHEMA\n         and 'composition_kind' not in new")
    code = replace(code, "        if version == 'r07':\n            need(q['schema'] == LEGACY_SCHEMA", "        if version in ('r07', 'A48'):\n            need(q['schema'] == LEGACY_SCHEMA")
    anchor = "    need(new['release_sha256'] != old['release_sha256'], 'candidate release is not distinct')\n"
    hook = ("    need(exact(protocol['continuation'], {'path': ENTRY_PATH, 'bytes': ENTRY_BYTES, 'sha256': ENTRY_SHA, 'schema': ENTRY_SCHEMA})\n"
            "         and exact(protocol['qualification_worker'], {'path': WORKER_PATH, 'bytes': WORKER_BYTES, 'sha256': WORKER_SHA, 'schema': WORKER_SCHEMA}),\n"
            "         'final guardian entry/worker protocol pins differ')\n"
            "    need(type(new['prepared_source_map_compact_sha256']) is str\n"
            "         and HEX.fullmatch(new['prepared_source_map_compact_sha256']), 'prepared source pin missing')\n")
    code = replace(code, anchor, anchor + hook)
    anchor = "    return result\n\n\ndef validate_host("
    hook = ("    entry_receipt, worker_receipt = outer['qualification_entry'], outer['qualification_worker']\n"
            "    need(entry_receipt['path'] == ENTRY_PATH and entry_receipt['sha256'] == ENTRY_SHA and entry_receipt['bytes'] == ENTRY_BYTES\n"
            "         and worker_receipt['path'] == WORKER_PATH and worker_receipt['sha256'] == WORKER_SHA and worker_receipt['bytes'] == WORKER_BYTES,\n"
            "         'original guardian entry/worker binding differs')\n"
            "    for receipt in (entry_receipt, worker_receipt):\n"
            "        module.normalized_receipt(receipt)\n"
            "        need(sum(exact(item, receipt) for item in outer['original_inputs']) == 1, 'guardian receipt missing from original-input fences or duplicated')\n"
            "    entry = inputs.document(inputs.root / 'qualification-entry.original.json', entry_receipt)\n"
            "    worker = inputs.document(inputs.root / 'qualification-worker.original.json', worker_receipt)\n"
            "    need(" + entry_condition() + ", 'original A48 guardian evidence failed')\n"
            "    need(" + worker_condition() + ", 'original A48 worker postchecks failed')\n"
            + guardian_chain_checks(4, 'module', "outer['qualifications']['A48']['report']", 'worker_receipt', "outer['qualifications']['A48']['source_map']")
            + "    need(set(q['source_input']) == set(q['source_tested'])\n"
            "         and digest(compact(q['source_input'])) == protocol['bindings']['A48']['prepared_source_map_compact_sha256'],\n"
            "         'captured qualification prepared source binding differs')\n"
            "    result['A48']['separate_guardian_receipt_verified'] = True\n"
            "    result['A48']['final_worker_postchecks_verified'] = True\n")
    code = replace(code, anchor, hook + anchor)
    code = replace(code, 'hepta-a46-small-composed-report-numeric-evaluation/v1', 'hepta-a48-small-ordinary-report-numeric-evaluation/v1')
    old_nodes = {n.name: ast.dump(n, include_attributes=False) for n in ast.parse(relabel(original)).body
        if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name not in ('validate_protocol', 'validate_qualifications')}
    new_nodes = {n.name: ast.dump(n, include_attributes=False) for n in ast.parse(code).body
        if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name not in ('validate_protocol', 'validate_qualifications')}
    # Only main's output schema string differs in addition to two admission functions.
    old_nodes.pop('main', None); new_nodes.pop('main', None)
    need(old_nodes == new_nodes, 'numeric evaluator algorithm changed')
    emit('evaluate_small_archive_a48_r01.py', code, original)
    emit('binding-diff.txt', '\n'.join(diffs.values()))
    emit('binding-manifest.json', canonical({'schema': 'hepta-a48-benchmark-binding/v1',
        'qualification_sha256': sha(qraw), 'entry': entry_pin, 'worker': worker_pin,
        'qualification_receipt': qreceipt, 'worker_receipt': wreceipt,
        'source_map_sha256': map_sha, 'prepared_source_map_sha256': prepared_sha,
        'release_sha256': q['binary']['sha256'], 'source_files': 168, 'template_pins': PINS,
        'outputs': dict(outputs), 'measurement_helpers_ast_unchanged_after_label_binding': True,
        'numeric_algorithms_unchanged': True, 'benchmark_executions': 0,
        'prior_a46_failed_comparison_preserved': True}))
    print(json.dumps({'out': str(args.out), 'outputs': outputs, 'benchmark_executions': 0}))


if __name__ == '__main__':
    main()
