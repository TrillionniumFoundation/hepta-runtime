#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Construct D2-only adapter preparation; never import or execute target code."""
import ast
import hashlib
import json
from pathlib import Path

BASE = Path('/tmp/hepta-runtime-recovery-20261106')
OUT = Path(__file__).parent
ORIGINAL = BASE / 'd1-c1-parent-template-05/run_c1_phase_cost.unsealed.py'
INTERPRETER = BASE / 'd1-c1-offline-interpretation-01/interpret_c1.py'
ROOT = '/home/qian/hepta-runtime-validation-cost-20261106-d2'

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def create(name, raw):
    path = OUT / name
    with path.open('xb') as stream:
        stream.write(raw)
    assert path.read_bytes() == raw
    return {'path': name, 'bytes': len(raw), 'sha256': digest(raw)}

def source_functions(raw):
    text = raw.decode()
    lines = text.splitlines(keepends=True)
    return {node.name: ''.join(lines[node.lineno - 1:node.end_lineno])
            for node in ast.parse(text).body if isinstance(node, ast.FunctionDef)}

def main():
    original = ORIGINAL.read_bytes()
    interpreter = INTERPRETER.read_bytes()
    assert digest(interpreter) == '7857a1f8960e82cbb1ba7700c1e805b87f7363cf5d8c3fecf32c5ebbf0dfa870'
    functions = source_functions(interpreter)
    names = ('need', 'uint', 'sha', 'json_object', 'canonical', 'transport_calls',
             'phase_values', 'correlate', 'aggregate', 'measured_counter')
    header = '''#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Pure D2 trace correlation copied from the completed D1 offline interpretation.

These definitions perform no process launch, host call, archive extraction,
native auditor execution or runtime mutation. The adapter supplies only its
already closed controller's byte-bound original raw transport/index inputs.
"""
from collections import defaultdict
import hashlib
import json

ROOT = "/home/qian/hepta-runtime-validation-cost-20261106-d2"
HOSTS = {"ai395", "mac", "main", "pocket4", "rog", "x230"}
TOOLS = {"process_status", "process_read"}

'''
    helper = (header + '\n\n'.join(functions[name] for name in names) + '\n').encode()
    ast.parse(helper)
    helper_pin = create('correlate_trace.py', helper)
    select = (OUT / 'select_trace.fragment.py').read_text()
    ast.parse(select)
    text = original.decode()
    before = source_functions(original)
    assert text.count(before['select_trace']) == 1
    text = text.replace(before['select_trace'], select.rstrip())
    substitutions = {
        'Unsealed D1 C1 adapter': 'Unsealed D2 C1 adapter',
        '/home/qian/hepta-runtime-phase-cost-20261106-d1': ROOT,
        'hepta-d1-': 'hepta-d2-',
        '/home/qian/hd1c01': '/home/qian/hd2c01',
        '_hepta_d1_': '_hepta_d2_',
        'D1 C1 adapter': 'D2 C1 adapter',
        'D1 input': 'D2 input',
        'D1 output': 'D2 output',
        'outside D1': 'outside D2',
    }
    for old, new in substitutions.items():
        text = text.replace(old, new)
    old = 'REFERENCE = {\n'
    assert text.count(old) == 1
    text = text.replace(old, old + '    "correlate_trace.py": (' + str(helper_pin['bytes'])
                        + ', "' + helper_pin['sha256'] + '"),\n')
    old = '"_hepta_d2_original_wrapper", "_hepta_d2_trace_parser")'
    assert text.count(old) == 1
    text = text.replace(old, '"_hepta_d2_original_wrapper", "_hepta_d2_trace_parser",\n'
                        '           "_hepta_d2_trace_correlation")')
    old = '    before_boot = boot_id()\n'
    assert text.count(old) == 1
    text = text.replace(old, old + '    output["boot_id_before"] = before_boot\n')
    old = '        parser = loader("_hepta_d2_trace_parser", "summarize_trace.py")\n'
    assert text.count(old) == 1
    text = text.replace(old, old + '        correlation = loader("_hepta_d2_trace_correlation", "correlate_trace.py")\n')
    old = 'select_trace(controller, parser, bench, before_boot, all_done_ns, next_start)'
    assert text.count(old) == 1
    text = text.replace(old, 'select_trace(controller, parser, bench, before_boot, all_done_ns, next_start, correlation)')
    old = '        need(len(output["traces"]) == 8, "trace matrix is incomplete")\n'
    assert text.count(old) == 1
    text = text.replace(old, old + '''        selected = [item for trace in output["traces"] for item in trace["selected_on_requests"]]
        native_ids = [item["trace_native_request_id"] for item in selected]
        need(len(selected) == 468 and len(set(native_ids)) == 468,
             "ON native identities are incomplete or reused across controller generations")
        need(sum(item["category"] == "measured" for item in selected) == 384,
             "ON measured request coverage is incomplete")
        output["strict_on_request_bijection_count"] = len(selected)
        output["measured_on_request_count"] = 384
        output["measured_phase_summary"] = correlation.aggregate(
            [item for item in selected if item["category"] == "measured"], parser)
        output["wire_native_request_id_policy"] = "absent on original status/read responses; never synthesized"
        output["validation_whole_cost_field"] = "inclusive CPU of validation_worker and validation_owner"
''')
    ast.parse(text)
    assert 'SPEC = None\n' in text
    after = source_functions(text.encode())
    changed = sorted(name for name in before if before[name] != after[name])
    # Changed functions are explicitly enumerated; the original controller,
    # workload cell, close, subprocess and resource modules remain unchanged.
    assert changed == ['main', 'original_modules', 'require_sealed', 'select_trace']
    out_pin = create('run_c1_phase_cost.unsealed.py', text.encode())
    manifest = {
        'schema': 'hepta-d2-c1-adapter-source-construction/v1',
        'sealed': False,
        'source_root': ROOT,
        'original_adapter_template': {'path': str(ORIGINAL), 'bytes': len(original), 'sha256': digest(original)},
        'completed_d1_interpreter': {'path': str(INTERPRETER), 'bytes': len(interpreter), 'sha256': digest(interpreter)},
        'exact_reused_helper_functions': {name: {'bytes': len(functions[name].encode()),
            'sha256': digest(functions[name].encode())} for name in names},
        'unchanged_original_adapter_functions': sorted(set(before) - set(changed)),
        'changed_original_adapter_functions': changed,
        'files': [helper_pin, out_pin],
        'pending_actual_bindings': ['D2 frozen parser bytes/hash', 'D2 qualification/CI/ordinary receipts',
                                    'D2 exact qualified source/ELF', 'D2 parent sealed input'],
        'old_parser_pin_retained_only_as_unsealed_placeholder': True,
        'target_modules_executed': False,
        'host_calls': 0,
        'original_workload_replayed': False,
        'performance_acceptance_claim': False,
    }
    create('source-construction.json', (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode())
    print(json.dumps({'constructed': True, 'sealed': False, 'files': manifest['files'],
                      'exact_reused_helper_functions': len(names), 'changed_functions': changed}))

if __name__ == '__main__':
    main()
