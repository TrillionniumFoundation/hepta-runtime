"""Declared installed surface and unchanged catalog ABI domains, without wires."""
from __future__ import annotations

import json
import struct

TARGET = 'd3d75c30719db966b004756f610007a7c723729e'
COMPILER = 'd3e2c90173cf733e42b299d0c4274df4b593a12f'
BASE_TOOLS = (
    'host_list', 'effective_config', 'execution_shadow_admit', 'view', 'workdir',
    'directory_create', 'file_move', 'directory_move', 'text_editor',
)
ADDED_TOOLS = ('batch_edit', 'weight_bellman_plan')
SELECTED_TOOLS = tuple(sorted((*BASE_TOOLS, *ADDED_TOOLS)))
FLAGS = (0, 1, 3, 5, 7, 9, 11, 13, 15)
VERSIONS = (None, '2024-11-05', '2025-03-26', '2025-06-18', '2025-11-25',
            '2026-07-27', '2026-07-28', '2026-08-01')
PROFILE = 'history.v1'
LIST_OPERATION = 1
FIXED_RUNTIME_FLAGS = 1
INVALID = 0xffffffff
CAPACITY = 0xfffffffe
GROW = 0xffffffd0


def frame(operation, argument, payload=b''):
    return b'HRMCD002' + struct.pack('<2Q', operation, argument) + payload


def retained_non_list():
    """All 18 original non-list opcode/argument branches remain executable."""
    values = []
    for argument in range(1, 5):
        values.append((f'op2-{argument}', frame(2, argument)))
    for argument in range(1, 4):
        values.append((f'op3-{argument}', frame(3, argument)))
    message = json.dumps('owned detail: "quote", \\ path, newline\n and Ω', ensure_ascii=False).encode()
    values.append(('op4-dynamic-json-string', frame(4, len(message), message)))
    for argument in range(2):
        values.append((f'op5-{argument}', frame(5, argument)))
    for argument in range(1, 9):
        values.append((f'op6-{argument}', frame(6, argument)))
    assert len(values) == 18
    return values


def specification():
    return {'schema': 'hepta.runtime.public-eleven-catalog-domain.v1',
        'target_commit': TARGET, 'compiler_commit': COMPILER,
        'baseline_tools': list(BASE_TOOLS), 'added_tools': list(ADDED_TOOLS),
        'target_router_order': list(SELECTED_TOOLS), 'policy_flags': list(FLAGS),
        'protocol_versions': list(VERSIONS), 'cursor_variants': 3,
        'actual_original_handler_comparisons': 216, 'distinct_policy_inputs': 18,
        'fixed_slot': 0, 'request_magic': 'HRMCD002', 'reply_magic': 'HRCATR02',
        'entry_return_bytes': 32, 'list_operation': LIST_OPERATION,
        'fixed_runtime_flags': FIXED_RUNTIME_FLAGS, 'modern_words': [0, 1],
        'non_list': [{'name': name, 'input_hex': raw.hex()} for name, raw in retained_non_list()],
        'output_capacity_edges': ['0', '31', '32', '33', 'required-1', 'required', 'required+1'],
        'workspace_capacity_edges': ['0', '4095', '4096', 'required-1', 'required', 'required+1'],
        'full_input_output_workspace_required': True,
        'public_all_configuration_qualified': False, 'full_136_route_qualified': False,
        'public_async_qualified': False, 'whole_runtime_replaced': False}
