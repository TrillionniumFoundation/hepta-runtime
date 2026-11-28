"""Extend the frozen SDK registry at the actual handler-queue/sink boundary."""
from pathlib import Path
import ast, hashlib, json

SOURCE = Path(__file__).resolve().parents[1]
BASE = SOURCE / 'authoring'
SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def main():
    path = SOURCE / 'authoring/request_tasks.txt'
    baseline = SOURCE / 'authoring/request_tasks_v1.txt'
    old = baseline.read_text() if baseline.exists() else path.read_text()
    assert SHA(old.encode()) == '0fededa03fbc786bce760ee71fbc675543a25cfaf0d2acc6a2dbaac2bb071cbf'
    (SOURCE / 'authoring/request_tasks_v1.txt').write_text(old)
    nodes = ast.parse(old).body
    functions = {node.name: ast.get_source_segment(old, node) for node in nodes}
    changed = {}

    def replace(name, before, after):
        value = changed.get(name, functions[name])
        assert value.count(before) == 1, (name, before)
        changed[name] = value.replace(before, after)

    replace('entry', 'op > 12', 'op > 14')
    replace('entry', 'length(o) < 160', 'length(o) < 192')
    replace('entry', 'grow(o, 2, 160)', 'grow(o, 2, 192)')
    replace('entry', 'put(w, 72, 256)', 'put(w, 72, 256)\n        put(w, 120, 1)')
    replace('entry', '    if read64(s, 32) != 0 or read64(s, 40) != 0:',
        '    if op == 13:\n        return queue_response(s, o, w)\n'
        '    if op == 14:\n        if controls_zero(s) == False:\n            return INVALID\n'
        '        return claim_response(o, w)\n'
        '    if read64(s, 32) != 0 or read64(s, 40) != 0:')
    replace('admit', '(96 + size + 7)', '(112 + size + 7)')
    replace('admit', 'used + 96, start, size', 'used + 112, start, size')
    changed['handler_response'] = '''def handler_response(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if no_arguments(s) == False:
        return INVALID
    if get(w, 112) != 0:
        return BUSY
    if get(w, 24) == 1:
        if get(w, 56) != 0 or get(w, 152) != 0:
            return BUSY
    code = queue_response(s, o, w)
    if code != 192:
        return code
    return claim_response(o, w)'''
    replace('send_ack', '    put(w, row + 48, 0)',
        '    if get(w, row + 104) == 1 and get(w, 24) == 1:\n'
        '        if read64(s, 32) == 0:\n            put(w, 152, 1)\n'
        '    put(w, row + 104, 0)\n    put(w, row + 48, 0)')
    replace('drain_progress',
        '    if get(w, 48) != 0 or get(w, 56) != 0:\n'
        '        if read64(s, 32) < get(w, 96):\n            return reply(o, w, 6, 0)',
        '    if get(w, 152) == 0:\n'
        '        if get(w, 48) != 0 or get(w, 56) != 0 or get(w, 112) != 0:\n'
        '            if read64(s, 32) < get(w, 96):\n                return reply(o, w, 6, 0)')
    replace('retire', '    size = get(w, row)',
        '    if get(w, row + 96) != 0:\n        return BUSY\n    size = get(w, row)')
    replace('find_input_id', 'row + 96, size', 'row + 112, size')
    replace('equal_rows', 'first + 96 + i', 'first + 112 + i')
    replace('equal_rows', 'second + 96 + i', 'second + 112 + i')
    replace('reply', 'fill_range(o, 0, 160, 0)', 'fill_range(o, 0, 192, 0)')
    replace('reply', '    return 160',
        '    put(o, 160, get(w, 112))\n    put(o, 168, get(w, 120))\n'
        '    put(o, 176, get(w, 152))\n    return 192')
    extra = '''
def queue_response(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if no_arguments(s) == False:
        return INVALID
    row = find_generation(w, read64(s, 24))
    if row == 0 or get(w, row + 32) != 0:
        return BUSY
    ordinal = get(w, 120)
    if ordinal == 18446744073709551615:
        return RESOURCE
    put(w, row + 32, 1)
    put(w, row + 40, 1)
    put(w, row + 56, 0)
    put(w, row + 96, ordinal)
    put(w, 120, ordinal + 1)
    put(w, 48, get(w, 48) - 1)
    put(w, 112, get(w, 112) + 1)
    advance(w)
    return reply(o, w, 12, read64(s, 24))

def claim_response(o:mutbuf, w:mutbuf) -> u32:
    if get(w, 24) == 1:
        if get(w, 56) != 0 or get(w, 152) != 0:
            return reply(o, w, 14, 0)
    row = first_queued(w)
    if row == 0:
        return reply(o, w, 13, 0)
    put(w, row + 96, 0)
    put(w, 112, get(w, 112) - 1)
    selected = find_row_id(w, row)
    if selected == 0 or get(w, 24) == 2:
        advance(w)
        return reply(o, w, 5, get(w, row + 8))
    put(w, selected + 16, 0)
    cancel_context(w, selected)
    put(w, 40, get(w, 40) - 1)
    put(w, row + 48, 1)
    put(w, row + 104, get(w, 24))
    put(w, 56, get(w, 56) + 1)
    advance(w)
    return reply(o, w, 4, get(w, row + 8))

def first_queued(w:mutbuf) -> u64:
    row = 256
    chosen = 0
    ordinal = 18446744073709551615
    while row < get(w, 72):
        current = get(w, row + 96)
        if current != 0 and current < ordinal:
            ordinal = current
            chosen = row
        row = row + get(w, row)
    return chosen
'''
    new = '\n\n'.join(changed.get(node.name, functions[node.name]) for node in nodes) + '\n\n' + extra.lstrip()
    old_ast = {node.name: ast.dump(node, include_attributes=False) for node in nodes}
    new_ast = {node.name: ast.dump(node, include_attributes=False) for node in ast.parse(new).body}
    same = sorted(name for name in old_ast if old_ast[name] == new_ast[name])
    assert set(old_ast) - set(same) == set(changed)
    path.write_text(new)
    author = SOURCE / 'authoring/author_registry.py'
    text = (SOURCE / 'authoring/author_registry_v1.py').read_text()
    for before, after in [('HRTKRQ01', 'HRTKRQ02'), ('HRTKRS01', 'HRTKRS02'), ('HRTKST01', 'HRTKST02')]:
        assert text.count(before) == 1
        text = text.replace(before, after)
    author.write_text(text)
    for name in ['sdk_request_task_registry.hepta', 'sdk_request_task_composition.json']:
        (SOURCE / 'native' / name).unlink(missing_ok=True)
    proof = dict(schema='hepta.sdk-request-task-queue.delta.v1', baseline_sha256=SHA(old.encode()),
        output_sha256=SHA(new.encode()), retained_exact_ast=same, changed_functions=sorted(changed),
        added_functions=['queue_response', 'claim_response', 'first_queued'],
        output_bytes=192, row_header_bytes=112, request_magic='HRTKRQ02',
        response_magic='HRTKRS02', state_magic='HRTKST02',
        queue_policy_owner='HIA', expected_wire_read_as_implementation=False)
    (BASE / 'QUEUE_DELTA.json').write_text(json.dumps(proof, indent=2, sort_keys=True) + '\n')
    print(json.dumps(proof, sort_keys=True))


if __name__ == '__main__':
    main()
