"""Add the public connection-to-task admission seam to the frozen queue owner.

Only the HIA owner selects bootstrap, request, notification, and ignored input.
The host supplies the complete current G1 borrow and the before/after modes
observed from the actual current G2 owner. No JSON fields are decoded here.
"""
from pathlib import Path
import argparse, ast, hashlib, json, sys

SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('baseline', 'output', 'hepta'):
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    base = a.baseline.resolve(strict=True)
    out = a.output.resolve(strict=True)
    source = (base / 'native/sdk_request_task_registry.hepta').read_bytes()
    assert SHA(source) == '483459f6cb5788d7c110e8d650af73f35e5e6ce3782a18d0f1f5ebe51e999892'
    comp = json.loads((base / 'native/sdk_request_task_composition.json').read_bytes())
    old = (base / 'authoring/request_tasks.txt').read_text()
    nodes = {n.name: ast.get_source_segment(old, n) for n in ast.parse(old).body}
    entry = nodes['entry'].replace('op > 14', 'op > 15')
    entry = entry.replace('if op > 2 and read64(s, 48) != 0:',
        'if op > 2 and op != 15 and read64(s, 48) != 0:')
    entry = entry.replace('    if op == 1:\n',
        '    if op == 15:\n        return observe_message(s, o, w)\n    if op == 1:\n', 1)
    admit = nodes['admit'].replace('controls_zero(s)', 'message_controls(s)', 1)
    notification = nodes['notification'].replace('controls_zero(s)', 'message_controls(s)', 1)
    extra = '''
def message_controls(s:readbuf) -> bool:
    if read64(s, 8) != 15:
        return controls_zero(s)
    if read64(s, 24) != 0 or read64(s, 32) > 3:
        return False
    return read64(s, 40) <= 3

def observe_message(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if message_controls(s) == False:
        return INVALID
    if read64(s, 48) < 256:
        return INVALID
    kind = read64(s, 72)
    if message_header(s, kind) == False or kind > 4:
        return INVALID
    before = read64(s, 32)
    after = read64(s, 40)
    if before == 3:
        return reply(o, w, 16, 0)
    if kind == 1:
        if before == 0 and after != 2:
            return reply(o, w, 15, 0)
        return admit(s, o, w)
    if kind == 2 and before != 0:
        return notification(s, o, w)
    return reply(o, w, 16, 0)
'''
    pseudo = '\n\n'.join([entry, admit, notification, extra])
    sys.path.insert(0, str(base / 'authoring'))
    sys.path.insert(0, str(a.hepta.resolve(strict=True)))
    from tools.generate_hia_selfhost import Builder
    previous = Builder.expr
    def expr(self, node):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'copy_range':
            values = [self.expr(value) for value in node.args]
            return self.op('buffer.copy_range', values[:2] + [self.cast(value, 'usize') for value in values[2:]])
        return previous(self, node)
    Builder.expr = expr
    from lower_support import compile_delta, substitute
    replacements = {name: comp['functions'][name] for name in ('entry', 'admit', 'notification')}
    additions = dict(message_controls='f37', observe_message='f38')
    raw, functions, retained = compile_delta(a.hepta.resolve(strict=True), source,
        comp['functions'], substitute(pseudo, comp['constants']), replacements, additions)
    proof = dict(schema='hepta.sdk-task-public-admission.delta.v1',
        baseline_sha256=SHA(source), output_sha256=SHA(raw), output_bytes=len(raw),
        retained_exact_ast=retained, changed_functions=replacements,
        added_functions=additions, functions=len(functions),
        pseudo_sha256=SHA(pseudo.encode()), author_sha256=SHA(Path(__file__).read_bytes()),
        operation=15, trusted_arguments=['G2 mode before this CALL', 'G2 mode after this CALL'],
        payload='complete current G1 HRCJR001 borrowed output',
        bootstrap_disposition=15, forward_only_disposition=16,
        ordinary_notification_drops_handler_future=False,
        expected_wire_read_as_implementation=False, public_async_qualified=False)
    (out / 'native/sdk_request_task_registry.hepta').write_bytes(raw)
    (out / 'native/sdk_request_task_admission_composition.json').write_text(
        json.dumps(proof, sort_keys=True, indent=2) + '\n')
    (out / 'native/sdk_request_task_admission_source.py.txt').write_text(pseudo)
    print(json.dumps(proof, sort_keys=True))


if __name__ == '__main__':
    main()
