"""Execute the frozen HIA emitter and retain every physical buffer."""
from pathlib import Path
import argparse
import ctypes
import sys

ROOT = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))
from hia_native_loader import NativeModule
from common import encoded, loads, pin, read, require, sha, source


def run(manifest, output):
    identity = source()
    composition = loads(read(ROOT / 'native/audit_sync_boundary.composition.json'))
    count = composition['emitted_instructions']['bytes']
    good = b'HASYPK01' + (1).to_bytes(8, 'little')
    cases = [('valid', good, count + 64, count),
             ('empty', b'', count + 64, 0xffffffff),
             ('short', good[:-1], count + 64, 0xffffffff),
             ('long', good + b'\0', count + 64, 0xffffffff),
             ('magic', b'X' + good[1:], count + 64, 0xffffffff),
             ('version', good[:8] + (2).to_bytes(8, 'little'), count + 64, 0xffffffff),
             ('capacity', good, count - 1, 0xfffffffe)]
    output.mkdir(parents=True, exist_ok=False)
    rows = []
    with NativeModule(manifest, manifest_sha256=sha(read(manifest))) as module:
        for name, wire, capacity, expected in cases:
            with module.session(output_capacity=capacity, workspace_capacity=64) as session:
                ctypes.memset(session._output, 0xa5, capacity + 16)
                ctypes.memset(session._workspace, 0xa5, 64)
                ctypes.memset(ctypes.addressof(session._workspace) + 64, 0x5a, 16)
                before_output = session._output.raw
                before_workspace = session._workspace.raw
                returned, logical_output, logical_workspace = session.invoke_raw(wire)
                after_output, after_workspace = session._output.raw, session._workspace.raw
                require(returned == expected, 'actual HIA emitter return: ' + name)
                require(after_workspace == before_workspace, 'emitter workspace unchanged')
                require(after_output[capacity:] == before_output[capacity:], 'emitter output guard')
                require(logical_output == after_output[:capacity] and logical_workspace == after_workspace[:64],
                        'complete loader physical buffers')
                if name == 'valid':
                    require(pin(after_output[:count]) == composition['emitted_instructions'], 'exact emitted instructions')
                    require(after_output[count:] == before_output[count:], 'emitter unused output tail')
                    (output / 'boundary.bin').write_bytes(after_output[:count])
                else:
                    require(after_output == before_output, 'refusal leaves output unchanged')
                buffers = {'input': wire, 'output-before': before_output, 'output-after': after_output,
                           'workspace-before': before_workspace, 'workspace-after': after_workspace}
                members = {}
                for label, raw in buffers.items():
                    filename = name + '.' + label + '.bin'
                    (output / filename).write_bytes(raw)
                    members[label] = dict(file=filename, **pin(raw))
                rows.append(dict(name=name, returned=returned, output_capacity=capacity,
                                 workspace_capacity=64, buffers=members))
    require(source() == identity, 'source unchanged during emission')
    report = dict(schema='hepta.audit-native-sync.emission.v1', source_manifest_sha256=identity,
                  native_calls=7, refusals=6, boundary=composition['emitted_instructions'],
                  module_manifest=pin(read(manifest)), calls=rows, whole_runtime_replaced=False)
    (output / 'EMISSION.json').write_bytes(encoded(report))
    print(encoded(report).decode(), end='')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    run(args.manifest.resolve(strict=True), args.output.absolute())
