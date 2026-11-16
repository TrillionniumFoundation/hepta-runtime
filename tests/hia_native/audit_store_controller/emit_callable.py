"""Run the frozen HIA packer; keep complete module inputs and physical buffers."""
from pathlib import Path
import argparse
import ctypes
import struct
import sys

ROOT = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))
from common import encoded, loads, pin, read, require, sha, source
from hia_native_loader import NativeModule


from callable_contract import inputs, cases


def run(manifest, controller, synchronization, output):
    identity = source()
    composition = loads(read(ROOT / 'native/audit_controller_callable.composition.json'))
    wire, expected_image = inputs(read(controller), read(synchronization), composition)
    output.mkdir(parents=True, exist_ok=False)
    rows = []
    with NativeModule(manifest, manifest_sha256=sha(read(manifest))) as module:
        for name, request, capacity, expected in cases(wire, len(expected_image)):
            with module.session(output_capacity=capacity, workspace_capacity=64) as session:
                ctypes.memset(session._output, 0xa5, capacity + 16)
                ctypes.memset(session._workspace, 0xa5, 64)
                ctypes.memset(ctypes.addressof(session._workspace) + 64, 0x5a, 16)
                before_output, before_workspace = session._output.raw, session._workspace.raw
                returned, logical_output, logical_workspace = session.invoke_raw(request)
                after_output, after_workspace = session._output.raw, session._workspace.raw
                require(returned == expected, 'actual callable packer return: ' + name)
                require(after_workspace == before_workspace, 'complete unchanged packer workspace')
                require(logical_output == after_output[:capacity] and logical_workspace == after_workspace[:64],
                        'complete logical and physical buffers')
                expected_output = (expected_image + before_output[len(expected_image):]
                                   if name == 'valid' else before_output)
                require(after_output == expected_output, 'complete callable image and unchanged output tails')
                buffers = dict(input=request, **{'output-before': before_output, 'output-after': after_output,
                                                'workspace-before': before_workspace, 'workspace-after': after_workspace})
                members = {}
                for label, raw in buffers.items():
                    name_on_disk = name + '.' + label + '.bin'
                    (output / name_on_disk).write_bytes(raw)
                    members[label] = dict(file=name_on_disk, **pin(raw))
                rows.append(dict(name=name, returned=returned, output_capacity=capacity,
                                 workspace_capacity=64, buffers=members))
    (output / 'callable.bin').write_bytes(expected_image)
    require(source() == identity, 'packer source remains frozen')
    report = dict(schema='hepta.audit-controller-callable.emission.v1',
                  source_manifest_sha256=identity, module_manifest=pin(read(manifest)),
                  composed_image=pin(expected_image), controller=pin(read(controller)),
                  synchronization=pin(read(synchronization)), adapter=composition['adapter'],
                  native_calls=len(rows), refusals=len(rows) - 1, calls=rows,
                  runtime_rust_required=False, runtime_python_required=False,
                  whole_runtime_replaced=False)
    (output / 'EMISSION.json').write_bytes(encoded(report))
    print(encoded(report).decode(), end='')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--controller', type=Path, required=True)
    parser.add_argument('--synchronization', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    run(args.manifest.resolve(strict=True), args.controller.resolve(strict=True),
        args.synchronization.resolve(strict=True), args.output.absolute())
