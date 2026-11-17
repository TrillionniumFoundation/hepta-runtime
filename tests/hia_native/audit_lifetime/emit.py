"""Execute fixed HIA emission contracts and retain every physical buffer."""
from pathlib import Path
import argparse
import ctypes
import sys

ROOT = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))
from common import encoded, loads, pin, read, require, sha, source
from emission_contract import refs_contract, callable_contract
from hia_native_loader import NativeModule


def exercise(manifest, image, cases, output):
    output.mkdir(parents=True, exist_ok=False)
    rows = []
    with NativeModule(manifest, manifest_sha256=sha(read(manifest))) as module:
        for name, request, capacity, expected in cases:
            with module.session(output_capacity=capacity, workspace_capacity=64) as session:
                ctypes.memset(session._output, 0xa5, capacity + 16)
                ctypes.memset(session._workspace, 0xa5, 64)
                ctypes.memset(ctypes.addressof(session._workspace) + 64, 0x5a, 16)
                before_output, before_workspace = session._output.raw, session._workspace.raw
                returned, logical_output, logical_workspace = session.invoke_raw(request)
                after_output, after_workspace = session._output.raw, session._workspace.raw
                require(returned == expected, 'actual HIA emitter return: ' + name)
                require(after_workspace == before_workspace, 'unchanged complete workspace')
                require(logical_output == after_output[:capacity] and logical_workspace == after_workspace[:64],
                        'complete logical/physical buffer agreement')
                wanted = image + before_output[len(image):] if name == 'valid' else before_output
                require(after_output == wanted, 'exact complete emission and unused output tails')
                buffers = dict(input=request, **{'output-before': before_output, 'output-after': after_output,
                                                'workspace-before': before_workspace, 'workspace-after': after_workspace})
                members = {}
                for label, raw in buffers.items():
                    filename = name + '.' + label + '.bin'
                    (output / filename).write_bytes(raw)
                    members[label] = dict(file=filename, **pin(raw))
                rows.append(dict(name=name, returned=returned, output_capacity=capacity,
                                 workspace_capacity=64, buffers=members))
    (output / 'image.bin').write_bytes(image)
    report = dict(schema='hepta.audit-lifetime.emission.v1', module_manifest=pin(read(manifest)),
                  image=pin(image), native_calls=len(rows), refusals=len(rows) - 1, calls=rows)
    (output / 'EMISSION.json').write_bytes(encoded(report))
    return report


def run(build, sync, output):
    identity = source()
    output.mkdir(parents=True, exist_ok=False)
    composition = loads(read(ROOT / 'native/audit_lifetime.composition.json'))
    _, refs, cases = refs_contract(composition)
    require(pin(refs) == {k: composition['reference_instructions'][k] for k in ('bytes', 'sha256')},
            'exact reference instructions')
    a = exercise(build / 'modules/audit-refs/manifest.json', refs, cases, output / 'refs')
    controller = read(build / 'modules/audit-lifetime/module.image.bin')
    synchronization = read(sync)
    pump = loads(read(ROOT / 'native/audit_lifetime_callable.composition.json'))
    require(pin(synchronization) == pump['synchronization'], 'qualified synchronization instructions')
    _, image, cases = callable_contract(controller, refs, synchronization, pump)
    b = exercise(build / 'modules/audit-lifetime-callable/manifest.json', image, cases, output / 'callable')
    require(source() == identity, 'emission source unchanged')
    result = dict(schema='hepta.audit-lifetime.composed-emission.v1', source_manifest_sha256=identity,
                  refs=a, callable=b, controller=pin(controller), synchronization=pin(synchronization),
                  runtime_python_required=False, runtime_rust_required=False,
                  public_handler_qualified=False, whole_runtime_replaced=False)
    (output / 'EMISSION.json').write_bytes(encoded(result))
    print(encoded(result).decode(), end='')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--sync', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    run(args.build.resolve(strict=True), args.sync.resolve(strict=True), args.output.absolute())
