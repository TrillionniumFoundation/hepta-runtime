"""Run the HIA policy, Value and current SDK owners; retain every buffer."""
import argparse
from contextlib import ExitStack
from pathlib import Path
import struct
import sys
import time
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import common as c

def run(build, output):
    base, _, _, _, raw_input = c.source_check()
    c.build_check(build)
    output.mkdir(parents=True, exist_ok=False)
    records = []; started = time.monotonic_ns()
    with ExitStack() as stack:
        policy, value, sdk = [stack.enter_context(c.load_module(build, name)) for name in c.module_pins()]
        for ordinal, (flags, modern) in enumerate(c.shape_domain()):
            label = f'shape-{ordinal:02d}'
            wire = base.frame(1, flags, modern, raw_input)
            oc, wc = 64, 16384; calls = []
            for number in range(3):
                code, out, work = policy.invoke_raw(wire, output_capacity=oc,
                    workspace_capacity=wc, output_fill=0xA7, workspace_fill=0x59)
                row = c.record(output, label + '-policy-' + str(number), wire, code, out, work)
                calls.append(row)
                assert out[:8] == b'HCATCR01'
                status, offset, size, count, got_flags, got_modern, zero = struct.unpack_from('<7Q', out, 8)
                assert (got_flags, got_modern, zero) == (flags, modern, 0)
                if status == 2: wc = size
                elif status == 3: oc = size
                else:
                    assert status == 0 and number == 2 and code == offset + size and offset == 64
                    policy_body = out[64:code]
            wire = b'HSJVAL01' + struct.pack('<2Q', 1, len(policy_body)) + policy_body
            code, out, work = value.invoke_raw(wire, output_capacity=len(policy_body) * 2 + 4096,
                workspace_capacity=32 << 20, output_fill=0xA7, workspace_fill=0x59)
            value_row = c.record(output, label + '-value', wire, code, out, work)
            assert 0 < code <= len(out); canonical = out[:code]
            sdk_rows = []
            for sdk_policy in (0, 2 if modern else 1):
                wire = b'HRRSP001' + struct.pack('<2Q', 4 | sdk_policy << 8, len(canonical)) + canonical
                code, out, work = sdk.invoke_raw(wire, output_capacity=len(canonical) * 2 + 4096,
                    workspace_capacity=96 << 20, output_fill=0xA7, workspace_fill=0x59)
                row = c.record(output, label + '-sdk-' + str(sdk_policy), wire, code, out, work)
                assert out[:8] == b'HRRPO001' and 64 < code <= len(out)
                c.put(output / (label + '-sdk-' + str(sdk_policy) + '.json'), out[64:code])
                sdk_rows.append({'policy': sdk_policy, 'call': row})
            records.append({'flags': flags, 'modern': modern, 'count': count,
                'policy_calls': calls, 'value': value_row, 'sdk': sdk_rows})
    result = {'schema': 'hepta.runtime.catalog-eleven-pipeline.v1', 'status': 'PASS',
        'shapes': records, 'native_calls': 108, 'elapsed_ns': time.monotonic_ns() - started,
        'source_profile': c.pin((ROOT / 'source-profile.json').read_bytes()),
        'original_compared': False, 'whole_runtime_replaced': False}
    c.put(output / 'result.json', result)
    from read_projection import verify
    verified = verify(ROOT, build, output)
    c.put(output / 'verification.json', verified)
    return verified

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--build', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    print(c.encoded(run(a.build.resolve(strict=True), a.output.absolute())).decode())
