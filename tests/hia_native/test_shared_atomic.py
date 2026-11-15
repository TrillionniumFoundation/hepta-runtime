"""Actual HIA cache-transition tests; injected completions are not OS evidence."""
from __future__ import annotations
import argparse
import ctypes
import hashlib
import itertools
import json
from pathlib import Path
import struct
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from hia_native_loader import NativeModule

EFFECT, CACHE, STATE = 0xfffffff0, 0xffffffe8, 0xfffffff9


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def frame(path=b'target', content=b'abcdef', op=1):
    return struct.pack('<8s7Q', b'HRAWI001', op, len(path), len(content), 0, 0, 0, 0) + path + content


def success():
    return struct.pack('<8s3Q', b'HRAWR001', 0, 0, 0)


def expected(initial, current, direct, libc_fallback, probe, probe_fallback, fallback):
    """Independent control projection of Rust 1.95 statx, then atomic_write."""
    events = [('cache', 0, initial)]
    effective = fallback
    global_value = initial
    if initial != 2:
        events.append(('effect', 1, direct))
        error = direct
        global_value = current
        if direct == 38:
            events.append(('effect', 10, libc_fallback))
            error = libc_fallback
        if error == 0:
            if initial == 0:
                events.append(('cache', 1, 1))
                global_value = 1
            effective = 0
        else:
            events.append(('cache', 0, current))
            if current == 1:
                effective = error
            else:
                events.append(('effect', 2, probe))
                test = probe
                if probe == 38:
                    events.append(('effect', 11, probe_fallback))
                    test = probe_fallback
                available = 1 if test == 14 else 2
                events.append(('cache', 1, available))
                global_value = available
                if available == 1:
                    effective = error
                else:
                    events.append(('effect', 3, fallback))
    else:
        events.append(('effect', 3, fallback))
    if effective in (0, 2):
        events += [('effect', 4, 0), ('effect', 5, 0), ('effect', 6, 0)]
        if effective == 0:
            events.append(('effect', 7, 0))
        events.append(('effect', 8, 0))
    return events, effective, global_value


def run(manifest, destination):
    destination = Path(destination)
    destination.mkdir(mode=0o700, parents=True)
    path = Path(manifest).resolve(strict=True)
    metadata = json.loads(path.read_bytes())
    assert metadata['source_sha256'] == sha((ROOT / 'native/atomic_write_shared.hepta').read_bytes())
    module = NativeModule(path, manifest_sha256=sha(path.read_bytes()))
    assert metadata['image_sha256'] == '600ed5f452b1c21b8b2c26421137edf87a9224b54c01529c4abb20ed600f0c15'
    properties = ROOT / 'tests/hia_native/atomic_write_rust_io_properties.txt'
    assert sha(properties.read_bytes()) == 'f88ff140c2c976db5a6c11e8c62fa16957af3205396344eccd43e16aea56bc7d'
    texts = {int(code): bytes.fromhex(value) for code, value in (line.split('\t') for line in properties.read_text().splitlines())}
    report = {'schema': 'hepta.runtime.shared-atomic-transition.v1', 'status': 'RUNNING',
        'native_calls': 0, 'synthetic_transition_cases': 0, 'refusals': 0,
        'actual_filesystem_effects': 0, 'original_rust_replay': 'PENDING',
        'source_sha256': metadata['source_sha256'], 'image_sha256': metadata['image_sha256'],
        'manifest_sha256': sha(path.read_bytes()),
        'test_sha256': sha(Path(__file__).read_bytes()),
        'loader_sha256': sha((ROOT / 'scripts/hia_native_loader.py').read_bytes()),
        'errno_properties_sha256': sha(properties.read_bytes())}
    started = time.monotonic()
    rows = []
    try:
        plans = set(itertools.product((0, 1, 2), (0, 1, 2), (0, 2, 4, 5, 13, 38),
            (0, 2, 13), (0, 5, 14, 38), (5, 14), (0, 2, 13)))
        # Every errno also exercises a concurrent Present publication before
        # the required second load, eliminating the availability probe.
        plans.update((0, 1, error, 13, 14, 14, 0) for error in range(1, 4096))
        for plan in sorted(plans):
            initial, current, direct, libc_fallback, probe, probe_fallback, fallback = plan
            want_events, error, final_cache = expected(*plan)
            wire = frame()
            sa = ctypes.create_string_buffer(wire + b'\x7c' * 16)
            out = ctypes.create_string_buffer(b'\xa5' * 1040)
            work = ctypes.create_string_buffer(4112)
            oa, wa = ctypes.addressof(out), ctypes.addressof(work)
            ctypes.memset(wa + 4096, 0x5a, 16)
            def get(at):
                return struct.unpack('<Q', ctypes.string_at(wa + at, 8))[0]
            def put(at, value):
                ctypes.memmove(wa + at, struct.pack('<Q', value), 8)
            cache = initial
            load_count = 0
            events = []
            for step in range(40):
                code = module._entry(sa, len(wire), out, 1024, work, 4096)
                report['native_calls'] += 1
                assert sa.raw[:len(wire) + 16] == wire + b'\x7c' * 16
                assert ctypes.string_at(oa + 1024, 16) == b'\xa5' * 16
                assert ctypes.string_at(wa + 4096, 16) == b'\x5a' * 16
                if code not in (EFFECT, CACHE):
                    assert code < 1024, (plan, code, events)
                    actual = ctypes.string_at(oa, code)
                    payload = b"Failed to read metadata for 'target': " + texts[error] if error not in (0, 2) else b''
                    wanted = struct.pack('<8s3Q', b'HRAWR001', 1, 1, len(payload)) + payload if payload else success()
                    assert actual == wanted, (plan, actual, wanted)
                    assert ctypes.string_at(oa + code, 1024 - code) == b'\xa5' * (1024 - code)
                    assert events == want_events, (plan, events, want_events)
                    assert cache == final_cache, (plan, cache, final_cache)
                    rows.append({'plan': plan, 'events': events, 'result_hex': actual.hex(), 'cache': cache})
                    report['synthetic_transition_cases'] += 1
                    break
                at = 640 if code == CACHE else 256
                effect = struct.unpack('<12Q', ctypes.string_at(wa + at, 96))
                assert effect[0] == int.from_bytes(b'HMTAC001' if code == CACHE else b'HIAATFX1', 'little')
                assert effect[6:] == (0,) * 6
                action = effect[2]
                value = auxiliary = err = 0
                if code == CACHE:
                    if action == 0:
                        value = cache
                        events.append(('cache', action, value))
                        load_count += 1
                    else:
                        assert action == 1 and effect[3] in (1, 2)
                        cache = effect[3]
                        events.append(('cache', action, cache))
                else:
                    err = {1: direct, 10: libc_fallback, 2: probe, 11: probe_fallback, 3: fallback}.get(action, 0)
                    events.append(('effect', action, err))
                    if action == 1:
                        cache = current
                    if err == 0:
                        if action in (1, 3, 10): auxiliary = 0o104751
                        if action == 4: auxiliary = 1
                        if action == 5: value = effect[5]
                put(at + 56, value); put(at + 64, err); put(at + 72, auxiliary); put(at + 80, 1)
            else:
                raise AssertionError(('infinite transition', plan))
        for offset, value in ((640, 0), (648, 0), (656, 1), (664, 1), (672, 1),
                              (680, 1), (688, 1), (696, 3), (704, 1), (712, 1), (720, 0), (728, 1)):
            wire = frame()
            sa = ctypes.create_string_buffer(wire)
            out = ctypes.create_string_buffer(b'\xa5' * 1040)
            work = ctypes.create_string_buffer(4112)
            assert module._entry(sa, len(wire), out, 1024, work, 4096) == CACHE
            report['native_calls'] += 1
            wa = ctypes.addressof(work)
            ctypes.memmove(wa + 720, struct.pack('<Q', 1), 8)
            ctypes.memmove(wa + offset, struct.pack('<Q', value), 8)
            assert module._entry(sa, len(wire), out, 1024, work, 4096) == STATE, (offset, value)
            assert out.raw[:1024] == b'\xa5' * 1024
            report['native_calls'] += 1
            report['refusals'] += 1
        raw = b''.join(json.dumps(row, sort_keys=True, separators=(',', ':')).encode() + b'\n' for row in rows)
        import gzip
        with gzip.open(destination / 'transitions.jsonl.gz', 'wb') as handle:
            handle.write(raw)
        report.update(status='PASS', transitions_sha256=sha(raw), transitions_bytes=len(raw))
    except BaseException as error:
        report.update(status='FAIL', failure=repr(error))
        raise
    finally:
        module.close()
        report['elapsed_seconds'] = time.monotonic() - started
        (destination / 'result.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.manifest, args.output), sort_keys=True))
