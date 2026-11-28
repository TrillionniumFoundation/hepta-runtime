"""Actual byte-mutation refusals over retained native/original body observations."""
from pathlib import Path
import argparse
import hashlib
import json
import struct
import sys

sys.dont_write_bytecode = True


def evaluate(source, capture):
    from types import SimpleNamespace
    args = SimpleNamespace(source=Path(source), capture=Path(capture))
    sys.path.insert(0, str(args.source.resolve(strict=True)))
    import cases
    import observations as original
    import native_observations as native
    definitions = cases.cases(); definition = definitions[0]
    root = args.capture / ('case-00-' + definition['name'])
    raw = (root / 'native/stderr.bin').read_bytes(); reference = (root / 'original/stderr.bin').read_bytes()
    good = native.decode(raw, definition['operations']); old = original.decode(reference, definition['operations'])
    native.compare(old, good)
    spans = []; at = 0
    while at < len(raw):
        length, = struct.unpack_from('<Q', raw, at + 8); spans.append((at, length)); at += length
    assert len(spans) == 7 and at == len(raw)
    controls = []
    def rejected(name, changed, decode=native.decode):
        try: decode(changed, definition['operations'])
        except (ValueError, UnicodeDecodeError, struct.error) as error:
            controls.append(dict(name=name, bytes=len(changed), sha256=hashlib.sha256(changed).hexdigest(), error=repr(error)))
        else: raise AssertionError('mutated actual observation was admitted: ' + name)
    def word(name, frame, offset, value):
        changed = bytearray(raw); struct.pack_into('<Q', changed, spans[frame][0] + offset, value)
        rejected(name, bytes(changed))
    for name, frame, offset, value in (
        ('outer_owner', 0, 32, 9), ('outer_phase', 0, 16, 2), ('outer_generation', 0, 24, 2),
        ('outer_reserved', 0, 48, 1), ('outer_capacity', 0, 40, 1), ('outer_extent', 0, 8, 63),
        ('lock_version', 0, 72, 2), ('lock_used_alignment', 0, 80, 257),
        ('lock_next_node', 0, 112, 0), ('lock_next_lease', 0, 120, 0),
        ('lock_live_lease', 0, 136, 1), ('lock_reserved_header', 0, 144, 1),
        ('lock_free_list', 4, 88, 256), ('lock_node_count', 4, 104, 0),
        ('history_version', 1, 72, 2), ('history_used', 1, 80, 65),
        ('history_poison', 1, 112, 2), ('history_snapshot_count', 5, 88, 0),
        ('history_total_bytes', 5, 104, 0), ('history_snapshot_end', 5, 120, 64),
        ('cache_version', 2, 72, 2), ('cache_used', 2, 80, 65),
        ('cache_count', 2, 88, 1), ('cache_poison', 2, 96, 2), ('cache_reserved', 2, 104, 1),
        ('hint_operation', 3, 24, 3), ('hint_generation', 3, 16, 2),
    ):
        word(name, frame, offset, value)
    for frame, name in ((0, 'lock_complete_tail'), (1, 'history_complete_tail'), (2, 'cache_complete_tail')):
        changed = bytearray(raw); changed[spans[frame][0] + spans[frame][1] - 1] = 1
        rejected(name, bytes(changed))
    node, = struct.unpack_from('<Q', raw, spans[4][0] + 64 + 32)
    assert node
    word('released_lock_refcount', 4, 64 + node + 24, 1)
    word('lock_key_hash', 4, 64 + node + 40, 0)
    word('lock_owner_after_completion', 4, 64 + node + 48, 1)
    a, b = spans[:2]
    rejected('before_owner_order', raw[b[0]:b[0]+b[1]] + raw[a[0]:a[0]+a[1]] + raw[b[0]+b[1]:])
    rejected('missing_complete_frame', raw[:-spans[-1][1]])
    rejected('extra_complete_frame', raw + raw[:spans[0][1]])
    rejected('truncated_final_byte', raw[:-1])
    changed = bytearray(reference); struct.pack_into('<Q', changed, 16, 1)
    rejected('original_before_phase', bytes(changed), original.decode)
    # A syntactically valid different history snapshot must fail the actual
    # original/native state comparison, independently of parser rejection.
    changed = bytearray(raw); at = spans[5][0] + 64 + 64
    kn, vn = struct.unpack_from('<QQ', changed, at); assert vn
    changed[at + 16 + kn] ^= 1
    modified = native.decode(bytes(changed), definition['operations'])
    try: native.compare(old, modified)
    except ValueError as error:
        controls.append(dict(name='valid_but_different_complete_history', bytes=len(changed),
            sha256=hashlib.sha256(changed).hexdigest(), error=repr(error)))
    else: raise AssertionError('different complete actual state was admitted')
    result = dict(status='LOCAL_TEXT_BODY_OBSERVER_MUTATIONS_PASS', actual_refusals=len(controls),
        controls=controls, baseline_native_bytes=len(raw), baseline_original_bytes=len(reference),
        source_sha256={name: hashlib.sha256((args.source / name).read_bytes()).hexdigest()
            for name in ('cases.py', 'observations.py', 'native_observations.py')},
        original_capture_unchanged=reference == (root / 'original/stderr.bin').read_bytes(),
        native_capture_unchanged=raw == (root / 'native/stderr.bin').read_bytes(),
        actual_body_processes_started=0, public_handler_qualified=False, full_body_async_qualified=False)
    return result


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--capture', type=Path, required=True); parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = evaluate(args.source, args.capture)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({key: result[key] for key in ('status', 'actual_refusals', 'baseline_native_bytes',
        'baseline_original_bytes', 'original_capture_unchanged', 'native_capture_unchanged', 'actual_body_processes_started')}))


if __name__ == '__main__': main()
