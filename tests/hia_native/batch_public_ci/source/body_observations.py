"""Strictly decode every before/after arena through the unchanged state readers."""
from pathlib import Path
import gzip
import hashlib
import json
import struct
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'corpus/state_reference'))
from native_observations import cache, history, locks, require

PARSERS = ((7, 'locks', locks), (3, 'history', history), (5, 'cache', cache))


def json_state(value):
    if isinstance(value, bytes):
        return {'hex': value.hex()}
    if isinstance(value, dict):
        if any(isinstance(key, bytes) for key in value):
            return [[key.hex(), json_state(item)] for key, item in sorted(value.items())]
        return {key: json_state(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [json_state(item) for item in value]
    return value


def read_native(path, operations, capture=None):
    digest = hashlib.sha256()
    total = 0
    with Path(path).open('rb') as stream:
        for generation in range(1, operations + 1):
            for phase in (0, 1):
                for owner, kind, parse in PARSERS:
                    header = stream.read(64)
                    require(len(header) == 64, 'incomplete Batch arena observer header')
                    magic, extent, got_phase, got_generation, got_owner, capacity, z0, z1 = struct.unpack('<8s7Q', header)
                    require(magic == b'HLBBNA01' and extent == 64 + capacity and
                        (got_phase, got_generation, got_owner) == (phase, generation, owner) and
                        not (z0 or z1) and 4096 <= capacity <= 1207959552 and capacity % 4096 == 0,
                        'Batch observer owner/order/extent differs')
                    arena = stream.read(capacity)
                    require(len(arena) == capacity, 'incomplete Batch arena bytes')
                    state = parse(arena, phase, generation)
                    raw = header + arena
                    digest.update(raw);total += len(raw)
                    if capture is not None:
                        row = {'phase':phase,'generation':generation,'owner':owner,'kind':kind,
                            'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'state':json_state(state)}
                        capture.write(json.dumps(row,sort_keys=True,separators=(',',':')).encode()+b'\n')
        require(stream.read(1) == b'', 'Batch observer has an unadmitted suffix')
    return {'operations':operations,'complete_frames':operations*6,'bytes':total,'sha256':digest.hexdigest(),
        'all_lock_boundaries_quiescent':True,'complete_cache_history_lock_arenas_decoded':True}


if __name__ == '__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture',type=Path,required=True)
    parser.add_argument('--operations',type=int,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    args.output.mkdir(parents=True,exist_ok=False)
    with gzip.open(args.output/'states.jsonl.gz','xb',compresslevel=1) as stream:
        report=read_native(args.capture,args.operations,stream)
    (args.output/'result.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    print(json.dumps(report,sort_keys=True))
