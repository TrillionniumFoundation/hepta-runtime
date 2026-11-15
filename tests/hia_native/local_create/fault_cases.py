"""Actual owned-file native/Tokio pairs with a child-only RLIMIT_FSIZE.

The original helper returns io::Result<()>; its fixture cannot report the
number of bytes written before an error. Compare that error and every retained
file byte, while checking the native progress field separately against the
actual file. No injected native completion is used here.
"""
from pathlib import Path
import argparse
import gzip
import hashlib
import json
import os
import resource
import signal
import struct
import subprocess
import time

CHUNK = 2 << 20
MASK = (1 << 64) - 1

def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def frame(data):
    return b'HLCREQ01' + struct.pack('<7Q', 1, 7, len(data), 0, 0, 0, 0) + b'created' + data


def run_one(binary, destination, data, limit, native):
    destination.mkdir()
    work=destination/'files';work.mkdir()
    wire = frame(data)
    stdin = struct.pack('<Q', len(wire)) + wire if native else wire

    def child_limits():
        signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
        resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))

    with gzip.open(destination/'stdin.bin.gz', 'wb', compresslevel=1) as stream:
        stream.write(stdin)
    began = time.monotonic()
    proc = subprocess.run([str(binary)], input=stdin, capture_output=True,
                          cwd=work, env={'PATH': '', 'LC_ALL': 'C'},
                          timeout=60, umask=0o022, preexec_fn=child_limits)
    elapsed = time.monotonic() - began
    (destination/'stdout.bin').write_bytes(proc.stdout)
    (destination/'stderr.bin').write_bytes(proc.stderr)
    assert proc.returncode == 0, (native, limit, len(data), proc.returncode, proc.stderr)
    body = proc.stdout
    effects = []
    if native:
        assert len(body) == 56 and struct.unpack_from('<Q', body)[0] == 48
        body = body[8:]
        assert len(proc.stderr) % 96 == 0
        for at in range(0, len(proc.stderr), 96):
            fields = struct.unpack_from('<12Q', proc.stderr, at)
            magic, sequence, action, a, b, c, d, ready, value, error, token, reserved = fields
            assert magic == int.from_bytes(b'HLCREF01', 'little')
            assert sequence == len(effects)+1 and ready == 1 and reserved == 0
            assert error <= 4095 and (not error or (value == (-error & MASK) and token == 0))
            effects.append(dict(sequence=sequence, action=action, args=[a, b, c, d],
                                raw=value, errno=error, token=token))
        assert effects[0]['action'] == 1 and effects[0]['args'] == [512, 7, 0x800c1, 0o666]
        assert effects[0]['errno'] == 0 and effects[0]['token'] == 1
        assert effects[-1]['action'] == 3 and effects[-1]['args'] == [1, 0, 0, 0]
        assert effects[-1]['errno'] == effects[-1]['raw'] == effects[-1]['token'] == 0
        assert all(row['action'] == 2 for row in effects[1:-1])
        progress = 0
        for row in effects[1:-1]:
            a, b, c, d = row['args']
            assert a == 1 and b == 520 + progress and 0 < c <= CHUNK and d == 0
            if row['errno'] == 0:
                assert 0 < row['raw'] <= c
                progress += row['raw']
            else:
                assert row is effects[-2] and row['errno'] == 27
    else:
        assert proc.stderr == b'HLCREATE-REFERENCE-BEGIN\nHLCREATE-REFERENCE-END\n'
    assert len(body) == 48 and body[:8] == b'HLCRER01'
    extent, kind, error, written, reserved = struct.unpack_from('<5Q', body, 8)
    assert extent == 48 and reserved == 0
    expected_written = min(limit, len(data))
    expected_result = (1, 27) if len(data) > limit else (0, 0)
    assert (kind, error) == expected_result
    actual = (work/'created').read_bytes()
    (destination/'created.bin').write_bytes(actual)
    assert actual == data[:expected_written]
    assert (work/'created').stat().st_mode & 0o7777 == 0o644
    if native:
        assert written == progress == expected_written
        assert len(data) <= limit or effects[-2]['errno'] == 27
    else:
        assert written == (len(data) if kind == 0 else 0)
    return {
        'kind': kind, 'errno': error, 'written_field': written,
        'command': [str(binary)], 'cwd': str(work),
        'environment': {'PATH': '', 'LC_ALL': 'C'}, 'timeout_seconds': 60,
        'umask': 0o022, 'rlimit_fsize': [limit, limit], 'sigxfsz': 'ignored',
        'file': {'bytes': len(actual), 'sha256': sha(actual), 'mode': 0o644},
        'effects': effects, 'elapsed_seconds': elapsed, 'exit_code': proc.returncode,
        'stdin': {'bytes': len(stdin), 'sha256': sha(stdin)},
        'stdout': {'bytes': len(proc.stdout), 'sha256': sha(proc.stdout)},
        'stderr': {'bytes': len(proc.stderr), 'sha256': sha(proc.stderr)},
    }, actual


def cases():
    return [(0, 0), (1, 1), (CHUNK+1, CHUNK+1), (0, 1), (1, 2),
            (CHUNK-1, CHUNK+1), (CHUNK, CHUNK+1), (CHUNK+1, CHUNK+2)]


def payload(size):
    pattern=bytes((i*73+11)&255 for i in range(256))
    return pattern*(size//256)+pattern[:size%256]


def run_faults(binary,output,*,native):
    output.mkdir(parents=True,exist_ok=False)
    began=time.monotonic();rows=[];status='FAIL';error=None
    try:
        for number,(limit,size) in enumerate(cases()):
            row,actual=run_one(binary,output/str(number),payload(size),limit,native)
            row.update(index=number,limit=limit,input_bytes=size)
            (output/str(number)/'result.json').write_text(json.dumps(row,sort_keys=True,indent=2)+'\n')
            rows.append(row)
        status='PASS'
    except BaseException as caught:
        error=repr(caught);raise
    finally:
        report=dict(schema='hepta.runtime.local-create-faults.v1',status=status,error=error,
            cases=len(rows),actual_processes=len(rows),native=native,
            executable=str(binary),executable_sha256=sha(binary.read_bytes()),
            actual_kernel_effects=sum(len(r['effects']) for r in rows) if native else 0,
            elapsed_seconds=time.monotonic()-began,timeout_seconds_per_process=60,
            actual_kernel_operations=True,injected_completions=False,
            original_rust_execution_performed=not native,public_handler_qualified=False,
            full_create_file_spec_qualified=False,async_cancellation_qualified=False,
            whole_runtime_replaced=False)
        (output/'summary.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--binary',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--original',action='store_true')
    args=parser.parse_args()
    print(json.dumps(run_faults(args.binary.resolve(strict=True),args.output.resolve(),native=not args.original),sort_keys=True))
