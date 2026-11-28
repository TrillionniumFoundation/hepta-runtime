"""Execute fixed admission-only controls and actual recovery on the native callable."""
from pathlib import Path
import argparse
import ctypes as C
import gzip
import os
import struct
import sys
import time
ROOT = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path[:0] = [str(ROOT), str(ROOT / "scripts")]
from common import encoded, loads, pin, read, require, source
from callable_loader import Callable
from callable_contract import CONTEXT_BYTES
from fixture import setup, snapshot, normalized, retire
from protocol import semantic, word
from transport_cases import SPECS, wire, sequence, argv, mutate

ORDER = ("input", "output", "context", "table")


def run(build, output, fixture):
    identity = source()
    output.mkdir(parents=True, exist_ok=False)
    domain = [dict(name=op + "/" + name,kind="missing",data_hex="",mode=0o600,steps=[]) for op,name,*_ in SPECS]
    setup(fixture, domain)
    machine = Callable(build / "callable/manifest.json", loads(read(build / "callable/BINDING.json")))
    rows = []
    observations = []
    raw_stream = (output / "buffers.bin.gz").open("xb")
    stream = gzip.GzipFile(filename="", mode="wb", compresslevel=1, fileobj=raw_stream, mtime=0)
    stream.write(b"AIOCTLOG")
    completed = False
    try:
        (output / "LIBC.bin").write_bytes(machine.libc_bytes)
        (output / "LIBC-BINDINGS.json").write_bytes(encoded(machine.bindings))
        (output / "PROCESS-MAPS.txt").write_bytes(Path("/proc/self/maps").read_bytes())
        for index, spec in enumerate(SPECS):
            folder = fixture / ("case-%04d" % index)
            descriptor = os.open(folder, os.O_RDONLY | os.O_CLOEXEC)
            request = wire()
            bodies = dict(input=request + b"\xc3" * 16 + b"\xc7" * (4369 - len(request) - 16),
                          output=b"\xa5" * 8208, context=bytes(CONTEXT_BYTES) + b"\x5a" * 16,
                          table=bytes(machine.table))
            allocated = {name: C.create_string_buffer(value, len(value)) for name, value in bodies.items()}
            addresses = {name: C.addressof(value) for name, value in allocated.items()}
            addresses["root"] = descriptor
            before_fs = snapshot(folder)
            try:
                for phase, function, parameters, mutations, expected in sequence(spec):
                    prior = {name: value.raw for name, value in allocated.items()}
                    changed = mutate(prior, mutations)
                    for name in ORDER:
                        C.memmove(addresses[name], changed[name], len(changed[name]))
                    before = [allocated[name].raw for name in ORDER]
                    arguments = argv(function, parameters, addresses)
                    start = time.monotonic_ns()
                    returned = int(getattr(machine, function)(*arguments))
                    elapsed = time.monotonic_ns() - start
                    after = [allocated[name].raw for name in ORDER]
                    row = dict(index=len(rows), case=index, name=spec[0] + "/" + spec[1],
                        phase=phase, function=function, parameters=parameters,
                        mutations=[list(x) for x in mutations], expected=expected, returned=returned,
                        addresses=addresses, arguments=arguments, elapsed_ns=elapsed,
                        before=[pin(x) for x in before], after=[pin(x) for x in after])
                    meta = encoded(row)
                    stream.write(b"AIOCTL01" + struct.pack("<7Q", len(rows), returned, len(meta), *map(len, before)))
                    stream.write(meta)
                    for data in before + after:
                        stream.write(data)
                    rows.append(row)
                    if expected is not None:
                        require(returned == expected, "actual native transport result: " + row["name"] + "/" + phase)
                    if phase == "refusal":
                        require(before == after, "all admission-refusal buffers remain byte-for-byte unchanged")
                        # Only caller-owned deliberate test mutations are restored.
                        for name in ORDER:
                            C.memmove(addresses[name], prior[name], len(prior[name]))
                    elif phase == "recovery-run":
                        require(128 <= returned <= 8192 and after[0] == before[0] and after[3] == before[3] and
                                after[1][returned:] == b"\xa5" * (8208 - returned) and
                                after[2][CONTEXT_BYTES:] == b"\x5a" * 16 and word(after[2], 8) == 0,
                                "complete actual native recovery, guards, and quiescence")
                        observations.append(dict(case=index, name=row["name"],
                            semantic_hex=semantic(after[1][:returned]).hex(), before=before_fs, after=snapshot(folder)))
                require(allocated["context"].raw == bytes(CONTEXT_BYTES) + b"\x5a" * 16 and
                        normalized(before_fs) == normalized(snapshot(folder)), "actual recovery/disposal leaves full fixture unchanged")
                os.fstat(descriptor)
            finally:
                os.close(descriptor)
        require(len(rows) == 4 * len(SPECS) and len(observations) == len(SPECS),
                "all controls, successful initialization/recovery/disposal calls")
        stream.write(b"AIOCTEND" + struct.pack("<Q", len(rows)))
        completed = True
    finally:
        try:
            stream.close()
        finally:
            raw_stream.close()
            machine.close()
        (output / "CALLS.json").write_bytes(encoded(rows))
        (output / "OBSERVATIONS.json").write_bytes(encoded(observations))
    require(completed, "complete native transport controls")
    (output / "RETIREMENT.json").write_bytes(encoded(retire(fixture, domain)))
    require(source() == identity, "same frozen complete callable-control source")
    result = dict(schema="hepta.audit-pinned-anchor-callable.transport-controls.v1", status="PASS",
        source_manifest_sha256=identity, cases=len(SPECS), actual_calls=len(rows), refusals=len(SPECS),
        recoveries=len(SPECS), original_rust_replay=0,
        pid=os.getpid(), parent_pid=os.getppid(), pgid=os.getpgrp(), uid=os.geteuid(), gid=os.getegid(),
        source_root=str(ROOT), output_root=str(output), fixture=str(fixture), build_root=str(build),
        callable=pin(read(build / "callable/callable.image.bin")),
        files={name: pin(read(output / name)) for name in
               ("CALLS.json", "OBSERVATIONS.json", "RETIREMENT.json", "buffers.bin.gz",
                "LIBC.bin", "LIBC-BINDINGS.json", "PROCESS-MAPS.txt")},
        admission_only_refusal_atomicity=True, foreign_executable_capabilities=False,
        whole_audit_caller_qualified=False, public_handler_qualified=False)
    (output / "CONTROLS.json").write_bytes(encoded(result))
    print(encoded(result).decode(), end="")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--build", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--fixture", type=Path, required=True)
    a = p.parse_args()
    run(a.build.resolve(strict=True), a.output.absolute(), a.fixture.absolute())
