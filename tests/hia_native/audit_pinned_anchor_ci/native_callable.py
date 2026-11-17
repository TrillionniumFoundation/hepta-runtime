"""Complete frozen audit filesystem domain through one native callable.

Python creates owned fixtures and records memory/files. It never chooses an
effect, calls the semantic HIA entries, or supplies a continuation ACK.
"""
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
from protocol import cases, initial, response, semantic, word
from fixture import setup, snapshot, retire, apply
from callable_loader import Callable
from callable_contract import CONTEXT_BYTES, OFFSETS, capabilities
from observe_callable import Observe

TOP_HEADER = struct.Struct("<12Q")


class Outer:
    def __init__(self, output):
        self.output = output
        self.rows = []
        self.raw = (output / "outer.bin.gz").open("xb")
        try:
            self.stream = gzip.GzipFile(filename="", mode="wb", compresslevel=1, fileobj=self.raw, mtime=0)
            self.stream.write(b"AIOTOP01")
        except BaseException:
            self.raw.close()
            raise
        self.closed = False

    def record(self, case, step, kind, returned, before, after, elapsed, args):
        ni = len(before[0]) - (16 if kind == 1 else 0)
        no = 8192 if kind == 1 else 0
        guards = (16 if kind == 1 else 0, 16 if kind == 1 else 0, 16)
        index = len(self.rows)
        fields = (index, case, step, kind, returned, ni, no, CONTEXT_BYTES, 144, *guards)
        require(len(before) == len(after) == 4 and
                all(len(x) == len(y) for x, y in zip(before, after)), "complete outer native buffers")
        self.stream.write(b"AIOENT01" + TOP_HEADER.pack(*fields))
        for raw in before + after:
            self.stream.write(raw)
        self.rows.append(dict(index=index, case=case, step=step, kind=kind, returned=returned,
            input_bytes=ni, output_capacity=no, context_capacity=CONTEXT_BYTES, table_bytes=144,
            guards=list(guards), elapsed_ns=elapsed, args=args,
            before=[pin(x) for x in before], after=[pin(x) for x in after]))

    def close(self, success):
        if self.closed:
            return
        self.closed = True
        try:
            if success:
                self.stream.write(b"AIOTEND1" + struct.pack("<Q", len(self.rows)))
        finally:
            try:
                self.stream.close()
            finally:
                self.raw.close()
            (self.output / "OUTER.json").write_bytes(encoded(self.rows))


def run(build, output, fixture, observed):
    identity = source()
    domain = cases(ROOT)
    require(type(observed) is bool, "exact observer mode")
    output.mkdir(parents=True, exist_ok=False)
    setup(fixture, domain)
    component = loads(read(build / "callable/BINDING.json"))
    machine = None
    observer = None
    outer = None
    observations = []
    bindings = []
    completed = False
    counts = dict(owner_calls=0, json_calls=0, filesystem_calls=0)
    try:
        machine = Callable(build / "callable/manifest.json", component)
        loaded_image = dict(address=machine.module._address, bytes=machine.module._size)
        (output / "LIBC.bin").write_bytes(machine.libc_bytes)
        (output / "LIBC-BINDINGS.json").write_bytes(encoded(machine.bindings))
        (output / "PROCESS-MAPS.txt").write_bytes(Path("/proc/self/maps").read_bytes())
        outer = Outer(output)
        if observed:
            observer = Observe(output)
        for ci, case in enumerate(domain):
            folder = fixture / ("case-%04d" % ci)
            directory = os.open(folder, os.O_RDONLY | os.O_CLOEXEC)
            context = machine.new_context()
            initialized = False
            disposed = False
            base = C.addressof(context)
            table_before = bytes(machine.table)
            observer_address = 0 if observer is None else C.cast(observer.callback, C.c_void_p).value
            info = os.fstat(directory)
            bindings.append(dict(case=ci, context=base, table=C.addressof(machine.table),
                observer=observer_address, root_fd=directory,
                root_identity=dict(device=info.st_dev, inode=info.st_ino, mode=info.st_mode)))
            try:
                before = (b"", b"", context.raw, table_before)
                start = time.monotonic_ns()
                returned = machine.init(context, directory, None if observer is None else observer.callback)
                elapsed = time.monotonic_ns() - start
                after = (b"", b"", context.raw, bytes(machine.table))
                outer.record(ci, 0, 0, returned, before, after, elapsed,
                    dict(directory=directory, table=C.addressof(machine.table),
                         observer=observer_address, user=0))
                require(returned == 0 and after[3] == table_before, "actual native context initialization")
                initialized = True
                for si, step in enumerate(case["steps"]):
                    apply(folder, step['actions'])
                    before_fs = snapshot(folder)
                    wire = initial(ci, si, step)
                    first = None if observer is None else len(observer.calls)
                    if observer is not None:
                        observer.select(ci, si, base)
                    os.write(2, ("ANCHOR_PUMP_BEGIN %d %d\n" % (ci, word(wire, 16))).encode())
                    table_at_start = bytes(machine.table)
                    start = time.monotonic_ns()
                    result, before3, after3 = machine.run(wire, context)
                    elapsed = time.monotonic_ns() - start
                    os.write(2, ("ANCHOR_PUMP_END %d %d\n" % (ci, word(wire, 16))).encode())
                    outer.record(ci, si, 1, result, (*before3, table_at_start),
                                 (*after3, bytes(machine.table)), elapsed, dict(observer=observed))
                    require(128 <= result <= 8192 and after3[1][result:] == b"\xa5" * (8208 - result),
                            "actual complete native terminal result and output tail")
                    full = after3[1][:result]
                    state = response(full, result)
                    require(state["kind"] in (0, 1) and state["generation"] == word(wire, 16),
                            "same complete source-owned native operation")
                    caps, actual = capabilities(context.raw[OFFSETS["caps"]:OFFSETS["caps"] + 384])
                    pinned = word(context.raw, OFFSETS["owner_work"] + 40)
                    token = word(context.raw, OFFSETS["owner_work"] + 120)
                    wanted = {"1": "file"}
                    if pinned:
                        require(pinned == 1 and token > 1, "actual pinned anchor capability")
                        wanted[str(token)] = "file"
                    require(caps == wanted and actual["1"]["actual"] == directory and
                            word(context.raw, 8) == 0 and word(context.raw, 176) == 0,
                            "exact retained anchor and borrowed root")
                    require(context.raw[OFFSETS["table"]:OFFSETS["table"] + 144] == table_before and
                            bytes(machine.table) == table_before, "immutable actual libc capability table")
                    if observer is not None:
                        require(not observer.errors and observer.pending is None and observer.deferred_json is None,
                                "complete actual observer lifecycle: " + repr(observer.errors))
                        require(observer.last_terminal == full, "public result is the complete actual HIA terminal frame")
                    observations.append(dict(case=ci, step=si, initial_hex=wire.hex(),
                        first_call=first, last_call=None if observer is None else len(observer.calls) - 1,
                        semantic_hex=semantic(full).hex(), before=before_fs, after=snapshot(folder)))
                counts["owner_calls"] += word(context.raw, 80)
                counts["json_calls"] += word(context.raw, 88)
                counts["filesystem_calls"] += word(context.raw, 96)
                if observer is not None:
                    observer.select(ci, len(case["steps"]), base)
                retained_caps = capabilities(context.raw[256:640])[1]
                before = (b"", b"", context.raw, bytes(machine.table))
                start = time.monotonic_ns()
                returned = int(machine.dispose(base, CONTEXT_BYTES))
                elapsed = time.monotonic_ns() - start
                after = (b"", b"", context.raw, bytes(machine.table))
                outer.record(ci, len(case["steps"]), 2, returned, before, after, elapsed, {})
                require(returned == 0 and context.raw == bytes(CONTEXT_BYTES) + b"\x5a" * 16 and
                        after[3] == table_before, "actual native disposal clears complete private context")
                disposed = True
                for token, row in retained_caps.items():
                    if token != "1":
                        try:
                            os.fstat(row["actual"])
                        except OSError as failure:
                            require(failure.errno == 9, "disposed actual anchor descriptor")
                        else:
                            raise ValueError("native dispose retained an owned file")
                final_info = os.fstat(directory)
                require((final_info.st_dev, final_info.st_ino) == (info.st_dev, info.st_ino),
                        "borrowed root still open after native disposal")
            finally:
                # No Python effect fallback. On any native fault the process fails;
                # only the borrowed fixture FD is ours to close.
                os.close(directory)
                if initialized and not disposed:
                    (output / ("FAILED-CONTEXT-%04d.bin" % ci)).write_bytes(context.raw)
        require(len(observations) == sum(len(row["steps"]) for row in domain), "all complete original anchor operations")
        completed = True
    finally:
        try:
            if observer is not None:
                observer.close(completed)
        finally:
            try:
                if outer is not None:
                    outer.close(completed)
            finally:
                if machine is not None:
                    machine.close()
        (output / "OBSERVATIONS.json").write_bytes(encoded(observations))
        (output / "CONTEXTS.json").write_bytes(encoded(bindings))
    retirement = retire(fixture, domain)
    (output / "RETIREMENT.json").write_bytes(encoded(retirement))
    require(source() == identity, "source unchanged throughout the complete actual native cohort")
    report = dict(schema="hepta.audit-pinned-anchor-callable.native.v1", status="PASS",
        source_manifest_sha256=identity, cases=len(domain), operations=len(observations), observer_enabled=observed,
        pid=os.getpid(), parent_pid=os.getppid(), pgid=os.getpgrp(), uid=os.geteuid(), gid=os.getegid(),
        source_root=str(ROOT), output_root=str(output), build_root=str(build), loaded_image=loaded_image,
        context_count=len(domain), outer_calls=len(outer.rows), counts=counts,
        observations=pin(read(output / "OBSERVATIONS.json")), contexts=pin(read(output / "CONTEXTS.json")),
        outer=pin(read(output / "OUTER.json")), outer_buffers=pin(read(output / "outer.bin.gz")),
        retirement=pin(read(output / "RETIREMENT.json")),
        libc=pin(read(output / "LIBC.bin")), libc_bindings=pin(read(output / "LIBC-BINDINGS.json")),
        maps=pin(read(output / "PROCESS-MAPS.txt")),
        callable=pin(read(build / "callable/callable.image.bin")), root=str(fixture),
        complete_audit_archive_qualified=False, public_handler_qualified=False, whole_runtime_replaced=False)
    if observer is not None:
        report.update(native_calls=len(observer.calls), boundaries=len(observer.boundaries),
            total_effects=len(observer.events),
            buffers=pin(read(output / "buffers.bin.gz")), invocations=pin(read(output / "INVOCATIONS.json")),
            boundary_buffers=pin(read(output / "boundaries.bin.gz")), boundary_rows=pin(read(output / "BOUNDARIES.json")),
            effects=pin(read(output / "effects.jsonl")), observer_errors=pin(read(output / "OBSERVER-ERRORS.json")))
    (output / "NATIVE.json").write_bytes(encoded(report))
    print(encoded(report).decode(), end="")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--build", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--fixture", type=Path, required=True)
    p.add_argument("--observer", choices=("on", "off"), required=True)
    a = p.parse_args()
    run(a.build.resolve(strict=True), a.output.absolute(), a.fixture.absolute(), a.observer == "on")
