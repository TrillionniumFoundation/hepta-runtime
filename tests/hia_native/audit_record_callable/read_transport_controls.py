"""Pure complete-buffer admission-control and successful-recovery reader."""
from common import ROOT, loads, read, pin, require, source, files
from protocol import semantic, response, word
from fixture import normalized
from callable_contract import CONTEXT_BYTES, capabilities
from read_physical import Physical
from read_context import Context
from read_libc import verify as verify_libc
from transport_cases import SPECS, wire, sequence, argv, mutate
import struct

ORDER = ("input", "output", "context", "table")


def verify(folder, image, ordinary):
    report = loads(read(folder / "CONTROLS.json"))
    names = {"CALLS.json", "OBSERVATIONS.json", "RETIREMENT.json", "buffers.bin.gz",
             "LIBC.bin", "LIBC-BINDINGS.json", "PROCESS-MAPS.txt"}
    require(set(files(folder)) == names | {"CONTROLS.json"} and set(report["files"]) == names,
            "complete exact native admission-control file set")
    for name in names:
        require(report["files"][name] == pin(read(folder / name)), "all control file bytes: " + name)
    require(report["schema"] == "hepta.audit-record-callable.transport-controls.v1" and
            report["status"] == "PASS" and report["source_manifest_sha256"] == source() and
            report["cases"] == report["refusals"] == report["recoveries"] == len(SPECS) == 45 and
            report["actual_calls"] == 4 * len(SPECS) and report["callable"] == image and
            report["original_rust_replay"] == 0 and report["admission_only_refusal_atomicity"] is True and
            report["foreign_executable_capabilities"] is False and
            report["whole_audit_caller_qualified"] is False and report["public_handler_qualified"] is False,
            "fixed admission/refusal/recovery scope and count")
    require(report["uid"] == ordinary["uid"] and report["gid"] == ordinary["gid"],
            "same actual native filesystem identity")
    library = verify_libc(folder)
    rows = loads(read(folder / "CALLS.json"))
    observations = loads(read(folder / "OBSERVATIONS.json"))
    require(len(rows) == 4 * len(SPECS) and len(observations) == len(SPECS), "entire physical control domain")
    stream = Physical(folder / "buffers.bin.gz", b"AIOCTLOG")
    request = wire()
    expected_semantic = ordinary["observations"][5]["semantic_hex"]
    try:
        for ci, spec in enumerate(SPECS):
            current = dict(input=request + b"\xc3" * 16 + b"\xc7" * (4369 - len(request) - 16),
                           output=b"\xa5" * 8208, context=bytes(CONTEXT_BYTES) + b"\x5a" * 16,
                           table=library["table"])
            addresses = None
            for phase, function, parameters, changes, expected in sequence(spec):
                require(stream.exact(8) == b"AIOCTL01", "exact actual transport-control invocation")
                index, returned, nm, ni, no, nc, nt = struct.unpack("<7Q", stream.exact(56))
                require((index, ni, no, nc, nt) == (stream.count, 4369, 8208, 98320, 128) and
                        0 < nm <= 65536, "whole actual transport-control buffer extents")
                raw_meta = stream.exact(nm)
                record = loads(raw_meta)
                before = [stream.exact(n) for n in (ni, no, nc, nt)]
                after = [stream.exact(n) for n in (ni, no, nc, nt)]
                require(record == rows[index] and record == dict(index=index, case=ci,
                    name=spec[0] + "/" + spec[1], phase=phase, function=function, parameters=parameters,
                    mutations=[list(x) for x in changes], expected=expected, returned=returned,
                    addresses=record["addresses"], arguments=record["arguments"],
                    elapsed_ns=record["elapsed_ns"], before=[pin(x) for x in before], after=[pin(x) for x in after]) and
                    type(record["elapsed_ns"]) is int and record["elapsed_ns"] >= 0,
                    "all actual control scalar fields and full pre/post buffers")
                here = record["addresses"]
                require(set(here) == {"input", "output", "context", "table", "root"} and
                        all(type(v) is int and 0 <= v < 1 << 64 for v in here.values()) and
                        all(here[k] > 0 and here[k] % 8 == 0 for k in ORDER) and here["root"] <= 0x7fffffff,
                        "actual owned native allocations and borrowed FD")
                if addresses is None:
                    addresses = here
                require(here == addresses, "same actual owned test allocations throughout recovery")
                intervals = sorted((here[k], here[k] + n) for k, n in zip(ORDER, (ni, no, nc, nt)))
                require(all(a[1] <= b[0] for a, b in zip(intervals, intervals[1:])),
                        "all real control allocations disjoint")
                changed = mutate(current, changes)
                require(before == [changed[k] for k in ORDER] and
                        record["arguments"] == argv(function, parameters, addresses),
                        "only the declared caller-owned test mutation and actual export arguments")
                if expected is not None:
                    require(returned == expected, "actual exact exported return code")
                if phase == "refusal":
                    require(after == before, "every original admission-refusal input/output/context/table byte unchanged")
                    # The fixed fixture restores only this exact deliberate mutation.
                elif function == "initialize":
                    binding = dict(context=here["context"], root_fd=here["root"], observer=0)
                    wanted = dict(current, context=Context(binding, library["table"]).raw())
                    require(after == [wanted[k] for k in ORDER], "all actual successful initialization writes")
                    current = wanted
                elif function == "dispose":
                    wanted = dict(current, context=bytes(CONTEXT_BYTES) + b"\x5a" * 16)
                    require(after == [wanted[k] for k in ORDER], "complete actual successful disposal")
                    current = wanted
                else:
                    require(128 <= returned <= 8192 and after[0] == before[0] and after[3] == before[3] and
                            after[1][returned:] == b"\xa5" * (8208 - returned) and
                            after[2][CONTEXT_BYTES:] == b"\x5a" * 16,
                            "complete actual recovery output and borrowed guards")
                    terminal = after[1][:returned]
                    result = response(terminal, returned)
                    require(result["generation"] == word(request, 16) and result["operation"] == 1 and
                            semantic(terminal).hex() == expected_semantic,
                            "actual recovery equals the fixed original empty-directory read")
                    ctx = after[2]
                    require(ctx[:8] == b"HAICTX01" and word(ctx, 8) == word(ctx, 48) == word(ctx, 56) ==
                            word(ctx, 176) == word(ctx, 200) == 0 and ctx[640:768] == library["table"] and
                            word(ctx, 16) == here["root"] and word(ctx, 80) == 2 and word(ctx, 88) == 0 and
                            word(ctx, 96) == word(ctx, 72) == 1 and
                            capabilities(ctx[256:640])[0] == {"1": "file"} and
                            capabilities(ctx[256:640])[1]["1"]["actual"] == here["root"],
                            "real recovery is native-owned, observer-free, and leaves no owned resource")
                    observation = observations[ci]
                    require(observation["case"] == ci and observation["name"] == spec[0] + "/" + spec[1] and
                            observation["semantic_hex"] == expected_semantic and
                            normalized(observation["before"]) == normalized(observation["after"]) ==
                            [dict(path_hex="", kind="directory", mode=0o40700, uid=report["uid"],
                                  gid=report["gid"], nlink=2)], "complete real control fixture before/after")
                    current = dict(zip(ORDER, after))
                stream.count += 1
        require(stream.count == len(rows), "no extra or omitted actual control calls")
        summary = stream.end(b"AIOCTEND")
    finally:
        stream.close()
    retired = loads(read(folder / "RETIREMENT.json"))
    require(retired["owned_root"] == report["fixture"] and retired["removed_after_capture"] is True and
            len(retired["complete_final_observations"]) == len(SPECS) and
            all(normalized(retired["complete_final_observations"][i]) == normalized(observations[i]["after"])
                for i in range(len(SPECS))), "all complete control fixture retirement states")
    return dict(status="COMPLETE_TRANSPORT_CONTROLS_READBACK_PASS", cases=len(SPECS), refusals=len(SPECS),
                recoveries=len(SPECS), actual_calls=stream.count, complete_buffers=summary,
                native_or_rust_executions=0, reader_writes=0)
