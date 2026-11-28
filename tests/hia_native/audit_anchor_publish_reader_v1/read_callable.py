"""Full pure reader for both actual native callable cohorts.

The observed cohort replays no executable: every byte written by the adapter is
accounted from its actual HIA and libc journals. The observer-off cohort retains
all outer buffers and verifies complete external outputs/files plus independent
real syscall order. Neither cohort can substitute a summary for physical bytes.
"""
from pathlib import Path
import struct
from common import ROOT, loads, pin, read, require, files, source
from protocol import cases, initial, response, semantic, word
from fixture import normalized
from read_filesystem import complete,before_step,after_step,retired
from read_native import Calls
from read_context import Context
from read_physical import Outer, Boundaries
from read_libc import verify as verify_libc
from read_trace import records,signature_from_effects,from_syscalls
from environment_policy import filters,GROUPS
from callable_contract import CONTEXT_BYTES, OFFSETS, capabilities

BASE_FILES = {"NATIVE.json", "OBSERVATIONS.json", "CONTEXTS.json", "OUTER.json", "outer.bin.gz",
              "RETIREMENT.json", "RETIRED.json", "ENVIRONMENT.json", "LIBC.bin", "LIBC-BINDINGS.json", "PROCESS-MAPS.txt"}
OBSERVED_FILES = {"buffers.bin.gz", "INVOCATIONS.json", "boundaries.bin.gz", "BOUNDARIES.json",
                  "effects.jsonl", "OBSERVER-ERRORS.json"}


def verify(folder, image, *, observed, group, peer=None, trace=None, stderr=None):
    domain = cases(ROOT,group)
    report = loads(read(folder / "NATIVE.json"))
    require(type(observed) is bool and report["schema"] == "hepta.audit-anchor-publish-callable.native.v1" and
            report["status"] == "PASS" and report["source_manifest_sha256"] == source() and
            report["observer_enabled"] is observed and report["group"]==group and report["cases"] == len(domain) and
            report["operations"] == sum(len(c["steps"]) for _,c in domain) and report["context_count"] == len(domain) and
            report["outer_calls"] == len(domain)*2+sum(len(c["steps"]) for _,c in domain) and report["callable"] == image and
            report["complete_audit_archive_qualified"] is False and
            report["public_handler_qualified"] is False and report["whole_runtime_replaced"] is False,
            "entire fixed private callable cohort and scope")
    require(set(files(folder)) == BASE_FILES | (OBSERVED_FILES if observed else set()),
            "complete exact native cohort file set")
    for key in ("pid", "parent_pid", "pgid", "uid", "gid"):
        require(type(report[key]) is int and report[key] >= (2 if key in ("pid", "parent_pid", "pgid") else 0),
                "actual native process identity")
    require(report["pid"] != report["parent_pid"], "native process has an actual parent")
    for key in ("root", "source_root", "output_root", "build_root"):
        require(type(report[key]) is str and Path(report[key]).is_absolute(), "exact recorded producer path")
    mapping = report["loaded_image"]
    require(set(mapping) == {"address", "bytes"} and type(mapping["address"]) is int and
            mapping["address"] > 0 and mapping["bytes"] == image["bytes"], "exact actual loaded image extent")
    library = verify_libc(folder)
    mapped = [m for m in library["maps"] if m["lo"] == mapping["address"]]
    require(len(mapped) == 1 and mapped[0]["hi"] >= mapping["address"] + image["bytes"] and
            mapped[0]["permissions"] == "r-xp" and mapped[0]["offset"] == 0 and
            mapped[0]["path"] == "/memfd:hepta-runtime-native (deleted)",
            "actual complete sealed-loader RX mapping observation")
    observations = loads(read(folder / "OBSERVATIONS.json"))
    bindings = loads(read(folder / "CONTEXTS.json"))
    require(len(observations) == sum(len(c["steps"]) for _,c in domain) and len(bindings) == len(domain), "all native cases/operations retained")
    outer = Outer(folder)
    calls = Calls(folder) if observed else None
    boundaries = Boundaries(folder) if observed else None
    events = [loads(line) for line in read(folder / "effects.jsonl").splitlines()] if observed else []
    if observed:
        require(read(folder / "OBSERVER-ERRORS.json") == b"[]\n", "no swallowed callback failure")
    else:
        require(peer is not None and peer["observer_enabled"] is True and trace is not None and stderr is not None,
                "observer-off crosschecks an admitted full observed cohort and its own actual syscalls")
        require(report["uid"] == peer["uid"] and report["gid"] == peer["gid"] and
                report["root"] == peer["fixture"], "same actual identity and owned fixture domain")
    event_index = obs_index = 0
    counts = dict(owner_calls=0, json_calls=0, filesystem_calls=0)
    per_case = []
    effect_kinds = set()
    table_addresses = set()
    observer_addresses = set()
    try:
        for bi,(ci, case) in enumerate(domain):
            binding = bindings[bi]
            require(set(binding) == {"case", "context", "table", "observer", "root_fd", "root_identity"} and
                    binding["case"] == ci and all(type(binding[k]) is int for k in
                    ("context", "table", "observer", "root_fd")) and binding["context"] > 0 and
                    binding["context"] % 8 == 0 and binding["table"] > 0 and binding["table"] % 8 == 0 and
                    0 <= binding["root_fd"] <= 0x7fffffff and
                    ((observed and binding["observer"] > 0) or (not observed and binding["observer"] == 0)),
                    "exact per-case private capabilities")
            require(binding["context"] + CONTEXT_BYTES <= binding["table"] or
                    binding["table"] + 168 <= binding["context"], "private context/table ranges disjoint")
            table_addresses.add(binding["table"])
            observer_addresses.add(binding["observer"])
            model = Context(binding, library["table"])
            row, before, after = outer.call(ci, 0, 0)
            require(row["returned"] == 0 and row["args"] == dict(directory=binding["root_fd"],
                    table=binding["table"], observer=binding["observer"], user=0) and
                    before == [b"", b"", bytes(CONTEXT_BYTES) + b"\x5a" * 16, library["table"]] and
                    after == [b"", b"", model.raw(), library["table"]],
                    "every complete initialization write and immutable table")
            previous_context = after[2]
            previous_files = None
            case_counts = dict(owner_calls=0, json_calls=0, filesystem_calls=0)
            for si, step in enumerate(case["steps"]):
                wire = initial(ci, si, case)
                row, before, after = outer.call(ci, si, 1)
                require(row["args"] == dict(observer=observed) and
                        before == [wire + b"\xc3" * 16, b"\xa5" * 8208, previous_context, library["table"]] and
                        after[0] == before[0] and after[3] == library["table"],
                        "all actual outer preimages and persistent same-case context")
                returned = row["returned"]
                require(128 <= returned <= 8192 and after[1][returned:] == b"\xa5" * (8208 - returned),
                        "complete outer terminal result and untouched output tail")
                terminal = after[1][:returned]
                final = response(terminal, returned)
                require(final["kind"] in (0, 1) and final["generation"] == word(wire, 16) and
                        final["operation"] == 1, "actual native completed operation identity")
                observation = observations[obs_index]
                require(set(observation) == {"case", "step", "initial_hex", "first_call", "last_call",
                                            "semantic_hex", "before", "after"} and
                        observation["case"] == ci and observation["step"] == si and
                        observation["initial_hex"] == wire.hex() and
                        observation["semantic_hex"] == semantic(terminal).hex(),
                        "complete external native response bound to actual returned bytes")
                root_info=observation["before"][0]["stat"]
                require(binding["root_identity"]==dict(device=root_info["st_dev"],inode=root_info["st_ino"],mode=root_info["st_mode"]),
                        "same actual borrowed directory throughout every retained turn")
                previous_files=observation["after"]
                if observed:
                    model.begin(wire)
                    turn = wire
                    first = calls.index
                    while True:
                        state, complete, last = model.owner(calls, turn, ci, si)
                        if state["kind"] < 2:
                            require(complete == terminal, "actual copied outer result equals whole final HIA frame")
                            break
                        require(event_index < len(events), "no missing actual native effect")
                        event = events[event_index]
                        event_index += 1
                        effect_kinds.add((state["kind"], state["operation"]))
                        if state["kind"] == 2:
                            turn = model.filesystem(boundaries, state, event, ci, si)
                        else:
                            turn, expected_event = model.json(calls, state, ci, si)
                            require(event == expected_event, "whole actual codec input/output and native ACK")
                    require(observation["first_call"] == first and observation["last_call"] == last,
                            "exact HIA call range for every external operation")
                    require(after[2] == model.terminal(),
                            "every context byte, including all scratch/input/work/output tails, accounted")
                else:
                    require(observation["first_call"] is None and observation["last_call"] is None,
                            "observer-off does not invent internal callback evidence")
                    reference = peer["observations"][obs_index]
                    require(observation["semantic_hex"] == reference["semantic_hex"],
                            "complete observer-off response equals observed peer")
                    ctx = after[2]
                    require(ctx[:8] == b"HAPUCX01" and word(ctx, 8) == word(ctx, 176) == word(ctx, 200) == 0 and
                            word(ctx, 16) == binding["root_fd"] and word(ctx, 32) == 0 and
                            word(ctx, 40) == 21 and word(ctx, 48) == word(ctx, 56) == 0 and
                            ctx[208:256] == bytes(48) and ctx[640:808] == library["table"] and
                            word(ctx, 64) == word(wire, 16) and word(ctx, 72) == final["sequence"] and
                            word(ctx, 128) == returned and word(ctx, 144) == returned and
                            ctx[OFFSETS["owner_out"]:OFFSETS["owner_out"] + returned] == terminal,
                            "complete observer-off private admission, terminal and counters")
                    require(ctx[OFFSETS["owner_out"] + returned:OFFSETS["owner_out"] + 8208] ==
                            b"\xa5" * (8208 - returned) and
                            ctx[OFFSETS["owner_work"] + 32768:OFFSETS["owner_work"] + 32784] == b"\x5a" * 16,
                            "observer-off inner output/workspace guards")
                caps, actual = capabilities(after[2][256:640])
                wanted={"1":"file"}
                token=word(after[2],OFFSETS["owner_work"]+144)
                if token:
                    require(word(after[2],OFFSETS["owner_work"]+40)==2 and token>1,"retained entropy FD mode")
                    wanted[str(token)]="file"
                require(caps==wanted and actual["1"]["actual"]==binding["root_fd"],"exact borrowed root plus retained entropy capability")
                previous_context = after[2]
                obs_index += 1
            for name, offset in (("owner_calls", 80), ("json_calls", 88), ("filesystem_calls", 96)):
                value = word(previous_context, offset)
                require(value > 0 if name == "owner_calls" else value >= 0, "actual case counters")
                case_counts[name] = value
                counts[name] += value
            if not observed:
                require(case_counts == peer["per_case_counts"][bi], "all observer-off native pump iterations conserved")
            per_case.append(case_counts)
            if observed:
                disposed=model.dispose(boundaries,ci,len(case["steps"]))
                require(disposed==bytes(CONTEXT_BYTES)+b"\x5a"*16,"entire modeled native disposal")
            row, before, after = outer.call(ci, len(case["steps"]), 2)
            require(row["returned"] == 0 and row["args"] == {} and
                    before == [b"", b"", previous_context, library["table"]] and
                    after == [b"", b"", bytes(CONTEXT_BYTES) + b"\x5a" * 16, library["table"]],
                    "actual disposal clears every private byte while keeping the borrowed table")
        require(len(table_addresses) == len(observer_addresses) == 1, "one immutable actual capability table/callback")
        outer_summary = outer.finish(len(domain)*2+len(observations))
        require(obs_index == len(observations) == sum(len(c["steps"]) for _,c in domain), "all complete native operations")
        if observed:
            require(event_index==len(events) and effect_kinds<=({(2,i) for i in (1,4,5,6,7,8,9,17,18,19)}|{(3,4)}),
                    "all actual effects accounted and confined to publisher protocol")
            call_summary=calls.finish();boundary_summary=boundaries.finish()
            require(call_summary["calls"]==report["native_calls"]==counts["owner_calls"]+counts["json_calls"] and
                    boundary_summary["records"]==report["boundaries"] and report["total_effects"]==len(events)==counts["filesystem_calls"]+counts["json_calls"] and
                    boundary_summary["records"]>=counts["filesystem_calls"],"all actual HIA, filesystem, codec and destructor calls")
        else:
            call_summary = boundary_summary = None
    finally:
        outer.close()
        if calls is not None:
            calls.close()
        if boundaries is not None:
            boundaries.close()
    require(counts==report["counts"] and counts["owner_calls"]==len(observations)+counts["filesystem_calls"]+counts["json_calls"],
            "every actual native effect has exactly one owning continuation")
    by_case={};signatures={};traced=None
    if observed:
        for ci,case in domain:
            actual=signature_from_effects([e for e in events if e["case"]==ci],case)
            require(len(actual["signatures"])==len(case["steps"]),"all actual observed operation signatures")
            by_case[ci]=actual["temporaries"];signatures[ci]=actual["signatures"]
    else:
        groups,trace_stderr,all_calls=records(read(trace),report["pid"],domain,b"PUBLISH_PUMP")
        expected_stderr=b"".join(("PUBLISH_PUMP_%s %d %d\n"%(phase,ci,1+ci*100+si)).encode()
            for ci,case in domain for si in range(len(case["steps"])) for phase in ("BEGIN","END"))
        require(trace_stderr==read(stderr)==expected_stderr,"entire observer-off stderr and marked syscall turns")
        previous=-1;trace_cases=[]
        for bi,(ci,case) in enumerate(domain):
            selected={key:value for key,value in groups.items() if key[0]==ci}
            end=min((r["index"] for key,values in groups.items() if key[0]>ci for r in values),default=len(all_calls))
            local=[r for r in all_calls if previous<r["index"]<end]
            actual=from_syscalls(selected,[(ci,case)],bindings[bi]["root_fd"],local,original=False)
            by_case[ci]=actual["temporaries"];signatures[ci]=actual["signatures"]
            require(actual["signatures"]==peer["signatures"][ci],"all exact observer-off actual syscall/effect order")
            previous=max(r["index"] for values in selected.values() for r in values)
            trace_cases.append(dict(case=ci,syscalls=sum(len(x) for x in actual["signatures"]),
                                    actual_temporary_names=actual["temporaries"],outside_closes=actual["outside_closes"]))
        traced=dict(trace=pin(read(trace)),cases=trace_cases)
    by_observation={(r["case"],r["step"]):r for r in observations}
    for ci,case in domain:
        previous=None
        for si,step in enumerate(case["steps"]):
            row=by_observation[ci,si]
            before_step(case,step,row["before"],previous,by_case[ci],report["uid"],report["gid"])
            after_step(row["before"],row["after"],signatures[ci][si],by_case[ci],report["uid"],report["gid"])
            if not observed:
                other=next(r for r in peer["observations"] if (r["case"],r["step"])==(ci,si))
                require(all(complete(row[k],by_case[ci])==complete(other[k],peer["temporaries"][ci]) for k in ("before","after")),
                        "all observer-off filesystem bytes and policy fields match its observed peer")
            previous=row["after"]
    retirement_pin=retired(folder,report,observations,by_case)
    environment=loads(read(folder/"ENVIRONMENT.json"))
    require(environment==dict(group=group,installed=bool(GROUPS[group]),filters=[list(row) for row in filters(group)]),
            "source-owned real kernel environment")
    bound = dict(observations="OBSERVATIONS.json", contexts="CONTEXTS.json", outer="OUTER.json",
                 outer_buffers="outer.bin.gz", retirement="RETIREMENT.json", libc="LIBC.bin",
                 libc_bindings="LIBC-BINDINGS.json", maps="PROCESS-MAPS.txt",environment="ENVIRONMENT.json")
    if observed:
        bound.update(buffers="buffers.bin.gz", invocations="INVOCATIONS.json", boundary_buffers="boundaries.bin.gz",
                     boundary_rows="BOUNDARIES.json", effects="effects.jsonl", observer_errors="OBSERVER-ERRORS.json")
    for key, name in bound.items():
        require(report[key] == pin(read(folder / name)), "complete retained native file identity: " + name)
    return dict(status="COMPLETE_NATIVE_CALLABLE_READBACK_PASS", observer_enabled=observed,
        cases=len(domain), operations=len(observations), outer=outer_summary, hia=call_summary, boundaries=boundary_summary,
        counts=counts, per_case_counts=per_case, fixture=report["root"], uid=report["uid"], gid=report["gid"],
        observations=observations, events=events, libc=library["library"],
        signatures=signatures,temporaries=by_case,retired=retirement_pin,
        effect_kinds=sorted(effect_kinds),
        observer_off_syscalls=traced,
        native_or_rust_executions=0, reader_writes=0)
