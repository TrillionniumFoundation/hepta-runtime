"""Actual HIA continuation, capacity and atomic-refusal controls.

An unchanged full workspace is represented losslessly by an admitted full base
plus the explicit pre-call patches. Every call hashes every declared workspace
byte before and after; output buffers are retained completely. This avoids
retaining identical 256 MiB arrays once for every refusal.
"""
import argparse
import ctypes
import gzip
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import time

sys.dont_write_bytecode = True
from native_transport import Transport, request, PACK, UNPACK, CALL, CONTRACT, INVALID, CAPACITY, WORK, QUERY, REPLY, REGION, CONSTRUCTOR_REPLY, CONSTRUCTOR_GROW

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
NAMES = ("input-short", "input-magic", "input-op", "input-auth", "input-search", "input-reserved",
         "input-length", "input-utf8", "input-above-eight-mib", "state-magic", "state-phase", "state-sequence",
         "pending-input", "pending-snapshot", "pending-query", "pending-ack", "pending-query-size", "pending-reply-capacity",
         "pending-reserved", "pending-code-width", "pending-recovery", "child-capacity", "child-capacity-recovery",
         "short-output", "short-workspace", "output-capacity-after-serialization", "output-capacity-recovery",
         "constructor-query-byte", "constructor-query-policy", "constructor-response-policy",
         "constructor-response-extent", "constructor-ack", "constructor-pending-recovery",
         "constructor-workspace-growth", "constructor-workspace-growth-recovery",
         "constructor-output-growth", "constructor-output-growth-recovery",
         "constructor-small-output", "constructor-small-output-recovery")


def dump(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2, allow_nan=False)+"\n")


def chunks(session):
    address = ctypes.addressof(session._workspace)
    for at in range(0, session.workspace_capacity, 1 << 20):
        yield ctypes.string_at(address+at, min(1 << 20, session.workspace_capacity-at))


def workspace_sha(session):
    digest = hashlib.sha256()
    for raw in chunks(session):
        digest.update(raw)
    return digest.hexdigest()


def base(output, name, session):
    digest = hashlib.sha256()
    size = 0
    with gzip.open(output/(name+".workspace.gz"), "wb", compresslevel=1) as stream:
        for raw in chunks(session):
            stream.write(raw); digest.update(raw); size += len(raw)
    raw = ctypes.string_at(session._output, session.output_capacity)
    (output/(name+".output.bin")).write_bytes(raw)
    return dict(name=name, workspace_bytes=size, workspace_sha256=digest.hexdigest(),
                output_bytes=len(raw), output_sha256=SHA(raw))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    build_path = args.build.resolve(strict=True)
    builds = json.loads(build_path.read_bytes())
    builds = builds.get("modules", builds)
    manifests = {}
    for name, row in builds.items():
        path = Path(row["manifest"])
        path = path if path.is_absolute() else build_path.parent/path
        assert SHA(path.read_bytes()) == row["manifest_sha256"]
        manifests[name] = path
    output = args.output.absolute()
    output.mkdir(parents=True, exist_ok=False)
    report = dict(schema="hepta.scope-annotation.actual-controls.v1", status="IN_PROGRESS", controls=[], bases=[],
        execution=dict(pid=os.getpid(), parent_pid=os.getppid(), cwd=str(Path.cwd().resolve())),
        build_sha256=SHA(build_path.read_bytes()), full_refusal_workspace_bytes_hashed=0,
        public_handler_qualified=False, original_execution_qualified=False, whole_runtime_replaced=False)
    save = lambda: dump(output/"result.json", report)
    started = time.monotonic()
    save()
    try:
        with Transport(args.runtime.resolve(strict=True), manifests) as transport:
            owner = transport.owner
            ctypes.memset(owner._output, 0xCC, owner.output_capacity)
            initial = base(output, "initial", owner)
            report["bases"].append(initial)
            valid = request(b"{}")

            def refuse(label, wire, expected, baseline, patches=(), session=owner):
                old = []
                for at, raw in patches:
                    old.append((at, transport.read(session, at, len(raw))))
                    transport.write(session, at, raw)
                try:
                    before = ctypes.string_at(session._output, session.output_capacity)
                    before_hash = workspace_sha(session)
                    code, response = transport.invoke(session, wire)
                    after = ctypes.string_at(session._output, session.output_capacity)
                    after_hash = workspace_sha(session)
                    assert code == expected and not response, (label, code)
                    assert before == after and before_hash == after_hash, label
                    path = "control-" + str(len(report["controls"]))
                    (output/(path+".input.bin")).write_bytes(wire)
                    (output/(path+".before.bin")).write_bytes(before)
                    (output/(path+".after.bin")).write_bytes(after)
                    report["controls"].append(dict(label=label, code=code, files_prefix=path, base=baseline["name"],
                        patches=[dict(at=at, bytes=raw.hex()) for at, raw in patches],
                        input_bytes=len(wire), input_sha256=SHA(wire), output_bytes=len(before),
                        output_sha256=SHA(before), workspace_bytes=session.workspace_capacity,
                        workspace_before_sha256=before_hash, workspace_after_sha256=after_hash,
                        output_unchanged=True, workspace_unchanged=True))
                    report["full_refusal_workspace_bytes_hashed"] += 2*session.workspace_capacity
                    save()
                finally:
                    for at, raw in reversed(old):
                        transport.write(session, at, raw)

            def changed(wire, at, raw):
                return wire[:at]+raw+wire[at+len(raw):]

            invalids = [
                ("input-short", valid[:47]), ("input-magic", b"?"+valid[1:]),
                ("input-op", changed(valid, 8, PACK(2))), ("input-auth", changed(valid, 16, PACK(2))),
                ("input-search", changed(valid, 24, PACK(2))), ("input-reserved", changed(valid, 40, PACK(1))),
                ("input-length", changed(valid, 32, PACK(1))), ("input-utf8", request(b'"\xff"')),
                ("input-above-eight-mib", request(b" "*((8 << 20)+1))),
            ]
            for name, wire in invalids:
                refuse(name, wire, INVALID, initial)
            state = int.from_bytes(b"HSCANW01", "little")
            refuse("state-magic", valid, CONTRACT, initial, [(0, PACK(1))])
            refuse("state-phase", valid, CONTRACT, initial, [(0, PACK(state, 3))])
            refuse("state-sequence", valid, CONTRACT, initial, [(0, PACK(state, 0, (1 << 64)-1))])
            code, response = transport.invoke(owner, valid)
            assert code == CALL and not response
            pending = base(output, "pending", owner)
            report["bases"].append(pending)
            sequence = UNPACK(transport.read(owner, 16, 8))[0]
            refuse("pending-input", request(b"[]"), CONTRACT, pending)
            for name, at, raw in (
                ("pending-snapshot", (1 << 20)+48, b"[]"), ("pending-query", QUERY+24, b"[]"),
                ("pending-ack", 320, PACK(sequence+1)), ("pending-query-size", 296, PACK(0)),
                ("pending-reply-capacity", 312, PACK(REGION-1)), ("pending-reserved", 280, PACK(1)),
                ("pending-code-width", 320, PACK(sequence, 1 << 32)),
            ):
                refuse(name, valid, CONTRACT, pending, [(at, raw)])

            child_input = transport.read(owner, QUERY, len(valid)-24)
            child_code, child_response = transport.invoke(transport.value, child_input)
            assert child_code == len(child_response) and child_response == b"{}"
            transport.write(owner, REPLY, child_response)
            transport.write(owner, 320, PACK(sequence, child_code))
            transport.sequence = sequence
            actual = transport.run(valid)
            assert actual["code"] < 0xffff0000
            transport.check_typed(actual["annotation"], actual["wire"])
            (output/"pending-recovery.bin").write_bytes(actual["response"]+actual["wire"])
            report["controls"].append(dict(label="pending-recovery", code=actual["code"], child_code=child_code,
                retained="pending-recovery.bin", sha256=SHA(actual["response"]+actual["wire"])))

            code, _ = transport.invoke(owner, valid)
            assert code == CALL
            sequence = UNPACK(transport.read(owner, 16, 8))[0]
            before = ctypes.string_at(owner._output, owner.output_capacity)
            with transport.modules["serde_json"].session(output_capacity=1, workspace_capacity=WORK) as small:
                code, _ = transport.invoke(small, child_input)
                assert code == CAPACITY
            transport.write(owner, 320, PACK(sequence, code)); transport.sequence = sequence
            code, _ = transport.invoke(owner, valid)
            assert code == CAPACITY and UNPACK(transport.read(owner, 8, 8))[0] == 0
            assert ctypes.string_at(owner._output, owner.output_capacity) == before
            report["controls"].append(dict(label="child-capacity", code=code, actual_child_code=CAPACITY,
                output_unchanged=True, phase_reset=True))
            actual = transport.run(valid)
            assert actual["code"] < 0xffff0000
            (output/"child-capacity-recovery.bin").write_bytes(actual["response"]+actual["wire"])
            report["controls"].append(dict(label="child-capacity-recovery", code=actual["code"],
                retained="child-capacity-recovery.bin", sha256=SHA(actual["response"]+actual["wire"])))
            for name, output_size, workspace_size in (("short-output", 63, WORK), ("short-workspace", 128, WORK-1)):
                with transport.modules["scope_annotation"].session(output_capacity=output_size, workspace_capacity=workspace_size) as small:
                    ctypes.memset(small._output, 0xCE, output_size)
                    snapshot = base(output, name, small)
                    report["bases"].append(snapshot)
                    refuse(name, valid, CAPACITY, snapshot, session=small)
            # Preserve the same workspace and ticket sequence across an output
            # capacity refusal; only the disjoint output loan is replaced.
            owner._output = ctypes.create_string_buffer(64+16)
            owner.output_capacity = 64
            ctypes.memset(owner._output, 0xD2, 64)
            actual = transport.run(valid)
            assert actual["code"] == CAPACITY
            assert ctypes.string_at(owner._output, 64) == b"\xd2"*64
            assert UNPACK(transport.read(owner, 8, 8))[0] == 0
            report["controls"].append(dict(label="output-capacity-after-serialization", code=CAPACITY,
                output_unchanged=True, phase_reset=True))
            owner._output = ctypes.create_string_buffer(65600+16)
            owner.output_capacity = 65600
            actual = transport.run(valid)
            assert actual["code"] < 0xffff0000
            transport.check_typed(actual["annotation"], actual["wire"])
            (output/"output-capacity-recovery.bin").write_bytes(actual["response"]+actual["wire"])
            report["controls"].append(dict(label="output-capacity-recovery", code=actual["code"],
                retained="output-capacity-recovery.bin", sha256=SHA(actual["response"]+actual["wire"])))
            def prepare_constructor():
                code, _ = transport.invoke(owner, valid)
                assert code == CALL
                seq = UNPACK(transport.read(owner, 16, 8))[0]
                assert seq == transport.sequence+1
                child_code, child_reply = transport.invoke(transport.value, child_input)
                assert child_reply == b"{}" and child_code == 2
                transport.write(owner, REPLY, child_reply)
                transport.write(owner, 320, PACK(seq, child_code))
                transport.sequence = seq
                code, _ = transport.invoke(owner, valid)
                assert code == CALL
                seq = UNPACK(transport.read(owner, 16, 8))[0]
                assert seq == transport.sequence+1
                action = UNPACK(transport.read(owner, 264, 88))
                assert action[1] == 3 and action[5:7] == (CONSTRUCTOR_REPLY, REGION+64)
                query = transport.read(owner, QUERY, action[4])
                transport.sequence = seq
                return seq, query

            seq, query = prepare_constructor()
            code, reply = transport.call_constructor(transport.constructor, query)
            assert code == 64 and len(reply) == 355
            transport.write(owner, CONSTRUCTOR_REPLY, reply)
            transport.write(owner, 320, PACK(seq, code))
            constructor_pending = base(output, "constructor-pending", owner)
            report["bases"].append(constructor_pending)
            for label, at, value in (
                ("constructor-query-byte", QUERY+64, b"["),
                ("constructor-query-policy", QUERY+24, PACK(1)),
                ("constructor-response-policy", CONSTRUCTOR_REPLY+24, PACK(1)),
                ("constructor-response-extent", CONSTRUCTOR_REPLY+40, PACK(REGION+1)),
                ("constructor-ack", 320, PACK(seq+1)),
            ):
                refuse(label, valid, CONTRACT, constructor_pending, [(at, value)])
            actual = transport.run(valid)
            assert actual["code"] == 262
            name = "constructor-pending-recovery"
            (output/(name+".bin")).write_bytes(actual["response"]+actual["wire"])
            report["controls"].append(dict(label=name, code=262, retained=name+".bin",
                sha256=SHA(actual["response"]+actual["wire"])))

            for label, child_output, child_workspace, wanted_kind in (
                ("constructor-workspace-growth", 512, 16384+198-1, 1),
                ("constructor-output-growth", 32, 16384+198, 2),
                ("constructor-small-output", 31, 16384+198, 0),
            ):
                seq, query = prepare_constructor()
                owner_before = ctypes.string_at(owner._output, owner.output_capacity)
                state_before = transport.read(owner, 0, 352)
                with transport.modules["text_result_constructor"].session(
                        output_capacity=child_output, workspace_capacity=child_workspace) as small:
                    ctypes.memset(small._output, 0xA6, child_output)
                    before = ctypes.string_at(small._output, child_output)
                    work_before = transport.read(small, 0, child_workspace)
                    code, reply = transport.call_constructor(small, query)
                    after = ctypes.string_at(small._output, child_output)
                    work_after = transport.read(small, 0, child_workspace)
                assert code == (CONSTRUCTOR_GROW if wanted_kind else CAPACITY)
                if wanted_kind:
                    required = 16384+198 if wanted_kind == 1 else 355
                    assert reply == b"HGRWS002"+PACK(wanted_kind, required, 0)
                    assert after == reply+before[32:]
                    transport.write(owner, CONSTRUCTOR_REPLY, reply)
                else:
                    assert not reply and after == before and work_after == work_before
                transport.write(owner, 320, PACK(seq, code))
                owner_code, response = transport.invoke(owner, valid)
                owner_after = ctypes.string_at(owner._output, owner.output_capacity)
                state_after = transport.read(owner, 0, 352)
                assert owner_code == CAPACITY and not response and owner_before == owner_after
                assert UNPACK(state_after[8:16])[0] == 0
                retained = {}
                for suffix, raw in (("request",query),("child-before",before),("child-after",after),
                        ("child-work-before",work_before),("child-work-after",work_after),
                        ("owner-before",owner_before),("owner-after",owner_after),
                        ("state-before",state_before),("state-after",state_after)):
                    filename = label+"."+suffix+".bin"
                    (output/filename).write_bytes(raw)
                    retained[suffix] = dict(file=filename, bytes=len(raw), sha256=SHA(raw))
                report["controls"].append(dict(label=label, code=owner_code, actual_child_code=code,
                    child_output_capacity=child_output, child_workspace_capacity=child_workspace,
                    growth_kind=wanted_kind, output_unchanged=True, phase_reset=True,
                    constructor_observation=retained))
                actual = transport.run(valid)
                assert actual["code"] == 262
                name = label+"-recovery"
                (output/(name+".bin")).write_bytes(actual["response"]+actual["wire"])
                report["controls"].append(dict(label=name, code=262, retained=name+".bin",
                    sha256=SHA(actual["response"]+actual["wire"])))
        assert tuple(row["label"] for row in report["controls"]) == NAMES
        report["status"] = "HIA_CONTROLS_PASS"
    finally:
        report["elapsed_seconds"] = time.monotonic()-started
        save()
    print(json.dumps({k: report[k] for k in ("status", "full_refusal_workspace_bytes_hashed", "elapsed_seconds")}, sort_keys=True))


if __name__ == "__main__":
    main()
