"""Actual private-boundary refusals and resumed, byte-observed recovery."""
from contextlib import ExitStack
from pathlib import Path
import argparse
import ctypes
import hashlib
import json
import os
import struct
import sys
import time

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from build import verify_source
from capture import Capture, CALL, GROW, PACK, WORD, line
from cases import cases, frame

INVALID, CONTRACT, CAPACITY = 0xffffffff, 0xfffffff8, 0xfffffffe
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
INITIAL = ("short", "magic", "operation", "authenticated", "search", "reserved", "length", "utf8", "effect-search-required")
STATE = ("state-magic", "state-phase", "state-sequence-overflow")
PENDING = ("changed-input", "changed-authentication", "changed-search", "changed-operation",
           "saved-input", "saved-output-capacity", "saved-workspace-capacity", "layout-snapshot", "layout-query",
           "layout-reply", "action-magic", "action-sequence", "action-child", "action-reserved",
           "action-query", "action-query-length", "action-reply", "action-reply-capacity", "missing-ack",
           "stale-ack", "result-wide", "action-reserved-tail", "query-magic", "query-body", "reply-magic",
           "reply-growth", "reply-empty", "reply-reserved", "pending-snapshot")
CONSTRUCTOR = ("constructor-query-policy", "constructor-query-is-error", "constructor-query-reserved",
               "constructor-response-magic", "constructor-response-status", "constructor-response-policy",
               "constructor-response-header", "constructor-response-extent", "constructor-response-reserved", "constructor-stale-ack",
               "constructor-query-byte", "constructor-result-capacity", "constructor-result-growth")
SECOND = ("second-parse-nonobject", "second-parse-error", "second-parse-stale-ack")
CONTROL_NAMES = INITIAL + STATE + PENDING + CONSTRUCTOR + tuple("short-output-" + str(n) for n in (0,31,63)) + SECOND
RECOVERY_NAMES = ("valid-after-refusals", "workspace-growth-0", "workspace-growth-1", "workspace-growth-16384",
                  "output-growth-64", "effect-after-second-parse-refusals")
CHILD_NAMES = ("constructor-small-output-0", "constructor-small-output-31", "constructor-small-output-63")


def plan():
    return dict(schema="hepta.scope-annotation-span.control-domain.v2", refusals=list(CONTROL_NAMES),
                recoveries=list(RECOVERY_NAMES), child_refusals=list(CHILD_NAMES),
                child_expected_codes={name:(CAPACITY if capacity < 32 else GROW)
                                      for name,capacity in zip(CHILD_NAMES,(0,31,63),strict=True)},
                old_fixed_8mib_rejection_removed=True,
                replacement="four complete original-compared span-wide semantic cases")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source_sha = verify_source()
    assert json.loads((ROOT / "CONTROL_DOMAIN.json").read_bytes()) == plan()
    args.output.mkdir(parents=True, exist_ok=False)
    capture = Capture(args.build, args.output)
    expected = {row["label"]: row for row in cases()}
    empty_label = "baseline-empty-00"
    assert empty_label in expected
    request = frame(expected[empty_label])
    records, recoveries, baselines, child_refusals = [], [], [], []
    started = time.monotonic()
    result = dict(schema="hepta.scope-annotation-span.controls.v2", status="RUNNING",
                  source_manifest_sha256=source_sha, build_sha256=SHA(args.build.read_bytes()),
                  control_domain_sha256=SHA((ROOT / "CONTROL_DOMAIN.json").read_bytes()),
                  execution_pid=os.getpid(),
                  original_execution=False,whole_runtime_replaced=False,
                  refusals=records, recoveries=recoveries, baselines=baselines,child_refusals=child_refusals)

    def save():
        (args.output / "CAPTURE.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")

    def raw(session):
        return ctypes.string_at(session._workspace, session.workspace_capacity)

    def baseline(session, name):
        data = raw(session)
        snapshot = capture.buffers.snapshot(session._workspace, session.workspace_capacity)
        baselines.append(dict(name=name, session=capture.session_ids[session], after_call=capture.calls, buffer=snapshot))
        return data

    def refuse(session, name, data, base, base_name, patches=(), code=CONTRACT):
        assert raw(session) == base
        for at, replacement in patches:
            ctypes.memmove(ctypes.addressof(session._workspace) + at, replacement, len(replacement))
        before = raw(session)
        actual = capture.invoke(session, "scope_annotation_span", data, name)
        assert actual == code and raw(session) == before, (name, actual, code)
        assert capture.last["output_before"] == capture.last["output_after"], name
        records.append(dict(name=name, call=capture.calls, baseline=base_name, expected_code=code,
                            input_sha256=SHA(data), patches=[dict(at=at, hex=value.hex()) for at, value in patches]))
        ctypes.memmove(session._workspace, base, len(base))
        save()

    def drive(owner, children, data, name):
        for _ in range(32):
            code = capture.invoke(owner, "scope_annotation_span", data, name)
            head = ctypes.string_at(owner._output, min(64, owner.output_capacity))
            if code == GROW:
                assert head[:8] == b"HGRWS002" and WORD(head, 24) == 0
                capture.resize(owner, WORD(head, 8), WORD(head, 16), name)
            elif code == CALL:
                capture.complete_child(owner, children, name)
            else:
                assert code == 64 and head[:8] == b"HSCAR002"
                return capture.observation(owner)
        raise AssertionError("control recovery did not terminate")

    def recovery(owner, children, data, name, label):
        first = capture.calls + 1
        observed = drive(owner, children, data, name)
        path = name + ".observation.bin"
        (args.output / path).write_bytes(observed)
        recoveries.append(dict(name=name, semantic_label=label, first_call=first, last_call=capture.calls,
                               file=path, bytes=len(observed), sha256=SHA(observed)))
        save()

    def changed(data, at, value):
        return data[:at] + value + data[at + len(value):]

    save()
    try:
        with ExitStack() as stack:
            owner = stack.enter_context(capture.session("scope_annotation_span", "private-controls", 65600, 65536))
            children = {name: stack.enter_context(capture.session(name, "private-controls", 64))
                        for name in ("serde_json_span", "serde_error_span", "text_result_constructor")}
            fresh = baseline(owner, "fresh")
            invalid = [request[:47], changed(request, 0, b"BADFRAME"), changed(request, 8, PACK(3)),
                       changed(request, 16, PACK(2)), changed(request, 24, PACK(2)), changed(request, 40, PACK(1)),
                       changed(request, 32, PACK(3)), changed(request, 48, b"\xff"),
                       changed(changed(request, 8, PACK(2)), 24, PACK(0))]
            for name, data in zip(INITIAL, invalid):
                refuse(owner, name, data, fresh, "fresh", code=INVALID)
            state_patches = (((0,b"BADSTATE"),), ((0,b"HSCAWS02"),(8,PACK(5))),
                             ((0,b"HSCAWS02"),(16,PACK(0xffffffffffffffff))))
            for name, patches in zip(STATE, state_patches):
                refuse(owner, name, request, fresh, "fresh", patches)
            assert capture.invoke(owner, "scope_annotation_span", request, "valid-begin") == CALL
            assert capture.complete_child(owner, children, "valid-value")[0] == 1
            pending = baseline(owner, "value-completed")
            query, reply = WORD(pending, 136), WORD(pending, 144)
            changes = [(changed(request,48,b"[]"),()), (changed(request,16,PACK(1)),()),
                       (changed(request,24,PACK(1)),()),
                       (changed(changed(request,8,PACK(2)),24,PACK(1)),())]
            mutations = [(24,PACK(0)),(32,PACK(0)),(40,PACK(0)),(128,PACK(0)),(136,PACK(0)),(144,PACK(0)),
                         (256,b"BADACTION"[:8]),(264,PACK(0)),(272,PACK(3)),(280,PACK(1)),(288,PACK(0)),
                         (296,PACK(0)),(304,PACK(0)),(312,PACK(0)),(320,PACK(0)),(320,PACK(2)),
                         (328,PACK(1<<32)),(344,PACK(1)),(query,b"BADQUERY"),(query+24,b"[]"),
                         (reply,b"BADREPLY"),(reply+8,PACK(2)),(reply+16,PACK(0)),(reply+24,PACK(1)),(16384+48,b"[")]
            changes += [(request,(patch,)) for patch in mutations]
            assert len(changes) == len(PENDING)
            for name,(data,patches) in zip(PENDING,changes):
                refuse(owner,name,data,pending,"value-completed",patches)
            assert capture.invoke(owner,"scope_annotation_span",request,"valid-constructor-issue") == CALL
            assert capture.complete_child(owner,children,"valid-constructor")[0] == 3
            constructed = baseline(owner,"constructor-completed")
            query, reply, capacity = WORD(constructed,136),WORD(constructed,160),WORD(constructed,176)
            mutations = [(query+16,PACK(1)),(query+24,PACK(1)),(query+40,PACK(1)),(reply,b"BADREPLY"),
                         (reply+8,PACK(1)),(reply+24,PACK(1)),(reply+32,PACK(63)),(reply+40,PACK(capacity)),
                         (reply+56,PACK(1)),(320,PACK(0)),(query+64,b"["),(328,PACK(CAPACITY)),(328,PACK(GROW))]
            for name,patch in zip(CONSTRUCTOR,mutations):
                refuse(owner,name,request,constructed,"constructor-completed",(patch,))
            child_request=ctypes.string_at(ctypes.addressof(owner._workspace)+query,WORD(constructed,296))
            for capacity,name in zip((0,31,63),CHILD_NAMES,strict=True):
                with capture.session("text_result_constructor",name,capacity) as child:
                    code=capture.invoke(child,"text_result_constructor",child_request,name)
                    expected_code = CAPACITY if capacity < 32 else GROW
                    assert code==expected_code and capture.last["workspace_before"]==capture.last["workspace_after"]
                    if capacity < 32:
                        assert capture.last["output_before"]==capture.last["output_after"]
                    else:
                        actual=ctypes.string_at(child._output,capacity)
                        assert actual==b"HGRWS002"+PACK(1,16384+len(child_request)-64,0)+b"\xa5"*(capacity-32)
                    child_refusals.append(dict(name=name,call=capture.calls,output_capacity=capacity,
                        expected_code=expected_code,request_sha256=SHA(child_request),owner_baseline="constructor-completed"))
            recovery(owner,children,request,"valid-after-refusals",empty_label)
        for capacity in (0,31,63):
            name = "short-output-" + str(capacity)
            with capture.session("scope_annotation_span",name,capacity,65536) as owner:
                fresh = baseline(owner,name)
                refuse(owner,name,request,fresh,name,code=CAPACITY)
        for capacity in (0,1,16384):
            name = "workspace-growth-" + str(capacity)
            with ExitStack() as stack:
                owner = stack.enter_context(capture.session("scope_annotation_span",name,65600,capacity))
                children = {child:stack.enter_context(capture.session(child,name,64)) for child in
                            ("serde_json_span","serde_error_span","text_result_constructor")}
                recovery(owner,children,request,name,empty_label)
        name="output-growth-64"
        with ExitStack() as stack:
            owner=stack.enter_context(capture.session("scope_annotation_span",name,64))
            children={child:stack.enter_context(capture.session(child,name,64)) for child in
                      ("serde_json_span","serde_error_span","text_result_constructor")}
            recovery(owner,children,request,name,empty_label)
        label = "effect-search-missing-0"
        data = frame(expected[label])
        with ExitStack() as stack:
            owner = stack.enter_context(capture.session("scope_annotation_span","second-parse",65600))
            children = {name:stack.enter_context(capture.session(name,"second-parse",64)) for name in
                        ("serde_json_span","serde_error_span","text_result_constructor")}
            for _ in range(32):
                code = capture.invoke(owner,"scope_annotation_span",data,"second-parse-prepare")
                if code == GROW:
                    head = ctypes.string_at(owner._output,32)
                    capture.resize(owner,WORD(head,8),WORD(head,16),"second-parse-prepare")
                else:
                    assert code == CALL
                    child,_ = capture.complete_child(owner,children,"second-parse-prepare")
                    if child == 4:
                        break
            else:
                raise AssertionError("second original parse was not issued")
            second = baseline(owner,"second-value-completed")
            reply = WORD(second,144)
            for name,patches in zip(SECOND, (((reply+32,b"["),),((reply+8,PACK(1)),(reply+16,PACK(0))),((320,PACK(0)),))):
                refuse(owner,name,data,second,"second-value-completed",patches)
            recovery(owner,children,data,"effect-after-second-parse-refusals",label)
        assert [row["name"] for row in records] == list(CONTROL_NAMES)
        assert [row["name"] for row in recoveries] == list(RECOVERY_NAMES)
        assert [row["name"] for row in child_refusals] == list(CHILD_NAMES)
        result["status"] = "COMPLETE_NATIVE_CONTROLS"
    except BaseException as error:
        result.update(status="FAIL",error=dict(type=type(error).__name__,message=str(error)))
        raise
    finally:
        result.update(native_calls=capture.calls,sessions=capture.sessions,
                      physical_buffer_bytes=capture.buffers.logical_bytes,unique_buffer_chunks=len(capture.buffers.known),
                      elapsed_seconds=time.monotonic()-started,source_unchanged=verify_source()==source_sha)
        capture.close()
        save()
    print(json.dumps({key:result[key] for key in ("status","native_calls","sessions","elapsed_seconds")},sort_keys=True))


if __name__ == "__main__":
    main()
