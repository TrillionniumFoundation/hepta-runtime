"""Private mechanical transport for the scope-annotation HIA owner.

There is no host implementation of annotation, JSON parsing, or budgeting here.
The only dispatch choices are the three source-declared child image numbers.
"""
from contextlib import ExitStack
import ctypes
import hashlib
import json
from pathlib import Path
import struct
import sys

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
PACK = lambda *values: struct.pack("<" + "Q" * len(values), *values)
UNPACK = lambda raw: struct.unpack("<" + "Q" * (len(raw) // 8), raw)
WORK = 256 << 20
REGION = 64 << 20
SNAPSHOT = 1 << 20
QUERY = 16 << 20
REPLY = 32 << 20
ANNOTATED = 96 << 20
CONSTRUCTOR_REPLY = 160 << 20
WIRE = CONSTRUCTOR_REPLY+64
CONSTRUCTOR_GROW = 0xffffffd0
CALL = 0xffffffe0
CONTRACT = 0xfffffff8
INVALID = 0xffffffff
CAPACITY = 0xfffffffe


def request(raw, authenticated=False, search=False):
    assert type(raw) is bytes and type(authenticated) is bool and type(search) is bool
    return b"HSCANQ01" + PACK(1, int(authenticated), int(search), len(raw), 0) + raw


class Transport:
    def __init__(self, runtime, manifests, *, output_capacity=65536+64):
        sys.path.insert(0, str(Path(runtime) / "scripts"))
        from hia_native_loader import NativeModule, NativeRejected, NativeCapacityError
        self.rejections = (NativeRejected, NativeCapacityError)
        self.stack = ExitStack()
        try:
            self.modules = {}
            for name, manifest in manifests.items():
                path = Path(manifest)
                self.modules[name] = self.stack.enter_context(NativeModule(path, manifest_sha256=SHA(path.read_bytes())))
            self.owner = self.stack.enter_context(self.modules["scope_annotation"].session(
                output_capacity=output_capacity, workspace_capacity=WORK))
            self.value = self.stack.enter_context(self.modules["serde_json"].session(
                output_capacity=REGION, workspace_capacity=WORK))
            self.error = self.stack.enter_context(self.modules["serde_error"].session(
                output_capacity=1024, workspace_capacity=9 << 20))
            self.typed = self.stack.enter_context(self.modules["typed_result_json"].session(
                output_capacity=16 << 20, workspace_capacity=96 << 20))
            self.constructor = self.stack.enter_context(self.modules["text_result_constructor"].session(
                output_capacity=REGION+64, workspace_capacity=REGION+16384))
            self.events = []
            self.sequence = 0
        except BaseException:
            self.stack.close()
            raise

    def close(self):
        self.stack.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    @staticmethod
    def read(session, at, size):
        if not 0 <= at <= session.workspace_capacity or not 0 <= size <= session.workspace_capacity-at:
            raise ValueError("source-declared workspace span differs")
        return ctypes.string_at(ctypes.addressof(session._workspace)+at, size)

    @staticmethod
    def write(session, at, raw):
        if not 0 <= at <= session.workspace_capacity or len(raw) > session.workspace_capacity-at:
            raise ValueError("source-declared workspace destination differs")
        ctypes.memmove(ctypes.addressof(session._workspace)+at, raw, len(raw))

    def invoke(self, session, wire):
        try:
            result = session.invoke(wire)
            return len(result), result
        except self.rejections as error:
            return error.code, b""

    def call_constructor(self, session, wire):
        code, response = self.invoke(session, wire)
        if code == 64:
            assert response[:8] == b"HRTCRS01" and len(response) == 64
            status, error, policy, offset, size, zero1, zero2 = UNPACK(response[8:64])
            assert (status, error, policy, offset, zero1, zero2) == (0, 0, 0, 64, 0, 0)
            assert size <= session.output_capacity-64
            return code, ctypes.string_at(session._output, 64+size)
        if code == CONSTRUCTOR_GROW:
            assert session.output_capacity >= 32
            response = ctypes.string_at(session._output, 32)
            assert response[:8] == b"HGRWS002"
            kind, required, zero = UNPACK(response[8:])
            assert kind in (1, 2) and required > 0 and zero == 0
        else:
            assert code >= 0xffff0000 and response == b""
        return code, response

    def run(self, framed):
        before = ctypes.string_at(self.owner._output, self.owner.output_capacity)
        calls = []
        for _ in range(4):
            code, response = self.invoke(self.owner, framed)
            state = self.read(self.owner, 0, 352)
            full_output = ctypes.string_at(self.owner._output, self.owner.output_capacity)
            calls.append(dict(owner="scope_annotation", code=code, request=framed,
                              response=response, output_buffer=full_output, state=state))
            if code != CALL:
                if code >= 0xffff0000:
                    assert ctypes.string_at(self.owner._output, self.owner.output_capacity) == before
                    return dict(code=code, response=b"", annotation=b"", wire=b"", calls=calls)
                assert response[:8] == b"HSCANR01" and len(response) >= 64
                kind, count, wire_size, category, annotation_size, zero1, zero2 = UNPACK(response[8:64])
                assert kind in (0, 1) and count == len(response)-64 and category in range(4) and (zero1, zero2) == (0, 0)
                assert 0 <= annotation_size <= REGION and 0 <= wire_size <= REGION
                assert ctypes.string_at(ctypes.addressof(self.owner._output)+len(response), self.owner.output_capacity-len(response)) == before[len(response):]
                annotation = self.read(self.owner, ANNOTATED, annotation_size)
                sdk_wire = self.read(self.owner, WIRE, wire_size)
                return dict(code=code, response=response, annotation=annotation, wire=sdk_wire, calls=calls)
            action = self.read(self.owner, 256, 96)
            assert full_output == before, "a child request published a partial caller result"
            assert action[:8] == b"HSCAA001"
            sequence, child, reserved, query, query_size, reply, capacity, ack, status, zero1, zero2 = UNPACK(action[8:])
            assert sequence == self.sequence+1 and child in (1, 2, 3) and reserved == 0
            assert query == QUERY and (ack, status, zero1, zero2) == (0, 0, 0, 0)
            child_input = self.read(self.owner, query, query_size)
            if child == 3:
                size = UNPACK(state[72:80])[0]
                assert size <= REGION and (query_size, reply, capacity) == (64+size, CONSTRUCTOR_REPLY, REGION+64)
                expected = b"HRTCRQ01"+PACK(1, 0, 0, size, 0, 0, 0)+self.read(self.owner, ANNOTATED, size)
                assert child_input == expected
                child_code, child_response = self.call_constructor(self.constructor, child_input)
                child_name = "text_result_constructor"
            else:
                assert reply == REPLY and query_size == len(framed)-24
                assert capacity == (REGION if child == 1 else 1024)
                expected = (b"HSJVAL01" if child == 1 else b"HSJERQ01")+PACK(1, len(framed)-48)+framed[48:]
                assert child_input == expected
                session = self.value if child == 1 else self.error
                child_code, child_response = self.invoke(session, child_input)
                child_name = "serde_json" if child == 1 else "serde_error"
            calls[-1]["action"] = action
            calls.append(dict(owner=child_name, code=child_code, request=child_input, response=child_response))
            if child_response:
                assert len(child_response) <= capacity
                self.write(self.owner, reply, child_response)
            self.write(self.owner, 320, PACK(sequence, child_code))
            self.sequence = sequence
        raise AssertionError("annotation exceeded the fixed Value/diagnostic/constructor child sequence")

    def check_typed(self, annotation, sdk_wire):
        """Independent already-qualified HIA typed serializer, within its profile."""
        typed = dict(resultType="complete", content=[dict(type="text", text=annotation.decode())], isError=False)
        projection = json.dumps(typed, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        if len(projection) > 8 << 20:
            return None
        framed = b"HRTYP001" + PACK(1, len(projection)) + projection
        code, actual = self.invoke(self.typed, framed)
        assert code < 0xffff0000 and actual == sdk_wire, (code, actual[:200], sdk_wire[:200])
        return dict(request=framed, response=actual, code=code)
