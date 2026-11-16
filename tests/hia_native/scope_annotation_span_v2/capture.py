"""Invoke actual HIA owners and losslessly retain every physical buffer byte."""
from contextlib import ExitStack
from pathlib import Path
import ctypes
import gzip
import hashlib
import json
import struct
import sys
import time

ROOT = Path(__file__).resolve().parent
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
PACK = lambda *values: struct.pack("<" + "Q" * len(values), *values)
WORD = lambda raw, at: struct.unpack_from("<Q", raw, at)[0]
CALL, GROW = 0xffffffe0, 0xffffffd0
CHUNK = 128 << 10
WARNING = b"search scope annotation unavailable; existing identity retained"


def line(stream, row):
    stream.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
    stream.flush()


class Buffers:
    """Content addressing deduplicates storage, never physical reads or hashes."""
    def __init__(self, folder):
        self.folder = folder / "buffers"
        self.folder.mkdir()
        self.ledger = (folder / "buffers.jsonl").open("x")
        self.known = {}
        self.logical_bytes = 0

    def snapshot(self, buffer, count):
        digest, chunks = hashlib.sha256(), []
        address = ctypes.addressof(buffer)
        for offset in range(0, count, CHUNK):
            raw = ctypes.string_at(address + offset, min(CHUNK, count - offset))
            digest.update(raw)
            identity = SHA(raw)
            if identity not in self.known:
                path = self.folder / (identity + ".gz")
                compressed = gzip.compress(raw, compresslevel=1, mtime=0)
                path.write_bytes(compressed)
                row = dict(sha256=identity, bytes=len(raw), file="buffers/" + path.name,
                           compressed_bytes=len(compressed), compressed_sha256=SHA(compressed))
                self.known[identity] = row
                line(self.ledger, row)
            assert self.known[identity]["bytes"] == len(raw)
            chunks.append(identity)
        self.logical_bytes += count
        return dict(bytes=count, sha256=digest.hexdigest(), chunks=chunks)

    def close(self):
        self.ledger.close()

    def __enter__(self):
        return self

    def __exit__(self,*args):
        self.close()


class Capture:
    def __init__(self, build_path, folder):
        sys.path.insert(0, str(ROOT / "scripts"))
        from hia_native_loader import NativeModule, NativeRejected, NativeCapacityError
        build_path = Path(build_path).resolve(strict=True)
        build = json.loads(build_path.read_bytes())
        self.rejected = (NativeRejected, NativeCapacityError)
        self.stack = ExitStack()
        try:
            self.modules = {}
            for name, row in build["members"].items():
                path = Path(row["manifest"])
                if not path.is_absolute():
                    path = build_path.parent / path
                self.modules[name] = self.stack.enter_context(NativeModule(path, manifest_sha256=row["manifest_sha256"]))
            assert set(self.modules) == {"scope_annotation_span", "serde_json_span", "serde_error_span", "text_result_constructor"}
            self.folder = Path(folder)
            self.calls = 0
            self.sessions = 0
            self.call_ledger = self.stack.enter_context((folder / "calls.jsonl").open("x"))
            self.session_ledger = self.stack.enter_context((folder / "sessions.jsonl").open("x"))
            self.growth_ledger = self.stack.enter_context((folder / "growth.jsonl").open("x"))
            self.handoff_ledger = self.stack.enter_context((folder / "handoffs.jsonl").open("x"))
            self.buffers = self.stack.enter_context(Buffers(folder))
            self.session_ids = {}
            self.last = None
        except BaseException:
            self.stack.close()
            raise

    def close(self):
        self.stack.close()

    def session(self, name, case, output=64, workspace=0):
        session = self.modules[name].session(output_capacity=output, workspace_capacity=workspace)
        self.sessions += 1
        self.session_ids[session] = self.sessions
        line(self.session_ledger, dict(session=self.sessions, owner=name, case=case,
             output_capacity=output, workspace_capacity=workspace))
        return session

    def resize(self, session, kind, count, case):
        assert kind in (1, 2)
        attr = "_workspace" if kind == 1 else "_output"
        cap = "workspace_capacity" if kind == 1 else "output_capacity"
        old_count = getattr(session, cap)
        assert type(count) is int and old_count < count <= session.module.metadata[cap]
        previous = getattr(session, attr)
        before = self.buffers.snapshot(previous, old_count)
        fresh = ctypes.create_string_buffer(count + 16)
        ctypes.memmove(fresh, previous, old_count)
        after = self.buffers.snapshot(fresh, count)
        line(self.growth_ledger, dict(session=self.session_ids[session], case=case,
             after_call=self.calls, kind=kind, before=before, after=after,
             previous_address=ctypes.addressof(previous), next_address=ctypes.addressof(fresh)))
        assert ctypes.addressof(previous) != ctypes.addressof(fresh)
        setattr(session, attr, fresh)
        setattr(session, cap, count)

    def invoke(self, session, name, request, case, *, fill_output=True):
        self.calls += 1
        label = f"{self.calls:06d}"
        path = self.folder / label
        path.mkdir()
        (path / "input.bin").write_bytes(request)
        if fill_output:
            ctypes.memset(session._output, 0xa5, session.output_capacity)
        ctypes.memset(ctypes.addressof(session._output) + session.output_capacity, 0xa5, 16)
        ctypes.memset(ctypes.addressof(session._workspace) + session.workspace_capacity, 0x5a, 16)
        record = dict(call=self.calls, session=self.session_ids[session], owner=name, case=case,
             folder=label, input=dict(bytes=len(request), sha256=SHA(request)),
             output_capacity=session.output_capacity, workspace_capacity=session.workspace_capacity,
             workspace_address=ctypes.addressof(session._workspace), output_address=ctypes.addressof(session._output),
             output_prefilled_a5=fill_output)
        record["workspace_before"] = self.buffers.snapshot(session._workspace, session.workspace_capacity)
        record["output_before"] = self.buffers.snapshot(session._output, session.output_capacity)
        started, error, code = time.monotonic(), None, None
        try:
            code = len(session.invoke(request))
        except self.rejected as rejected:
            code = rejected.code
        except BaseException as failure:
            error = failure
        finally:
            record["elapsed_seconds"] = time.monotonic() - started
            record["return_code"] = code
            record["workspace_after"] = self.buffers.snapshot(session._workspace, session.workspace_capacity)
            record["output_after"] = self.buffers.snapshot(session._output, session.output_capacity)
            record["output_guard"] = ctypes.string_at(ctypes.addressof(session._output) + session.output_capacity, 16).hex()
            record["workspace_guard"] = ctypes.string_at(ctypes.addressof(session._workspace) + session.workspace_capacity, 16).hex()
            record["error"] = None if error is None else dict(type=type(error).__name__, message=str(error))
            line(self.call_ledger, record)
            self.last = record
        if error is not None:
            raise error
        assert record["output_guard"] == "a5" * 16 and record["workspace_guard"] == "5a" * 16
        return code

    def child(self, session, name, request, case):
        for _ in range(64):
            code = self.invoke(session, name, request, case)
            head = ctypes.string_at(session._output, min(64, session.output_capacity))
            if code == GROW:
                assert head[:8] == b"HGRWS002" and WORD(head, 24) == 0
                self.resize(session, WORD(head, 8), WORD(head, 16), case)
                continue
            if name == "serde_json_span":
                assert code == 32 and head[:8] == b"HJSVR002"
                status, count, needed = WORD(head, 8), WORD(head, 16), WORD(head, 24)
                if status in (2, 3):
                    assert count == 0
                    self.resize(session, 1 if status == 2 else 2, needed, case)
                    continue
                assert status in (0, 1) and needed == 0
                return code, ctypes.string_at(session._output, 32 + count)
            if name == "text_result_constructor":
                assert code == 64 and head[:8] == b"HRTCRS01"
                return code, ctypes.string_at(session._output, 64 + WORD(head, 40))
            assert 64 <= code <= session.output_capacity and head[:8] == b"HSJERR01"
            return code, ctypes.string_at(session._output, code)
        raise AssertionError("nonterminating child growth")

    def complete_child(self, owner, children, case):
        issued = self.calls
        state = ctypes.string_at(owner._workspace, 352)
        assert state[256:264] == b"HSCAA002"
        sequence, child, reserved, at, size, reply, capacity, ack, result, z1, z2 = struct.unpack_from("<11Q", state, 264)
        assert child in (1, 2, 3, 4) and (reserved, ack, result, z1, z2) == (0, 0, 0, 0, 0)
        assert 0 <= at <= owner.workspace_capacity and size <= owner.workspace_capacity - at
        assert 0 <= reply <= owner.workspace_capacity and capacity <= owner.workspace_capacity - reply
        wire = ctypes.string_at(ctypes.addressof(owner._workspace) + at, size)
        name = {1: "serde_json_span", 2: "serde_error_span", 3: "text_result_constructor", 4: "serde_json_span"}[child]
        first = self.calls + 1
        child_code, response = self.child(children[name], name, wire, case)
        assert len(response) <= capacity
        ctypes.memmove(ctypes.addressof(owner._workspace) + reply, response, len(response))
        ctypes.memmove(ctypes.addressof(owner._workspace) + 320, PACK(sequence, child_code), 16)
        line(self.handoff_ledger, dict(owner_session=self.session_ids[owner], issued_call=issued,
             case=case, child=child, sequence=sequence, query_at=at, query_bytes=size,
             reply_at=reply, reply_capacity=capacity, first_child_call=first, last_child_call=self.calls,
             request_sha256=SHA(wire), response_bytes=len(response), response_sha256=SHA(response), child_code=child_code))
        return child, response

    def run(self, request, case, *, output_capacity=65536 + 64):
        start = self.calls + 1
        with ExitStack() as sessions:
            owner = sessions.enter_context(self.session("scope_annotation_span", case, output_capacity))
            children = {name: sessions.enter_context(self.session(name, case, 64))
                        for name in ("serde_json_span", "serde_error_span", "text_result_constructor")}
            for _ in range(32):
                code = self.invoke(owner, "scope_annotation_span", request, case)
                head = ctypes.string_at(owner._output, min(64, owner.output_capacity))
                if code == GROW:
                    assert head[:8] == b"HGRWS002" and WORD(head, 24) == 0
                    self.resize(owner, WORD(head, 8), WORD(head, 16), case)
                    continue
                if code == CALL:
                    self.complete_child(owner, children, case)
                    continue
                assert code == 64 and head[:8] == b"HSCAR002", (case, code, head.hex())
                return dict(first_call=start, last_call=self.calls, response=self.observation(owner))
        raise AssertionError("private owner did not terminate")

    def observation(self, owner):
        head = ctypes.string_at(owner._output, 64)
        state = ctypes.string_at(owner._workspace, 224)
        count, wire_count, annotation_count, warning = WORD(head, 16), WORD(head, 24), WORD(head, 40), WORD(head, 56)
        assert count <= owner.output_capacity - 64 and warning in (0, 1)
        response = ctypes.string_at(owner._output, 64 + count)
        assert WORD(state, 152) <= owner.workspace_capacity - annotation_count
        assert WORD(state, 160) + 64 <= owner.workspace_capacity - wire_count
        annotation = ctypes.string_at(ctypes.addressof(owner._workspace) + WORD(state, 152), annotation_count)
        wire = ctypes.string_at(ctypes.addressof(owner._workspace) + WORD(state, 160) + 64, wire_count)
        message = ctypes.string_at(ctypes.addressof(owner._workspace) + 1024, len(WARNING)) if warning else b""
        return b"HSCASR02" + PACK(len(response), len(annotation), len(wire), len(message)) + response + annotation + wire + message
