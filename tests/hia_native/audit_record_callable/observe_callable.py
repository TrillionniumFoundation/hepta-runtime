"""Read-only callback capture of a native-owned HIA/filesystem pump.

The callback never calls HIA or libc, changes a borrowed byte, supplies an ACK,
or chooses the next effect. Native continues independently when it is absent.
"""
import ctypes as C
from contextlib import ExitStack
import gzip
import json
import struct
import time
from common import encoded, pin, require
from protocol import response, word
from callable_loader import OBSERVER
from callable_contract import OFFSETS, CONTEXT_BYTES, capabilities

CALL_HEADER = struct.Struct("<9Q")
BOUNDARY_HEADER = struct.Struct("<12Q")


def signed(value):
    return value if value < (1 << 63) else value - (1 << 64)




class Observe:
    def __init__(self, output):
        self.output = output
        self.calls = []
        self.boundaries = []
        self.events = []
        resources = ExitStack()
        try:
            self.raw_calls = resources.enter_context((output / "buffers.bin.gz").open("xb"))
            self.call_stream = resources.enter_context(gzip.GzipFile(filename="", mode="wb", compresslevel=1,
                                                    fileobj=self.raw_calls, mtime=0))
            self.call_stream.write(b"AIOLOG01")
            self.raw_boundaries = resources.enter_context((output / "boundaries.bin.gz").open("xb"))
            self.boundary_stream = resources.enter_context(gzip.GzipFile(filename="", mode="wb", compresslevel=1,
                                                        fileobj=self.raw_boundaries, mtime=0))
            self.boundary_stream.write(b"AIOFXLOG")
            self.effects_file = resources.enter_context((output / "effects.jsonl").open("xb"))
        except BaseException:
            resources.close()
            raise
        self.resources = resources.pop_all()
        self.pending = None
        self.deferred_json = None
        self.last_state = None
        self.last_terminal = None
        self.errors = []
        self.case = self.step = self.context = None
        self.callback = OBSERVER(self.observe)
        self.closed = False

    def select(self, case, step, context):
        require(self.pending is None and self.deferred_json is None, "no unfinished callback")
        self.case, self.step, self.context = case, step, context
        self.last_terminal = None

    def snapshot(self, pointer, user):
        require(user in (None, 0) and pointer == self.context + OFFSETS["observation"],
                "exact borrowed native observation record")
        raw = C.string_at(pointer, 128)
        words = struct.unpack("<16Q", raw)
        category, phase, returned, ip, ni, op, no, wp, nw, context, sequence, generation, ret, err, detail, nd = words
        require(category in (1, 2, 3, 4) and phase in (0, 1) and context == self.context,
                "exact native observation identity")
        if category in (1, 2):
            prefix = "owner" if category == 1 else "json"
            expected = (self.context + OFFSETS[prefix + "_in"],
                        self.context + OFFSETS[prefix + "_out"], 8192 if category == 1 else 4096,
                        self.context + OFFSETS[prefix + "_work"], 32768 if category == 1 else 8192)
            require((ip, op, no, wp, nw) == expected and 0 < ni <= 4352 and detail == nd == 0,
                    "exact native HIA borrowed spans")
            guards = (16, 16, 16)
        elif category == 3:
            require(ip == self.context + OFFSETS["owner_out"] and 128 <= ni <= 8192 and
                    (op, no, wp, nw) == (self.context + OFFSETS["ack"], 4352,
                                        self.context + OFFSETS["caps"], 384),
                    "exact native filesystem borrowed spans")
            require((detail == nd == 0) or
                    (detail == self.context + OFFSETS["scratch"] + 8224 and nd == 144) or
                    (detail == self.context + OFFSETS["scratch"] + 8384 and 20 <= nd <= 8192),
                    "complete actual stat or dirent observation")
            guards = (16, 16, 0)
        else:
            require(ip >= self.context + OFFSETS["caps"] + 24 and
                    (ip - self.context - OFFSETS["caps"]) % 24 == 0 and
                    ip + ni <= self.context + OFFSETS["caps"] + 384 and ni == 24 and
                    op == no == 0 and wp == self.context + OFFSETS["caps"] and nw == 384 and
                    detail == nd == 0, "exact native failure-cleanup observation")
            guards = (0, 0, 0)
        spans = tuple(C.string_at(p, n + g) if n + g else b""
                      for p, n, g in zip((ip, op, wp), (ni, no, nw), guards))
        return dict(raw=raw, words=words, guards=guards, spans=spans,
                    detail=b"" if not nd else C.string_at(detail, nd),
                    observed_ns=time.monotonic_ns())

    def event(self, value):
        self.effects_file.write(json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        self.events.append(value)

    def observe(self, pointer, user):
        # ctypes callbacks cannot propagate an exception through the native stack.
        # Preserve its first failure and all already written bytes. Never ACK it.
        if self.errors:
            return
        try:
            value = self.snapshot(pointer, user)
            words = value["words"]
            category, phase = words[:2]
            if phase == 0:
                require(self.pending is None, "strict before/after native observation order")
                if category == 1 and self.deferred_json is not None:
                    wire = value["spans"][0][:words[4]]
                    child = self.deferred_json
                    self.event(dict(case=self.case, step=self.step, generation=child["generation"],
                        sequence=child["sequence"], operation=child["operation"], kind=3,
                        child_call=child["index"], input_hex=child["input_hex"],
                        acknowledgement_hex=wire.hex()))
                    self.deferred_json = None
                if category == 2:
                    require(self.last_state is not None and self.last_state["kind"] == 3,
                            "JSON call follows the actual HIA JSON effect")
                if category == 3:
                    require(self.last_state is not None and self.last_state["kind"] == 2,
                            "filesystem call follows the actual HIA filesystem effect")
                self.pending = value
                return
            before = self.pending
            require(before is not None and before["words"][0] == category and
                    before["words"][3:12] == words[3:12], "unchanged complete native callback views")
            if category != 4:
                require(before["spans"][0] == value["spans"][0], "native input bytes remain borrowed read-only")
            self.pending = None
            if category in (1, 2):
                self.hia(before, value)
            else:
                self.boundary(before, value)
        except BaseException as error:
            self.errors.append(repr(error))

    def hia(self, before, after):
        w = after["words"]
        category, returned = w[0], w[2]
        ni, no, nw = w[4], w[6], w[8]
        module = category - 1
        before_spans, after_spans = before["spans"], after["spans"]
        require(after_spans[1][no:] == b"\xa5" * 16 and
                after_spans[2][nw:] == b"\x5a" * 16 and
                after_spans[0][ni:] == b"\xc3" * 16, "all actual HIA borrowed guards")
        require(before_spans[1] == b"\xa5" * (no + 16), "entire output initialized before HIA")
        if module == 1:
            require(before_spans[2] == bytes(nw) + b"\x5a" * 16, "independent JSON workspace")
        index = len(self.calls)
        self.call_stream.write(b"AIOCAL01" + CALL_HEADER.pack(index, self.case, self.step, module,
                               returned, ni, no, nw, 0))
        for raw in before_spans + after_spans:
            self.call_stream.write(raw)
        row = dict(index=index, case=self.case, step=self.step, module=module, result=returned,
            probe=None, input_bytes=ni, output_capacity=no, workspace_capacity=nw,
            elapsed_ns=after["observed_ns"] - before["observed_ns"],
            before=[pin(raw) for raw in before_spans], after=[pin(raw) for raw in after_spans])
        self.calls.append(row)
        if category == 1 and 128 <= returned <= 8192:
            state = response(after_spans[1][:returned], returned)
            self.last_state = state
            if state["kind"] in (0, 1):
                self.last_terminal = after_spans[1][:returned]
        elif category == 2:
            state = self.last_state
            require(state["payloads"][0] == before_spans[0][:ni], "actual unchanged JSON child request")
            self.deferred_json = dict(index=index, generation=state["generation"],
                sequence=state["sequence"], operation=state["operation"],
                input_hex=before_spans[0][:ni].hex())

    def boundary(self, before, after):
        w = after["words"]
        category, ni, no, nw = w[0], w[4], w[6], w[8]
        index = len(self.boundaries)
        header = BOUNDARY_HEADER.pack(index, self.case, self.step, category, ni, no, nw,
            *after["guards"], len(before["detail"]), len(after["detail"]))
        full = before["raw"] + after["raw"] + b"".join(before["spans"] + after["spans"]) + before["detail"] + after["detail"]
        self.boundary_stream.write(b"AIOFX001" + header + full)
        row = dict(index=index, case=self.case, step=self.step, category=category,
            input_bytes=ni, output_capacity=no, workspace_capacity=nw, guards=list(after["guards"]),
            before_record=pin(before["raw"]), after_record=pin(after["raw"]),
            before=[pin(raw) for raw in before["spans"]], after=[pin(raw) for raw in after["spans"]],
            detail_before=pin(before["detail"]), detail_after=pin(after["detail"]),
            elapsed_ns=after["observed_ns"] - before["observed_ns"], complete_record=pin(header + full))
        self.boundaries.append(row)
        if category == 4:
            return
        state = response(after["spans"][0][:ni], ni)
        require(state == self.last_state, "actual filesystem request exactly retained")
        ack = after["spans"][1]
        extent = word(ack, 72)
        require(128 <= extent <= no and ack[:8] == b"HAIOACK1" and
                ack[extent:no] == bytes(no - extent) and ack[no:] == b"\x5a" * 16,
                "complete native ACK and unused tail")
        caps_before, _ = capabilities(before["spans"][2])
        caps_after, _ = capabilities(after["spans"][2])
        actual = dict(actual_return=signed(w[12]), actual_errno=w[13])
        if state["operation"] == 2:
            actual["complete_linux_x86_64_stat_hex"] = after["detail"].hex()
        if state["operation"] == 13:
            actual["readdir_nonnull"] = bool(actual["actual_return"])
            if actual["readdir_nonnull"]:
                actual["complete_linux_dirent_hex"] = after["detail"].hex()
        self.event(dict(case=self.case, step=self.step, generation=state["generation"],
            sequence=state["sequence"], operation=state["operation"], arguments=list(state["arguments"]),
            payloads=[raw.hex() for raw in state["payloads"]], acknowledgement_hex=ack[:extent].hex(),
            capabilities_before=caps_before, capabilities_after=caps_after, observed=actual))

    def close(self, success):
        if self.closed:
            return
        self.closed = True
        try:
            if success:
                require(not self.errors and self.pending is None and self.deferred_json is None,
                        "complete callback lifecycle before footer")
                self.call_stream.write(b"AIOEND01" + struct.pack("<Q", len(self.calls)))
                self.boundary_stream.write(b"AIOFXEND" + struct.pack("<Q", len(self.boundaries)))
        finally:
            self.resources.close()
            (self.output / "INVOCATIONS.json").write_bytes(encoded(self.calls))
            (self.output / "BOUNDARIES.json").write_bytes(encoded(self.boundaries))
            (self.output / "OBSERVER-ERRORS.json").write_bytes(encoded(self.errors))
            if self.pending is not None:
                pending = self.pending
                (self.output / "FAILED-PENDING.bin").write_bytes(pending["raw"] +
                    b"".join(pending["spans"]) + pending["detail"])
