"""Inert byte-for-byte model of adapter writes, using actual HIA and libc observations.

This validates transport custody, not an alternative audit implementation.
Every policy result is read from the unchanged owner/codec's complete buffers.
"""
import struct
from common import require
from protocol import word, put, response, acknowledgement
from callable_contract import CONTEXT_BYTES, OFFSETS, capabilities
from read_native import filesystem_reply

MASK = (1 << 64) - 1


def signed(value):
    return value if value < 1 << 63 else value - (1 << 64)


class Context:
    def __init__(self, binding, table):
        self.binding = binding
        self.base = binding["context"]
        self.data = bytearray(CONTEXT_BYTES)
        self.data[:8] = b"HAPUCX01"
        for at, value in ((16, binding["root_fd"]), (24, 2), (40, 21),
                          (48, binding["observer"]), (56, 0),
                          (256, 1), (264, 1), (272, binding["root_fd"])):
            put(self.data, at, value)
        self.data[640:808] = table

    def raw(self):
        return bytes(self.data) + b"\x5a" * 16

    def write(self, at, raw):
        require(0 <= at <= len(self.data) and len(raw) <= len(self.data) - at,
                "entire modeled native write extent")
        self.data[at:at + len(raw)] = raw

    def span(self, label, n):
        at = OFFSETS[label]
        return bytes(self.data[at:at + n])

    def set_observation(self, category, phase, returned, ni, detail=b"", actual_return=0, errno=0):
        seq, gen = word(self.data, 72), word(self.data, 64)
        if category in (1, 2):
            prefix = "owner" if category == 1 else "json"
            fields = [category, phase, returned, self.base + OFFSETS[prefix + "_in"], ni,
                      self.base + OFFSETS[prefix + "_out"], 8192 if category == 1 else 4096,
                      self.base + OFFSETS[prefix + "_work"], 32768 if category == 1 else 8192,
                      self.base, seq, gen, 0, 0, 0, 0]
        else:
            require(category == 3, "ordinary native effect category")
            op = word(self.data, 160)
            ptr = 0 if not detail else self.base + OFFSETS["scratch"] + (8384 if op == 13 else 8224)
            fields = [3, phase, returned, self.base + OFFSETS["owner_out"], ni,
                      self.base + OFFSETS["ack"], 4352, self.base + OFFSETS["caps"], 384,
                      self.base, seq, gen, actual_return & MASK, errno, ptr, len(detail)]
        raw = struct.pack("<16Q", *fields)
        self.write(OFFSETS["observation"], raw)
        return raw

    def begin(self, wire):
        put(self.data, 8, 1)
        put(self.data, 64, word(wire, 16))
        put(self.data, 72, 0)
        put(self.data, 184, 0)
        put(self.data, 200, 0)

    def owner(self, calls, wire, case, step):
        require(len(wire) <= 4352, "native copied owner input")
        self.write(OFFSETS["owner_in"], wire + b"\xc3" * 16)
        put(self.data, 136, len(wire))
        self.write(OFFSETS["owner_out"], b"\xa5" * 8208)
        self.write(OFFSETS["owner_work"] + 32768, b"\x5a" * 16)
        returned, out, work, index = calls.call(0, wire, 8192, self.span("owner_work", 32768), case, step)
        require(128 <= returned <= 8192, "actual ordinary complete HIA result")
        self.write(OFFSETS["owner_out"], out + b"\xa5" * 16)
        self.write(OFFSETS["owner_work"], work + b"\x5a" * 16)
        put(self.data, 128, returned)
        put(self.data, 80, word(self.data, 80) + 1)
        self.set_observation(1, 1, returned, len(wire))
        put(self.data, 144, returned)
        state = response(out[:returned], returned)
        require(state["generation"] == word(self.data, 64), "actual native owner generation")
        if state["kind"] < 2:
            require(state["sequence"] == word(self.data, 72), "actual terminal effect sequence")
            return state, out[:returned], index
        require(state["sequence"] == word(self.data, 72) + 1, "every native effect exactly once")
        put(self.data, 168, state["kind"])
        put(self.data, 160, state["operation"])
        put(self.data, 72, state["sequence"])
        ack = acknowledgement(state)
        self.write(OFFSETS["ack"], ack + bytes(4352 - len(ack)) + b"\x5a" * 16)
        put(self.data, 152, 128)
        return state, out[:returned], index

    def json(self, calls, state, case, step):
        wire = state["payloads"][0]
        self.write(OFFSETS["json_in"], wire + b"\xc3" * 16)
        self.write(OFFSETS["json_work"], bytes(8192) + b"\x5a" * 16)
        self.write(OFFSETS["json_out"], b"\xa5" * 4112)
        returned, out, work, index = calls.call(1, wire, 4096, bytes(8192), case, step)
        require(returned == 0xffffffff or returned <= 4096, "complete actual JSON return")
        self.write(OFFSETS["json_out"], out + b"\xa5" * 16)
        self.write(OFFSETS["json_work"], work + b"\x5a" * 16)
        put(self.data, 88, word(self.data, 88) + 1)
        self.set_observation(2, 1, returned, len(wire))
        ack = acknowledgement(state, status=2 if returned == 0xffffffff else 0,
                              value=returned, payload=b"" if returned == 0xffffffff else out[:returned])
        self.write(OFFSETS["ack"], ack + bytes(4352 - len(ack)) + b"\x5a" * 16)
        put(self.data, 152, len(ack))
        row = dict(case=case, step=step, generation=state["generation"], sequence=state["sequence"],
                   operation=state["operation"], kind=3, child_call=index,
                   input_hex=wire.hex(), acknowledgement_hex=ack.hex())
        return ack, row

    def filesystem(self, boundaries, state, row, case, step):
        op = state["operation"]
        caps_raw = self.span("caps", 384)
        caps, actual_caps = capabilities(caps_raw)
        a, b, c = state["arguments"]
        for at in (104, 112, 120, 192):
            put(self.data, at, 0)
        if op not in (17,18):
            require(str(a) in actual_caps, "actual capability requested by HIA")
            record = actual_caps[str(a)]
            require(record["kind"] == (2 if op in (13, 14) else 1), "native file/stream capability kind")
            if op in (7, 12, 13, 14):
                require(a != 1, "borrowed root never consumed")
            put(self.data, 192, self.base + OFFSETS["caps"] + record["slot"] * 24)
        if op in (1, 8, 9, 10, 15, 18):
            first, second = state["payloads"]
            require(0 < len(first) <= 4096 and b"\0" not in first, "complete first native name")
            self.write(OFFSETS["scratch"], first + b"\0")
            if op in (8, 10):
                require(0 < len(second) <= 4096 and b"\0" not in second, "complete second native name")
                self.write(OFFSETS["scratch"] + 4112, second + b"\0")
            else:
                require(not second, "absent native second name")
        before_detail = b""
        if op==19:
            require(b==1 and c==MASK and not any(state["payloads"]),"actual fixed poll request")
            before_detail=struct.pack("<iHH",actual_caps[str(a)]["actual"],1,0)
            self.write(OFFSETS["scratch"]+8224,before_detail);put(self.data,120,8)
        if op in (2, 15):
            before_detail = bytes(144)
            self.write(OFFSETS["scratch"] + 8224, before_detail)
            put(self.data, 120, 144)
        expected_before_record = self.set_observation(3, 0, 0, word(self.data, 144), before_detail)
        observed = boundaries.call(case, step)
        require(observed["before_record"] == expected_before_record and
                observed["before"] == [self.span("owner_out", word(self.data, 144) + 16),
                                       self.span("ack", 4368), caps_raw] and
                observed["detail_before"] == before_detail,
                "all actual filesystem preimages and raw before-record")
        w = struct.unpack("<16Q", observed["after_record"])
        ret, err = signed(w[12]), w[13]
        require(w[2] == w[12] and type(err) is int and 0 <= err <= 4095,
                "immediate complete actual libc return/errno")
        observed_result = dict(actual_return=ret, actual_errno=err)
        detail = observed["detail_after"]
        if op in (2, 15):
            require(len(detail) == 144, "all native stat bytes, including an error result")
            observed_result["complete_linux_x86_64_stat_hex"] = detail.hex()
        elif op==19:
            require(len(detail)==8 and detail[:6]==before_detail[:6],"whole actual pollfd including revents")
            observed_result["complete_pollfd_hex"]=detail.hex()
        elif op == 13:
            observed_result["readdir_nonnull"] = bool(ret)
            require((ret == 0 and not detail) or
                    (ret > 0 and 20 <= len(detail) <= 8192), "complete actual directory result")
            if ret:
                observed_result["complete_linux_dirent_hex"] = detail.hex()
        else:
            require(not detail, "no unrelated native detail bytes")
        ack_extent = word(observed["after"][1], 72)
        require(128 <= ack_extent <= 4352, "complete actual native acknowledgement")
        actual_before, _ = capabilities(observed["before"][2])
        actual_after, _ = capabilities(observed["after"][2])
        expected_row = dict(case=case, step=step, generation=state["generation"],
            sequence=state["sequence"], operation=op, arguments=list(state["arguments"]),
            payloads=[x.hex() for x in state["payloads"]],
            acknowledgement_hex=observed["after"][1][:ack_extent].hex(),
            capabilities_before=actual_before, capabilities_after=actual_after, observed=observed_result)
        require(row == expected_row, "semantic effect row is exactly the complete physical native boundary")
        ack, wanted_caps = filesystem_reply(state, row, caps)
        changed = bytearray(caps_raw)
        if op in (7, 14) or (op == 12 and ret >= 0):
            at = actual_caps[str(a)]["slot"] * 24
            changed[at:at + 24] = bytes(24)
        if op in (1, 11, 12, 18) and ret >= 0:
            token = word(self.data, 24)
            require(2 <= token < MASK and word(ack, 56) == token, "monotonic private native capability")
            free = [i for i in range(1, 16) if changed[i * 24:i * 24 + 24] == bytes(24)]
            require(free, "actual new resource has a tracked private slot")
            kind = 2 if op == 12 else 1
            for i in range(16):
                old_token, old_kind, old_actual = struct.unpack_from("<3Q", changed, i * 24)
                require(not old_token or old_kind != kind or old_actual != ret,
                        "no duplicate in-flight native descriptor")
            struct.pack_into("<3Q", changed, free[0] * 24, token, kind, ret)
            put(self.data, 24, token + 1)
        require(observed["after"][2] == bytes(changed) and capabilities(bytes(changed))[0] == wanted_caps,
                "exact native capability slots, descriptors, consumption and reuse")
        self.write(OFFSETS["caps"], changed)
        self.write(OFFSETS["ack"], ack + bytes(4352 - len(ack)) + b"\x5a" * 16)
        require(observed["after"][1] == self.span("ack", 4368), "every ACK byte and unused output tail")
        if op in (2, 15, 19):
            self.write(OFFSETS["scratch"] + 8224, detail)
        if op == 13 and ret:
            self.write(OFFSETS["scratch"] + 8384, detail)
            put(self.data, 120, len(detail))
        for at, value in ((104, ret & MASK), (112, err), (184, err),
                          (152, len(ack)), (96, word(self.data, 96) + 1)):
            put(self.data, at, value)
        after_record = self.set_observation(3, 1, ret & MASK, word(self.data, 144), detail, ret, err)
        require(observed["after_record"] == after_record, "every complete native after-record word")
        return ack

    def terminal(self):
        expected={"1":"file"}
        work=OFFSETS["owner_work"]
        mode=word(self.data,work+40);token=word(self.data,work+144)
        if token:
            require(mode==2 and token>1,"actual fallback cache descriptor")
            expected[str(token)]="file"
        require(capabilities(self.span("caps",384))[0]==expected,"exact persistent entropy capability")
        put(self.data, 8, 0)
        put(self.data, 176, 0)
        return self.raw()

    def dispose(self,boundaries,case,step):
        caps,actual=capabilities(self.span("caps",384))
        for token,held in sorted(actual.items(),key=lambda item:item[1]["slot"],reverse=True):
            if token=="1":continue
            offset=OFFSETS["caps"]+held["slot"]*24
            record=bytearray(128)
            for at,value in ((0,4),(24,self.base+offset),(32,24),(56,self.base+OFFSETS["caps"]),(64,384),
                             (72,self.base),(80,word(self.data,72)),(88,word(self.data,64))):put(record,at,value)
            before_caps=self.span("caps",384);before_slot=bytes(self.data[offset:offset+24])
            actual_record=boundaries.call(case,step)
            require(actual_record["before_record"]==bytes(record) and actual_record["before"]==[before_slot,b"",before_caps] and
                    actual_record["detail_before"]==actual_record["detail_after"]==b"","entire actual dispose close preimage")
            words=struct.unpack("<16Q",actual_record["after_record"]);ret=signed(words[12]);err=words[13]
            require(ret in (0,-1) and 0<=err<=4095 and (ret==0 or err>0),"actual dispose libc close")
            self.write(offset,bytes(24))
            for at,value in ((8,1),(16,ret&MASK),(96,ret&MASK),(104,err)):put(record,at,value)
            require(actual_record["after_record"]==bytes(record) and actual_record["after"]==[bytes(24),b"",self.span("caps",384)],"all complete dispose bytes and exact consumed capability")
        self.data[:]=bytes(CONTEXT_BYTES)
        return self.raw()
