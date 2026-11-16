"""Independent, non-executing readers of complete physical HIA observations."""
from collections import OrderedDict
from pathlib import Path
import gzip
import hashlib
import io
import json
import math
import stat
import struct

ROOT = Path(__file__).resolve().parent
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
PACK = lambda *values: struct.pack("<" + "Q" * len(values), *values)
WORD = lambda raw, at: struct.unpack_from("<Q", raw, at)[0]
CHUNK = 128 << 10
CALL, GROW = 0xffffffe0, 0xffffffd0
WARNING = b"search scope annotation unavailable; existing identity retained"
# Each reader instance still reads, decompresses and hashes every physical
# chunk. These caches reuse only already-proved concatenations/patch identities
# over those same verified content-addressed bytes, including relocated copies.
VERIFIED_CONCATENATIONS = set()
VERIFIED_PATCHES = set()
VERIFIED_ZERO_EXTENSIONS = set()
FIXED_BYTE_DIGESTS = {}


def require(value, message):
    if not value:
        raise ValueError(message)


def fixed_byte_digest(value, size):
    """Memoize a mathematical constant, never an unverified physical buffer."""
    require(type(value) is int and 0 <= value <= 255 and type(size) is int and size >= 0,
            "invalid fixed-byte span")
    key = (value,size)
    if key not in FIXED_BYTE_DIGESTS:
        digest = hashlib.sha256()
        block = bytes((value,))*min(CHUNK,size)
        for at in range(0,size,CHUNK):
            digest.update(block[:min(CHUNK,size-at)])
        FIXED_BYTE_DIGESTS[key] = digest.hexdigest()
    return FIXED_BYTE_DIGESTS[key]


def pairs(rows):
    result = {}
    for key, value in rows:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def parse(raw):
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def read(path, maximum=128 << 20):
    path = Path(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and not path.is_symlink() and path.resolve() == path.absolute(), "nonordinary reader input")
    require(info.st_size <= maximum, "reader file bound exceeded")
    raw = path.read_bytes()
    require(len(raw) == info.st_size, "file changed during read")
    return raw


def pin(raw):
    return dict(bytes=len(raw), sha256=SHA(raw))


def file_pin(path):
    path = Path(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and path.resolve() == path.absolute(), "nonordinary streamed reader input")
    digest, count = hashlib.sha256(), 0
    with path.open("rb") as stream:
        while raw := stream.read(1 << 20):
            count += len(raw)
            digest.update(raw)
    require(count == info.st_size, "stream changed during read")
    return dict(bytes=count, sha256=digest.hexdigest())


def jsonlines(path):
    return [parse(raw) for raw in read(path).splitlines()]


class PacketStream:
    def __init__(self, path, compressed=True):
        self.path, self.compressed = Path(path), compressed
        self.digest, self.bytes, self.count = hashlib.sha256(), 0, 0

    def __enter__(self):
        self.stream = gzip.open(self.path, "rb") if self.compressed else self.path.open("rb")
        return self

    def __exit__(self, *args):
        self.stream.close()

    def take(self):
        head = self.stream.read(8)
        if not head:
            return None
        require(len(head) == 8, "truncated outer packet header")
        count = WORD(head,0)
        require(count <= 128 << 20, "observation packet bound exceeded")
        raw = self.stream.read(count)
        require(len(raw) == count, "truncated complete observation")
        self.digest.update(head)
        self.digest.update(raw)
        self.bytes += len(head) + len(raw)
        self.count += 1
        return raw

    def finish(self):
        require(self.take() is None, "extra packet outside frozen domain")
        return dict(bytes=self.bytes, sha256=self.digest.hexdigest(), count=self.count)


class Buffers:
    def __init__(self, folder):
        self.folder = Path(folder)
        self.rows, self.cache, self.seen, self.used = {}, OrderedDict(), VERIFIED_CONCATENATIONS, set()
        for row in jsonlines(self.folder / "buffers.jsonl"):
            key = row["sha256"]
            require(type(key) is str and len(key) == 64 and all(c in "0123456789abcdef" for c in key), "invalid chunk identity")
            require(key not in self.rows and 0 < row["bytes"] <= CHUNK, "duplicate/empty/oversized chunk")
            require(row["file"] == "buffers/" + key + ".gz", "chunk path alias")
            self.rows[key] = row
            self.chunk(key)
        require({p.name for p in (self.folder / "buffers").iterdir()} == {k + ".gz" for k in self.rows}, "unbound chunk inventory")
        self.physical_bytes = 0

    def chunk(self, key):
        require(key in self.rows, "unbound physical chunk")
        if key in self.cache:
            self.cache.move_to_end(key)
            return self.cache[key]
        row = self.rows[key]
        encoded = read(self.folder / row["file"])
        require(pin(encoded) == dict(bytes=row["compressed_bytes"],sha256=row["compressed_sha256"]), "compressed physical chunk changed")
        raw = gzip.decompress(encoded)
        require(pin(raw) == dict(bytes=row["bytes"],sha256=key), "complete physical chunk changed")
        self.cache[key] = raw
        while len(self.cache) > 256:
            self.cache.popitem(last=False)
        return raw

    def verify(self, row):
        require(set(row) == {"bytes","sha256","chunks"} and type(row["bytes"]) is int and row["bytes"] >= 0, "invalid complete buffer descriptor")
        self.physical_bytes += row["bytes"]
        self.used.update(row["chunks"])
        key = (row["bytes"],row["sha256"],tuple(row["chunks"]))
        require(len(row["chunks"]) == (row["bytes"] + CHUNK - 1) // CHUNK, "physical chunk span differs")
        for index,item in enumerate(row["chunks"]):
            require(item in self.rows and self.rows[item]["bytes"] == min(CHUNK,row["bytes"]-index*CHUNK), "unbound or incomplete physical chunk span")
        if key in self.seen:
            return
        digest, total = hashlib.sha256(), 0
        for item in row["chunks"]:
            raw = self.chunk(item)
            require(len(raw) == min(CHUNK,row["bytes"]-total), "physical chunk extent differs")
            digest.update(raw)
            total += len(raw)
        require(total == row["bytes"] and digest.hexdigest() == row["sha256"], "whole physical buffer digest differs")
        self.seen.add(key)

    def span(self, row, start=0, size=None):
        size = row["bytes"] - start if size is None else size
        require(0 <= start <= row["bytes"] and 0 <= size <= row["bytes"]-start, "buffer read outside actual complete span")
        result = bytearray()
        end = start + size
        for index in range(start // CHUNK,(end + CHUNK - 1) // CHUNK):
            raw = self.chunk(row["chunks"][index])
            result.extend(raw[max(0,start-index*CHUNK):min(len(raw),end-index*CHUNK)])
        require(len(result) == size, "complete range truncated")
        return bytes(result)

    def zero_extended(self, before, after):
        """Prove the unchanged prefix and zero extension over freshly read chunks."""
        require(before["bytes"] <= after["bytes"], "zero extension shrank the buffer")
        key=(before["bytes"],before["sha256"],tuple(before["chunks"]),
             after["bytes"],after["sha256"],tuple(after["chunks"]))
        if key in VERIFIED_ZERO_EXTENSIONS:
            return
        digest = hashlib.sha256()
        for identity in before["chunks"]:
            digest.update(self.chunk(identity))
        for at in range(before["bytes"],after["bytes"],CHUNK):
            digest.update(bytes(min(CHUNK,after["bytes"]-at)))
        require(digest.hexdigest() == after["sha256"],
                "growth changed old prefix or invented uninitialized bytes")
        VERIFIED_ZERO_EXTENSIONS.add(key)

    def changed(self, before, after, patches):
        require(before["bytes"] == after["bytes"], "patch changed complete buffer extent")
        ordered = sorted(patches)
        prior = 0
        for at, raw in ordered:
            require(prior <= at and at + len(raw) <= before["bytes"], "overlapping or escaping mechanical patch")
            prior = at + len(raw)
        key=(before["bytes"],before["sha256"],tuple(before["chunks"]),after["sha256"],tuple(after["chunks"]),tuple(ordered))
        if key in VERIFIED_PATCHES:
            return
        digest = hashlib.sha256()
        for index, identity in enumerate(before["chunks"]):
            raw = bytearray(self.chunk(identity))
            start, end = index * CHUNK, index * CHUNK + len(raw)
            for at, value in ordered:
                left, right = max(start,at), min(end,at+len(value))
                if left < right:
                    raw[left-start:right-start] = value[left-at:right-at]
            digest.update(raw)
        require(digest.hexdigest() == after["sha256"], "bytes changed outside exact mechanical patch")
        VERIFIED_PATCHES.add(key)


def observation(raw):
    require(len(raw) >= 104 and raw[:8] == b"HSCASR02", "observation envelope differs")
    sizes = struct.unpack_from("<4Q",raw,8)
    require(sizes[0] >= 64 and len(raw) == 40 + sum(sizes), "observation complete extent differs")
    at, parts = 40, []
    for size in sizes:
        parts.append(raw[at:at+size]);at += size
    response, annotation, wire, warning = parts
    require(response[:8] == b"HSCAR002", "annotation response magic differs")
    kind,payload_size,wire_size,category,annotation_size,fallback,warnings = struct.unpack_from("<7Q",response,8)
    require(len(response) == 64 + payload_size and len(wire) == wire_size and len(annotation) == annotation_size, "response inner extents differ")
    require(kind in (0,1) and category in (0,1,2,3) and fallback in (0,1,2) and warnings in (0,1), "invalid response discriminator")
    require(warning == (WARNING if warnings else b""), "actual warning content differs")
    response[64:].decode("utf-8")
    for part in (annotation,wire,warning):
        part.decode("utf-8")
    return dict(response=response, annotation=annotation, wire=wire, warning=warning,
                kind=kind,category=category,fallback=fallback,warnings=warnings)


def retained_observation(buffers, call):
    output, workspace = call["output_after"], call["workspace_after"]
    head = buffers.span(output,0,64)
    state = buffers.span(workspace,0,224)
    require(call["return_code"] == 64 and head[:8] == b"HSCAR002" and WORD(state,8) == 0, "owner did not complete")
    parts = [buffers.span(output,0,64+WORD(head,16)),
             buffers.span(workspace,WORD(state,152),WORD(head,40)),
             buffers.span(workspace,WORD(state,160)+64,WORD(head,24)),
             buffers.span(workspace,1024,len(WARNING)) if WORD(head,56) else b""]
    raw = b"HSCASR02" + PACK(*(len(part) for part in parts)) + b"".join(parts)
    observation(raw)
    return raw


def physical(folder, report):
    folder = Path(folder)
    session_rows = jsonlines(folder/"sessions.jsonl")
    sessions = {row["session"]:row for row in session_rows}
    require(len(sessions) == len(session_rows) and list(sessions) == list(range(1,len(sessions)+1)), "session identity domain changed")
    calls = jsonlines(folder/"calls.jsonl")
    require(len(calls) == report["native_calls"] and len(sessions) == report["sessions"], "native call/session count differs")
    require({p.name for p in folder.iterdir() if p.is_dir()} == {"buffers"} | {f"{n:06d}" for n in range(1,len(calls)+1)}, "physical call folder domain differs")
    first_calls = {}
    for number,row in enumerate(calls,1):
        first_calls.setdefault(row["session"],row)
        require(row["call"] == number and row["folder"] == f"{number:06d}" and row["session"] in sessions, "call identity differs")
        require(row["owner"] == sessions[row["session"]]["owner"], "call owner changed within session")
        require(row["error"] is None and type(row["return_code"]) is int and 0 <= row["return_code"] <= 0xffffffff, "native call did not return")
        require(row["output_guard"] == "a5"*16 and row["workspace_guard"] == "5a"*16, "actual buffer guard changed")
        require(math.isfinite(row["elapsed_seconds"]) and 0 <= row["elapsed_seconds"] <= 180, "native timing differs")
        for kind in ("workspace","output"):
            for phase in ("before","after"):
                descriptor = row[kind+"_"+phase]
                require(descriptor["bytes"] == row[kind+"_capacity"], "physical buffer capacity differs")
        require(row["output_prefilled_a5"] is True, "undeclared caller output preparation")
    buffers = Buffers(folder)
    for session in session_rows:
        require(set(session) == {"session","owner","case","output_capacity","workspace_capacity","admission"},
                "session allocation declaration differs")
        admission = session["admission"]
        if admission is None:
            continue
        if session["owner"] == "scope_annotation_span":
            require(type(admission) is dict
                    and set(admission) == {"policy","input_bytes","input_sha256","capacity"}
                    and admission["policy"] == "complete-request-span-plus-header"
                    and session["session"] in first_calls,
                    "owner initial output lacks its complete request admission")
            first = first_calls[session["session"]]
            request = read(folder/first["folder"]/"input.bin")
            require(first["case"] == session["case"]
                    and type(admission["input_bytes"]) is int
                    and admission["input_bytes"] == len(request)
                    and admission["input_sha256"] == SHA(request)
                    and type(admission["capacity"]) is int
                    and admission["capacity"] == max(65600,64+len(request))
                    and type(session["output_capacity"]) is int
                    and session["output_capacity"] == admission["capacity"] <= 1073741824
                    and type(session["workspace_capacity"]) is int and session["workspace_capacity"] == 0,
                    "owner initial output differs from the complete actual request")
            continue
        require(session["owner"] == "serde_json_span" and type(admission) is dict
                and set(admission) == {"policy","issued_call","capacity"}
                and admission["policy"] == "actual-owner-reply-capacity"
                and type(admission["issued_call"]) is int and 1 <= admission["issued_call"] <= len(calls),
                "Value initial capacity lacks a bound owner instruction")
        require(session["session"] in first_calls
                and first_calls[session["session"]]["call"] == admission["issued_call"] + 1,
                "Value initial allocation is not immediately before its first actual call")
        issued = calls[admission["issued_call"]-1]
        require(issued["owner"] == "scope_annotation_span" and issued["return_code"] == CALL
                and issued["case"] == session["case"], "Value initial allocation belongs to another owner call")
        action = buffers.span(issued["workspace_after"],256,96)
        require(action[:8] == b"HSCAA002" and WORD(action,16) == 1
                and type(admission["capacity"]) is int
                and 64 <= admission["capacity"] == WORD(action,56) == session["output_capacity"] <= 1073741824
                and session["workspace_capacity"] == 0,
                "Value initial allocation differs from the actual owner reply capacity")
    growth = jsonlines(folder/"growth.jsonl")
    for row in growth:
        require(row["session"] in sessions and row["kind"] in (1,2) and row["previous_address"] != row["next_address"], "growth did not relocate owned buffer")
        old,new = row["before"]["bytes"],row["after"]["bytes"]
        minimum = row["minimum"]
        require(type(minimum) is int and 0 <= old < minimum <= new, "growth did not satisfy actual minimum")
        expected_policy = "exact-minimum"
        expected_size = minimum
        if sessions[row["session"]]["owner"] == "serde_json_span" and row["kind"] == 1:
            require(minimum <= 1207959552, "Value workspace exceeds the bound module profile")
            expected_policy = "value-workspace-double-minimum-bounded"
            expected_size = min(1207959552, 2 * minimum)
        require(row["allocation_policy"] == expected_policy and new == expected_size,
                "physical allocation differs from the declared mechanical growth policy")
        buffers.verify(row["before"]);buffers.verify(row["after"])
        buffers.zero_extended(row["before"],row["after"])
        require(type(row["after_call"]) is int and 1 <= row["after_call"] <= len(calls), "unbound growth call")
        previous = calls[row["after_call"]-1]
        require(previous["session"] == row["session"], "growth process custody differs")
        kind = "workspace" if row["kind"] == 1 else "output"
        require(previous[kind+"_after"] == row["before"] and previous[kind+"_address"] == row["previous_address"], "growth origin differs from complete call")
        head = buffers.span(previous["output_after"],0,32)
        if previous["return_code"] == GROW:
            require(head == b"HGRWS002" + PACK(row["kind"],minimum,0), "growth differs from actual owner instruction")
        else:
            require(previous["owner"] == "serde_json_span" and previous["return_code"] == 32
                    and head == b"HJSVR002" + PACK(2 if row["kind"] == 1 else 3,0,minimum), "growth differs from actual Value instruction")
    handoffs = jsonlines(folder/"handoffs.jsonl")
    for row in handoffs:
        issued = calls[row["issued_call"]-1]
        require(issued["owner"] == "scope_annotation_span" and issued["return_code"] == CALL and issued["session"] == row["owner_session"], "child was not actually requested")
        state = buffers.span(issued["workspace_after"],256,96)
        require(state[:8] == b"HSCAA002" and struct.unpack_from("<11Q",state,8) == (row["sequence"],row["child"],0,row["query_at"],row["query_bytes"],row["reply_at"],row["reply_capacity"],0,0,0,0), "actual child action differs")
        request = buffers.span(issued["workspace_after"],row["query_at"],row["query_bytes"])
        require(SHA(request) == row["request_sha256"], "complete child request differs")
        name = {1:"serde_json_span",2:"serde_error_span",3:"text_result_constructor",4:"serde_json_span"}.get(row["child"])
        children = calls[row["first_child_call"]-1:row["last_child_call"]]
        require(children and row["first_child_call"] == row["issued_call"]+1 and all(c["owner"] == name for c in children), "actual child call range differs")
        require(len({c["session"] for c in children}) == 1 and all(read(folder/c["folder"]/"input.bin") == request for c in children), "child input replay differs")
        last = children[-1]
        response = buffers.span(last["output_after"],0,row["response_bytes"])
        require(row["response_bytes"] <= row["reply_capacity"] and SHA(response) == row["response_sha256"] and last["return_code"] == row["child_code"], "complete child response differs")
        if name == "serde_json_span":
            require(row["child_code"] == 32 and response[:8] == b"HJSVR002" and len(response) == 32+WORD(response,16) and WORD(response,8) in (0,1) and WORD(response,24) == 0, "incomplete Value child response")
        elif name == "text_result_constructor":
            require(row["child_code"] == 64 and response[:8] == b"HRTCRS01" and len(response) == 64+WORD(response,40), "incomplete constructor wire response")
        else:
            require(row["child_code"] == len(response) and response[:8] == b"HSJERR01", "incomplete error child response")
    for row in calls:
        require(file_pin(folder/row["folder"]/"input.bin") == row["input"], "complete actual call input changed")
        require({p.name for p in (folder/row["folder"]).iterdir()} == {"input.bin"}, "call folder has unbound file")
        for kind in ("workspace","output"):
            for phase in ("before","after"):
                descriptor = row[kind+"_"+phase]
                buffers.verify(descriptor)
        require(fixed_byte_digest(165,row["output_capacity"]) == row["output_before"]["sha256"],
                "caller output sentinel differs")
    return buffers,calls,sessions,growth,handoffs

def lifecycle(folder, buffers, calls, sessions, growth, handoffs, *, baselines=(), refusals=()):
    """Reconstruct only transport copies/growth; never substitute HIA semantics."""
    growth_map = {(row["session"],row["after_call"],row["kind"]):row for row in growth}
    require(len(growth_map) == len(growth), "duplicate growth event")
    handoff_map = {row["issued_call"]:row for row in handoffs}
    require(len(handoff_map) == len(handoffs), "duplicate child handoff")
    baseline_map = {row["name"]:row for row in baselines}
    refusal_map = {row["call"]:row for row in refusals}
    previous, last_refusal = {}, {}
    for row in calls:
        session = row["session"]
        prior = previous.get(session)
        before = row["workspace_before"]
        if row["call"] in refusal_map:
            control = refusal_map[row["call"]]
            base = baseline_map[control["baseline"]]
            require(base["session"] == session, "refusal baseline belongs to another session")
            buffers.changed(base["buffer"],before,[(item["at"],bytes.fromhex(item["hex"])) for item in control["patches"]])
            last_refusal[session] = base["buffer"]
        elif session in last_refusal:
            require(before == last_refusal.pop(session), "restored control baseline differs")
        elif prior is None:
            require(before["bytes"] == sessions[session]["workspace_capacity"], "first workspace capacity differs")
            digest = hashlib.sha256()
            for at in range(0,before["bytes"],CHUNK):
                digest.update(bytes(min(CHUNK,before["bytes"]-at)))
            require(digest.hexdigest() == before["sha256"], "fresh workspace not zero initialized")
        elif prior["call"] in handoff_map:
            child = handoff_map[prior["call"]]
            final = calls[child["last_child_call"]-1]
            response = buffers.span(final["output_after"],0,child["response_bytes"])
            buffers.changed(prior["workspace_after"],before,[(320,PACK(child["sequence"],child["child_code"])),(child["reply_at"],response)])
        elif (session,prior["call"],1) in growth_map:
            require(before == growth_map[(session,prior["call"],1)]["after"], "grown workspace was not resumed")
        else:
            require(before == prior["workspace_after"], "host changed workspace between actual calls")
        if prior is not None:
            for kind,number in (("workspace",1),("output",2)):
                growing = growth_map.get((session,prior["call"],number))
                want = growing["next_address"] if growing else prior[kind+"_address"]
                require(row[kind+"_address"] == want, "undeclared physical buffer relocation")
                capacity=growing["after"]["bytes"] if growing else prior[kind+"_capacity"]
                require(row[kind+"_capacity"]==capacity,"undeclared physical buffer capacity change")
        else:
            require(row["output_capacity"]==sessions[session]["output_capacity"],"first output capacity differs from actual session")
        previous[session] = row
    for base in baselines:
        buffers.verify(base["buffer"])
        session, after = base["session"],base["after_call"]
        prior = next((c for c in reversed(calls[:after]) if c["session"] == session),None)
        if prior is None:
            require(not any(buffers.span(base["buffer"])), "fresh control baseline is not actual zero state")
        elif prior["call"] in handoff_map:
            child = handoff_map[prior["call"]]
            final = calls[child["last_child_call"]-1]
            response = buffers.span(final["output_after"],0,child["response_bytes"])
            buffers.changed(prior["workspace_after"],base["buffer"],[(320,PACK(child["sequence"],child["child_code"])),(child["reply_at"],response)])
        else:
            require(base["buffer"] == prior["workspace_after"], "control baseline not from actual call")
    require(buffers.used == set(buffers.rows), "physical chunk lacks an admitted observation")
