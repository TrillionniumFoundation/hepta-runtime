"""Reopen complete public Batch streams and compare actual SDK/HIA sessions.

No process is launched by this module. Absolute producer paths are identities;
artifact reads use only the admitted files under the supplied capture folder.
"""
from pathlib import Path, PurePosixPath
import argparse
import gzip
import hashlib
import json
import math
import os
import stat
import struct

from receipt_support import regular, PIN, require
import public_cases as cases
import public_observations as observations
import qualify_public as capture

common = capture.common
fixture = capture.fixture_io
EMPTY = PIN(b"")
DRIVER_FILES = capture.DRIVER_FILES
STREAM_NAMES = ("attempted-stdin", "stdin", "stdout", "stderr")


def decode(raw):
    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate evidence JSON key")
            result[key] = value
        return result
    def constant(value):
        raise ValueError("nonfinite evidence JSON: " + value)
    return json.loads(raw, object_pairs_hook=object_pairs, parse_constant=constant)


def number(value, maximum):
    return type(value) in (int, float) and math.isfinite(value) and 0 <= value <= maximum


def hex_bytes(value):
    require(type(value) is str, "complete byte span must be hex text")
    raw = bytes.fromhex(value)
    require(raw.hex() == value, "noncanonical complete byte span")
    return raw


class Stream:
    def __init__(self, owner, relative, identity):
        self.owner, self.relative, self.identity = owner, relative, identity
        require(set(identity) == {"path", "compressed", "uncompressed"}, "complete stream fields")
        require(Path(identity["path"]) == owner.producer_folder / relative,
            "stream producer path escaped capture")
        path = owner.folder / relative
        require(PIN(regular(path)) == identity["compressed"], "compressed stream identity: " + relative)
        owner.artifacts[relative] = identity["compressed"]
        self.file = gzip.open(path, "rb")
        self.offset = 0
        self.digest = hashlib.sha256()

    def take(self, count):
        require(type(count) is int and 0 <= count <= self.identity["uncompressed"]["bytes"] - self.offset,
            "stream range exceeds its complete bytes: " + self.relative)
        raw = self.file.read(count)
        require(len(raw) == count, "truncated complete stream: " + self.relative)
        self.offset += count
        self.digest.update(raw)
        return raw

    def line(self):
        raw = self.file.readline()
        self.offset += len(raw)
        self.digest.update(raw)
        require(raw.endswith(b"\n"), "truncated complete evidence record")
        return raw

    def finish(self):
        require(self.file.read(1) == b"", "unclaimed complete stream bytes: " + self.relative)
        self.file.close()
        require(self.identity["uncompressed"] == {"bytes": self.offset, "sha256": self.digest.hexdigest()},
            "uncompressed stream identity: " + self.relative)


class Traces:
    SIZES = {b"HRGTR002": 224, b"HRCNAK02": 128, b"HWDIOAK2": 160,
        b"HFSPCL02": 80, b"HFSPAK02": 192, b"HVRDACK1": 128, b"HFLKEYFX": 128}

    def __init__(self, role, poison_labels=()):
        self.role, self.pending, self.counts = role, bytearray(), {}
        self.poison_labels=tuple(poison_labels)

    def add(self, raw):
        if self.role == "original":
            if self.poison_labels:self.pending.extend(raw)
            else:require(raw == b"", "original fixture wrote undeclared diagnostics")
            return
        self.pending.extend(raw)
        while len(self.pending) >= 8:
            size = self.SIZES.get(bytes(self.pending[:8]))
            require(size is not None, "unknown actual private journal")
            if len(self.pending) < size:
                break
            frame = bytes(self.pending[:size])
            del self.pending[:size]
            if frame[:8] == b"HRGTR002":
                words = struct.unpack("<28Q", frame)
                seq, slot, event, result, work, output = words[1:7]
                require(seq > 0 and slot < 64 and event in (1, 2, 3, 4)
                    and work >= 4096 and output >= 4096, "actual growth-engine receipt fields")
                if event == 1:
                    require(result <= 0xffffffff and (result <= output or result >= 0xffff0000),
                        "actual HIA return encoding/capacity")
                elif event == 2:
                    require(result == 0, "actual successful arena-resize status")
                else:
                    magic, child_seq, _, flags, input_at, input_len, output_at, output_len = words[10:18]
                    require(magic != 0 and child_seq == words[8] and child_seq > 0 and flags in (0, 1)
                        and 4096 <= input_at <= work and input_len <= work - input_at
                        and 4096 <= output_at <= work and 32 <= output_len <= work - output_at
                        and (input_at + input_len <= output_at or output_at + output_len <= input_at),
                        "complete admitted parent child spans")
                    if event == 3:
                        require(result == input_len and words[18:24] == (0, 0, 0, 0, 0, 0),
                            "actual child input-extent journal")
                    else:
                        require(words[18] == child_seq and words[19] <= 0xffffffff and words[20:22] == (0, 0)
                            and words[22] == result and words[23] == 0,
                            "actual child completed-extent journal")
                name = "HRGTR002"
                self.counts[name] = self.counts.get(name, 0) + 1
            else:
                for name, count in observations.trace_frames(frame).items():
                    self.counts[name] = self.counts.get(name, 0) + count

    def finish(self):
        if self.role=="original" and self.poison_labels:
            raw=bytes(self.pending)
            for label in self.poison_labels:require(raw.count(label.encode())==1,"complete declared poison diagnostic")
            require(raw.count(b"panicked at ")==len(self.poison_labels) and b"RUST_BACKTRACE" in raw,"actual caught poison diagnostic framing")
            self.counts["original_poison_diagnostic_bytes"]=len(raw);self.pending.clear()
        require(not self.pending, "partial final actual private journal")
        if self.role == "native":
            require(self.counts.get("HRGTR002", 0) > 0, "no actual HIA calls recorded")


def filesystem(trees, root, uid):
    require(type(trees) is list and len(trees) == 1, "one exact owned fixture snapshot")
    tree = trees[0]
    require(set(tree) == {"root_hex", "nodes"} and hex_bytes(tree["root_hex"]) == os.fsencode(root),
        "snapshot escaped the admitted fixture")
    nodes, known, paths = tree["nodes"], {}, []
    require(type(nodes) is list and nodes, "complete fixture snapshot nodes")
    for node in nodes:
        require(type(node) is dict and "relative_hex" in node, "complete raw-name node")
        raw = hex_bytes(node["relative_hex"])
        require(b"\0" not in raw and not raw.startswith(b"/") and
            all(part not in (b"", b".", b"..") for part in raw.split(b"/")) if raw else True,
            "snapshot node path escaped fixture")
        require(raw not in known, "duplicate complete snapshot node")
        if raw:
            parent = raw.rsplit(b"/", 1)[0] if b"/" in raw else b""
            require(parent in known and stat.S_ISDIR(known[parent].get("mode", 0)),
                "snapshot descends through a missing or non-directory parent")
        if "errno" in node:
            require(set(node) == {"relative_hex", "errno"} and type(node["errno"]) is int and node["errno"] > 0,
                "snapshot error fields")
        else:
            base = {"relative_hex", "device", "inode", "mode", "uid", "gid", "links", "size", "mtime", "ctime"}
            require(base <= set(node) and all(type(node[k]) is int and node[k] >= 0 for k in
                ("device", "inode", "mode", "uid", "gid", "links", "size")) and node["links"] > 0
                and node["uid"] == uid, "owned snapshot metadata")
            require(all(type(node[k]) is list and len(node[k]) == 2 and all(type(v) is int for v in node[k])
                and 0 <= node[k][1] < 1000000000 for k in ("mtime", "ctime")), "complete timestamp fields")
            mode = node["mode"]
            extra = set(node) - base
            if stat.S_ISREG(mode):
                require(extra in ({"content_hex"}, {"read_errno"}), "complete regular-file observation")
                if "content_hex" in node:
                    require(len(hex_bytes(node["content_hex"])) == node["size"], "full file-byte extent")
                else:
                    require(type(node["read_errno"]) is int and node["read_errno"] > 0, "actual file read refusal")
            elif stat.S_ISDIR(mode):
                require(extra in (set(), {"readdir_errno"}), "directory observation fields")
            elif stat.S_ISLNK(mode):
                require(extra == {"target_hex"} and len(hex_bytes(node["target_hex"])) == node["size"],
                    "complete symlink target")
            else:
                require(False, "undeclared nonregular fixture node")
        known[raw] = node
        paths.append(raw)
    require(paths[0] == b"" and paths == sorted(paths) and stat.S_ISDIR(nodes[0].get("mode", 0)),
        "complete ordered fixture root")
    return trees


def open_process(owner, expected_binary, *, single_reference_session=False):
    r = owner.report
    require(type(single_reference_session) is bool and (not single_reference_session or
        owner.role == "original" and r["schema"] == "hepta.runtime.batch-public-stdio-capture.v2"
        and r["original_fixture_sessions"] == 1), "explicit single-session original stdio mode")
    tool = r["binary"]
    owner.binary = {k: tool[k] for k in ("bytes", "sha256")}
    require(tool["captured_file"] == "tool-" + owner.role + ".bin" and tool["path"] == tool["resolved_path"],
        "actual independent executable identity")
    shared=r["shared_binary_relative"]
    if shared is None:
        raw=owner.file(tool["captured_file"])
    else:
        require(owner.domain.startswith("body-") and owner.folder.parent.name=="cases" and owner.folder.name==f'{r["case_index"]:03d}' and shared=="../../"+tool["captured_file"],"fixed complete shared-binary location")
        raw=regular(owner.folder.parent.parent/tool["captured_file"]);owner.artifacts[shared]=PIN(raw)
    require(PIN(raw) == owner.binary, "complete captured executable bytes")
    if expected_binary is not None:
        require(owner.binary == expected_binary, "executed binary differs from the fresh admitted build")
    owner.process = owner.json("process/process.json")
    p, started = owner.process, owner.json("process/started.json")
    require(r["process"] == p, "capture/process receipt differs")
    require(set(started) == {"binary", "command", "native_argv", "cwd", "environment", "observer_fd", "pid"}
        and started["observer_fd"] is None and all(started[k] == p[k] for k in started if k != "observer_fd"),
        "actual start/completion identity")
    argv = [tool["path"], *(["--fixture-single-session"] if single_reference_session else [])]
    config=r["runtime_config"]
    if config is not None:
        require(owner.domain.startswith("catalog-") and config["path"]==str(Path(p["streams"]["stdin"]["path"]).parent.parent/"runtime-config.json"),"fixed original catalog config path")
        config_raw=owner.file("runtime-config.json");require(PIN(config_raw)=={k:config[k] for k in ("bytes","sha256")} and config_raw==common.canonical(owner.plan["runtime_config"]),"complete catalog policy input")
        if owner.role=="original":argv.append(config["path"])
        else:argv.extend(["--runtime-config",config["path"]])
    require(p["command"] == p["native_argv"] == argv and p["binary"] == owner.binary
        and p["cwd"] == r["fixture"] and p["environment"] == {"PATH": "", "LC_ALL": "C"}
        and type(p["pid"]) is int and p["pid"] > 0, "actual process/cwd/environment custody")
    require(p["exit_code"] == 0 and p["timed_out"] is False and p["start_error"] is None
        and p["failure_cleanup_requested"] is False and p["kill_requested"] is False
        and p["cleanup_error"] is None and p["wait_timed_out"] is False
        and p["pipe_eof"] == {"stdout": True, "stderr": True} and p["unconsumed_stdout"] == EMPTY
        and p["drain_deadline_seconds"] == 60 and p["wait_deadline_seconds"] == 5
        and p["kill_cleanup_deadline_seconds"] == 5 and number(p["drain_elapsed_seconds"], 65)
        and number(p["elapsed_seconds"], r["elapsed_seconds"]), "actual process termination custody")
    require(set(p["streams"]) == set(STREAM_NAMES), "all four actual process streams")
    stdin_path = Path(p["streams"]["stdin"]["path"])
    require(stdin_path.is_absolute() and stdin_path.name == "stdin.bin.gz"
        and stdin_path.parent.name == "process" and ".." not in stdin_path.parts,
        "complete process producer path")
    owner.producer_folder = stdin_path.parent.parent
    if not getattr(owner, "legacy", False):
        journal = p["exchange_journal"]
        require(set(journal) == {"path", "bytes", "sha256", "format", "records", "recording_error"}
            and journal["path"] == str(owner.producer_folder / "process/exchanges.jsonl")
            and journal["format"] == "canonical-json-lines.v1" and journal["recording_error"] is None
            and type(journal["records"]) is int and journal["records"] == p["exchanges"],
            "complete append journal identity")
        raw = owner.file("process/exchanges.jsonl")
        require(PIN(raw) == {key: journal[key] for key in ("bytes", "sha256")},
            "complete append journal bytes")
        lines = raw.splitlines(keepends=True)
        require(len(lines) == journal["records"] and all(line.endswith(b"\n") for line in lines)
            and owner.file("process/exchanges.json") == b"[" + b",".join(line[:-1] for line in lines) + b"]\n",
            "append journal differs from final complete exchange array")
    owner.streams = {name: Stream(owner, "process/" + name + ".bin.gz", p["streams"][name]) for name in STREAM_NAMES}
    return owner.streams


class Capture:
    def __init__(self, folder, source_root, *, expected_binary=None, allow_development_v1=False):
        self.folder = Path(folder).resolve(strict=True)
        self.source = Path(source_root).resolve(strict=True)
        self.artifacts = {}
        self.report = self.json("result.json")
        r = self.report
        self.role, self.domain = r["role"], r["domain"]
        require(self.role in ("native", "original") and self.domain in capture.DOMAINS, "capture provider/domain")
        self.legacy = False
        require(r["schema"] == "hepta.runtime.extract-public-complete-capture.v1" and not allow_development_v1,"complete current extract capture schema")
        self.plan=cases.plan(self.domain,Path(r["fixture"]),r["case_index"])
        require(r["input_plan"]==cases.serial(self.plan) and r["case_name"]==self.plan["case_name"],"complete frozen input plan")
        require(r["status"] == "PASS" and r["completed_cases"] == r["case_count"] == len(self.plan["rows"])
            and number(r["elapsed_seconds"], 180) and r["per_exchange_deadline_seconds"] == 60
            and r["outer_lane_deadline_seconds"] == 180, "complete capture completion/deadlines")
        for name in ("public_extract_qualified", "full_async_cancellation_qualified", "remote_sftp_qualified", "whole_runtime_replaced"):
            require(r[name] is False, "capture makes an unsupported global qualification claim")
        require(set(r["driver_sources"]) == set(DRIVER_FILES), "exact executed capture source closure")
        for name, identity in r["driver_sources"].items():
            require(PIN(regular(self.source / name)) == identity, "actual capture driver source changed: " + name)
            if name != "qualify_public.py":
                require(regular(self.source / name) == regular(Path(__file__).parent / name),
                    "reader does not use the captured input/observation implementation: " + name)
        self.streams = open_process(self, expected_binary)
        self.events = Stream(self, "events.jsonl.gz", r["events"])
        self.exchanges = self.json("process/exchanges.json")
        require(type(self.exchanges) is list and len(self.exchanges) == self.process["exchanges"], "complete exchange count")
        spec=self.plan["body_spec"];labels=[]
        if spec is not None:
            if spec["cache_poison"]:labels.append("test-only original Mutex poisoning event")
            if spec["history_poison"]:labels.append("test-only original history Mutex poisoning")
        self.trace = Traces(self.role,labels)
        self.index = 0
        self.initial = []
        self.rows = self.plan["rows"]
        self.actions(r["initial_actions"],self.plan["actions"])
        filesystem(r["initial_filesystem"],r["fixture"],r["effective_uid"])
        self.actual_rows = 0
        self.full_filesystem_bytes = 0
        self.unreadable_observations = 0

    def file(self, name):
        rel = PurePosixPath(name)
        require(not rel.is_absolute() and ".." not in rel.parts and str(rel) == name, "admitted artifact path")
        raw = regular(self.folder / name)
        self.artifacts[name] = PIN(raw)
        return raw

    def json(self, name):
        return decode(self.file(name))

    def exchange(self, kind, session, raw=b"", response=False, slot=None):
        index = self.index
        require(index < len(self.exchanges), "missing actual exchange")
        self.index += 1
        row = self.exchanges[index]
        base = {"index", "deadline_seconds", "elapsed_seconds", "timed_out", "transport", "error",
            "attempted_input", "accepted_input", "stdout_range", "stderr_range", "stdout_eof", "stderr_eof"}
        expected = base | ({"session", "slot", "response", "body", "header"} if self.role == "native" else {"responses"})
        require(set(row) == expected and row["index"] == index and row["deadline_seconds"] == 60
            and number(row["elapsed_seconds"], 60) and row["timed_out"] is False and row["error"] is None
            and row["stdout_eof"] is False and row["stderr_eof"] is False, "actual complete exchange fields")
        if self.role == "native":
            require(slot is not None and row["session"] == session and row["slot"] == slot
                and row["transport"] == "private-frame", "native actual exchange selection")
            wanted = fixture.request_frame(session, slot, raw)
            command = None
        else:
            require(row["transport"] == "response", "actual original outer response")
            command = {"id": index, "session": session, "kind": kind}
            if kind != "observe":
                command.update(wire_hex=raw.hex(), response=response)
            wanted = cases.encode(command) + b"\n"
        for key, stream_name in (("attempted_input", "attempted-stdin"), ("accepted_input", "stdin")):
            identity = row[key]
            stream = self.streams[stream_name]
            require(identity == {"offset": stream.offset, **PIN(wanted)} and stream.take(len(wanted)) == wanted,
                "full regenerated actual input differs: " + str(index))
        out_range = row["stdout_range"]
        require(set(out_range) == {"offset", "bytes"} and out_range["offset"] == self.streams["stdout"].offset,
            "contiguous complete stdout custody")
        out = self.streams["stdout"].take(out_range["bytes"])
        err_range = row["stderr_range"]
        require(set(err_range) == {"offset", "bytes"} and err_range["offset"] == self.streams["stderr"].offset,
            "contiguous complete stderr custody")
        self.trace.add(self.streams["stderr"].take(err_range["bytes"]))
        if self.role == "native":
            head, body = fixture.decode_response(out, session, slot)
            require(row["header"] == head and row["response"] == {"offset": out_range["offset"], **PIN(out)}
                and row["body"] == {"offset": out_range["offset"] + head["header_bytes"], **PIN(body)},
                "complete native carrier response fields")
            if slot == 34:
                require(head["closed"] == 0 and bool(body) == response, "public response/connection custody")
            elif slot in (33, 41):
                require(head["native_return"] == 0, "actual observer return")
            elif slot == 32:
                require(head["native_return"] == 32, "actual cache setup return")
            elif slot==64:
                require(head["native_return"]==64 and len(body)==64 and body[:8]==b"HHISTR01","actual original shared-history fixture return")
            return index, body, None
        require(out.endswith(b"\n") and b"\n" not in out[:-1] and row["responses"] == [PIN(out)],
            "complete original carrier line")
        parsed = decode(out)
        state = observations.original_state(parsed, command)
        body = hex_bytes(parsed["output_hex"])
        return index, body, state

    def observe(self):
        if self.role == "original":
            index, body, state = self.exchange("observe", 0)
            require(body == b"", "original read-only observer output")
            return {"exchanges": [index], "state": state}
        a, left, _ = self.exchange("observe", 0, slot=33)
        b, right, _ = self.exchange("observe", 1, slot=33)
        c, shared, _ = self.exchange("observe", 0, slot=41)
        return {"exchanges": [a, b, c], "state": observations.native_state((left, right), shared)}

    def wire(self, session, raw, response):
        require(raw.endswith(b"\n"), "complete input LF")
        index, body, _ = self.exchange("wire", session, raw[:-1] if self.role == "native" else raw,
            response, slot=34)
        require(bool(body) == response, "exact actual response presence")
        if body:
            require(body.endswith(b"\n") and b"\n" not in body[:-1], "one complete actual JSON response")
            decode(body)
        return {"exchange": index, "wire": body}

    def tree(self, value):
        filesystem(value, self.report["fixture"], self.report["effective_uid"])
        for item in value[0]["nodes"]:
            if "content_hex" in item:
                self.full_filesystem_bytes += len(item["content_hex"]) // 2
            self.unreadable_observations += int("read_errno" in item)
        return value

    @staticmethod
    def actions(actual, expected):
        require(type(actual) is list and len(actual) == len(expected), "complete fixture action list")
        for row, action in zip(actual, expected, strict=True):
            require(set(row) == {"action", "status", "elapsed_seconds"} and row["action"] == action
                and row["status"] == "EXECUTED" and number(row["elapsed_seconds"], 180), "exact declared fixture action")

    def begin(self):
        for item in self.plan["initial"]:
            raw,wanted,session=item["wire"],item["response"],item["session"]
            result=self.wire(session,raw,wanted)
            self.initial.append({"session":session,"input":PIN(raw),"exchange":result["exchange"],"response":PIN(result["wire"])})
            yield result["wire"]
        require(self.report["initial"]==self.initial,"complete actual initialization receipts")
        seeds=[]
        for seed in self.plan["seeds"]:
            seq,body,_=self.exchange(seed["owner"],seed["session"],seed["wire"],slot=32 if seed["owner"]=="cache" else 64)
            if seed["owner"]=="cache":require(body==b"HVCAR001"+bytes(24),"actual seed cache bytes")
            else:require(len(body)==64 and body[:8]==b"HHISTR01","actual seed history complete bytes")
            seeds.append({"owner":seed["owner"],"session":seed["session"],"input":PIN(seed["wire"]),"exchange":seq,"response":PIN(body)})
            yield body
        require(seeds==self.report["initial_seeds"],"all initial actual owner seeds")

    def body_tree(self,full,tree):
        if self.plan["body_spec"] is None:
            require(full is None,"undeclared body-only full-file observation");return None
        require(type(full) is dict and set(full)=={"nodes","hardlink_groups"},"complete body snapshot fields")
        ordinary={n["relative_hex"]:n for n in tree[0]["nodes"] if n["relative_hex"]}
        require([n["path_hex"] for n in full["nodes"]]==list(ordinary),"complete body snapshot node set/order")
        groups={}
        for node in full["nodes"]:
            base=ordinary[node["path_hex"]]
            require(all(node[k]==base[k] for k in ("uid","gid","links")) and node["mode"]==stat.S_IMODE(base["mode"]),"full snapshot metadata")
            fields={"path_hex","uid","gid","links","mode","kind"}
            if stat.S_ISREG(base["mode"]):
                require(set(node)==fields|{"content"} and node["kind"]=="file","complete full regular body file")
                row=node["content"];require(set(row)=={"path","bytes","sha256"} and row["path"]==row["sha256"]+".bin","complete content-addressed full file")
                raw=self.file("blobs/"+row["path"]);require(PIN(raw)=={k:row[k] for k in ("bytes","sha256")} and len(raw)==base["size"],"full unreadable/readable file extent")
                if "content_hex" in base:require(raw==hex_bytes(base["content_hex"]),"two actual file observations differ")
                groups.setdefault((base["device"],base["inode"]),[]).append(node["path_hex"])
            elif stat.S_ISDIR(base["mode"]):require(set(node)==fields and node["kind"]=="directory","full body directory")
            elif stat.S_ISLNK(base["mode"]):require(set(node)==fields|{"target_hex"} and node["kind"]=="symlink" and node["target_hex"]==base["target_hex"],"full body symlink")
            else:require(False,"nonregular body snapshot")
        require(full["hardlink_groups"]==sorted(sorted(x) for x in groups.values() if len(x)>1),"full body hardlink identity groups")
        return full

    def records(self):
        for index, row in enumerate(self.rows):
            encoded = self.events.line()
            event = decode(encoded)
            require(encoded == common.canonical(event), "canonical complete event record")
            keys = {"index", "name", "domain", "original_case_id", "session", "input", "exchange", "response",
                "actions", "seeds", "before", "after", "before_filesystem", "after_filesystem", "after_actions", "recovery", "body_full_filesystem"}
            if not self.legacy:
                keys.add("after_cleanup_filesystem")
            require(set(event) == keys and event["index"] == index and event["name"] == row["name"]
                and event["domain"] == row["domain"] and event["original_case_id"] == row.get("original_case_id")
                and event["session"] == row.get("session", 0), "complete original input index/domain")
            self.actions(event["actions"], row["actions"])
            seeds = []
            for seed in row.get("seed") or []:
                raw = capture.cache_set(seed["path"], seed["content"])
                seq, body, _ = self.exchange("cache", seed["session"], raw, slot=32)
                require(body == b"HVCAR001" + b"\0" * 24, "actual cache setup bytes")
                seeds.append({"input": PIN(raw), "exchange": seq, "response": PIN(body)})
            require(event["seeds"] == seeds, "complete exact cache setup")
            before = self.observe()
            raw = cases.row_wire(row,index,self.plan["modern"])
            result = self.wire(row.get("session", 0), raw, row["response"])
            recovery = None
            recovery_wire = None
            if not row["response"]:
                ping = cases.encode({"jsonrpc": "2.0", "id": 100000 + index, "method": "ping"}) + b"\n"
                reply = self.wire(row.get("session", 0), ping, True)
                require(decode(reply["wire"])["id"] == 100000 + index, "actual same-session discard recovery")
                recovery = {"input": PIN(ping), "exchange": reply["exchange"], "response": PIN(reply["wire"])}
                recovery_wire = reply["wire"]
            after = self.observe()
            require(event["before"] == before and event["after"] == after and event["recovery"] == recovery
                and event["input"] == PIN(raw) and event["response"] == PIN(result["wire"])
                and event["exchange"] == result["exchange"], "complete stream-derived event differs")
            self.actions(event["after_actions"], row["after_actions"])
            snapshots = [self.tree(event[key]) for key in ("before_filesystem", "after_filesystem")]
            if not self.legacy:
                snapshots.append(self.tree(event["after_cleanup_filesystem"]))
            full=event["body_full_filesystem"]
            if self.plan["body_spec"] is None:require(full is None,"undeclared full body snapshot")
            else:
                require(type(full) is list and len(full)==2,"both complete body file observations")
                self.body_tree(full[0],snapshots[0]);self.body_tree(full[1],snapshots[1])
            self.actual_rows += 1
            yield {"body_full_filesystem":full,"index": index, "name": row["name"], "input": raw, "wire": result["wire"],
                "before": before["state"], "after": after["state"], "recovery_wire": recovery_wire,
                "filesystem": common.structural_snapshots(snapshots)}

    def finish(self):
        require(self.actual_rows == len(self.rows) == self.report["case_count"], "missing complete public rows")
        final = self.observe()
        require(final == self.report["final_observation"], "complete final session observation")
        self.tree(self.report["final_filesystem"])
        self.body_tree(self.report["final_full_body_filesystem"],self.report["final_filesystem"])
        require(self.index == len(self.exchanges), "unclaimed actual exchanges")
        err = self.streams["stderr"]
        while err.offset < err.identity["uncompressed"]["bytes"]:
            self.trace.add(err.take(min(65536, err.identity["uncompressed"]["bytes"] - err.offset)))
        self.trace.finish()
        for stream in self.streams.values():
            stream.finish()
        self.events.finish()
        return {"status": "PASS", "role": self.role, "domain": self.domain, "actual_rows": self.actual_rows,
            "actual_root_processes": 1, "actual_exchanges": self.index, "binary": self.binary,
            "full_filesystem_bytes": self.full_filesystem_bytes, "unreadable_observations": self.unreadable_observations,
            "post_cleanup_filesystem_captured": not self.legacy,
            "complete_stream_bytes": sum(s["uncompressed"]["bytes"] for s in self.process["streams"].values()),
            "actual_native_journals": self.trace.counts, "process_launches": 0,
            "artifact_sha256": {name: value["sha256"] for name, value in sorted(self.artifacts.items())},
            "public_extract_qualified": False, "whole_runtime_replaced": False}


def inspect(folder, source_root, *, expected_binary=None, allow_development_v1=False):
    value = Capture(folder, source_root, expected_binary=expected_binary, allow_development_v1=allow_development_v1)
    list(value.begin())
    for _ in value.records():
        pass
    return value.finish()


def compare(native_folder, original_folder, source_root, *, native_binary, original_binary, original_source_root=None):
    left = Capture(native_folder, source_root, expected_binary=native_binary)
    right = Capture(original_folder, source_root if original_source_root is None else original_source_root, expected_binary=original_binary)
    require(left.role == "native" and right.role == "original" and left.domain == right.domain
        and left.report["fixture"] == right.report["fixture"]
        and left.report["effective_uid"] == right.report["effective_uid"] and left.report["case_index"]==right.report["case_index"], "actual paired lane/cwd/uid")
    require(common.structural_snapshots([left.report["initial_filesystem"]])==common.structural_snapshots([right.report["initial_filesystem"]]),"complete initial filesystem input")
    require(list(left.begin()) == list(right.begin()), "full actual SDK initialization wire differs")
    count, wire_bytes = 0, 0
    for a, b in zip(left.records(), right.records(), strict=True):
        require(a == b, "actual public wire/state/filesystem difference at " + str(a["index"]) + ": " + a["name"])
        count += 1
        wire_bytes += len(a["wire"]) + len(a["recovery_wire"] or b"")
    final_left, final_right = left.finish(), right.finish()
    require(left.report["final_observation"]["state"] == right.report["final_observation"]["state"]
        and common.structural_snapshots([left.report["final_filesystem"]]) ==
            common.structural_snapshots([right.report["final_filesystem"]]) and left.report["final_full_body_filesystem"]==right.report["final_full_body_filesystem"], "actual final paired state/filesystem")
    return {"status": "PASS", "domain": left.domain, "actual_rows_per_provider": count,
        "compared_complete_response_bytes": wire_bytes, "native": final_left, "original": final_right,
        "process_launches": 0, "full_async_cancellation_qualified": False,
        "remote_sftp_qualified": False, "whole_runtime_replaced": False}


def compare_lane(native_folder,original_folder,source_root,*,native_binary,original_binary,domain,original_source_root=None):
    native_folder,original_folder=Path(native_folder),Path(original_folder)
    if not domain.startswith("body-"):
        return compare(native_folder,original_folder,source_root,native_binary=native_binary,original_binary=original_binary,original_source_root=original_source_root)
    lanes=[decode(regular(root/"lane.json")) for root in (native_folder,original_folder)]
    for lane,role,root in zip(lanes,("native","original"),(native_folder,original_folder),strict=True):
        require(lane["status"]=="PASS" and lane["domain"]==domain and lane["role"]==role and lane["case_count"]==153 and lane["operation_count"]==175 and lane["outer_lane_deadline_seconds"]==180 and number(lane["elapsed_seconds"],180),"complete 153-case body lane custody")
        require(len(lane["cases"])==153,"full body case set")
        for index,(record,spec) in enumerate(zip(lane["cases"],cases.body_specs(),strict=True)):
            require(record=={"index":index,"name":spec["name"],"operations":len(spec["operations"]),"result":PIN(regular(root/"cases"/f"{index:03d}"/"result.json"))},"body ordinal/source/result binding")
    rows=[]
    for index in range(153):
        rows.append(compare(native_folder/"cases"/f"{index:03d}",original_folder/"cases"/f"{index:03d}",source_root,native_binary=native_binary,original_binary=original_binary,original_source_root=original_source_root))
    require(sum(row["actual_rows_per_provider"] for row in rows)==175,"complete public body operation count")
    return {"status":"PASS","domain":domain,"actual_cases_per_provider":153,"actual_rows_per_provider":175,"actual_root_processes":306,"pairs":rows,"process_launches":0,"full_async_cancellation_qualified":False,"remote_sftp_qualified":False,"whole_runtime_replaced":False}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--capture", type=Path, required=True)
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--allow-development-v1", action="store_true")
    a = p.parse_args()
    print(json.dumps(inspect(a.capture, a.source, allow_development_v1=a.allow_development_v1), sort_keys=True))
