"""Read actual native streams; keep expected semantics out of the Rust input."""
from __future__ import annotations
import gzip
import hashlib
import json
import math
from pathlib import Path
import struct


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def exact_json(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def read_stream(corpus, metadata):
    relative = metadata["path"]
    if type(relative) is not str or Path(relative).name != relative or (corpus / relative).is_symlink():
        raise ValueError("native stream is not a direct regular file")
    compressed = (corpus / relative).read_bytes()
    raw = gzip.decompress(compressed)
    if len(compressed) != metadata["gzip_bytes"] or sha(compressed) != metadata["gzip_sha256"]:
        raise ValueError("compressed native stream changed")
    if len(raw) != metadata["bytes"] or sha(raw) != metadata["sha256"]:
        raise ValueError("complete native stream changed")
    return raw


def packet(raw, magic):
    if len(raw) < 64 or raw[:8] != magic:
        raise ValueError("native frame identity differs")
    return struct.unpack_from("<7Q", raw, 8), raw[64:]


def observation(target, wire, native):
    words, payload = packet(wire, b"HRCLQ001" if target == 5 else b"HRSCQ001")
    op, generation, sequence, a, b, size, reserved = words
    if size != len(payload) or reserved != 0:
        raise ValueError("successful native request framing differs")
    event = {}
    if target == 5:
        words, body = packet(native, b"HRCLR001")
        epoch, alias, count, phase, size, z1, z2 = words
        if size != len(body) or z1 != 0 or z2 != 0 or phase not in (0, 1):
            raise ValueError("native lease reply differs")
        event["source"] = sequence
        expected = {"strong_count": count, "alive": bool(phase)}
        if op == 1:
            event.update(op="create", alias=alias)
            category = "scope_and_cache_lifecycle_adapters"
        elif op == 2:
            event.update(op="clone", alias=alias)
            category = "original_arc_observations"
        elif op in (3, 5):
            event["op"] = "release" if op == 3 else "inspect"
            category = "original_arc_observations"
        elif op == 4:
            event.update(op="owned_cache", wire_hex=payload.hex())
            expected = {"strong_count": count, "payload_hex": body.hex()}
            category = "original_cache_methods"
        else:
            raise ValueError("unknown successful lease operation")
    else:
        words, body = packet(native, b"HRSCR001")
        gen, continuation, phase, tag, epoch, alias, size = words
        if size != len(body) or phase not in (0, 1, 2, 3):
            raise ValueError("native scope reply differs")
        event["actor"] = target
        if op == 1:
            if len(payload) != 16 or tag != 0 or phase != 1:
                raise ValueError("native OPEN result differs")
            _, source = struct.unpack("<2Q", payload)
            event.update(op="open", source=source, alias=alias)
            expected = {"active": True}
            category = "scope_and_cache_lifecycle_adapters"
        elif op in (7, 8):
            event.update(op="close" if op == 7 else "cancel", error=bool(a), reason=a)
            expected = {"active": False}
            category = "scope_and_cache_lifecycle_adapters"
        elif op in (5, 6):
            if op == 6 and tag == 3:
                event["op"] = "late_retire"
                expected = {"active": False}
            else:
                event["op"] = "yield" if op == 5 else "resume"
                expected = {"pending": True, "outside_absent": True}
            category = "continuation_poll_observations"
        else:
            event["bound"] = generation != 0 or sequence != 0
            category = "original_context_accessors"
            if op == 2:
                event["op"] = "access"
                expected = {"present": tag == 1, "identity_matches": tag == 1}
            elif op == 3:
                event.update(op="push", hint=payload.decode("utf-8", "strict"))
                expected = {"unit": True}
            elif op == 4:
                event["op"] = "drain"
                expected = {"payload_hex": body.hex()}
            elif op == 9:
                event.update(op="cache", wire_hex=payload.hex())
                expected = {"payload_hex": body.hex()}
                category = "original_cache_methods"
            else:
                raise ValueError("unknown successful scope operation")
    return event, expected, category, len(body) if "payload_hex" in expected else 0


def prepare(corpus, output):
    metadata_raw = (corpus / "native-corpus.json").read_bytes()
    metadata = exact_json(metadata_raw)
    if (metadata.get("schema") != "hepta.runtime.request-scope-lifecycle-native-corpus.v1"
            or metadata.get("status") != "PASS" or metadata.get("original_rust_processes") != 0):
        raise ValueError("wrong native lifetime capture")
    counts = dict.fromkeys(("native_rows", "native_only_refusals", "existing_context_fixture_rows",
                           "original_context_accessors", "original_cache_methods", "original_arc_observations",
                           "scope_and_cache_lifecycle_adapters", "continuation_poll_observations",
                           "compared_owner_payload_bytes"), 0)
    expected, traces, boundaries = {}, [], []
    for name, run in sorted(metadata["runs"].items()):
        elapsed = run["elapsed_seconds"]
        if (type(run["exit_code"]) is not int or run["exit_code"] != 0
                or type(elapsed) not in (int, float) or not math.isfinite(elapsed)
                or not 0 <= elapsed < run["timeout_seconds"]):
            raise ValueError("native process did not complete successfully")
        streams = {kind: read_stream(corpus, row) for kind, row in run["streams"].items()}
        if streams["stderr"] or streams["stdout"] != streams["expected"]:
            raise ValueError("native process comparison failed")
        requests, replies = streams["input"].splitlines(), streams["stdout"].splitlines()
        domains = exact_json(streams["domains"])
        if len(requests) != run["requests"] or len(replies) != len(requests) or len(domains) != len(requests):
            raise ValueError("native ordered cardinality differs")
        events, wanted = [], []
        for ordinal, (request_line, reply_line, domain) in enumerate(zip(requests, replies, domains, strict=True)):
            prefix, raw_hex = request_line.split(b":", 1)
            target = int(prefix[:1])
            if target not in (1, 2, 3, 4, 5):
                raise ValueError("unknown private fixture target")
            if len(prefix) != 1:
                if len(prefix) != 10 or prefix[1:2] != b"@":
                    raise ValueError("unknown short-output selector")
                int(prefix[2:], 16)
            wire = bytes.fromhex(raw_hex.decode("ascii"))
            code_hex, body_hex = reply_line.split(b":", 1)
            if len(code_hex) != 8:
                raise ValueError("native code width differs")
            code, native = int(code_hex, 16), bytes.fromhex(body_hex.decode("ascii"))
            if (domain["ordinal"] != ordinal or domain["input_bytes"] != len(wire)
                    or domain["input_sha256"] != sha(wire) or domain["expected_code"] != code
                    or domain["expected_output_sha256"] != sha(native)):
                raise ValueError("native ordered complete input/output differs")
            counts["native_rows"] += 1
            if code >= 0xffff0000:
                if native:
                    raise ValueError("native refusal has output")
                counts["native_only_refusals"] += 1
                boundaries.append({"trace": name, "ordinal": ordinal, "code": code, "domain": domain["domain"]})
                continue
            if code != len(native):
                raise ValueError("native response length differs")
            if name == "preexisting-context":
                counts["existing_context_fixture_rows"] += 1
                boundaries.append({"trace": name, "ordinal": ordinal, "code": code,
                                   "domain": "explicit-private-context-precondition-control"})
                continue
            if target not in (1, 2, 5):
                raise ValueError("raw context fixture escaped its separate control domain")
            event, value, category, compared = observation(target, wire, native)
            event["ordinal"] = ordinal
            events.append(event)
            wanted.append({"ordinal": ordinal, "value": value})
            counts[category] += 1
            counts["compared_owner_payload_bytes"] += compared
        if events:
            traces.append({"trace": name, "events": events})
            expected[name] = wanted
    if counts["native_rows"] != metadata["native_elf_requests"] or counts["native_only_refusals"] != metadata["native_refusals"]:
        raise ValueError("native totals differ")
    raw = ("\n".join(canonical(value) for value in traces) + "\n").encode()
    (output / "original-input.jsonl").write_bytes(raw)
    (output / "native-boundaries-not-original.json").write_text(canonical(boundaries) + "\n")
    return raw, expected, counts, sha(metadata_raw)


def compare(raw, expected):
    lines = [exact_json(line) for line in raw.splitlines()]
    if len(lines) != len(expected) + 1:
        raise ValueError("original trace cardinality differs")
    polls = observations = 0
    for value, (name, wanted) in zip(lines[:-1], expected.items(), strict=True):
        if value.get("trace") != name or canonical(value.get("observations")) != canonical(wanted):
            for original, native in zip(value.get("observations", []), wanted):
                if canonical(original) != canonical(native):
                    raise ValueError({"trace": name, "original": original, "native": native})
            raise ValueError("original trace differs: " + name)
        if value.get("final_cache_dropped") is not True or value.get("all_outside_poll_access_absent") is not True:
            raise ValueError("original lifetime invariant failed")
        if type(value.get("actual_scoped_future_polls")) is not int or value["actual_scoped_future_polls"] < 0:
            raise ValueError("original poll count invalid")
        polls += value["actual_scoped_future_polls"]
        observations += len(wanted)
    probe = lines[-1]
    required = {"actual_tokio_abort_join_cancelled", "actual_spawn_does_not_inherit", "cancelled_hints_discarded",
                "owned_worker_survives_request_cancel_and_session_drop", "worker_only_releases_own_arc",
                "actual_owned_forget_all_after_cancel", "actual_tokio_panic_join", "final_weak_upgrade_none"}
    if probe.get("probe") != "actual-tokio-lifetime" or set(probe.get("result", {})) != required | {"stdio_async_writer_implemented"}:
        raise ValueError("actual Tokio probe inventory differs")
    if any(probe["result"][key] is not True for key in required) or probe["result"]["stdio_async_writer_implemented"] is not False:
        raise ValueError("actual Tokio lifetime probe failed")
    return {"native_trace_groups": len(expected), "compared_observations": observations,
            "actual_original_scoped_future_polls": polls, "all_semantic_observations_equal": True,
            "actual_tokio_probes": probe["result"]}
