"""Read actual typed/public/private behavior; never computes the expected answer."""
from pathlib import Path
import hashlib
import itertools
import json
import os
import struct
import subprocess
import time

SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def request(params, *, command=0, mode=0, metadata=b"{}", legacy=None):
    previous = b"" if legacy is None else legacy
    return (b"HMWDRQ01" + struct.pack("<7Q", command, mode, int(legacy is not None),
            len(metadata), len(previous), len(params), 0) + metadata + previous + params)


def split(raw):
    at = 0
    results = []
    while at < len(raw):
        assert len(raw) - at >= 8
        size = struct.unpack_from("<Q", raw, at)[0]
        at += 8
        frame = raw[at:at + size]
        assert len(frame) == size and size >= 56 and frame[:8] == b"HMWDRS01"
        code, latch, current, text, normalized, zero = struct.unpack_from("<6Q", frame, 8)
        assert zero == 0 and code <= 2 and latch <= 1 and 56 + current + text + normalized == size
        payload = frame[56:]
        results.append(dict(code=code, latch=latch, current_hex=payload[:current].hex(),
            result=payload[current:current + text].decode(),
            normalized=payload[current + text:].decode()))
        at += size
    assert at == len(raw)
    return results


def main(root):
    root = Path(root)
    binary = root / "target/release/hia-workdir-reference"
    out = root / "probe-v1"
    out.mkdir(mode=0o700, exist_ok=False)
    fixture = out / "fixture"
    fixture.mkdir()
    (fixture / "sub").mkdir()
    (fixture / "sub/two").mkdir()
    (fixture / "ordinary").write_bytes(b"data")
    (fixture / "link").symlink_to("sub", target_is_directory=True)
    (fixture / "bad-link").symlink_to("missing")
    (fixture / "loop").symlink_to("loop")
    (fixture / " spaced ").mkdir()
    (fixture / "left|right").mkdir()
    values = [None, False, True, 0, -1, 1, 1.0, -0.0, 1e-12, 1e40, "", "str", [], {}, [None], [None, None], [None, None, None]]
    cases = []
    def add(label, value):
        cases.append((label, json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()))
    for i, value in enumerate(values):
        add("root-" + str(i), value)
        add("path-" + str(i), {"path": value})
        add("reset-" + str(i), {"reset": value})
    for a, b in itertools.product(values, values):
        add("array-" + str(len(cases)), [a, b])
        add("map-" + str(len(cases)), {"path": a, "reset": b})
    for n in range(8):
        add("sequence-length-" + str(n), [None] * n)
    for value in ["\0", "\n", "\r", "\t", "\b", "\f", "\x1b", "\x7f", "\u0085", "\u00a0", "\u200b", "\u2028", "\u2029", "\u202e", "\u2060", "\ufeff", "a\\\"b", "中文🙂", "é", "e\u0301"]:
        add("string-debug-" + str(len(cases)), {"reset": value})
    for raw in [b'18446744073709551615', b'-9223372036854775808', b'18446744073709551616',
                b'-9223372036854775809', b'1.7976931348623157e308', b'5e-324', b'1e16', b'1e15',
                b'1e-6', b'1e-7', b'-0', b'1.0000000000000001', b'0.00000000000000001']:
        cases.append(("number-debug-" + str(len(cases)), b'{"path":' + raw + b'}'))
    for raw in [b'{"path":false,"path":"sub"}', b'{"path":"sub","path":false}',
                b'{"reset":null,"reset":true}', b'{"p\\u0061th":"sub"}',
                b'{"path":true,"reset":1}', b'{"reset":1,"path":true}',
                b'{"unknown":{"path":false},"reset":true}', b'["sub",true,null]',
                b'[false,true,null]', b'{"z":[null,false],"a":{},"path":"sub"}']:
        cases.append(("priority-" + str(len(cases)), raw))
    records = []
    def run(name, rows):
        framed = [request(params, **options) for _, params, options in rows]
        wire = b"".join(struct.pack("<Q", len(x)) + x for x in framed)
        start = time.monotonic()
        p = subprocess.run([str(binary), "--session-root", str(fixture)], input=wire, capture_output=True, timeout=180)
        for suffix, raw in [("input.bin", wire), ("stdout", p.stdout), ("stderr", p.stderr)]:
            (out / (name + "." + suffix)).write_bytes(raw)
        receipt = dict(name=name, exit_code=p.returncode, elapsed_seconds=time.monotonic() - start,
            input_bytes=len(wire), input_sha256=SHA(wire), stdout_bytes=len(p.stdout), stdout_sha256=SHA(p.stdout),
            stderr_bytes=len(p.stderr), stderr_sha256=SHA(p.stderr), actual_original_process=True)
        records.append(receipt)
        assert p.returncode == 0, (name, p.stderr.decode(errors="replace"))
        bootstrap = json.loads(p.stderr)
        assert bootstrap["schema"] == "hepta.client-context.actual-sdk-bootstrap.v1"
        results = split(p.stdout)
        assert len(rows) == len(results)
        entries = [dict(label=label, parameters=raw.decode(), options={k: v.decode() if isinstance(v, bytes) else v for k, v in options.items()}, observed=result)
                   for (label, raw, options), result in zip(rows, results, strict=True)]
        (out / (name + ".json")).write_text(json.dumps(dict(process=receipt, cases=entries), ensure_ascii=False, indent=2, sort_keys=True) + "\n")
        return entries
    typed = run("parameters", [(name, raw, {}) for name, raw in cases])
    public_rows = [("missing", b'{}', {"command": 1}),
        ("reset-null", b'{"reset":null}', {"command": 1}),
        ("private-get", b'{}', {"command": 2}),
        ("set-sub", b'{"path":"sub"}', {"command": 1}),
        ("get-after-set", b'{}', {"command": 2}),
        ("set-parent", b'{"path":".."}', {"command": 1}),
        ("set-link", b'{"path":"link"}', {"command": 1}),
        ("reset-path-empty", b'{"reset":true,"path":""}', {"command": 1}),
        ("reset-wrong-type", b'{"reset":true,"path":false}', {"command": 1}),
        ("plain-file", b'{"path":"ordinary"}', {"command": 1}),
        ("missing-file", b'{"path":"missing"}', {"command": 1}),
        ("symlink-loop", b'{"path":"loop"}', {"command": 1}),
        ("nul", b'{"path":"x\\u0000y"}', {"command": 1}),
        ("literal-roots", b'{"path":"left|right"}', {"command": 1}),
        ("reset", b'{"reset":true}', {"command": 1})]
    public = run("public", public_rows)
    meta = json.dumps({"io.modelcontextprotocol/clientCapabilities": {"experimental": {"session": {"workdir": str(fixture / "sub")}}}}, separators=(",", ":")).encode()
    priority = run("latch-priority", [("invalid-does-not-latch", b'{"path":false}', {"command": 1, "metadata": meta}),
        ("valid-sets-context-first", b'{"path":"two"}', {"command": 1, "metadata": meta}),
        ("reset-retains-root", b'{"reset":true}', {"command": 1, "metadata": meta})])
    assert priority[0]["observed"]["latch"] == 0
    assert priority[1]["observed"]["latch"] == 1
    report = dict(schema="hepta.workdir.original-probe.v1", status="PASS", processes=records,
        typed_cases=len(typed), public_cases=len(public), priority_cases=len(priority),
        accepted=sum(x["observed"]["code"] == 0 for x in typed),
        rejected=sum(x["observed"]["code"] == 2 for x in typed),
        actual_rmcp_request_context=True, actual_original_workdir=True,
        native_executions=0, remote_effects_executed=0, whole_runtime_replaced=False,
        original_binary_sha256=SHA(binary.read_bytes()))
    (out / "result.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    return report


if __name__ == "__main__":
    import sys
    print(json.dumps(main(sys.argv[1]), sort_keys=True))
