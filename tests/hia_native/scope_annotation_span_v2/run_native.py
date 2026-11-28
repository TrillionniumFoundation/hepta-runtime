"""Execute every frozen original-domain input on actual HIA images."""
from pathlib import Path
import argparse
import gzip
import hashlib
import json
import os
import struct
import sys
import time

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from build import verify_source
from capture import Capture, line
from cases import cases, domain, frame, packet

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
WORD = lambda raw, at: struct.unpack_from("<Q", raw, at)[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source_sha = verify_source()
    expected = json.loads((ROOT / "DOMAIN.json").read_bytes())
    assert domain() == expected
    build = json.loads(args.build.read_bytes())
    assert build["source_manifest_sha256"] == source_sha
    args.output.mkdir(parents=True, exist_ok=False)
    result = dict(schema="hepta.scope-annotation-span.native.v2", status="RUNNING", cases=0,
                  source_manifest_sha256=source_sha, build_sha256=SHA(args.build.read_bytes()),
                  domain_sha256=SHA((ROOT / "DOMAIN.json").read_bytes()), execution_pid=os.getpid(),
                  original_execution=False, whole_runtime_replaced=False)
    capture = Capture(args.build, args.output)
    started, input_count, output_count = time.monotonic(), 0, 0
    input_hash, output_hash = hashlib.sha256(), hashlib.sha256()
    save = lambda: (args.output / "CAPTURE.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    save()
    try:
        with (args.output / "cases.jsonl").open("x") as index, \
             gzip.open(args.output / "inputs.bin.gz", "wb", compresslevel=1) as inputs, \
             gzip.open(args.output / "observed.bin.gz", "wb", compresslevel=1) as observations:
            for row in cases():
                request = frame(row)
                encoded = packet(request)
                inputs.write(encoded)
                input_hash.update(encoded)
                input_count += len(encoded)
                observed = capture.run(request, row["label"])
                raw = observed.pop("response")
                a, b, c, d = struct.unpack_from("<4Q", raw, 8)
                assert raw[:8] == b"HSCASR02" and len(raw) == 40 + a + b + c + d and a >= 64
                response = raw[40:40 + a]
                assert response[:8] == b"HSCAR002"
                values = dict(expected_kind=WORD(response, 8), expected_wire_bytes=c,
                              expected_category=WORD(response, 32), expected_fallback=WORD(response, 48),
                              expected_warning=WORD(response, 56))
                for key, actual in values.items():
                    if key in row:
                        assert actual == row[key], (row["label"], key, actual, row[key])
                encoded = packet(raw)
                observations.write(encoded)
                output_hash.update(encoded)
                output_count += len(encoded)
                line(index, dict(index=row["index"], label=row["label"], group=row["group"],
                     input_bytes=len(request), input_sha256=SHA(request), observed_bytes=len(raw),
                     observed_sha256=SHA(raw), response_bytes=a, annotation_bytes=b, wire_bytes=c,
                     warning_bytes=d, **observed))
                result["cases"] += 1
        assert input_count == expected["input_bytes"] and input_hash.hexdigest() == expected["input_sha256"]
        assert result["cases"] == len(expected["cases"])
        result["status"] = "COMPLETE_NATIVE_CAPTURE"
    except BaseException as error:
        result.update(status="FAIL", error=dict(type=type(error).__name__, message=str(error)))
        raise
    finally:
        result.update(native_calls=capture.calls, sessions=capture.sessions,
                      physical_buffer_bytes=capture.buffers.logical_bytes, unique_buffer_chunks=len(capture.buffers.known),
                      input_bytes=input_count, input_sha256=input_hash.hexdigest(),
                      observed_bytes=output_count, observed_sha256=output_hash.hexdigest(),
                      elapsed_seconds=time.monotonic() - started)
        capture.close()
        result["source_unchanged"] = verify_source() == source_sha
        save()
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
