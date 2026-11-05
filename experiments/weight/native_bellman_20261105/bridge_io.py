"""Deterministic, bounded records for the independent native migration replay."""
import gzip
import hashlib
import json
from pathlib import Path
import time


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def raw_bytes(path):
    path = Path(path)
    if path.exists():
        return path.read_bytes()
    manifest = json.loads(path.with_name(path.name+".parts.json").read_text())
    chunks = []
    for part in manifest["parts"]:
        chunk = path.with_name(part["name"]).read_bytes()
        assert len(chunk) == part["bytes"] and sha(chunk) == part["sha256"]
        chunks.append(chunk)
    payload = b"".join(chunks)
    assert len(payload) == manifest["bytes"] and sha(payload) == manifest["sha256"]
    return payload


def read(path):
    payload = raw_bytes(path)
    return json.loads(gzip.decompress(payload) if str(path).endswith(".gz") else payload)


def lines(path):
    payload = raw_bytes(path)
    if str(path).endswith(".gz"):
        payload = gzip.decompress(payload)
    return [json.loads(row) for row in payload.splitlines()]


def write_bytes(path, payload):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    if len(payload) >= 480000:
        parts = []
        for number, offset in enumerate(range(0, len(payload), 479000)):
            chunk = payload[offset:offset+479000]; item = path.with_name(path.name+f".part{number:04d}")
            with item.open("xb") as stream:
                stream.write(chunk)
            parts.append(dict(name=item.name, bytes=len(chunk), sha256=sha(chunk)))
        write(path.with_name(path.name+".parts.json"), dict(bytes=len(payload), sha256=sha(payload), parts=parts))
    else:
        with path.open("xb") as stream:
            stream.write(payload)
    return dict(bytes=len(payload), sha256=sha(payload))


def write(path, value):
    payload = (canonical(value)+"\n").encode()
    if str(path).endswith(".gz"):
        payload = gzip.compress(payload, compresslevel=9, mtime=0)
    return write_bytes(path, payload)


def write_lines(path, values):
    payload = ("\n".join(canonical(value) for value in values)+"\n").encode()
    return write_bytes(path, gzip.compress(payload, compresslevel=9, mtime=0))


def measured_sources(paths):
    return {name: sha(Path(path).read_bytes()) for name, path in paths.items()}


def counter():
    return dict(cpu_seconds=time.process_time(), wall_seconds=time.perf_counter())


def elapsed(start):
    return dict(cpu_seconds=time.process_time()-start["cpu_seconds"], wall_seconds=time.perf_counter()-start["wall_seconds"])
