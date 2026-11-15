"""Complete retained-byte framing, JSON and process readers; no live I/O fixture.

Byte offsets refer to the exact original raw stream. A hash cannot replace a
missing stream or blob, and JSON booleans are not accepted as integer fields.
"""
from pathlib import Path
import hashlib
import json
import math
import os
import stat
import struct


def need(value, message):
    if not value:
        raise ValueError('batch original evidence: ' + message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                      separators=(',', ':')).encode() + b'\n'


def same(actual, expected, message):
    if type(actual) is bytes or type(expected) is bytes:
        need(type(actual) is type(expected) is bytes and actual == expected, message)
        return
    need(canonical(actual) == canonical(expected), message)


def uint(value, message):
    need(type(value) is int and 0 <= value < 1 << 64, message)
    return value


def positive(value, ceiling, message):
    need(type(value) in (int, float) and math.isfinite(value) and 0 < value <= ceiling, message)
    return value


def fields(value, names, message):
    need(type(value) is dict and set(value) == set(names), message)


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate evidence JSON field')
            result[key] = value
        return result
    def constant(value):
        raise ValueError('batch original evidence: nonfinite JSON token ' + value)
    result = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    def visit(value):
        if type(value) is float:
            need(math.isfinite(value), 'nonfinite evidence JSON number')
        elif type(value) is str:
            value.encode('utf-8')
        elif type(value) is dict:
            for key, child in value.items():
                key.encode('utf-8')
                visit(child)
        elif type(value) is list:
            for child in value: visit(child)
    visit(result)
    return result


def pin(path):
    path = Path(path)
    with path.open('rb') as stream:
        return {'bytes': os.fstat(stream.fileno()).st_size,
                'sha256': hashlib.file_digest(stream, 'sha256').hexdigest()}


class Files:
    """Explicit origin-to-read roots. No fallback to an execution-origin path."""
    def __init__(self, origins):
        self.origins = sorted([(Path(old), Path(new).absolute()) for old, new in origins],
                              key=lambda pair: len(pair[0].parts), reverse=True)
        need(self.origins and all(old.is_absolute() for old, _ in self.origins), 'origin roots')
        self.artifacts = {}

    def path(self, recorded):
        need(type(recorded) is str and Path(recorded).is_absolute(), 'artifact origin is not absolute')
        path = Path(recorded)
        need('..' not in path.parts, 'artifact path traverses parent')
        for old, new in self.origins:
            if path.is_relative_to(old):
                suffix = path.relative_to(old)
                current = new
                for ancestor in (new, *new.parents):
                    need(not stat.S_ISLNK(ancestor.lstat().st_mode), 'read root traverses symlink')
                need(not current.is_symlink() and current.is_dir(), 'invalid explicit read root')
                for component in suffix.parts:
                    current /= component
                    info = current.lstat()
                    need(not stat.S_ISLNK(info.st_mode), 'artifact traverses symlink')
                need(stat.S_ISREG(current.stat().st_mode), 'artifact is not a regular file')
                return current
        raise ValueError('batch original evidence: unmapped artifact origin ' + recorded)

    def file(self, recorded):
        path = self.path(recorded)
        actual = pin(path)
        previous = self.artifacts.setdefault(recorded, actual)
        same(previous, actual, 'artifact changed while reading')
        return path

    def raw(self, recorded):
        raw = self.file(recorded).read_bytes()
        same({'bytes': len(raw), 'sha256': sha(raw)}, self.artifacts[recorded], 'artifact changed during full read')
        return raw

    def json(self, recorded):
        return strict_json(self.raw(recorded))


def parse_records(raw, magic, *, counted=True):
    need(type(raw) is bytes and len(raw) >= 8 and raw[:8] == magic, 'binary record magic')
    at = 8
    def take(n):
        nonlocal at
        need(type(n) is int and 0 <= n <= len(raw) - at, 'truncated binary record')
        begin = at
        at += n
        return raw[begin:at]
    def word():
        return struct.unpack('<Q', take(8))[0]
    count = word() if counted else None
    need(count is None or count <= (len(raw)-at)//16, 'impossible binary record count')
    rows = []
    while at < len(raw) and (count is None or len(rows) < count):
        begin = at
        size, blob_count = word(), word()
        metadata_at = at
        metadata_raw = take(size)
        metadata = strict_json(metadata_raw)
        need(type(metadata) is dict and blob_count <= (len(raw)-at)//8, 'record metadata/blob extent')
        blobs = []
        for _ in range(blob_count):
            n = word()
            body_at = at
            body = take(n)
            blobs.append({'offset': body_at, 'bytes': n, 'sha256': sha(body)})
        rows.append({'metadata': metadata,
                     'metadata_span': {'offset': metadata_at, 'bytes': size, 'sha256': sha(metadata_raw)},
                     'blobs': blobs,
                     'record': {'offset': begin, 'bytes': at-begin, 'sha256': sha(raw[begin:at])}})
    need(at == len(raw) and (count is None or len(rows) == count), 'trailing or missing complete records')
    return rows


def blob(raw, row, index, *, text=False):
    need(type(index) is int and 0 <= index < len(row['blobs']), 'invalid body index')
    span = row['blobs'][index]
    body = raw[span['offset']:span['offset']+span['bytes']]
    need(len(body) == span['bytes'] and sha(body) == span['sha256'], 'body changed after parse')
    if text:
        body.decode('utf-8')
    return body


def actual_process(row, command, cwd, *, timeout=180):
    need(type(row) is dict, 'missing actual process record')
    same(row.get('command'), command, 'actual process argv')
    same(row.get('cwd'), str(cwd), 'actual process cwd')
    need(uint(row.get('pid'), 'actual process PID') > 0, 'zero process PID')
    same(row.get('timeout_seconds'), timeout, 'actual process deadline')
    need(row.get('timed_out') is False and row.get('start_error') is None, 'actual timeout/start failure')
    same(row.get('exit_code'), 0, 'actual process exit')
    start = uint(row.get('started_monotonic_ns'), 'actual monotonic start')
    finish = uint(row.get('finished_monotonic_ns'), 'actual monotonic finish')
    need(finish > start, 'nonpositive process interval')
    positive(row.get('elapsed_seconds'), timeout, 'actual elapsed budget')
    same(row['elapsed_seconds'], (finish-start)/1e9, 'actual elapsed interval identity')
    # Intervals from different boots/runners are never ordered against each other.
    for name in ('stdout', 'stderr'):
        pin_value = row.get(name)
        need(type(pin_value) is dict, 'missing full process '+name)
        uint(pin_value.get('bytes'), 'process '+name+' extent')
        need(type(pin_value.get('sha256')) is str and len(pin_value['sha256']) == 64 and
             all(c in '0123456789abcdef' for c in pin_value['sha256']), 'process '+name+' identity')
    return row
